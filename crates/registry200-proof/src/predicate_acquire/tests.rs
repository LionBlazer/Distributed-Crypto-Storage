//! Conditional mathematical fixtures only. Genuine prerequisite pairs live in the consumer tests.
use super::*;
use crate::{
    Val,
    admission::CanonicalSource,
    coefficient_encoding::{
        commitment,
        statement::{BfvBinding, Expected as QueryExpected, Statement as Query},
    },
    lifecycle::statement::{self as life, Statement as Lifecycle},
    source,
};
use circuit::{Opening, Witness};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn opening() -> Opening {
    let mut mask = [0; 32];
    mask[0] = 1;
    mask[31] = 0x80;
    Opening {
        mask,
        transaction: 1 + (1u64 << 40),
        principal: 1,
        controller: [0x41; 32],
        revision: 3 + (1u64 << 40),
        sequence: 9 + (1u64 << 40),
        mode: 4,
        wait: 2,
        offset: 1,
        limit: 2,
        projection: 3,
        flags: [
            [false, false, false, true],
            [false, true, false, false],
            [true, false, false, true],
        ],
        salts: [[17; 4], [19; 4], [23; 4]],
    }
}
fn limbs(value: u64) -> [Val; 2] {
    [
        Val::from_u32(value as u32),
        Val::from_u32((value >> 32) as u32),
    ]
}
fn fixture(command_padding: bool) -> Expected {
    let owner = compact_store::Owner::generate([0x42; 16]).unwrap();
    let limits = source::statement::limits();
    let data = owner
        .seal(
            compact_store::Layout {
                schema: source::DATA_SCHEMA,
                row_width: 3,
                rows_per_page: 256,
                row_count: 4,
            },
            &[0; 12],
            limits,
        )
        .unwrap();
    let index = owner
        .seal(
            compact_store::Layout {
                schema: source::INDEX_SCHEMA,
                row_width: 1,
                rows_per_page: 4096,
                row_count: 2336,
            },
            &[0; 2336],
            limits,
        )
        .unwrap();
    let source = CanonicalSource::checked(
        [&data.encode(), &index.encode()],
        [data.commitment(), index.commitment()],
        [0xA7; 32],
        [0; 32],
        [0; 32],
    )
    .unwrap();
    let binding = BfvBinding::new(
        [0x53; 32],
        bfv_key_transform::Statement {
            expected: bfv_key_transform::Expected {
                descriptor: bfv_key_transform::SetupDescriptor {
                    database: [0x42; 16],
                    key_domain: [0x71; 16],
                    public_setup_digest: [0x95; 32],
                    key_epoch: 1,
                },
                coefficients: [Val::ONE; 4],
            },
            transformed: [Val::TWO; 4],
        },
    );
    let draft =
        QueryExpected::private_mask(&source, binding.clone(), [0xB1; 32], [0xB2; 32], [0; 32])
            .unwrap();
    let o = opening();
    let cmask = commitment::command_digest(&commitment::command_fields(
        &draft,
        o.mask,
        o.salts[0].map(Val::from_u64),
    ));
    let query = Query {
        expected: QueryExpected::private_mask(
            &source,
            binding,
            [0xB1; 32],
            [0xB2; 32],
            source::statement::encode_digest(cmask),
        )
        .unwrap(),
        encoded: [Val::from_u8(37); 4],
    };
    let mut e = life::Expected::transition(
        source.claim(),
        [0xC1; 32],
        [0xC2; 32],
        [0; 32],
        [0; 32],
        [0; 32],
    )
    .unwrap();
    let command = command_fields(&e, &o, command_padding);
    e.phase = life::Phase::Transition {
        old: [Val::ZERO; 4],
        command: life::digest(&command),
    };
    let mut l = Lifecycle {
        expected: e,
        next: [Val::from_u8(41); 4],
        result: [Val::ZERO; 4],
    };
    l.result = life::digest(&result_fields(&l, &o));
    Expected::new(&query, &l).unwrap()
}
// Independent original field ABI, not the shared prefix or new AIR assembler.
fn command_fields(e: &life::Expected, o: &Opening, padding: bool) -> Vec<Val> {
    let life::Phase::Transition { old, .. } = e.phase else {
        unreachable!()
    };
    let mut out: Vec<_> = source::statement::words(&life::COMMAND_DOMAIN)
        .chain([Val::from_u8(2)])
        .chain(e.context())
        .chain(old)
        .collect();
    out.push(Val::ONE);
    out.extend(limbs(o.transaction));
    out.push(Val::from_u8(o.principal));
    out.extend(source::statement::words(&o.controller));
    out.extend(limbs(o.revision));
    out.extend(limbs(o.sequence));
    out.extend(source::statement::words(&o.mask));
    out.extend([o.mode, o.wait, o.offset, o.limit, o.projection].map(Val::from_u8));
    out.extend([Val::ZERO; 17]);
    out.extend(o.salts[1].map(Val::from_u64));
    out.push(Val::from_bool(padding));
    assert_eq!(out.len(), 160);
    out
}
fn result_fields(l: &Lifecycle, o: &Opening) -> Vec<Val> {
    let life::Phase::Transition { old, command } = l.expected.phase else {
        unreachable!()
    };
    let mut out: Vec<_> = source::statement::words(&life::RESULT_DOMAIN)
        .chain([Val::from_u8(2)])
        .chain(l.expected.context())
        .chain(old)
        .chain(command)
        .chain(l.next)
        .collect();
    out.extend([Val::ONE, Val::ZERO]);
    out.extend(limbs(o.transaction));
    out.extend(o.flags.iter().flatten().map(|v| Val::from_bool(*v)));
    out.extend(o.salts[2].map(Val::from_u64));
    out.extend([Val::ZERO; 7]);
    assert_eq!(out.len(), 144);
    out
}
fn reject(e: &Expected, trace: RowMajorMatrix<Val>) {
    let backend = crate::fixed::Backend::predicate_acquire(e).unwrap();
    if let Ok(Ok(proof)) = catch_unwind(AssertUnwindSafe(|| backend.prove(trace))) {
        assert!(
            backend.verify(&proof).is_err(),
            "coherent false link trace accepted"
        );
    }
}
// Rebuild ALL real Poseidon gadget/control cells, including final checkpoints.
// Only the attacker-selected message field differs from the mandatory bank mapping.
fn refresh(
    e: &Expected,
    trace: &mut RowMajorMatrix<Val>,
    foreign_mask: Option<[u8; 32]>,
    pad: bool,
) -> [[Val; 4]; 3] {
    use layout::*;
    let air = air::PredicateAcquireAir::new(e);
    let mut cp = [Val::ZERO; 12];
    let mut roots = [[Val::ZERO; 4]; 3];
    for (r, row) in trace
        .values
        .as_chunks_mut::<WIDTH>()
        .0
        .iter_mut()
        .enumerate()
    {
        row[CP..CP + 12].copy_from_slice(&cp);
        let mut input = [Val::ZERO; 12];
        if let Some((stream, block)) = absorb(r) {
            for (i, v) in input[..8].iter_mut().enumerate() {
                let f = 8 * block + i;
                *v = air.field(row, stream, f);
                if let Some(mask) = foreign_mask
                    && matches!(stream, Stream::Mask)
                    && (29..=36).contains(&f)
                {
                    *v = source::statement::words(&mask).nth(f - 29).unwrap();
                }
                if pad && matches!(stream, Stream::Command) && f == 159 {
                    *v = Val::ONE;
                }
            }
            if !reset(r) {
                input[8..].copy_from_slice(&cp[8..]);
            }
        }
        let output = bfv_hiding_stark::poseidon::write(&mut row[..CP], input);
        if absorb(r).is_some() {
            cp = output;
        }
        if let Some(index) = [5, 25, 43].iter().position(|last| *last == r) {
            roots[index] = output[..4].try_into().unwrap();
        }
    }
    roots
}

#[test]
fn shared_command_result_prefixes_preserve_every_original_field_and_high_u64_limbs() {
    let e = fixture(false);
    let o = opening();
    let witness = Witness::new(&e, opening()).unwrap();
    let trace = witness.trace(&e).unwrap();
    let row = &trace.values[..layout::WIDTH];
    let air = air::PredicateAcquireAir::new(&e);
    let expected_cmd = command_fields(&e.lifecycle().expected, &o, false);
    let expected_result = result_fields(e.lifecycle(), &o);
    for (stream, expected) in [
        (layout::Stream::Command, expected_cmd),
        (layout::Stream::Result, expected_result),
        (
            layout::Stream::Mask,
            commitment::command_fields(&e.query().expected, o.mask, o.salts[0].map(Val::from_u64))
                .to_vec(),
        ),
    ] {
        let actual: Vec<Val> = (0..expected.len())
            .map(|f| air.field(row, stream, f))
            .collect();
        assert_eq!(actual, expected);
    }
    assert_eq!(e.values().len(), 896);
    assert_eq!(layout::WIDTH, 1005);
    let backend = crate::fixed::Backend::predicate_acquire(&e).unwrap();
    let proof = backend.prove(trace).unwrap();
    backend.verify(&proof).unwrap();
    let bytes = wire::encode(&e, &proof).unwrap();
    assert!(!wire::payload(&e, &bytes).unwrap().is_empty());
}

#[test]
fn repaired_hash_roots_cannot_hide_mask_bit255_substitution_or_command_padding() {
    let e = fixture(false);
    let witness = Witness::new(&e, opening()).unwrap();
    let mut mask = opening().mask;
    mask[31] ^= 0x80;
    let q = &e.query().expected;
    let cmask =
        commitment::command_digest(&commitment::command_fields(q, mask, [Val::from_u8(17); 4]));
    let canonical = CanonicalSource::checked_claim(q.source_claim()).unwrap();
    let foreign = Query {
        expected: QueryExpected::private_mask(
            &canonical,
            q.bfv().clone(),
            q.sql_identity(),
            q.public_nonce(),
            source::statement::encode_digest(cmask),
        )
        .unwrap(),
        encoded: e.query().encoded,
    };
    let mixed = Expected::new(&foreign, e.lifecycle()).unwrap();
    let mut trace = witness.trace(&mixed).unwrap();
    let roots = refresh(&mixed, &mut trace, Some(mask), false);
    assert_eq!(
        roots,
        [
            cmask,
            mixed.roots()[4..8].try_into().unwrap(),
            mixed.lifecycle().result
        ]
    );
    reject(&mixed, trace);
    let padding = fixture(true);
    let mut trace = witness.trace(&padding).unwrap();
    let roots = refresh(&padding, &mut trace, None, true);
    assert_eq!(
        roots,
        [
            padding.query().expected.command(),
            padding.roots()[4..8].try_into().unwrap(),
            padding.lifecycle().result
        ]
    );
    reject(&padding, trace);
}

#[test]
fn complete_context_identity_caps_and_missing_prerequisites_never_mint_verified_link() {
    let e = fixture(false);
    let witness = Witness::new(&e, opening()).unwrap();
    let backend = crate::fixed::Backend::predicate_acquire(&e).unwrap();
    let proof = backend.prove(witness.trace(&e).unwrap()).unwrap();
    let bytes = wire::encode(&e, &proof).unwrap();
    for at in [0, 8, 9, 16, 47, 48, 79, 80, 111, 112, 116, 119] {
        let mut bad = bytes.clone();
        bad[at] ^= 1;
        assert!(wire::payload(&e, &bad).is_err(), "header {at}");
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(wire::payload(&e, &trailing).is_err());
    let parents = Prerequisites {
        query: &[],
        lifecycle: &[],
    };
    assert!(matches!(
        verify(&e, &parents, &bytes),
        Err(wire::Error::Prerequisite)
    ));
    assert!(matches!(
        prove(&e, &witness, &parents),
        Err(wire::Error::Prerequisite)
    ));
    // A bounded child-resource bomb remains unread when genuine parents are absent.
    let mut bomb = bytes[..wire::HEADER].to_vec();
    bomb[112..116].copy_from_slice(&9u32.to_le_bytes());
    bomb.extend([0xff; 9]);
    assert!(matches!(
        verify(&e, &parents, &bomb),
        Err(wire::Error::Prerequisite)
    ));
    let mut query = e.query().clone();
    query.encoded[3] += Val::ONE;
    let changed = Expected::new(&query, e.lifecycle()).unwrap();
    assert_ne!(changed.identity(), e.identity());
    assert!(matches!(
        prove(&changed, &witness, &parents),
        Err(wire::Error::Proof(crate::BackendError::Shape))
    ));
    assert!(wire::payload(&changed, &bytes).is_err());
    assert!(wire::payload(&e, &vec![0; wire::MAX_FRAME + 1]).is_err());
}
