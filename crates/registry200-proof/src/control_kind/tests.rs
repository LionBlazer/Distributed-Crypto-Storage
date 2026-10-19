//! Explicit PUBLIC NONSECRET inputs. Conditional AIR controls are labelled;
//! only the final owning scenario supplies and verifies genuine prerequisite pairs.
use super::*;
use crate::{
    Val,
    admission::{self, CanonicalSource},
    lifecycle::{
        self,
        circuit::{
            Witness as LifecycleWitness, commitment,
            model::{Command, Operation, Registry},
        },
        statement::{self as life, Phase, Statement as Lifecycle},
    },
    source,
};
use bfv_hiding_stark::{Config, TRACE_HEIGHT, codec, poseidon};
use circuit::{Opening, Witness};
use compact_store::{Layout, Owner};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::Proof;
use std::panic::{AssertUnwindSafe, catch_unwind};
use zeroize::Zeroizing;

struct Fixture {
    source: CanonicalSource,
    mathematical: LifecycleWitness,
}
fn fixture() -> Fixture {
    let owner = Owner::from_key([0x42; 16], [0x73; 16], Zeroizing::new([0x71; 32]));
    let data = [255, 0, 0, 0, 255, 255, 255, 0, 1, 128, 255, 0];
    let stored = owner
        .seal(
            Layout {
                schema: source::DATA_SCHEMA,
                row_width: 3,
                rows_per_page: 256,
                row_count: 4,
            },
            &data,
            source::statement::limits(),
        )
        .unwrap();
    let suffix: Vec<_> =
        include_str!("../../../compact-query/tests/fixtures/index-v3-four-row-suffix.hex")
            .lines()
            .filter(|l| !l.starts_with('#'))
            .flat_map(str::split_whitespace)
            .map(|s| u8::from_str_radix(s, 16).unwrap())
            .collect();
    assert_eq!(suffix.len(), 2224);
    let mut index = stored.commitment().encode().to_vec();
    index.extend(suffix);
    let indexed = owner
        .seal(
            Layout {
                schema: source::INDEX_SCHEMA,
                row_width: 1,
                rows_per_page: 4096,
                row_count: 2336,
            },
            &index,
            source::statement::limits(),
        )
        .unwrap();
    let key = source::commitment::digest(&source::commitment::key_fields(
        &stored.commitment().encode(),
        [0x71; 32],
        [Val::ONE; 4],
    ));
    let mut claim = source::Statement::checked_relation(
        source::Relation::CanonicalIndex,
        [&stored.encode(), &indexed.encode()],
        [stored.commitment(), indexed.commitment()],
        [0x83; 32],
        source::statement::encode_digest(key),
        [0; 32],
    )
    .unwrap();
    let mut plain = [0; 2348];
    plain[..12].copy_from_slice(&data);
    plain[12..].copy_from_slice(&index);
    claim.open_commitment = source::commitment::digest(&source::commitment::opening_fields(
        &claim,
        [Val::TWO; 4],
        &plain,
    ));
    let source = CanonicalSource::checked_claim(&claim).unwrap();
    Fixture {
        source,
        mathematical: LifecycleWitness {
            plain,
            controllers: [[0x41; 32], [0x42; 32]],
            salts: [
                [Val::TWO; 4],
                [Val::from_u8(3); 4],
                [Val::from_u8(4); 4],
                [Val::from_u8(5); 4],
                [Val::from_u8(6); 4],
                [Val::from_u8(7); 4],
            ],
            old: Registry::default(),
            command: None,
        },
    }
}
fn bootstrap(f: &Fixture) -> life::Expected {
    let mut e =
        life::Expected::bootstrap(f.source.claim(), [0xa7; 32], [0xb7; 32], [0; 32]).unwrap();
    e.enrollment = source::commitment::digest(&commitment::enrollment_fields(&e, &f.mathematical));
    e
}
fn fields(e: &life::Expected, w: &LifecycleWitness) -> [u64; 160] {
    commitment::command_fields(e, w, w.command.as_ref().unwrap())
        .into_iter()
        .map(|v| v.as_canonical_u64())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}
fn transition(f: &Fixture, w: &LifecycleWitness, parent: u8) -> (Lifecycle, [u64; 160]) {
    let boot = bootstrap(f);
    let mut e = life::Expected::transition(
        f.source.claim(),
        boot.genesis,
        [parent; 32],
        life::encoded(boot.enrollment),
        [0; 32],
        [0; 32],
    )
    .unwrap();
    let old = life::digest(&commitment::registry_fields(&e, w, &w.old, w.salts[2]));
    e.phase = Phase::Transition {
        old,
        command: [Val::ZERO; 4],
    };
    let command = fields(&e, w);
    e.phase = Phase::Transition {
        old,
        command: life::digest(&command.map(Val::from_u64)),
    };
    (w.statement(&e).unwrap(), command)
}
fn original_opening(fields: [u64; 160]) -> Opening {
    Opening::new(fields).unwrap()
}
fn reject_raw(e: &Expected, trace: RowMajorMatrix<Val>) {
    let backend = crate::fixed::Backend::control_kind(e).unwrap();
    if let Ok(Ok(proof)) = catch_unwind(AssertUnwindSafe(|| backend.prove(trace))) {
        assert!(
            backend.verify(&proof).is_err(),
            "false control-kind AIR accepted"
        );
    }
}
// Rebuild every real P2 gadget and checkpoint. Only an explicitly forged field
// differs from the immutable bank; there is no fake proof or verifier callback.
fn refresh(
    e: &Expected,
    trace: &mut RowMajorMatrix<Val>,
    forged: Option<(usize, Val)>,
) -> [Val; 4] {
    use layout::*;
    let air = air::ControlKindAir::new(e);
    let mut cp = [Val::ZERO; 12];
    let mut root = [Val::ZERO; 4];
    for (r, row) in trace
        .values
        .as_chunks_mut::<WIDTH>()
        .0
        .iter_mut()
        .enumerate()
    {
        row[CP..CP + 12].copy_from_slice(&cp);
        let mut input = [Val::ZERO; 12];
        if r < END {
            for (i, value) in input[..8].iter_mut().enumerate() {
                let f = 8 * r + i;
                *value = air.field(row, f);
                if let Some((at, changed)) = forged
                    && f == at
                {
                    *value = changed;
                }
            }
            if r != 0 {
                input[8..].copy_from_slice(&cp[8..]);
            }
        }
        let output = poseidon::write(&mut row[..CP], input);
        if r < END {
            cp = output;
        }
        if r == END - 1 {
            root.copy_from_slice(&output[..4]);
        }
    }
    root
}

#[test]
fn original_cmd160_high_limbs_and_private_operation_membership_have_the_exact_abi() {
    let f = fixture();
    let mut e = bootstrap(&f);
    e.phase = Phase::Transition {
        old: [Val::from_u8(9); 4],
        command: [Val::ZERO; 4],
    };
    let mut command = Command::control(Operation::Savepoint, (1u64 << 40) + 3, 2, (1u64 << 42) + 7);
    command.name = [0x91; 32];
    let original = commitment::command_fields_opening(
        &e,
        &command,
        &commitment::CommandFieldsOpening {
            controller: [0x42; 32],
            revision: (1u64 << 43) + 11,
            salt: [Val::from_u8(13); 4],
        },
    );
    e.phase = Phase::Transition {
        old: [Val::from_u8(9); 4],
        command: life::digest(&original),
    };
    // Conditional mathematical statement; no Lifecycle proof is claimed here.
    let lifecycle = Lifecycle {
        expected: e,
        next: [Val::from_u8(17); 4],
        result: [Val::from_u8(19); 4],
    };
    let e = Expected::new(&lifecycle).unwrap();
    let raw = original
        .iter()
        .map(|v| v.as_canonical_u64())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let witness = Witness::new(&e, original_opening(raw)).unwrap();
    let trace = witness.trace(&e).unwrap();
    let air = air::ControlKindAir::new(&e);
    let row = &trace.values[..layout::WIDTH];
    let actual: Vec<Val> = (0..160).map(|f| air.field(row, f)).collect();
    assert_eq!(actual, original);
    assert_eq!(e.values().len(), 815);
    assert_eq!(layout::WIDTH, 315);
    println!("control_kind_security={:?}", analyze(&e).unwrap());
    let backend = crate::fixed::Backend::control_kind(&e).unwrap();
    let proof = backend.prove(trace).unwrap();
    backend.verify(&proof).unwrap();
    let frame = wire::encode(&e, &proof).unwrap();
    assert!(matches!(
        verify(&e, &Prerequisites { lifecycle: &[] }, &frame),
        Err(wire::Error::Prerequisite)
    ));
}

#[test]
fn coherent_padding_zero_membership_and_last_row_changes_fail_the_actual_air() {
    use layout::*;
    let f = fixture();
    let mut w = f.mathematical.clone();
    w.command = Some(Command::control(Operation::Begin, 1, 1, 0));
    let (life, raw) = transition(&f, &w, 0xb7);
    let e = Expected::new(&life).unwrap();
    let witness = Witness::new(&e, original_opening(raw)).unwrap();
    let mut padded = raw;
    padded[159] = 1;
    let mut l = life.clone();
    if let Phase::Transition { old, .. } = l.expected.phase {
        l.expected.phase = Phase::Transition {
            old,
            command: life::digest(&padded.map(Val::from_u64)),
        };
    }
    let changed = Expected::new(&l).unwrap();
    let mut trace = witness.trace(&changed).unwrap();
    assert_eq!(
        refresh(&changed, &mut trace, Some((159, Val::ONE))),
        changed.roots().1
    );
    reject_raw(&changed, trace);
    let mut trace = witness.trace(&e).unwrap();
    for row in trace.values.as_chunks_mut::<WIDTH>().0 {
        row[OPCODE..SUFFIX].fill(Val::ZERO);
    }
    assert_eq!(refresh(&e, &mut trace, None), e.roots().1);
    reject_raw(&e, trace); // sum is zero, opcode/hash still Begin0
    for at in [SUFFIX, WIDTH - 1, CP + 8] {
        let mut trace = witness.trace(&e).unwrap();
        trace.values[(TRACE_HEIGHT - 1) * WIDTH + at] += Val::ONE;
        reject_raw(&e, trace); // root row already passed; bank/carry must remain immutable through511
    }
}

#[test]
fn complete_expected_frame_bounds_and_missing_prerequisites_fail_closed() {
    let f = fixture();
    let mut w = f.mathematical.clone();
    w.command = Some(Command::control(Operation::Begin, 1, 1, 0));
    let (life, raw) = transition(&f, &w, 0xb7);
    let e = Expected::new(&life).unwrap();
    let witness = Witness::new(&e, original_opening(raw)).unwrap();
    let backend = crate::fixed::Backend::control_kind(&e).unwrap();
    let proof = backend.prove(witness.trace(&e).unwrap()).unwrap();
    let bytes = wire::encode(&e, &proof).unwrap();
    for at in [0, 8, 9, 16, 47, 48, 79, 80, 111, 112, 116, 119] {
        let mut bad = bytes.clone();
        bad[at] ^= 1;
        assert!(wire::payload(&e, &bad).is_err(), "header {at}");
    }
    for cut in [0, 7, wire::HEADER - 1, bytes.len() - 1] {
        assert!(wire::payload(&e, &bytes[..cut]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(wire::payload(&e, &trailing).is_err());
    assert!(matches!(
        wire::payload(&e, &vec![0; wire::MAX_FRAME + 1]),
        Err(wire::Error::ResourceLimit)
    ));
    assert!(matches!(
        prove(&e, &witness, &Prerequisites { lifecycle: &[] }),
        Err(wire::Error::Prerequisite)
    ));
    let mut bomb = bytes[..wire::HEADER].to_vec();
    bomb[112..116].copy_from_slice(&9u32.to_le_bytes());
    bomb.extend([0xff; 9]);
    assert!(matches!(
        verify(&e, &Prerequisites { lifecycle: &[] }, &bomb),
        Err(wire::Error::Prerequisite)
    ));
    for case in 0..9 {
        let mut l = life.clone();
        match case {
            0 => l.expected.genesis[31] ^= 1,
            1 => l.expected.parent[31] ^= 1,
            2 => l.expected.source.request[31] ^= 1,
            3 => l.expected.enrollment[3] += Val::ONE,
            4 => l.expected.source.key_commitment[3] += Val::ONE,
            5 => l.expected.source.open_commitment[3] += Val::ONE,
            6 => l.next[3] += Val::ONE,
            7 => l.result[3] += Val::ONE,
            _ => {
                if let Phase::Transition { old, command } = l.expected.phase {
                    let mut old = old;
                    old[3] += Val::ONE;
                    l.expected.phase = Phase::Transition { old, command };
                }
            }
        }
        let other = Expected::new(&l).unwrap();
        assert_ne!(e.identity(), other.identity());
        assert!(matches!(
            prove(&other, &witness, &Prerequisites { lifecycle: &[] }),
            Err(wire::Error::Proof(crate::BackendError::Shape))
        ));
        assert!(wire::payload(&other, &bytes).is_err());
    }
    let mut bad = f.source.claim().clone();
    bad.packets[1].pop();
    let mut l = life;
    l.expected.source = bad;
    assert!(Expected::new(&l).is_err());
    let mut noncanonical = raw;
    noncanonical[158] = Val::ORDER_U64;
    assert!(Opening::new(noncanonical).is_err());
    let bootstrap = Lifecycle {
        expected: bootstrap(&f),
        next: [Val::ZERO; 4],
        result: [Val::ZERO; 4],
    };
    assert!(Expected::new(&bootstrap).is_err());
}

fn actual_pair(
    e: &life::Expected,
    w: &LifecycleWitness,
    source_bytes: &[u8],
) -> (Lifecycle, Vec<u8>) {
    let checked = admission::Expected::checked_claim(e).unwrap();
    let prepared = lifecycle::PreparedWitness::new(&checked, w.clone()).unwrap();
    let evidence = lifecycle::prove(&checked, &prepared, source_bytes).unwrap();
    drop(prepared);
    let (s, bytes) = evidence.into_parts();
    assert_eq!(
        crate::wire::verify_claim(e, &bytes).unwrap().values(),
        s.values()
    );
    (s, bytes)
}

#[test]
fn all_six_real_controls_and_failed_endabort_verify_but_real_acquire_and_foreign_links_reject() {
    use layout::*;
    let f = fixture();
    let source_bytes = {
        let witness = source::circuit::Witness::new(
            [0x71; 32],
            [Val::ONE; 4],
            [Val::TWO; 4],
            [255, 0, 255, 128],
        );
        source::prove(&f.source, &witness).unwrap().into_bytes()
    };
    let (boot, _) = actual_pair(&bootstrap(&f), &f.mathematical, &source_bytes);
    let mut w = f.mathematical.clone();
    w.salts[2] = w.salts[4];
    let mut previous = boot.next;
    let mut first = None;
    let mut acquire_snapshot = None;
    let mut seen = std::collections::BTreeSet::new();
    for (index, op) in [
        Operation::Begin,
        Operation::Savepoint,
        Operation::FailCurrent,
        Operation::RollbackTo,
        Operation::Release,
        Operation::FailCurrent,
        Operation::End,
    ]
    .into_iter()
    .enumerate()
    {
        let sequence = w.old.transactions.first().map_or(0, |t| t.sequence);
        let mut command = Command::control(op, 1, 1, sequence);
        if matches!(
            op,
            Operation::Savepoint | Operation::RollbackTo | Operation::Release
        ) {
            command.name = [0x91; 32];
        }
        if op == Operation::End {
            assert!(w.old.transactions[0].failed);
            command.abort = true;
        }
        w.command = Some(command);
        let (claimed, raw) = transition(&f, &w, 0xb7 + index as u8);
        assert_eq!(
            match claimed.expected.phase {
                Phase::Transition { old, .. } => old,
                _ => unreachable!(),
            },
            previous
        );
        let (actual, pair) = actual_pair(&claimed.expected, &w, &source_bytes);
        let e = Expected::new(&actual).unwrap();
        let witness = Witness::new(&e, original_opening(raw)).unwrap();
        let evidence = prove(&e, &witness, &Prerequisites { lifecycle: &pair }).unwrap();
        drop(witness);
        assert_eq!(
            verify(&e, &Prerequisites { lifecycle: &pair }, evidence.as_bytes())
                .unwrap()
                .expected()
                .values(),
            e.values()
        );
        if index == 0 {
            first = Some((e.clone(), pair.clone(), evidence.as_bytes().to_vec(), raw));
        }
        if index == 1 {
            let (honest, parents, _, _) = first.as_ref().unwrap();
            assert!(
                verify(
                    honest,
                    &Prerequisites { lifecycle: &pair },
                    evidence.as_bytes()
                )
                .is_err()
            );
            let backend = crate::fixed::Backend::control_kind(&e).unwrap();
            let proof: Proof<Config> = codec::decode(
                wire::payload(&e, evidence.as_bytes()).unwrap(),
                &backend.shape,
                wire::MAX_SEQUENCE_ELEMENTS,
                wire::MAX_TOTAL_ELEMENTS,
            )
            .unwrap();
            let repaired = wire::encode(honest, &proof).unwrap(); // genuine foreign own-verified proof, honest outer envelope
            assert!(verify(honest, &Prerequisites { lifecycle: parents }, &repaired).is_err());
            assert!(
                verify(
                    honest,
                    &Prerequisites { lifecycle: &pair },
                    &first.as_ref().unwrap().2
                )
                .is_err()
            );
        }
        seen.insert(op as u8);
        let c = w.command.as_ref().unwrap();
        let step = w.old.step(c, claimed.expected.parent, w.ages()).unwrap();
        if op == Operation::End {
            assert_eq!(step.outcome, 3);
        } else {
            assert_eq!(step.outcome, 0);
        }
        w.old = step.next;
        w.salts[2] = w.salts[4];
        previous = actual.next;
        if index == 0 {
            acquire_snapshot = Some(w.clone());
        }
    }
    assert_eq!(seen.into_iter().collect::<Vec<_>>(), CONTROL_OPCODES);
    let (honest, pair, bytes, raw) = first.unwrap();
    let mut damaged = bytes.clone();
    *damaged.last_mut().unwrap() ^= 1;
    assert!(verify(&honest, &Prerequisites { lifecycle: &pair }, &damaged).is_err());
    let mut bomb = bytes[..wire::HEADER].to_vec();
    bomb[112..116].copy_from_slice(&9u32.to_le_bytes());
    bomb.extend([0xff; 9]);
    assert!(verify(&honest, &Prerequisites { lifecycle: &pair }, &bomb).is_err()); // reaches bounded decoder after genuine parents
    let mut acquire = acquire_snapshot.unwrap();
    let mut command = Command::control(
        Operation::Acquire,
        1,
        1,
        acquire.old.transactions[0].sequence,
    );
    command.mask = [255; 32];
    command.mode = 4;
    command.limit = 4;
    command.projection = 3;
    acquire.command = Some(command);
    let (claim, acquire_fields) = transition(&f, &acquire, 0xc7);
    let (actual, acquire_pair) = actual_pair(&claim.expected, &acquire, &source_bytes);
    let e = Expected::new(&actual).unwrap();
    assert!(Witness::new(&e, original_opening(acquire_fields)).is_err());
    assert!(
        verify(
            &honest,
            &Prerequisites {
                lifecycle: &acquire_pair
            },
            &bytes
        )
        .is_err()
    );
    let witness = Witness::new(&honest, original_opening(raw)).unwrap();
    // Real Acquire prefix/suffix/Ccmd and real Lifecycle proof. A fractional
    // selector can interpolate opcode1 but MUST fail Boolean membership.
    let mut trace = witness.trace(&e).unwrap();
    for row in trace.values.as_chunks_mut::<WIDTH>().0 {
        row[OPCODE..SUFFIX].fill(Val::ZERO);
        row[OPCODE] = Val::TWO.inverse();
        row[OPCODE + 1] = Val::TWO.inverse();
        for (cell, value) in row[SUFFIX..].iter_mut().zip(&acquire_fields[110..159]) {
            *cell = Val::from_u64(*value);
        }
    }
    assert_eq!(refresh(&e, &mut trace, None), e.roots().1);
    reject_raw(&e, trace);
    let mut trace = witness.trace(&e).unwrap();
    for row in trace.values.as_chunks_mut::<WIDTH>().0 {
        for (cell, value) in row[SUFFIX..].iter_mut().zip(&acquire_fields[110..159]) {
            *cell = Val::from_u64(*value);
        }
    }
    assert_eq!(refresh(&e, &mut trace, Some((109, Val::ONE))), e.roots().1);
    reject_raw(&e, trace);
    // A genuinely different Source request/opening has its OWN valid Source,
    // Lifecycle and Control proofs before any honest-context rejection.
    let mut foreign_source = f.source.claim().clone();
    foreign_source.request[31] ^= 1;
    foreign_source.open_commitment = source::commitment::digest(
        &source::commitment::opening_fields(&foreign_source, [Val::TWO; 4], &f.mathematical.plain),
    );
    let foreign = Fixture {
        source: CanonicalSource::checked_claim(&foreign_source).unwrap(),
        mathematical: f.mathematical.clone(),
    };
    let foreign_source_bytes = {
        let witness = source::circuit::Witness::new(
            [0x71; 32],
            [Val::ONE; 4],
            [Val::TWO; 4],
            [255, 0, 255, 128],
        );
        source::prove(&foreign.source, &witness)
            .unwrap()
            .into_bytes()
    };
    let mut foreign_w = foreign.mathematical.clone();
    foreign_w.salts[2] = foreign_w.salts[4];
    foreign_w.command = Some(Command::control(Operation::Begin, 1, 1, 0));
    let (claim, raw) = transition(&foreign, &foreign_w, 0xb7);
    let (actual, foreign_pair) = actual_pair(&claim.expected, &foreign_w, &foreign_source_bytes);
    let foreign_e = Expected::new(&actual).unwrap();
    let foreign_witness = Witness::new(&foreign_e, original_opening(raw)).unwrap();
    assert_eq!(
        foreign_e.source().claim().heads,
        honest.source().claim().heads
    );
    assert_eq!(foreign_e.lifecycle().next, honest.lifecycle().next);
    assert_ne!(
        foreign_e.source().claim().request,
        honest.source().claim().request
    );
    let foreign_link = prove(
        &foreign_e,
        &foreign_witness,
        &Prerequisites {
            lifecycle: &foreign_pair,
        },
    )
    .unwrap();
    verify(
        &foreign_e,
        &Prerequisites {
            lifecycle: &foreign_pair,
        },
        foreign_link.as_bytes(),
    )
    .unwrap();
    assert!(
        verify(
            &honest,
            &Prerequisites {
                lifecycle: &foreign_pair
            },
            &bytes
        )
        .is_err()
    );
    let backend = crate::fixed::Backend::control_kind(&foreign_e).unwrap();
    let proof: Proof<Config> = codec::decode(
        wire::payload(&foreign_e, foreign_link.as_bytes()).unwrap(),
        &backend.shape,
        wire::MAX_SEQUENCE_ELEMENTS,
        wire::MAX_TOTAL_ELEMENTS,
    )
    .unwrap();
    let repaired = wire::encode(&honest, &proof).unwrap();
    assert!(verify(&honest, &Prerequisites { lifecycle: &pair }, &repaired).is_err());
    drop(proof);
    drop(backend);
    drop(foreign_link);
    drop(foreign_witness);
    drop(foreign_w);
    drop(foreign);
    drop(foreign_source_bytes);
    drop(witness);
    drop(acquire);
    drop(w);
    drop(f);
    drop(source_bytes);
    // Fresh complete verification after typed private inputs and original Source buffer drop.
    verify(&honest, &Prerequisites { lifecycle: &pair }, &bytes).unwrap();
}
