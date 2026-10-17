//! PUBLIC NONSECRET source-owned values, real SDK proofs, and canonical rebuilt attacks.
use super::super::{
    model::{Command, Operation},
    statement as lifecycle,
};
use super::{
    air::*,
    compiler::{CommandOpening, CompiledQuery},
    fixture::Fixture,
    statement::{Expected, Statement},
    trace::{self, Witness},
    *,
};
use crate::backend::{Backend, Val};
use crate::opening::{proof_codec, selection::encoding::air::LANE_BITS};
use crate::primitive::PublicStatement;
use p3_air::{BaseAir, check_all_constraints, check_constraints};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use std::{cell::Cell, sync::OnceLock};

fn valid(s: &Statement, w: &Witness) -> RowMajorMatrix<Val> {
    Backend::new(s).unwrap();
    let t = w.trace(s).unwrap();
    check_constraints(&s.air(), &t, &s.public_values());
    t
}
fn rejects(s: &Statement, t: RowMajorMatrix<Val>) {
    assert!(!check_all_constraints(&s.air(), &t, &s.public_values(), Some(1)).is_ok());
    let b = Backend::new(s).unwrap();
    if let Ok(p) = p3_uni_stark::prove(&b.config, &s.air(), t, &s.public_values()) {
        assert!(Backend::new(s).unwrap().verify(s, &p).is_err());
    }
}
fn bits(out: &mut [Val], v: u64) {
    for (i, x) in out.iter_mut().enumerate() {
        *x = Val::from_u64((v >> i) & 1);
    }
}
fn no_factory(e: &Expected, s: &Statement, parent: Option<&super::super::CompositeProof>) {
    let called = Cell::new(false);
    assert!(
        prove_with_trace(e, s, parent, || {
            called.set(true);
            Err(Error::Shape)
        })
        .is_err()
    );
    assert!(!called.get());
}
struct Stored {
    expected: Expected,
    statement: Statement,
    bytes: Vec<u8>,
}
fn stored() -> &'static Stored {
    static CELL: OnceLock<Stored> = OnceLock::new();
    CELL.get_or_init(|| {
        let f = Fixture::new(1).unwrap();
        let (_, parent) =
            super::super::prove(&f.parent, &f.source.source_witness, &f.parent_witness).unwrap();
        let p = prove_with_trace(&f.expected, &f.statement, Some(&parent), || {
            f.witness.trace(&f.statement)
        })
        .unwrap();
        verify(&f.expected, &f.statement, Some(&parent), &p).unwrap();
        let bytes = encode(&f.expected, &f.statement, &parent, &p).unwrap();
        let expected = f.expected.clone();
        let statement = f.statement.clone();
        drop(p);
        drop(parent);
        drop(f);
        let fresh = decode_and_verify(&expected, &bytes).unwrap();
        assert_eq!(fresh.public_values(), statement.public_values());
        Stored {
            expected,
            statement,
            bytes,
        }
    })
}
fn parts() -> super::super::CompositeProof {
    let x = stored();
    let f = frame::Frame::parse(&x.bytes).unwrap();
    // Test-only typed reconstruction uses the exact trusted fixed policies.
    let (_, r) = crate::backend::analyze(&x.expected.parent.source.air()).unwrap();
    let source = proof_codec::decode(
        f.parts[0],
        &proof_codec::Topology::checked(11521, r.quotient_chunks).unwrap(),
        16384,
        24 * 1024 * 1024,
    )
    .unwrap();
    let (_, r) = crate::backend::analyze(&x.expected.producer.air()).unwrap();
    let child = proof_codec::decode(
        f.parts[1],
        &proof_codec::Topology::checked(6741, r.quotient_chunks).unwrap(),
        16384,
        16 * 1024 * 1024,
    )
    .unwrap();
    super::super::CompositeProof {
        source: Some(source),
        child,
    }
}
fn upstream(w: &Witness) -> Vec<u64> {
    use fhe::bfv::{BfvParametersBuilder, Encoding, Plaintext};
    use fhe_math::rq::{Poly, Representation, traits::TryConvertFrom};
    use fhe_traits::FheEncoder;
    let mut slots = vec![0; 8192];
    for (i, v) in w.original().into_iter().enumerate() {
        slots[[0, 1, 2, 3, 4096, 4097, 4098, 4099, 512, 513, 514, 515][i]] = v;
    }
    let parameters = BfvParametersBuilder::new()
        .set_degree(8192)
        .set_plaintext_modulus(114689)
        .set_moduli(&[
            8796092858369,
            8796092792833,
            17592186028033,
            17592185438209,
            17592184717313,
        ])
        .set_variance(10)
        .build_arc()
        .unwrap();
    let plain = Plaintext::try_encode(&slots, Encoding::simd(), &parameters).unwrap();
    Poly::try_convert_from(
        &plain,
        parameters.context_at_level(0).unwrap(),
        false,
        Representation::PowerBasis,
    )
    .unwrap()
    .coefficients()
    .row(0)
    .to_vec()
}
fn opening(f: &Fixture) -> CommandOpening {
    let c = f.parent_witness.command.as_ref().unwrap();
    CommandOpening {
        transaction: c.transaction,
        principal: c.principal,
        controller: f.parent_witness.controllers[usize::from(c.principal - 1)],
        revision: f.parent_witness.old.revision,
        sequence: c.sequence,
        salt: f.parent_witness.salts[3],
    }
}
#[test]
fn compact_originals_sparse_skip_offset_and_all8192_coefficients_match_the_real_sdk() {
    for limit in [0, 1] {
        let f = Fixture::new(limit).unwrap();
        assert_eq!(
            f.witness.flags[..4],
            if limit == 0 {
                [false; 4]
            } else {
                [false, false, false, true]
            }
        );
        if limit == 1 {
            assert_eq!(f.witness.tuples[0][..4], [1, 3, 128, 255]);
            assert_eq!(
                f.witness.original(),
                [128, 0, 0, 0, 255, 0, 0, 0, 1, 0, 0, 0]
            );
            assert!(f.witness.flags[4]);
            assert!(f.witness.flags[10]);
        } else {
            assert!(f.witness.original().iter().all(|v| *v == 0));
        }
        let _ = valid(&f.statement, &f.witness);
        for ((m, w), sdk) in f
            .witness
            .coefficients()
            .into_iter()
            .zip(upstream(&f.witness))
        {
            assert_eq!(m, sdk);
            assert_eq!(w, sdk * 78307 % 114689);
        }
        assert_eq!(
            (
                f.statement.air().width(),
                f.statement.public_values().len(),
                f.statement.air().num_periodic_columns()
            ),
            (4028, 136, 297)
        );
    }
}
#[test]
fn genuine_three_component_frame_freshly_decodes_after_original_proof_objects_drop() {
    let s = stored();
    let fresh = decode_and_verify(&s.expected, &s.bytes).unwrap();
    assert_eq!(fresh.public_values(), s.statement.public_values());
    let f = frame::Frame::parse(&s.bytes).unwrap();
    assert!(f.parts.iter().all(|p| !p.is_empty()));
    assert_eq!(
        s.bytes.len(),
        212 + f.parts.iter().map(|p| p.len()).sum::<usize>()
    );
    assert!(s.bytes.len() < frame::MAX_FRAME);
}
#[test]
fn independent_full_source_packets_parent_roots_and_sql_identity_reject_before_factory() {
    let f = Fixture::new(1).unwrap();
    let parent = parts();
    for field in 0..18 {
        let mut e = f.expected.clone();
        match field {
            0 => e.parent.source.request[0] ^= 1,
            1 => e.parent.source.heads[0][0] ^= 1,
            2 => e.parent.source.heads[1][111] ^= 1,
            3 => e.parent.source.packets[0][0] ^= 1,
            4 => e.parent.source.packets[0][59] ^= 1,
            5 => e.parent.source.packets[1][0] ^= 1,
            6 => e.parent.source.packets[1][2383] ^= 1,
            7 => e.parent.source.key_commitment[3] += Val::ONE,
            8 => e.parent.source.open_commitment[3] += Val::ONE,
            9 => e.parent.genesis[31] ^= 1,
            10 => e.parent.parent[31] ^= 1,
            11 => e.parent.enrollment[3] += Val::ONE,
            12 => {
                let lifecycle::Phase::Transition { old, .. } = &mut e.parent.phase else {
                    unreachable!()
                };
                old[3] += Val::ONE;
            }
            13 => {
                let lifecycle::Phase::Transition { command, .. } = &mut e.parent.phase else {
                    unreachable!()
                };
                command[3] += Val::ONE;
            }
            14 => e.producer.next[3] += Val::ONE,
            15 => e.producer.result[3] += Val::ONE,
            16 => e.sql_identity[31] ^= 1,
            _ => e.projection = 0,
        }
        no_factory(&e, &f.statement, Some(&parent));
        assert!(decode_and_verify(&e, &stored().bytes).is_err());
    }
    for packet in 0..2 {
        for side in 0..3 {
            let mut e = f.expected.clone();
            if side != 1 {
                e.parent.source.packets[packet].pop();
            }
            if side != 0 {
                e.producer.expected.source.packets[packet].pop();
            }
            no_factory(&e, &f.statement, Some(&parent));
            assert!(decode_and_verify(&e, &stored().bytes).is_err());
        }
    }
    no_factory(&f.expected, &f.statement, None);
}
#[test]
fn missing_and_genuine_byte_source_proofs_never_enter_the_encoding_factory() {
    let f = Fixture::new(1).unwrap();
    let mut parent = parts();
    let original = parent.source.take();
    no_factory(&f.expected, &f.statement, Some(&parent));
    let (s, w) = crate::opening::fixture::fixture().unwrap();
    let b = Backend::new(&s).unwrap();
    let p = b.prove_with_trace(&s, || w.trace(&s)).unwrap();
    b.verify(&s, &p).unwrap();
    parent.source = Some(p);
    no_factory(&f.expected, &f.statement, Some(&parent));
    parent.source = original;
    super::super::verify(&f.parent, &f.expected.producer, &parent).unwrap();
}
#[test]
fn compiler_binds_exact_cmd160_u64_high_words_and_rejects_private_opening_substitution() {
    let mut f = Fixture::new(1).unwrap();
    let base = (1u64 << 40) + 9;
    let old = &mut f.parent_witness.old;
    old.revision = base + 100;
    old.allocator = base + 1;
    old.transactions[0].id = base;
    old.transactions[0].sequence = base + 2;
    old.transactions[1].id = base + 1;
    let compiled =
        CompiledQuery::compile(fixture::SQL, [0x77; 32], f.parent.source.request).unwrap();
    let mut o = opening(&f);
    o.transaction = base;
    o.revision = base + 100;
    o.sequence = base + 2;
    let c = compiled.command(&o).unwrap();
    let (e, w) = f
        .source
        .transition(
            f.parent_witness.old.clone(),
            c,
            f.parent.source.request,
            f.parent.parent,
        )
        .unwrap();
    let s = w.statement(&e).unwrap();
    let bound = compiled.bind(&e, &s, o).unwrap();
    let ew = Witness::from_parent(&bound, &w, [Val::ONE; 4]).unwrap();
    let es = ew.statement(bound);
    let _ = valid(&es, &ew);
    for field in 0..9 {
        let mut o = CommandOpening {
            transaction: base,
            principal: 1,
            controller: w.controllers[0],
            revision: base + 100,
            sequence: base + 2,
            salt: w.salts[3],
        };
        match field {
            0 => o.transaction ^= 1 << 32,
            1 => o.revision ^= 1 << 32,
            2 => o.sequence ^= 1 << 32,
            3 => o.controller[31] ^= 1,
            4 => o.principal = 2,
            5 => o.salt[3] += Val::ONE,
            6 => o.revision = u64::MAX,
            7 => o.sequence = u64::MAX,
            _ => o.principal = 0,
        }
        assert!(compiled.bind(&e, &s, o).is_err());
    }
}
#[test]
fn exact_sql_and_nonce_identity_is_separate_from_the_journal_intent_query() {
    let f = Fixture::new(1).unwrap();
    let a = CompiledQuery::compile(fixture::SQL, [1; 32], f.parent.source.request)
        .unwrap()
        .bind(&f.parent, &f.expected.producer, opening(&f))
        .unwrap();
    let b = CompiledQuery::compile(
        &format!("{} ", fixture::SQL),
        [1; 32],
        f.parent.source.request,
    )
    .unwrap()
    .bind(&f.parent, &f.expected.producer, opening(&f))
    .unwrap();
    let c = CompiledQuery::compile(fixture::SQL, [2; 32], f.parent.source.request)
        .unwrap()
        .bind(&f.parent, &f.expected.producer, opening(&f))
        .unwrap();
    assert_ne!(a.sql_identity, b.sql_identity);
    assert_ne!(a.sql_identity, c.sql_identity);
    assert_ne!(
        f.witness.statement(a).context(),
        f.witness.statement(b).context()
    );
    for sql in [
        "SELECT amount FROM records WHERE age>=128 OFFSET 5 FOR UPDATE",
        "SELECT amount FROM records WHERE age>=128 LIMIT 5 FOR UPDATE",
    ] {
        assert!(CompiledQuery::compile(sql, [1; 32], f.parent.source.request).is_err());
    }
    for sql in [
        "SELECT amount FROM records WHERE age>=128 OFFSET 1 LIMIT 1 FOR SHARE SKIP LOCKED",
        "SELECT age FROM records WHERE age>=128 OFFSET 1 LIMIT 1 FOR UPDATE SKIP LOCKED",
    ] {
        let compiled = CompiledQuery::compile(sql, [1; 32], f.parent.source.request).unwrap();
        assert!(
            compiled
                .bind(&f.parent, &f.expected.producer, opening(&f))
                .is_err()
        );
    }
    assert!(decode_and_verify(&c, &stored().bytes).is_err());
    let bad = CompiledQuery::compile(fixture::SQL, [1; 32], [0xFF; 32]).unwrap();
    assert!(
        bad.bind(&f.parent, &f.expected.producer, opening(&f))
            .is_err()
    );
}
#[test]
fn equal_w_values_do_not_allow_a_distinct_row_id_or_ordinal_substitution() {
    let mut f = Fixture::new(1).unwrap();
    // A genuine encrypted canonical Source with rows0 and2 having equal age+amount,
    // but their distinct original RowIds. Only amounts change, so the age index is exact.
    let mut data: [u8; 12] = f.source.witness.plain[..12].try_into().unwrap();
    data[7] = 0;
    data[8] = 0;
    let (source, source_witness) = crate::opening::fixture::from_suffix(
        crate::opening::Relation::CanonicalIndex,
        [0x71; 32],
        ([Val::ONE; 4], [Val::TWO; 4]),
        [0x83; 32],
        data,
        &crate::opening::fixture::canonical_suffix(),
    )
    .unwrap();
    f.source.source = source;
    f.source.source_witness = source_witness;
    f.source.witness.plain[..12].copy_from_slice(&data);
    f.source.witness.plain[12..124].copy_from_slice(&f.source.source.heads[0]);
    let sql = "SELECT amount FROM records WHERE age=255 LIMIT 2 FOR UPDATE SKIP LOCKED";
    let compiled = CompiledQuery::compile(sql, [0x94; 32], [0x95; 32]).unwrap();
    let o = CommandOpening {
        transaction: 1,
        principal: 1,
        controller: f.parent_witness.controllers[0],
        revision: 2,
        sequence: 1,
        salt: f.parent_witness.salts[3],
    };
    let c = compiled.command(&o).unwrap();
    let mut old = f.parent_witness.old.clone();
    old.transactions[1].held = [0; 4];
    let (e, pw) = f
        .source
        .transition(old, c, [0x95; 32], f.parent.parent)
        .unwrap();
    let (producer, parent) = super::super::prove(&e, &f.source.source_witness, &pw).unwrap();
    super::super::verify(&e, &producer, &parent).unwrap();
    let bound = compiled.bind(&e, &producer, o).unwrap();
    let honest = Witness::from_parent(&bound, &pw, [Val::from_u8(11); 4]).unwrap();
    assert_eq!(honest.tuples[0][1], 0);
    assert_eq!(honest.tuples[1][1], 2);
    assert_eq!(honest.tuples[0][2..4], honest.tuples[1][2..4]);
    assert_ne!(honest.tuples[0][4..], honest.tuples[1][4..]);
    let original = honest.statement(bound.clone());
    let _ = valid(&original, &honest);
    for attack in 0..3 {
        let mut w = honest.clone();
        match attack {
            0 => {
                let left: [u32; 8] = w.tuples[0][4..].try_into().unwrap();
                let right: [u32; 8] = w.tuples[1][4..].try_into().unwrap();
                w.tuples[0][4..].copy_from_slice(&right);
                w.tuples[1][4..].copy_from_slice(&left);
            }
            1 => w.tuples[0][1] ^= 1,
            _ => w.tuples[0][11] ^= 1,
        }
        assert_eq!(w.coefficients(), honest.coefficients());
        let s = w.statement(bound.clone());
        assert_eq!(s.encoded, original.encoded);
        rejects(&s, w.trace(&s).unwrap());
    }
}
#[test]
fn rebuilt_returned_flags_cannot_be_replaced_by_visited_or_skipped_rows() {
    let f = Fixture::new(1).unwrap();
    for i in [0, 2] {
        let mut w = f.witness.clone();
        w.flags[i] = true;
        w.flags[3] = false;
        w.routing = [[false; 4]; 4];
        w.routing[0][i] = true;
        w.tuples[0][..4].copy_from_slice(&[
            1,
            i as u32,
            u32::from(w.plain[3 * i]),
            u32::from(u16::from_le_bytes([w.plain[3 * i + 1], w.plain[3 * i + 2]])),
        ]);
        for (j, v) in w.tuples[0][4..].iter_mut().enumerate() {
            *v = u32::from_le_bytes(
                w.plain[2220 + 32 * i + 4 * j..2224 + 32 * i + 4 * j]
                    .try_into()
                    .unwrap(),
            );
        }
        let s = w.statement(f.expected.clone());
        let t = w.trace(&s).unwrap();
        let report = check_all_constraints(&s.air(), &t, &s.public_values(), None);
        assert!(!report.is_ok());
        assert!(report.failures.iter().all(|f| f.row == 103));
        // Conditional repair pins the altered Result; it supplies NO genuine Lifecycle proof.
        let mut repaired = f.expected.clone();
        let c = f.parent_witness.command.as_ref().unwrap();
        let step = f
            .parent_witness
            .old
            .step(c, f.parent.parent, f.parent_witness.ages())
            .unwrap();
        let mut fields = lifecycle::result_fields(&repaired.producer, &f.parent_witness, &step);
        for (x, flag) in fields[121..133].iter_mut().zip(w.flags) {
            *x = Val::from_bool(flag);
        }
        repaired.producer.result = lifecycle::digest(&fields);
        let repair = w.statement(repaired);
        let _ = valid(&repair, &w);
        rejects(&s, t);
    }
}
#[test]
fn duplicate_reordered_false_original_and_inactive_tuple_claims_reach_real_sdk_rejection() {
    let f = Fixture::new(1).unwrap();
    for attack in 0..5 {
        let mut w = f.witness.clone();
        match attack {
            0 => w.tuples[0][2] ^= 1,
            1 => w.tuples[0][3] ^= 1,
            2 => w.tuples[1] = w.tuples[0],
            3 => w.tuples.swap(0, 1),
            _ => w.tuples[3][11] = 1,
        }
        let s = w.statement(f.expected.clone());
        rejects(&s, w.trace(&s).unwrap());
    }
}
#[test]
fn source_first_last_word_table_rowid_and_private_salts_are_all_bound() {
    let f = Fixture::new(1).unwrap();
    for attack in 0..6 {
        let mut w = f.witness.clone();
        match attack {
            0 => w.plain[0] ^= 1,
            1 => w.plain[124] ^= 1,
            2 => w.plain[2347] ^= 1,
            3 => w.source_salt[3] += Val::ONE,
            4 => w.result_salt[3] += Val::ONE,
            _ => w.transaction ^= 1 << 32,
        }
        let s = w.statement(f.expected.clone());
        rejects(&s, w.trace(&s).unwrap());
    }
}
#[test]
fn coefficient8191_quotient_slack_and_carry_are_not_just_a_hash_check() {
    let f = Fixture::new(1).unwrap();
    for attack in 0..4 {
        let mut t = valid(&f.statement, &f.witness);
        let mut s = f.statement.clone();
        if attack == 0 {
            let row = &mut t.values[511 * WIDTH..512 * WIDTH];
            let value = (lane::<Val, _>(row, 15, 1).as_canonical_u64() + 1) % 114689;
            let at = COEFF + 15 * LANE_BITS;
            bits(&mut row[at + 17..at + 34], value);
            bits(&mut row[at + 87..at + 104], 114688 - value);
        }
        if attack == 1 {
            t.values[200 * WIDTH + COEFF + 34] = Val::ONE - t.values[200 * WIDTH + COEFF + 34];
        }
        if attack == 2 {
            t.values[200 * WIDTH + COEFF + 70] = Val::ONE - t.values[200 * WIDTH + COEFF + 70];
        }
        s.encoded = trace::refresh(&s, &mut t);
        if attack == 3 {
            t.values[250 * WIDTH + CARRY + 7] += Val::ONE;
        }
        rejects(&s, t);
    }
}
#[test]
fn non_acquire_or_unsuccessful_genuine_parents_cannot_encode_an_empty_success() {
    let f = Fixture::new(1).unwrap();
    for tag in 0..4 {
        let mut old = f.parent_witness.old.clone();
        let mut c = f.parent_witness.command.as_ref().unwrap().clone();
        match tag {
            0 => c = Command::control(Operation::Savepoint, 1, 1, 1),
            1 => c.wait = 0,
            2 => c.wait = 1,
            _ => {
                old.transactions[0].failed = true;
                c = Command::control(Operation::End, 1, 1, 1);
            }
        }
        let (e, pw) = f
            .source
            .transition(old, c, [0xD0 + tag; 32], f.parent.parent)
            .unwrap();
        let (s, parent) = super::super::prove(&e, &f.source.source_witness, &pw).unwrap();
        super::super::verify(&e, &s, &parent).unwrap();
        let mut expected = f.expected.clone();
        expected.parent = e;
        expected.producer = s;
        let mut w = f.witness.clone();
        w.tuples = [[0; 12]; 4];
        w.routing = [[false; 4]; 4];
        w.flags = [false; 12];
        assert!(Witness::from_parent(&expected, &pw, [Val::ONE; 4]).is_err());
        let bad = w.statement(expected);
        rejects(&bad, w.trace(&bad).unwrap());
    }
}
#[test]
fn malformed_header_lengths_roots_profiles_and_trailing_bytes_reject_before_sdk() {
    let x = stored();
    for at in [0, 8, 39, 40, 71, 72, 103, 104, 135, 136, 167, 168, 199] {
        let mut bytes = x.bytes.clone();
        bytes[at] ^= 1;
        assert!(decode_and_verify(&x.expected, &bytes).is_err());
    }
    for (component, cap) in [frame::MAX_SOURCE, frame::MAX_PARENT, frame::MAX_ENCODING]
        .into_iter()
        .enumerate()
    {
        for length in [0, cap + 1, u32::MAX as usize] {
            let mut bytes = x.bytes.clone();
            bytes[200 + 4 * component..204 + 4 * component]
                .copy_from_slice(&(length as u32).to_le_bytes());
            assert!(decode_and_verify(&x.expected, &bytes).is_err());
        }
    }
    let mut bytes = x.bytes.clone();
    bytes.extend([0]);
    assert!(decode_and_verify(&x.expected, &bytes).is_err());
    let mut bytes = x.bytes.clone();
    bytes[168..176].copy_from_slice(&0xFFFFFFFF00000001u64.to_le_bytes());
    assert!(decode_and_verify(&x.expected, &bytes).is_err());
    assert!(frame::Frame::parse(&x.bytes[..211]).is_err());
}
#[test]
fn nested_topology_and_allocation_budgets_reject_before_cryptographic_verification() {
    let x = stored();
    let f = frame::Frame::parse(&x.bytes).unwrap();
    let (_, r) = crate::backend::analyze(&x.statement.air()).unwrap();
    let shape = proof_codec::Topology::checked(WIDTH, r.quotient_chunks).unwrap();
    for slots in [0, 1, 1024] {
        assert!(matches!(
            proof_codec::decode(f.parts[2], &shape, 16384, slots),
            Err(proof_codec::Error::ResourceLimit)
        ));
    }
    let mut proof = proof_codec::decode(f.parts[2], &shape, 16384, 16 * 1024 * 1024).unwrap();
    for attack in 0..7 {
        match attack {
            0 => proof.degree_bits += 1,
            1 => {
                let _ = proof.opened_values.trace_local.pop();
            }
            2 => {
                proof.opened_values.trace_next = None;
            }
            3 => {
                proof.opened_values.quotient_chunks.pop();
            }
            4 => {
                proof.opening_proof.0.pop();
            }
            5 => {
                proof.opening_proof.1.commit_phase_openings.pop();
            }
            _ => {
                proof.opening_proof.1.final_poly.push(Val::ONE.into());
            }
        }
        let bad = postcard::to_allocvec(&proof).unwrap();
        let roots = f.roots.as_chunks::<32>().0;
        let bytes = frame::join(
            [roots[0], roots[1], roots[2]],
            [f.parts[0], f.parts[1], &bad],
        )
        .unwrap();
        assert!(decode_and_verify(&x.expected, &bytes).is_err());
        proof = proof_codec::decode(f.parts[2], &shape, 16384, 16 * 1024 * 1024).unwrap();
    }
}
#[test]
fn legacy_return168_and_new_result144_proofs_cannot_be_relabelled_in_either_direction() {
    let old = crate::opening::locking::encoding::fixture().unwrap();
    let p = Backend::new(&old.statement)
        .unwrap()
        .prove_with_trace(&old.statement, || {
            old.witness.trace_returned(&old.statement)
        })
        .unwrap();
    Backend::new(&old.statement)
        .unwrap()
        .verify(&old.statement, &p)
        .unwrap();
    assert!(
        Backend::new(&stored().statement)
            .unwrap()
            .verify(&stored().statement, &p)
            .is_err()
    );
    let x = stored();
    let f = frame::Frame::parse(&x.bytes).unwrap();
    let (_, r) = crate::backend::analyze(&x.statement.air()).unwrap();
    let p = proof_codec::decode(
        f.parts[2],
        &proof_codec::Topology::checked(WIDTH, r.quotient_chunks).unwrap(),
        16384,
        16 * 1024 * 1024,
    )
    .unwrap();
    assert!(
        Backend::new(&old.statement)
            .unwrap()
            .verify(&old.statement, &p)
            .is_err()
    );
}

#[test]
fn successful_limit_zero_and_all_skipped_have_genuine_empty_encoding_evidence() {
    for all_skipped in [false, true] {
        let mut f = Fixture::new(0).unwrap();
        if all_skipped {
            let mut old = f.parent_witness.old.clone();
            old.transactions[1].held = [4; 4];
            let mut c = f.parent_witness.command.clone().unwrap();
            c.limit = 1;
            let (e, w) = f
                .source
                .transition(old, c, f.parent.source.request, f.parent.parent)
                .unwrap();
            let s = w.statement(&e).unwrap();
            let compiled =
                CompiledQuery::compile(fixture::SQL, [0x91; 32], e.source.request).unwrap();
            let bound = compiled
                .bind(
                    &e,
                    &s,
                    CommandOpening {
                        transaction: 1,
                        principal: 1,
                        controller: w.controllers[0],
                        revision: w.old.revision,
                        sequence: 1,
                        salt: w.salts[3],
                    },
                )
                .unwrap();
            f.parent = e;
            f.parent_witness = w;
            f.expected = bound;
        }
        let (_, parent) =
            super::super::prove(&f.parent, &f.source.source_witness, &f.parent_witness).unwrap();
        let w = Witness::from_parent(&f.expected, &f.parent_witness, [Val::TWO; 4]).unwrap();
        assert!(w.original().iter().all(|x| *x == 0));
        let s = w.statement(f.expected.clone());
        let p = prove_with_trace(&f.expected, &s, Some(&parent), || w.trace(&s)).unwrap();
        verify(&f.expected, &s, Some(&parent), &p).unwrap();
    }
}
#[test]
fn projection_changes_bound_context_but_preserves_full_original_amount_cells() {
    let f = Fixture::new(1).unwrap();
    let mut c = f.parent_witness.command.clone().unwrap();
    c.projection = 1;
    let (e, w) = f
        .source
        .transition(
            f.parent_witness.old.clone(),
            c,
            f.parent.source.request,
            f.parent.parent,
        )
        .unwrap();
    let (s, foreign_pair) = super::super::prove(&e, &f.source.source_witness, &w).unwrap();
    super::super::verify(&e, &s, &foreign_pair).unwrap();
    let original = CompiledQuery::compile(fixture::SQL, [0x93; 32], e.source.request).unwrap();
    assert!(
        original
            .bind(
                &e,
                &s,
                CommandOpening {
                    transaction: 1,
                    principal: 1,
                    controller: w.controllers[0],
                    revision: w.old.revision,
                    sequence: 1,
                    salt: w.salts[3]
                }
            )
            .is_err()
    );
    no_factory(&f.expected, &f.statement, Some(&foreign_pair));
    let compiled = CompiledQuery::compile(
        &fixture::SQL.replace("SELECT amount", "SELECT age"),
        [0x92; 32],
        e.source.request,
    )
    .unwrap();
    let bound = compiled
        .bind(
            &e,
            &s,
            CommandOpening {
                transaction: 1,
                principal: 1,
                controller: w.controllers[0],
                revision: w.old.revision,
                sequence: 1,
                salt: w.salts[3],
            },
        )
        .unwrap();
    let ew = Witness::from_parent(&bound, &w, f.witness.encoding_salt).unwrap();
    let es = ew.statement(bound);
    assert_eq!(ew.tuples[0][3], 255);
    assert_eq!(ew.coefficients(), f.witness.coefficients());
    assert_ne!(es.context(), f.statement.context());
    let _ = valid(&es, &ew);
    let x = stored();
    let frame = frame::Frame::parse(&x.bytes).unwrap();
    let (_, report) = crate::backend::analyze(&x.statement.air()).unwrap();
    let proof = proof_codec::decode(
        frame.parts[2],
        &proof_codec::Topology::checked(WIDTH, report.quotient_chunks).unwrap(),
        16384,
        16 * 1024 * 1024,
    )
    .unwrap();
    assert!(Backend::new(&es).unwrap().verify(&es, &proof).is_err());
}
#[test]
fn result_last_padding_and_source_padding_are_enforced_on_rebuilt_poseidon_rows() {
    let f = Fixture::new(1).unwrap();
    for row_index in [85, 103] {
        let mut t = valid(&f.statement, &f.witness);
        let row = &mut t.values[row_index * WIDTH..(row_index + 1) * WIDTH];
        let mut input: [Val; 12] = row[2 * P2..2 * P2 + 12].try_into().unwrap();
        assert_eq!(input[7], Val::ZERO);
        input[7] = Val::ONE;
        let output = crate::opening::poseidon::write(&mut row[2 * P2..3 * P2], input);
        assert_ne!(
            output[..4],
            if row_index == 85 {
                f.parent.source.open_commitment
            } else {
                f.expected.producer.result
            }
        );
        rejects(&f.statement, t);
    }
}
