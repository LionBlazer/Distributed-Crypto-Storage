//! PUBLIC NONSECRET fixtures. Only the explicit genuine cases claim actual encoding proofs.
use super::*;
use crate::{Val, admission::CanonicalSource, fixed::Backend, source};
use bfv_hiding_stark::{Config, codec};
use compact_store::{Layout, Owner};
use p3_air::check_all_constraints;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::Proof;
use statement::{Expected, KeyBinding, Statement};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::OnceLock,
    time::Instant,
};
use zeroize::Zeroizing;
struct Fixture {
    source: CanonicalSource,
    plain: [u8; 2348],
}
fn fixture() -> &'static Fixture {
    static PUBLIC: OnceLock<Fixture> = OnceLock::new();
    PUBLIC.get_or_init(|| {
        let key = [0x71; 32]; // Explicitly PUBLIC test authority, never production material.
        let owner = Owner::from_key([0x42; 16], [0x73; 16], Zeroizing::new(key));
        let data = [0, 255, 255, 1, 0, 0, 128, 255, 0, 255, 254, 255];
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
        let mut index = vec![0; 2336];
        index[..112].copy_from_slice(&stored.commitment().encode());
        index[112..144].fill(0x31);
        let ages = [0u8, 1, 128, 255];
        let mut count = 0u32;
        for age in 0..256 {
            let present = ages.contains(&(age as u8));
            index[144 + 4 * age..148 + 4 * age].copy_from_slice(&u32::from(present).to_le_bytes());
            index[1168 + 4 * age..1172 + 4 * age].copy_from_slice(&count.to_le_bytes());
            if present {
                index[2196 + count as usize] =
                    ages.iter().position(|a| usize::from(*a) == age).unwrap() as u8;
                count += 1;
            }
        }
        index[2192..2196].copy_from_slice(&count.to_le_bytes());
        for i in 0..4 {
            index[2208 + 32 * i] = i as u8 + 1;
        }
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
        let key_root = source::commitment::digest(&source::commitment::key_fields(
            &stored.commitment().encode(),
            key,
            [Val::ONE; 4],
        ));
        let mut claim = source::Statement::checked_relation(
            source::Relation::CanonicalIndex,
            [&stored.encode(), &indexed.encode()],
            [stored.commitment(), indexed.commitment()],
            [0x83; 32],
            source::statement::encode_digest(key_root),
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
        Fixture {
            source: CanonicalSource::checked_claim(&claim).unwrap(),
            plain,
        }
    })
}
fn source_bytes() -> &'static [u8] {
    static BYTES: OnceLock<Vec<u8>> = OnceLock::new();
    BYTES.get_or_init(|| {
        let witness = source::circuit::Witness::new(
            [0x71; 32],
            [Val::ONE; 4],
            [Val::TWO; 4],
            [0, 1, 128, 255],
        );
        let started = Instant::now();
        let bytes = source::prove(&fixture().source, &witness)
            .unwrap()
            .into_bytes();
        eprintln!(
            "two_lane_test phase=source_prove elapsed_ms={:.3} bytes={}",
            started.elapsed().as_secs_f64() * 1000.,
            bytes.len()
        );
        bytes
    })
}
fn binding(epoch: u32) -> KeyBinding {
    KeyBinding::new(
        [0x42; 16],
        [0x91; 16],
        epoch,
        [0x95; 32],
        source::statement::encode_digest([Val::from_u8(3); 4]),
    )
    .unwrap()
}
fn source_expected() -> Expected {
    Expected::source(&fixture().source, binding(7)).unwrap()
}
fn mask_expected(mask: [u8; 32]) -> Expected {
    let draft = Expected::private_mask(
        &fixture().source,
        binding(7),
        [0x51; 32],
        [0x61; 32],
        [0; 32],
    )
    .unwrap();
    let command = commitment::command_digest(&commitment::command_fields(
        &draft,
        mask,
        [Val::from_u8(4); 4],
    ));
    Expected::private_mask(
        &fixture().source,
        binding(7),
        [0x51; 32],
        [0x61; 32],
        source::statement::encode_digest(command),
    )
    .unwrap()
}
fn source_witness(e: &Expected) -> circuit::Witness {
    circuit::Witness::source(e, Zeroizing::new(fixture().plain.to_vec()), [2; 4], [5; 4]).unwrap()
}
fn mask_witness(e: &Expected, mask: [u8; 32]) -> circuit::Witness {
    circuit::Witness::private_mask(e, Zeroizing::new(mask), [4; 4], [6; 4]).unwrap()
}
fn truth_mask() -> [u8; 32] {
    let mut mask = [0; 32];
    mask[16..].fill(255);
    mask
}
struct Cases {
    source: Evidence,
    mask: Evidence,
}
fn cases() -> &'static Cases {
    static PROOFS: OnceLock<Cases> = OnceLock::new();
    PROOFS.get_or_init(|| {
        let e = source_expected();
        let witness = source_witness(&e);
        let original = source_bytes();
        let started = Instant::now();
        let source = prove(&e, &witness, original).unwrap();
        eprintln!(
            "two_lane_test phase=encoding_prove role=1 elapsed_ms={:.3} child_bytes={}",
            started.elapsed().as_secs_f64() * 1000.,
            source.as_bytes().len()
        );
        let bits = truth_mask();
        let e = mask_expected(bits);
        let witness = mask_witness(&e, bits);
        let started = Instant::now();
        let mask = prove(&e, &witness, original).unwrap();
        eprintln!(
            "two_lane_test phase=encoding_prove role=2 elapsed_ms={:.3} child_bytes={}",
            started.elapsed().as_secs_f64() * 1000.,
            mask.as_bytes().len()
        );
        Cases { source, mask }
    })
}
#[test]
fn sdk_scaling_matches_independently_built_full_two_lane_plaintext_and_all_private_mask_patterns() {
    use fhe_math::zq::Modulus;
    assert_eq!(
        SCALE,
        ((u128::from(Q[0]) * u128::from(Q[1])) % u128::from(T)) as u64
    );
    let modulus = Modulus::new(T).unwrap();
    let mut plaintext = vec![0; N];
    for (i, (age, amount)) in [(0usize, 65535), (1, 0), (128, 255), (255, 65534)]
        .into_iter()
        .enumerate()
    {
        plaintext[2 * i * 512 + age] = 256 + age as u64;
        plaintext[(2 * i + 1) * 512 + age] = amount;
    }
    modulus.scalar_mul_vec(&mut plaintext, SCALE);
    let expected = source_expected();
    let witness = source_witness(&expected);
    assert!(*witness.coefficients() == plaintext);
    for mask in [[0; 32], [255; 32], truth_mask()] {
        let mut plaintext = vec![0; N];
        for age in 0..256 {
            plaintext[255 - age] = u64::from((mask[age / 8] >> (age % 8)) & 1);
        }
        modulus.scalar_mul_vec(&mut plaintext, SCALE);
        let expected = mask_expected(mask);
        let witness = mask_witness(&expected, mask);
        assert!(*witness.coefficients() == plaintext);
    }
}
#[test]
fn all4096_vector_words_match_an_independent_sequential_hash_including_first_prefix_and_last_flush()
{
    let context = core::array::from_fn(|i| Val::from_usize(i + 17));
    let salt = [Val::from_u8(29); 4];
    let words = (0..N)
        .map(|i| Val::from_usize((i * 7919 + 4095) % T as usize))
        .collect::<Vec<_>>();
    let expected = commitment::vector_digest(context, salt, &words).unwrap();
    let mut checkpoint = [Val::ZERO; 12];
    let mut carry = [Val::ZERO; 8];
    let mut root = [Val::ZERO; 4];
    let mut row = vec![Val::ZERO; layout::SOURCE_WIDTH];
    for r in 0..512 {
        let w = core::array::from_fn(|l| words[8 * r + l]);
        let (next, digest) =
            commitment::write_vector(&mut row, r, context, salt, w, checkpoint, carry);
        checkpoint = next;
        carry = w;
        if r == 511 {
            root = digest;
        }
    }
    assert_eq!(root, expected);
    let mut changed = words;
    changed[N - 1] = Val::from_u64((changed[N - 1].as_canonical_u64() + 1) % T);
    assert_ne!(
        root,
        commitment::vector_digest(context, salt, &changed).unwrap()
    );
}
#[test]
fn genuine_source_and_both_new_encoding_proofs_roundtrip_with_complete_distinct_claims() {
    for evidence in [&cases().source, &cases().mask] {
        let e = &evidence.statement().expected;
        let started = Instant::now();
        let checked = wire::verify(e, source_bytes(), evidence.as_bytes()).unwrap();
        eprintln!(
            "two_lane_test phase=wire_verify role={} elapsed_ms={:.3} child_bytes={} source_bytes={}",
            e.role().tag(),
            started.elapsed().as_secs_f64() * 1000.,
            evidence.as_bytes().len(),
            source_bytes().len()
        );
        assert_eq!(checked.statement().values(), evidence.statement().values());
        assert_eq!(checked.statement().values().len(), e.role().public_values());
        assert!(evidence.as_bytes().len() <= wire::MAX_CHILD);
        assert!(
            wire::BorrowedFrame::parse(e, evidence.as_bytes())
                .unwrap()
                .child()
                .len()
                + wire::HEADER
                == evidence.as_bytes().len()
        );
        let old_role = if e.role() == Role::SourceAllOriginal {
            crate::coefficient_encoding::Role::SourceAllOriginal
        } else {
            crate::coefficient_encoding::Role::PrivateMask
        };
        assert_ne!(
            profile_digest(e.role()),
            crate::coefficient_encoding::profile_digest(old_role)
        );
    }
}
#[test]
fn matching_pair_verifies_the_original_source_and_both_complete_children() {
    let cases = cases();
    let source_expected = &cases.source.statement().expected;
    let mask_expected = &cases.mask.statement().expected;
    let original = source_bytes();

    let started = Instant::now();
    let separate_source = wire::verify(source_expected, original, cases.source.as_bytes()).unwrap();
    let separate_mask = wire::verify(mask_expected, original, cases.mask.as_bytes()).unwrap();
    let separate_ms = started.elapsed().as_secs_f64() * 1000.;

    let started = Instant::now();
    let pair = wire::verify_pair(
        source_expected,
        mask_expected,
        original,
        cases.source.as_bytes(),
        cases.mask.as_bytes(),
    )
    .unwrap();
    eprintln!(
        "two_lane_test phase=wire_pair_verify elapsed_ms={:.3} separate_ms={separate_ms:.3} source_bytes={} source_child_bytes={} mask_child_bytes={}",
        started.elapsed().as_secs_f64() * 1000.,
        original.len(),
        cases.source.as_bytes().len(),
        cases.mask.as_bytes().len(),
    );
    assert_eq!(
        pair.source().statement().values(),
        separate_source.statement().values()
    );
    assert_eq!(
        pair.private_mask().statement().values(),
        separate_mask.statement().values()
    );
}
#[test]
fn a_pair_requires_exact_roles_complete_source_and_key_before_any_proof_work() {
    let source_expected = source_expected();
    let mask = mask_expected(truth_mask());
    for (left, right) in [
        (&mask, &source_expected),
        (&source_expected, &source_expected),
        (&mask, &mask),
    ] {
        assert!(matches!(
            wire::verify_pair(left, right, &[], &[], &[]),
            Err(wire::Error::Proof(bfv_hiding_stark::Error::Shape))
        ));
    }
    let mut changed = fixture().source.claim().clone();
    changed.request[31] ^= 1;
    let changed_source = CanonicalSource::checked_claim(&changed).unwrap();
    let foreign = Expected::private_mask(
        &changed_source,
        binding(7),
        mask.sql_identity(),
        mask.public_nonce(),
        source::statement::encode_digest(mask.command()),
    )
    .unwrap();
    assert!(matches!(
        wire::verify_pair(&source_expected, &foreign, &[], &[], &[]),
        Err(wire::Error::Proof(bfv_hiding_stark::Error::Shape))
    ));
    for key in [
        KeyBinding::new(
            [0x42; 16],
            [0x92; 16],
            7,
            [0x95; 32],
            source::statement::encode_digest([Val::from_u8(3); 4]),
        )
        .unwrap(),
        binding(8),
        KeyBinding::new(
            [0x42; 16],
            [0x91; 16],
            7,
            [0x96; 32],
            source::statement::encode_digest([Val::from_u8(3); 4]),
        )
        .unwrap(),
        KeyBinding::new(
            [0x42; 16],
            [0x91; 16],
            7,
            [0x95; 32],
            source::statement::encode_digest([Val::from_u8(4); 4]),
        )
        .unwrap(),
    ] {
        let foreign = Expected::private_mask(
            &fixture().source,
            key,
            mask.sql_identity(),
            mask.public_nonce(),
            source::statement::encode_digest(mask.command()),
        )
        .unwrap();
        assert!(matches!(
            wire::verify_pair(&source_expected, &foreign, &[], &[], &[]),
            Err(wire::Error::Proof(bfv_hiding_stark::Error::Shape))
        ));
    }
}
#[test]
fn changed_source_or_child_and_repaired_context_headers_cannot_reuse_genuine_proofs() {
    let evidence = &cases().mask;
    let e = &evidence.statement().expected;
    let backend = Backend::two_lane_encoding(evidence.statement()).unwrap();
    let frame = wire::BorrowedFrame::parse(e, evidence.as_bytes()).unwrap();
    let proof: Proof<Config> = codec::decode(
        frame.child(),
        &backend.shape,
        wire::SEQUENCE,
        wire::CHILD_SLOTS,
    )
    .unwrap();
    for replacement in [
        Expected::private_mask(
            &fixture().source,
            binding(8),
            e.sql_identity(),
            e.public_nonce(),
            source::statement::encode_digest(e.command()),
        )
        .unwrap(),
        Expected::private_mask(
            &fixture().source,
            binding(7),
            [0x52; 32],
            e.public_nonce(),
            source::statement::encode_digest(e.command()),
        )
        .unwrap(),
        Expected::private_mask(
            &fixture().source,
            binding(7),
            e.sql_identity(),
            [0x62; 32],
            source::statement::encode_digest(e.command()),
        )
        .unwrap(),
        mask_expected([0; 32]),
    ] {
        let statement = Statement {
            expected: replacement.clone(),
            encoded: evidence.statement().encoded,
        };
        let repaired = wire::encode(&replacement, &statement, &proof).unwrap();
        assert!(wire::verify(&replacement, source_bytes(), &repaired).is_err());
        assert!(
            wire::verify_pair(
                &cases().source.statement().expected,
                &replacement,
                source_bytes(),
                cases().source.as_bytes(),
                &repaired
            )
            .is_err()
        );
    }
    let mut damaged = evidence.as_bytes().to_vec();
    *damaged.last_mut().unwrap() ^= 1;
    assert!(wire::verify(e, source_bytes(), &damaged).is_err());
    assert!(
        wire::verify_pair(
            &cases().source.statement().expected,
            e,
            source_bytes(),
            cases().source.as_bytes(),
            &damaged
        )
        .is_err()
    );
    let mut damaged_source_child = cases().source.as_bytes().to_vec();
    *damaged_source_child.last_mut().unwrap() ^= 1;
    assert!(
        wire::verify_pair(
            &cases().source.statement().expected,
            e,
            source_bytes(),
            &damaged_source_child,
            evidence.as_bytes()
        )
        .is_err()
    );
    let source_backend = Backend::source(fixture().source.claim()).unwrap();
    let mut source_proof: Proof<Config> = codec::decode(
        source_bytes(),
        &source_backend.shape,
        crate::wire::MAX_SEQUENCE_ELEMENTS,
        crate::wire::SOURCE_SLOTS,
    )
    .unwrap();
    let mut roots = source_proof.commitments.trace.roots().to_vec();
    roots[0][0] += Val::ONE;
    source_proof.commitments.trace = p3_symmetric::MerkleCap::new(roots);
    let corrupted_source =
        codec::serialize(&source_proof, &source_backend.shape, wire::MAX_SOURCE).unwrap();
    assert!(matches!(
        wire::verify(e, &corrupted_source, evidence.as_bytes()),
        Err(wire::Error::Verification)
    ));
    assert!(matches!(
        wire::verify_pair(
            &cases().source.statement().expected,
            e,
            &corrupted_source,
            cases().source.as_bytes(),
            evidence.as_bytes()
        ),
        Err(wire::Error::Verification)
    ));
    assert!(matches!(
        wire::verify(e, &[], evidence.as_bytes()),
        Err(wire::Error::ResourceLimit)
    ));
}
fn require_false_trace(statement: &Statement, trace: RowMajorMatrix<Val>) {
    let backend = Backend::two_lane_encoding(statement).unwrap();
    assert!(
        !check_all_constraints(
            &air::EncodingAir::new(statement),
            &trace,
            &statement.values(),
            Some(1)
        )
        .is_ok()
    );
    if let Ok(Ok(proof)) = catch_unwind(AssertUnwindSafe(|| backend.prove(trace))) {
        assert!(
            backend.verify(&proof).is_err(),
            "repaired false two-lane relation accepted"
        );
    }
}
#[test]
fn repaired_last_coefficient_roots_fail_the_actual_source_and_mask_air_and_proof() {
    let e = source_expected();
    let witness = source_witness(&e);
    let mut statement = witness.statement();
    let mut trace = witness.trace(&statement).unwrap();
    let mut words = witness.coefficients();
    words[N - 1] = 1;
    statement.encoded = circuit::refresh_for_test(&statement, &mut trace, &words);
    require_false_trace(&statement, trace);
    let mask = truth_mask();
    let e = mask_expected(mask);
    let witness = mask_witness(&e, mask);
    let mut statement = witness.statement();
    let mut trace = witness.trace(&statement).unwrap();
    let mut words = witness.coefficients();
    words[N - 1] = 1;
    statement.encoded = circuit::refresh_for_test(&statement, &mut trace, &words);
    require_false_trace(&statement, trace);
}
#[test]
fn complete_source_ids_weights_padding_and_private_mask_are_constrained_after_hash_repair() {
    let e = source_expected();
    let witness = source_witness(&e);
    let statement = witness.statement();
    for column in [
        layout::TABLE + 7,
        layout::IDS + 31,
        layout::weight(3, 1) + 34,
    ] {
        let mut trace = witness.trace(&statement).unwrap();
        for row in trace.values.as_chunks_mut::<{ layout::SOURCE_WIDTH }>().0 {
            row[column] += Val::ONE;
        }
        let mut repaired = statement.clone();
        let words = witness.coefficients();
        repaired.encoded = circuit::refresh_for_test(&repaired, &mut trace, &words);
        assert!(
            !check_all_constraints(
                &air::EncodingAir::new(&repaired),
                &trace,
                &repaired.values(),
                Some(1)
            )
            .is_ok()
        );
    }
    let mask = truth_mask();
    let e = mask_expected(mask);
    let witness = mask_witness(&e, mask);
    let statement = witness.statement();
    let mut trace = witness.trace(&statement).unwrap();
    for row in trace.values.as_chunks_mut::<{ layout::QUERY_WIDTH }>().0 {
        row[layout::MASK + 255] = Val::ZERO;
    }
    let mut changed = mask;
    changed[31] &= 127;
    let changed_witness = mask_witness(&mask_expected(changed), changed);
    let words = changed_witness.coefficients();
    let mut repaired = statement.clone();
    repaired.encoded = circuit::refresh_for_test(&repaired, &mut trace, &words);
    assert!(
        !check_all_constraints(
            &air::EncodingAir::new(&repaired),
            &trace,
            &repaired.values(),
            Some(1)
        )
        .is_ok()
    );
}
#[test]
fn full_expected_guarded_opening_and_bounded_new_frame_reject_without_acceptance_callbacks() {
    let e = source_expected();
    let witness = source_witness(&e);
    let wrong = Expected::source(&fixture().source, binding(8)).unwrap();
    assert!(matches!(
        prove(&wrong, &witness, &[]),
        Err(wire::Error::Proof(crate::BackendError::Shape))
    ));
    let mask = truth_mask();
    let query = mask_expected(mask);
    assert!(
        circuit::Witness::source(
            &query,
            Zeroizing::new(fixture().plain.to_vec()),
            [2; 4],
            [5; 4]
        )
        .is_err()
    );
    assert!(circuit::Witness::private_mask(&e, Zeroizing::new(mask), [4; 4], [6; 4]).is_err());
    assert!(
        circuit::Witness::source(
            &e,
            Zeroizing::new(fixture().plain.to_vec()),
            [Val::ORDER_U64; 4],
            [5; 4]
        )
        .is_err()
    );
    let mut changed_plain = fixture().plain;
    changed_plain[2347] ^= 1;
    assert!(
        circuit::Witness::source(&e, Zeroizing::new(changed_plain.to_vec()), [2; 4], [5; 4])
            .is_err()
    );
    let evidence = &cases().mask;
    let e = &evidence.statement().expected;
    for at in [0, 8, 9, 16, 48, 144, 148] {
        let mut changed = evidence.as_bytes().to_vec();
        changed[at] ^= 128;
        assert!(wire::BorrowedFrame::parse(e, &changed).is_err());
    }
    let mut root_claim = evidence.as_bytes().to_vec();
    let mut encoded = evidence.statement().encoded;
    encoded[0] += Val::ONE;
    root_claim[112..144].copy_from_slice(&source::statement::encode_digest(encoded));
    assert!(
        wire::BorrowedFrame::parse(e, &root_claim).is_ok(),
        "canonical Cw remains an unverified claim"
    );
    assert!(wire::verify(e, source_bytes(), &root_claim).is_err());
    let mut changed = evidence.as_bytes().to_vec();
    changed.push(0);
    assert!(wire::BorrowedFrame::parse(e, &changed).is_err());
    assert!(
        wire::BorrowedFrame::parse(e, &evidence.as_bytes()[..evidence.as_bytes().len() - 1])
            .is_err()
    );
    assert!(wire::BorrowedFrame::parse(e, &vec![0; wire::MAX_CHILD + 1]).is_err());
}
