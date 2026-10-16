//! Owning-boundary PUBLIC NONSECRET examples for the distinct periodic profile.
use super::{
    Relation, air::OpeningAir, commitment, factorized, fixture, layout, schedule,
    statement::Statement, trace::Witness,
};
use crate::backend::{self, Backend, TRACE_HEIGHT, Val};
use crate::primitive::{Kind, PublicStatement};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305,
    aead::{Aead, Payload},
};
use p3_air::{BaseAir, check_all_constraints, check_constraints};
use p3_commit::PeriodicColumns;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use std::{borrow::Cow, mem::size_of};

fn pair(relation: Relation, suffix: &[u8]) -> (Statement, Witness) {
    fixture::from_suffix(
        relation,
        core::array::from_fn(|i| i as u8),
        ([Val::from_u8(17); 4], [Val::from_u8(29); 4]),
        [0x83; 32],
        [255, 0, 0, 0, 255, 255, 255, 0, 1, 128, 255, 0],
        suffix,
    )
    .unwrap()
}
fn factored() -> (Statement, Witness) {
    pair(
        Relation::FactorizedPackedCanonicalIndex,
        &fixture::canonical_suffix(),
    )
}
fn valid(statement: &Statement, witness: &Witness) -> RowMajorMatrix<Val> {
    // The real numerical floor/shape gate precedes this helper's trace allocation.
    Backend::new(statement).unwrap();
    let trace = witness.trace(statement).unwrap();
    check_constraints(&statement.air(), &trace, &statement.public_values());
    trace
}
fn reject_rebuilt(statement: &Statement, trace: RowMajorMatrix<Val>) {
    assert!(
        !check_all_constraints(
            &statement.air(),
            &trace,
            &statement.public_values(),
            Some(1)
        )
        .is_ok()
    );
    let backend = Backend::new(statement).unwrap();
    // A false witness must either fail genuine proving or fail actual verification.
    if let Ok(proof) = p3_uni_stark::prove(
        &backend.config,
        &statement.air(),
        trace,
        &statement.public_values(),
    ) {
        assert!(backend.verify(statement, &proof).is_err());
    }
}
fn decrypted(statement: &Statement) -> Vec<u8> {
    let key: [u8; 32] = core::array::from_fn(|i| i as u8); // PUBLIC NONSECRET.
    let cipher = XChaCha20Poly1305::new(&key.into());
    let mut plain = Vec::new();
    for page in 0..2 {
        plain.extend(
            cipher
                .decrypt(
                    &statement.nonce(page).into(),
                    Payload {
                        msg: &statement.packets[page][32..],
                        aad: &statement.aad(page),
                    },
                )
                .unwrap(),
        );
    }
    plain
}

#[test]
fn factorized_public_columns_recover_every_original_row_selector_and_have_valid_periods() {
    let columns = factorized::columns();
    assert_eq!(columns.len(), 48);
    assert!(columns[..32].iter().all(|c| c.len() == 32));
    assert!(columns[32..].iter().all(|c| c.len() == 512));
    PeriodicColumns::new(&columns, TRACE_HEIGHT).unwrap();
    let original = schedule::columns();
    for physical in 0..TRACE_HEIGHT {
        let row: Vec<_> = columns.iter().map(|c| c[physical % c.len()]).collect();
        let selectors: [Val; TRACE_HEIGHT] = factorized::selectors(&row);
        for selected in 0..TRACE_HEIGHT {
            assert_eq!(selectors[selected], original[selected][physical]);
        }
        assert_eq!(selectors.iter().copied().sum::<Val>(), Val::ONE);
    }
    assert_eq!(
        columns
            .iter()
            .map(|c| c.len() * size_of::<Val>())
            .sum::<usize>(),
        73_728
    );
}

#[test]
fn factorized_air_reports_the_real_weighted_degree_and_preserves_complete_openings() {
    let (statement, _) = factored();
    let air = statement.air();
    assert_eq!(air.width(), 7161);
    assert_eq!(air.num_public_values(), 691);
    assert_eq!(air.num_periodic_columns(), 48);
    assert_eq!(air.max_constraint_degree(), Some(5));
    let first = air.periodic_columns();
    let second = air.periodic_columns();
    assert!(matches!(&first, Cow::Borrowed(_)));
    assert_eq!(first.as_ptr(), second.as_ptr());
    assert_eq!(first.as_ref(), factorized::columns());
    let (parameters, report) = backend::analyze(&air).unwrap();
    // Source-derived expectations: this actual numerical gate must establish them.
    assert_eq!(report.degree, 5);
    assert_eq!(report.constraints, 16_133);
    assert_eq!(report.quotient_chunks, 16);
    assert_eq!(report.batched_functions, 14_502);
    assert!(report.unique_decoding_bits >= 128 && report.list_decoding_bits >= 128);
    assert_eq!(parameters.max_combo, 2);
    let (old, _) = pair(Relation::PackedCanonicalIndex, &fixture::canonical_suffix());
    assert_eq!(old.air().num_periodic_columns(), 512);
    assert_eq!(backend::analyze(&old.air()).unwrap().1.degree, 3);
}

#[test]
fn factorized_core_fixture_retains_every_plain_word_and_the_same_original_schedule() {
    let (statement, witness) = factored();
    let trace = valid(&statement, &witness);
    let plain = decrypted(&statement);
    assert_eq!(&plain[124..], fixture::canonical_suffix());
    let air = OpeningAir::new(&statement);
    assert_eq!(air.schedule().captures(), [87, 178, 260, 342, 424]);
    assert_eq!(air.schedule().boundary(5), 491);
    assert_eq!(air.schedule().final_absorb(), 505);
    for (word, bytes) in plain.as_chunks::<4>().0.iter().enumerate() {
        let (group, lane, slot) = schedule::plain_location(word);
        let row = air.schedule().boundary(group);
        let actual = trace.values[row * trace.width + air.columns().buffers + lane * 16 + slot];
        assert_eq!(
            actual.as_canonical_u64(),
            u64::from(u32::from_le_bytes(*bytes))
        );
    }
    assert_eq!(
        statement.open_commitment,
        commitment::digest(&commitment::opening_fields(
            &statement,
            [Val::from_u8(29); 4],
            &plain
        )),
    );
    let (old, _) = pair(Relation::PackedCanonicalIndex, &fixture::canonical_suffix());
    assert_eq!(old.heads, statement.heads);
    assert_eq!(old.packets, statement.packets);
    assert_eq!(old.key_commitment, statement.key_commitment);
    assert_ne!(old.open_commitment, statement.open_commitment);
    assert_ne!(
        backend::profile_digest(old.kind()),
        backend::profile_digest(statement.kind())
    );
}

#[test]
fn genuine_factorized_proofs_and_fresh_original_profile_verifiers_are_not_interchangeable() {
    let (statement, witness) = factored();
    let backend = Backend::new(&statement).unwrap();
    let proof = backend
        .prove_with_trace(&statement, || witness.trace(&statement))
        .unwrap();
    backend.verify(&statement, &proof).unwrap();
    let (old, old_witness) = pair(Relation::PackedCanonicalIndex, &fixture::canonical_suffix());
    let old_backend = Backend::new(&old).unwrap();
    assert!(old_backend.verify(&old, &proof).is_err());
    assert!(
        p3_uni_stark::verify(
            &old_backend.config,
            &old.air(),
            &proof,
            &old.public_values()
        )
        .is_err()
    );
    let old_proof = old_backend
        .prove_with_trace(&old, || old_witness.trace(&old))
        .unwrap();
    old_backend.verify(&old, &old_proof).unwrap();
    assert!(backend.verify(&statement, &old_proof).is_err());
    let mut changed = statement.clone();
    changed.request[0] ^= 1;
    let fresh = Backend::new(&changed).unwrap();
    assert!(fresh.verify(&changed, &proof).is_err());
    assert_eq!(
        statement.kind(),
        Kind::FactorizedPackedCanonicalIndexOpening
    );
}

#[test]
fn rebuilt_factorized_capture_predecessor_reset_and_stale_paths_reject_substitution() {
    let (statement, witness) = factored();
    let genuine = valid(&statement, &witness);
    let c = layout::Columns::new(true);
    let mut capture = genuine.clone();
    for row in 81..163 {
        capture.values[row * capture.width + c.buffers + 4 * 16] += Val::ONE;
    }
    reject_rebuilt(&statement, capture);
    let mut predecessor = genuine.clone();
    predecessor.values[86 * predecessor.width + c.carry] += Val::ONE;
    reject_rebuilt(&statement, predecessor);
    let mut reset = genuine.clone();
    let at = 82 * reset.width + 4 * 32;
    reset.values[at] = Val::ONE - reset.values[at];
    reject_rebuilt(&statement, reset);
    let mut stale = genuine;
    for row in 87..178 {
        stale.values[row * stale.width + c.carry + 1] += Val::ONE;
    }
    reject_rebuilt(&statement, stale);
}

#[test]
fn rebuilt_factorized_u32_key_and_selected_polykey_view_cannot_escape_the_old_constraints() {
    let (statement, witness) = factored();
    let genuine = valid(&statement, &witness);
    let c = layout::Columns::new(true);
    let mut key = genuine.clone();
    for row in 0..TRACE_HEIGHT {
        key.values[row * key.width + c.master] += Val::from_u64(1 << 32);
    }
    reject_rebuilt(&statement, key);
    let mut poly = genuine;
    let at = 10 * poly.width + c.polykey_bits;
    poly.values[at] = Val::ONE - poly.values[at];
    reject_rebuilt(&statement, poly);
}

#[test]
fn rebuilt_factorized_zero_duplicate_and_forged_word_identity_checks_are_rejected() {
    let mut zero = fixture::canonical_suffix();
    zero[2096..2128].fill(0);
    let mut duplicate = fixture::canonical_suffix();
    let first: [u8; 32] = duplicate[2096..2128].try_into().unwrap();
    duplicate[2128..2160].copy_from_slice(&first);
    for suffix in [zero, duplicate] {
        let (statement, witness) = pair(Relation::FactorizedPackedCanonicalIndex, &suffix);
        let trace = witness.trace(&statement).unwrap();
        reject_rebuilt(&statement, trace);
    }
    let (statement, witness) = factored();
    let mut trace = valid(&statement, &witness);
    let identity = layout::CanonicalColumns::new(true).identity;
    let at = 491 * trace.width + identity + 11;
    trace.values[at] = Val::ONE - trace.values[at];
    reject_rebuilt(&statement, trace);
}
