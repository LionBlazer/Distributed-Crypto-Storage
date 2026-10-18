//! PUBLIC NONSECRET owning examples. No network grants or owner-key exporter.
use super::super::{
    certificate::{AdmissionError, StateLease},
    version_tag,
};
use super::*;
use crate::backend::{Config, PROOF_DEGREE_BITS};
use crate::opening::{Relation, locking::trace::Witness};
use p3_air::{BaseAir, check_all_constraints, check_constraints};
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::Proof;
use std::cell::Cell;

fn cold(
    state: &StateStatement,
    witness: &registry200_proof::source::circuit::Witness,
) -> Proof<Config> {
    Backend::new(state)
        .unwrap()
        .prove_with_trace(state, || witness.trace(state.source()))
        .unwrap()
}
fn admitted(
    state: &StateStatement,
    witness: &registry200_proof::source::circuit::Witness,
) -> CertificateCache {
    let mut cache = CertificateCache::new(super::super::CACHE_BYTES).unwrap();
    cache
        .admit(
            state,
            Candidate::new(state.clone(), Some(cold(state, witness))).unwrap(),
        )
        .unwrap();
    cache
}
fn expected_change(
    e: &Expected,
    state: &StateStatement,
    request: [u8; 32],
    parent: [u8; 32],
    old: [Val; 4],
    plan: [Val; 4],
) -> Expected {
    Expected::checked(
        state,
        request,
        e.inner.genesis,
        parent,
        locked::encoded(old),
        locked::encoded(plan),
    )
    .unwrap()
}
fn reject_before_factory(lease: &StateLease<'_>, expected: &Expected, s: &Statement) {
    let calls = Cell::new(0);
    assert!(matches!(
        lease.prove_lock_with_trace(expected, s, || {
            calls.set(calls.get() + 1);
            Err(Error::Verification)
        }),
        Err(Error::Shape)
    ));
    assert_eq!(calls.get(), 0);
}
fn raw_rejects(s: &Statement, witness: &Witness) {
    let trace = witness.trace(s.source()).unwrap();
    assert!(!check_all_constraints(&s.air(), &trace, &s.public_values(), Some(1)).is_ok());
    let backend = Backend::new(s).unwrap();
    if let Ok(proof) = p3_uni_stark::prove(&backend.config, &s.air(), trace, &s.public_values()) {
        assert!(backend.verify(s, &proof).is_err());
    }
}

#[test]
fn typed_state_context_keeps_version_tag_and_fresh_query_in_separate_commitments() {
    let (state, _, plain, salt) = super::super::fixture().unwrap();
    let (expected, witness) = fixture(&state, plain, salt, [0x11; 32], [0xB1; 32], false).unwrap();
    let s = Statement::proposed(&expected, &witness).unwrap();
    assert_eq!(s.kind(), Kind::VersionLockingSelection);
    assert_eq!(expected.inner.source.request, version_tag(state.source()));
    assert_eq!(expected.inner.request(), &[0x11; 32]);
    assert_ne!(expected.inner.source.request, *expected.inner.request());
    assert_eq!(s.public_values().len(), 116);
    assert_eq!(
        (
            s.air().width(),
            s.air().num_periodic_columns(),
            s.air().main_next_row_columns().len()
        ),
        (1948, 512, 1948)
    );
    assert_eq!(
        commitment::prefix(&expected.inner.source, salt),
        commitment::prefix(state.source(), salt)
    );
    assert_eq!(
        commitment::digest(&commitment::opening_fields(state.source(), salt, &plain)),
        state.source.open_commitment
    );
    let trace = witness.trace(s.source()).unwrap();
    check_constraints(&s.air(), &trace, &s.public_values());
    assert_ne!(
        profile_digest(Kind::VersionLockingSelection),
        profile_digest(Kind::LockingSelection)
    );
    assert_ne!(
        profile_digest(Kind::VersionLockingSelection),
        profile_digest(Kind::VersionSelection)
    );
}

#[test]
fn one_actual_cold_admission_supports_two_fresh_sequential_warm_lock_proofs() {
    let (state, source_witness, plain, salt) = super::super::fixture().unwrap();
    let mut cache = {
        let cold_witness = source_witness;
        admitted(&state, &cold_witness)
    };
    let charged = cache.owned_bytes();
    let (first_expected, first_witness) =
        fixture(&state, plain, salt, [1; 32], [0xB1; 32], false).unwrap();
    let first = Statement::proposed(&first_expected, &first_witness).unwrap();
    let (mut second_expected, mut second_witness) =
        fixture(&state, plain, salt, [2; 32], [0xB2; 32], true).unwrap();
    second_witness.old = first_witness.walk().unwrap().next;
    second_witness.salts[1] = first_witness.salts[3];
    pin(&mut second_expected, &second_witness);
    assert_eq!(second_expected.inner.old, first.inner.next);
    let second = Statement::proposed(&second_expected, &second_witness).unwrap();
    assert_ne!(first.public_values(), second.public_values());
    assert_eq!(
        first_expected.inner.source.public_values(),
        second_expected.inner.source.public_values()
    );
    assert!(second_witness.walk().unwrap().returned.iter().all(|v| !v));
    let lease = cache.lease(&state).unwrap();
    assert_eq!(lease.source_proof_degree_bits(), PROOF_DEGREE_BITS);
    let first_proof = lease
        .prove_lock(&first_expected, &first, &first_witness)
        .unwrap();
    lease
        .verify_lock(&first_expected, &first, &first_proof)
        .unwrap();
    let second_proof = lease
        .prove_lock(&second_expected, &second, &second_witness)
        .unwrap();
    lease
        .verify_lock(&second_expected, &second, &second_proof)
        .unwrap();
    assert!(
        lease
            .verify_lock(&second_expected, &second, &first_proof)
            .is_err()
    );
    assert_eq!(cache.owned_bytes(), charged);
    cache.clear();
    assert!(matches!(cache.lease(&state), Err(AdmissionError::Missing)));
}

#[test]
fn independent_query_parent_old_root_and_plan_are_checked_before_any_trace_factory() {
    let (state, source_witness, plain, salt) = super::super::fixture().unwrap();
    let mut cache = admitted(&state, &source_witness);
    let (expected, witness) = fixture(&state, plain, salt, [1; 32], [0xB1; 32], false).unwrap();
    let s = Statement::proposed(&expected, &witness).unwrap();
    let lease = cache.lease(&state).unwrap();
    for field in 0..5 {
        let mut changed = expected.clone();
        match field {
            0 => {
                changed = expected_change(
                    &expected,
                    &state,
                    [2; 32],
                    expected.inner.parent,
                    expected.inner.old,
                    expected.inner.plan,
                )
            }
            1 => changed.inner.parent[0] ^= 1,
            2 => changed.inner.old[0] += Val::ONE,
            3 => changed.inner.plan[0] += Val::ONE,
            4 => changed.inner.genesis[0] ^= 1,
            _ => unreachable!(),
        }
        reject_before_factory(&lease, &changed, &s);
    }
}

#[test]
fn fresh_sdk_verification_rejects_genuine_lock_proof_under_changed_query_context() {
    let (state, source_witness, plain, salt) = super::super::fixture().unwrap();
    let mut cache = admitted(&state, &source_witness);
    let (expected, witness) = fixture(&state, plain, salt, [1; 32], [0xB1; 32], false).unwrap();
    let s = Statement::proposed(&expected, &witness).unwrap();
    let lease = cache.lease(&state).unwrap();
    let proof = lease.prove_lock(&expected, &s, &witness).unwrap();
    for field in 0..4 {
        let mut changed = expected.clone();
        match field {
            0 => {
                changed = expected_change(
                    &expected,
                    &state,
                    [2; 32],
                    expected.inner.parent,
                    expected.inner.old,
                    expected.inner.plan,
                )
            }
            1 => changed.inner.parent[0] ^= 1,
            2 => changed.inner.old[0] += Val::ONE,
            3 => changed.inner.plan[0] += Val::ONE,
            _ => unreachable!(),
        }
        let changed_statement = Statement::checked(
            &changed,
            locked::encoded(s.inner.returned),
            locked::encoded(s.inner.owned),
            locked::encoded(s.inner.next),
        )
        .unwrap();
        // Exact typed guards pass; a fresh Backend reaches actual SDK verification.
        changed_statement.require_expected(&changed).unwrap();
        changed.require_state(&state).unwrap();
        assert!(
            Backend::new(&changed_statement)
                .unwrap()
                .verify(&changed_statement, &proof)
                .is_err()
        );
        assert!(
            lease
                .verify_lock(&changed, &changed_statement, &proof)
                .is_err()
        );
    }
}

#[test]
fn complete_state_heads_packets_key_and_commitment_cannot_alias_a_verified_lease() {
    let (state, source_witness, plain, salt) = super::super::fixture().unwrap();
    let mut cache = admitted(&state, &source_witness);
    let (expected, witness) = fixture(&state, plain, salt, [1; 32], [0xB1; 32], false).unwrap();
    let lease = cache.lease(&state).unwrap();
    for field in 0..6 {
        let mut changed_state = state.clone();
        match field {
            0 => changed_state.source.heads[0][56] ^= 1,
            1 => changed_state.source.packets[1][40] ^= 1,
            2 => changed_state.source.key_commitment[0] += Val::ONE,
            3 => changed_state.source.open_commitment[0] += Val::ONE,
            4 => {
                let (query, _) =
                    super::super::query::fixture(&state, plain, salt, [0xCC; 32], false).unwrap();
                changed_state.source.open_commitment = query.source().selected;
            }
            5 => {
                changed_state.source.packets[1].truncate(1);
            }
            _ => unreachable!(),
        }
        changed_state.source.request = version_tag(changed_state.source());
        let changed_expected = expected_change(
            &expected,
            &changed_state,
            [1; 32],
            expected.inner.parent,
            expected.inner.old,
            expected.inner.plan,
        );
        let changed = Statement::proposed(&changed_expected, &witness).unwrap();
        reject_before_factory(&lease, &changed_expected, &changed);
    }
    // All three malformed pairings reject before any field-to-public-word
    // conversion: expected-only, submitted-only, and both sides partial.
    let genuine = Statement::proposed(&expected, &witness).unwrap();
    let mut partial_expected = expected.clone();
    partial_expected.inner.source.packets[1].truncate(1);
    partial_expected.inner.source.request = version_tag(&partial_expected.inner.source);
    let partial_statement = Statement::proposed(&partial_expected, &witness).unwrap();
    reject_before_factory(&lease, &partial_expected, &genuine);
    reject_before_factory(&lease, &expected, &partial_statement);
    reject_before_factory(&lease, &partial_expected, &partial_statement);
}

#[test]
fn missing_restart_and_old_source_profiles_cannot_construct_verified_lock_authority() {
    let (state, _, plain, salt) = super::super::fixture().unwrap();
    assert!(matches!(
        Candidate::new(state.clone(), None),
        Err(AdmissionError::Missing)
    ));
    let mut cache = CertificateCache::new(super::super::CACHE_BYTES).unwrap();
    assert!(matches!(cache.lease(&state), Err(AdmissionError::Missing)));
    cache.clear();
    let mut restart = CertificateCache::new(super::super::CACHE_BYTES).unwrap();
    assert!(matches!(
        restart.lease(&state),
        Err(AdmissionError::Missing)
    ));
    let (expected, _) = fixture(&state, plain, salt, [1; 32], [0xB1; 32], false).unwrap();
    assert!(
        locked::Expected::checked(
            state.source(),
            expected.inner.genesis,
            expected.inner.parent,
            [0; 32],
            [0; 32]
        )
        .is_err()
    );
    for relation in [
        Relation::Bytes,
        Relation::CanonicalIndex,
        Relation::PackedCanonicalIndex,
    ] {
        let mut foreign = state.clone();
        foreign.source.relation = relation;
        assert!(
            Expected::checked(
                &foreign,
                [1; 32],
                expected.inner.genesis,
                expected.inner.parent,
                [0; 32],
                [0; 32]
            )
            .is_err()
        );
    }
}

#[test]
fn stable_registry_encoding_is_identical_for_exact_anchor_despite_query_source_profiles() {
    let (state, _, plain, salt) = super::super::fixture().unwrap();
    let (version, witness) = fixture(&state, plain, salt, [1; 32], [0xB1; 32], false).unwrap();
    let mut canonical = state.source().clone();
    canonical.relation = Relation::CanonicalIndex;
    canonical.request = [0x83; 32];
    canonical.open_commitment =
        commitment::digest(&commitment::opening_fields(&canonical, salt, &plain));
    let old = locked::Expected::checked(
        &canonical,
        version.inner.genesis,
        [0xB7; 32],
        [0; 32],
        [0; 32],
    )
    .unwrap();
    assert_eq!(
        locked::registry_fields(&old, &witness, &witness.old, witness.salts[1]),
        locked::registry_fields(&version.inner, &witness, &witness.old, witness.salts[1])
    );
    assert_ne!(
        locked::plan_fields(&old, &witness),
        locked::plan_fields(&version.inner, &witness)
    );
    let mut reblinded = version.clone();
    reblinded.inner.source.key_commitment[0] += Val::ONE;
    assert_ne!(
        locked::registry_fields(&reblinded.inner, &witness, &witness.old, witness.salts[1]),
        locked::registry_fields(&version.inner, &witness, &witness.old, witness.salts[1])
    );
}

#[test]
fn canonical_expected_cannot_be_relabelled_by_mutating_its_generic_source_statement() {
    let (state, _, plain, salt) = super::super::fixture().unwrap();
    let (version, witness) = fixture(&state, plain, salt, [1; 32], [0xB1; 32], false).unwrap();
    let mut canonical = state.source().clone();
    canonical.relation = Relation::CanonicalIndex;
    let mut old =
        locked::Expected::checked(&canonical, [0xA1; 32], [0xB1; 32], [0; 32], [0; 32]).unwrap();
    old.source = state.source().clone();
    assert_eq!(old.kind(), Kind::LockingSelection);
    assert!(locked::proposed(&old, &witness).is_err());
    let mut forged = version.clone();
    forged.inner.source.relation = Relation::CanonicalIndex;
    assert_eq!(forged.inner.kind(), Kind::VersionLockingSelection);
    assert!(Statement::proposed(&forged, &witness).is_err());
}

#[test]
fn rebuilt_foreign_table_and_all_row_ids_fail_against_the_same_authenticated_state() {
    let (state, _, plain, salt) = super::super::fixture().unwrap();
    let (mut expected, mut witness) =
        fixture(&state, plain, salt, [1; 32], [0xB1; 32], false).unwrap();
    witness.plan.table = [0x57; 32];
    witness.plain[124..156].copy_from_slice(&witness.plan.table);
    for i in 0..4 {
        witness.plain[2220 + i * 32..2252 + i * 32].fill(0x61 + i as u8);
    }
    pin(&mut expected, &witness);
    let s = Statement::proposed(&expected, &witness).unwrap();
    raw_rejects(&s, &witness);
}

#[test]
fn rebuilt_alternate_original_fields_fail_even_with_honest_plan_and_registry_outputs() {
    let (state, _, plain, salt) = super::super::fixture().unwrap();
    let (mut expected, mut witness) =
        fixture(&state, plain, salt, [1; 32], [0xB1; 32], false).unwrap();
    witness.plain[0] = 2;
    witness.plain[1] ^= 0x40;
    pin(&mut expected, &witness);
    let s = Statement::proposed(&expected, &witness).unwrap();
    raw_rejects(&s, &witness);
}

#[test]
fn rebuilt_state_salt_cannot_change_the_committed_original_source() {
    let (state, _, plain, salt) = super::super::fixture().unwrap();
    let (expected, mut witness) = fixture(&state, plain, salt, [1; 32], [0xB1; 32], false).unwrap();
    witness.salts[0][0] += Val::ONE;
    let s = Statement::proposed(&expected, &witness).unwrap();
    raw_rejects(&s, &witness);
}

#[test]
fn failed_joint_replacement_preserves_a_certificate_that_still_proves_a_warm_lock() {
    let (state, source_witness, plain, salt) = super::super::fixture().unwrap();
    let first = Candidate::new(state.clone(), Some(cold(&state, &source_witness))).unwrap();
    let second = Candidate::new(state.clone(), Some(cold(&state, &source_witness))).unwrap();
    let metadata = CertificateCache::new(super::super::CACHE_BYTES)
        .unwrap()
        .owned_bytes();
    let cap = metadata
        .checked_add(first.owned_bytes().unwrap())
        .unwrap()
        .max(metadata.checked_add(second.owned_bytes().unwrap()).unwrap());
    let mut cache = CertificateCache::new(cap).unwrap();
    cache.admit(&state, first).unwrap();
    let old_charge = cache.owned_bytes();
    assert!(
        old_charge
            .checked_add(second.owned_bytes().unwrap())
            .unwrap()
            > cap
    );
    assert_eq!(cache.admit(&state, second), Err(AdmissionError::Capacity));
    assert_eq!(cache.owned_bytes(), old_charge);
    let (expected, witness) = fixture(&state, plain, salt, [1; 32], [0xB1; 32], false).unwrap();
    let s = Statement::proposed(&expected, &witness).unwrap();
    let lease = cache.lease(&state).unwrap();
    let proof = lease.prove_lock(&expected, &s, &witness).unwrap();
    lease.verify_lock(&expected, &s, &proof).unwrap();
}
