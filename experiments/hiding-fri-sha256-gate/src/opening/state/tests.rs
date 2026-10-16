//! PUBLIC NONSECRET owning-boundary examples. No live answer/key API.
use super::certificate::{AdmissionError, Candidate, CertificateCache};
use super::*;
use crate::backend::{Challenge, Config, PROOF_DEGREE_BITS};
use crate::primitive::PublicStatement;
use p3_air::{BaseAir, check_all_constraints, check_constraints};
use p3_field::PrimeCharacteristicRing;
use p3_symmetric::MerkleCap;
use p3_uni_stark::{Commitments, OpenedValues, Proof};
use std::mem::size_of;

fn genuine(state: &StateStatement, witness: &trace::Witness) -> Proof<Config> {
    Backend::new(state)
        .unwrap()
        .prove_with_trace(state, || witness.trace(state.source()))
        .unwrap()
}
fn admitted(state: &StateStatement, witness: &trace::Witness) -> CertificateCache {
    let mut cache = CertificateCache::new(CACHE_BYTES).unwrap();
    let proof = genuine(state, witness);
    cache
        .admit(state, Candidate::new(state.clone(), Some(proof)).unwrap())
        .unwrap();
    cache
}
/// Deliberately malformed native input ONLY for missing/resource/verification
/// rejection. This is never reported as a proof or a correctness control.
fn malformed() -> Proof<Config> {
    Proof {
        commitments: Commitments {
            trace: MerkleCap::new(vec![[Val::ZERO; 4]]),
            quotient_chunks: MerkleCap::new(vec![[Val::ZERO; 4]]),
            random: None,
        },
        opened_values: OpenedValues {
            trace_local: vec![],
            trace_next: None,
            preprocessed: None,
            quotient_chunks: vec![],
            random: None,
        },
        opening_proof: (
            vec![],
            p3_fri::FriProof {
                batch_pow_witness: Val::ZERO,
                commit_phase_commits: vec![],
                commit_pow_witnesses: vec![],
                input_openings: vec![],
                commit_phase_openings: vec![],
                final_poly: vec![],
                query_pow_witness: Val::ZERO,
            },
        ),
        degree_bits: PROOF_DEGREE_BITS,
        ood_pow_witness: Val::ZERO,
    }
}

#[test]
fn version_tag_and_new_profiles_keep_the_complete_canonical_state_request_independent() {
    let (state, witness, _, _) = fixture().unwrap();
    let source = state.source();
    assert_eq!(source.request, version_tag(source));
    assert_eq!(source.public_values().len(), 691);
    assert_eq!(source.air().width(), 7161);
    let trace = witness.trace(source).unwrap();
    check_constraints(&state.air(), &trace, &state.public_values());
    assert_ne!(
        profile_digest(Kind::StateCertificate),
        profile_digest(Kind::PackedCanonicalIndexOpening)
    );
    assert_ne!(
        profile_digest(Kind::VersionSelection),
        profile_digest(Kind::SelectionOpening)
    );
    let mut changed = source.clone();
    changed.heads[0][56] ^= 1;
    assert_ne!(version_tag(source), version_tag(&changed));
    let mut changed = source.clone();
    changed.packets[1][40] ^= 1;
    assert_ne!(version_tag(source), version_tag(&changed));
    let mut changed = source.clone();
    changed.key_commitment[0] += Val::ONE;
    assert_ne!(version_tag(source), version_tag(&changed));
}
#[test]
fn one_genuine_cold_certificate_supports_two_distinct_warm_private_queries() {
    let (state, source_witness, plain, salt) = fixture().unwrap();
    let mut cache = admitted(&state, &source_witness);
    let charged = cache.owned_bytes();
    let (first, first_witness) = query::fixture(&state, plain, salt, [1; 32], false).unwrap();
    let (second, second_witness) = query::fixture(&state, plain, salt, [2; 32], true).unwrap();
    assert_ne!(first.public_values(), second.public_values());
    assert_eq!(
        first.source().source.open_commitment,
        second.source().source.open_commitment
    );
    assert_eq!(first.source().source.request, state.source.request);
    let lease = cache.lease(&state).unwrap();
    assert_eq!(lease.source_proof_degree_bits(), PROOF_DEGREE_BITS);
    for (statement, witness) in [(first, first_witness), (second, second_witness)] {
        let proof = lease.prove_query(&statement, &witness).unwrap();
        lease.verify_query(&statement, &proof).unwrap();
    }
    // Lease carries references only. Old+prospective admission and clear cannot
    // borrow cache mutably until this last use of the lease has ended.
    assert_eq!(cache.owned_bytes(), charged);
    cache.clear();
    assert!(matches!(cache.lease(&state), Err(AdmissionError::Missing)));
}
#[test]
fn missing_cold_proof_and_restart_never_inherit_an_authority_marker() {
    let (state, _, _, _) = fixture().unwrap();
    assert!(matches!(
        Candidate::new(state.clone(), None),
        Err(AdmissionError::Missing)
    ));
    let mut cache = CertificateCache::new(CACHE_BYTES).unwrap();
    assert!(matches!(cache.lease(&state), Err(AdmissionError::Missing)));
    let mut restarted = CertificateCache::new(CACHE_BYTES).unwrap();
    assert!(matches!(
        restarted.lease(&state),
        Err(AdmissionError::Missing)
    ));
    assert!(matches!(
        CertificateCache::new(0),
        Err(AdmissionError::Capacity)
    ));
}
#[test]
fn capacity_not_length_and_old_plus_prospective_are_charged_before_replacement() {
    let (state, witness, _, _) = fixture().unwrap();
    let mut cache = admitted(&state, &witness);
    let old_bytes = cache.owned_bytes();
    let mut proof = malformed();
    proof
        .opened_values
        .trace_local
        .reserve_exact(CACHE_BYTES / size_of::<Challenge>() + 1);
    assert!(proof.opened_values.trace_local.is_empty());
    let actual_capacity = proof.opened_values.trace_local.capacity();
    let candidate = Candidate::new(state.clone(), Some(proof)).unwrap();
    assert!(candidate.owned_bytes().unwrap() >= actual_capacity * size_of::<Challenge>());
    assert_eq!(
        cache.admit(&state, candidate),
        Err(AdmissionError::Capacity)
    );
    assert_eq!(cache.owned_bytes(), old_bytes);
    assert!(cache.lease(&state).is_ok());
}
#[test]
fn two_genuine_individually_fitting_entries_cannot_exceed_the_joint_replacement_cap() {
    let (state, witness, _, _) = fixture().unwrap();
    let first = Candidate::new(state.clone(), Some(genuine(&state, &witness))).unwrap();
    let proof = genuine(&state, &witness);
    Backend::new(&state)
        .unwrap()
        .verify(&state, &proof)
        .unwrap();
    let second = Candidate::new(state.clone(), Some(proof)).unwrap();
    let metadata = CertificateCache::new(CACHE_BYTES).unwrap().owned_bytes();
    let first_alone = metadata.checked_add(first.owned_bytes().unwrap()).unwrap();
    let second_alone = metadata.checked_add(second.owned_bytes().unwrap()).unwrap();
    let cap = first_alone.max(second_alone);
    assert!(first_alone <= cap && second_alone <= cap);
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
    assert!(cache.lease(&state).is_ok());
}
#[test]
fn genuine_proof_corruption_is_rejected_and_the_existing_certificate_survives() {
    let (state, witness, _, _) = fixture().unwrap();
    let mut cache = admitted(&state, &witness);
    let old_bytes = cache.owned_bytes();
    let mut proof = genuine(&state, &witness);
    proof.opened_values.trace_local[0] += Challenge::ONE;
    let candidate = Candidate::new(state.clone(), Some(proof)).unwrap();
    assert!(matches!(
        cache.admit(&state, candidate),
        Err(AdmissionError::Proof(_))
    ));
    assert_eq!(cache.owned_bytes(), old_bytes);
    assert!(cache.lease(&state).is_ok());
}
#[test]
fn equal_version_tag_is_not_a_cache_key_for_foreign_state_or_commitment() {
    let (state, witness, _, _) = fixture().unwrap();
    let mut cache = admitted(&state, &witness);
    let old_bytes = cache.owned_bytes();
    // C_state is deliberately outside the deterministic tag. An independent
    // second commitment to the same public version is still a distinct statement.
    let mut other = state.clone();
    other.source.open_commitment[0] += Val::ONE;
    assert_eq!(other.source.request, state.source.request);
    assert!(matches!(cache.lease(&other), Err(AdmissionError::Foreign)));
    // Model a collided/forged short key: full public comparison still rejects.
    let mut changed = state.clone();
    changed.source.heads[0][56] ^= 1;
    changed.source.request = version_tag(&changed.source);
    assert!(matches!(
        cache.lease(&changed),
        Err(AdmissionError::Foreign)
    ));
    changed.source.request = state.source.request;
    assert!(matches!(
        cache.lease(&changed),
        Err(AdmissionError::Foreign)
    ));
    changed = state.clone();
    changed.source.packets[1][40] ^= 1;
    changed.source.request = version_tag(&changed.source);
    assert!(matches!(
        cache.lease(&changed),
        Err(AdmissionError::Foreign)
    ));
    changed.source.request = state.source.request;
    assert!(matches!(
        cache.lease(&changed),
        Err(AdmissionError::Foreign)
    ));
    changed = state.clone();
    changed.source.key_commitment[0] += Val::ONE;
    changed.source.request = version_tag(&changed.source);
    assert!(matches!(
        cache.lease(&changed),
        Err(AdmissionError::Foreign)
    ));
    changed.source.request = state.source.request;
    assert!(matches!(
        cache.lease(&changed),
        Err(AdmissionError::Foreign)
    ));
    assert_eq!(cache.owned_bytes(), old_bytes);
    assert!(cache.lease(&state).is_ok());
}
#[test]
fn old_profile_proof_cannot_be_renamed_as_a_verified_state_certificate() {
    let (old, witness) = fixture::packed_canonical_fixture().unwrap();
    let proof = Backend::new(&old)
        .unwrap()
        .prove_with_trace(&old, || witness.trace(&old))
        .unwrap();
    let (state, _, _, _) = fixture().unwrap();
    let candidate = Candidate::new(state.clone(), Some(proof)).unwrap();
    let mut cache = CertificateCache::new(CACHE_BYTES).unwrap();
    assert!(matches!(
        cache.admit(&state, candidate),
        Err(AdmissionError::Proof(_))
    ));
    assert!(matches!(cache.lease(&state), Err(AdmissionError::Missing)));
}
#[test]
fn a_verified_state_never_credits_foreign_query_request_plan_or_result_proofs() {
    let (state, witness, plain, salt) = fixture().unwrap();
    let mut cache = admitted(&state, &witness);
    let (query, query_witness) = query::fixture(&state, plain, salt, [4; 32], false).unwrap();
    let lease = cache.lease(&state).unwrap();
    let proof = lease.prove_query(&query, &query_witness).unwrap();
    let values = query.source();
    for (request, plan, selected) in [
        ([5; 32], values.plan, values.selected),
        (
            [4; 32],
            {
                let mut v = values.plan;
                v[0] += Val::ONE;
                v
            },
            values.selected,
        ),
        ([4; 32], values.plan, {
            let mut v = values.selected;
            v[0] += Val::ONE;
            v
        }),
    ] {
        let changed = query::QueryStatement::checked(
            &state,
            request,
            source::encode_digest(plan),
            source::encode_digest(selected),
        )
        .unwrap();
        assert!(lease.verify_query(&changed, &proof).is_err());
    }
    let mut foreign = state.clone();
    foreign.source.open_commitment[0] += Val::ONE;
    let (changed, _) = query::fixture(&foreign, plain, salt, [4; 32], false).unwrap();
    assert!(lease.verify_query(&changed, &proof).is_err());
}
#[test]
fn rebuilt_query_cannot_replace_original_private_bytes_under_the_cached_state() {
    let (state, _, mut plain, salt) = fixture().unwrap();
    plain[1] ^= 1;
    let (query, witness) = query::fixture(&state, plain, salt, [7; 32], false).unwrap();
    let trace = witness.trace(query.source()).unwrap();
    assert!(!check_all_constraints(&query.air(), &trace, &query.public_values(), Some(1)).is_ok());
    let backend = Backend::new(&query).unwrap();
    if let Ok(proof) =
        p3_uni_stark::prove(&backend.config, &query.air(), trace, &query.public_values())
    {
        assert!(backend.verify(&query, &proof).is_err());
    }
}
