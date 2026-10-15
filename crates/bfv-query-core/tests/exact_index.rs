use bfv_query_core::{
    Error, Geometry, Owner, PeerEvaluator, Predicate, ProofStatus, PublicSetup, QueryContext,
    SelectedField,
};
use sha2::{Digest, Sha256};

fn context(id: u8) -> QueryContext {
    QueryContext::new([id; 16], [2; 112], [3; 112])
}
fn selected(amount: u16, active: bool) -> SelectedField {
    SelectedField {
        age: 18,
        amount,
        active,
    }
}
// Public non-secret fixtures assert exact age equality BEFORE preparing weights. Production callers
// additionally own authenticated complete postings, duplicate rejection, exact heads and update gates.
fn exact_age18(fields: &[SelectedField]) {
    assert!(fields.iter().filter(|f| f.active).all(|f| f.age == 18));
}

#[test]
fn genuine_encrypted_reduction_covers_empty_one_sixteen_and_max256_unsigned() {
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let cases = [
        (vec![], 0, 0, 0, 0),
        (vec![selected(65_535, true)], 1, 65_535, 255, 255),
        (vec![selected(65_535, true); 16], 16, 1_048_560, 4080, 4080),
        (
            vec![selected(65_535, true); 256],
            256,
            16_776_960,
            65_280,
            65_280,
        ),
        (vec![selected(0, true); 256], 256, 0, 0, 0),
        (
            vec![
                selected(255, true),
                selected(256, true),
                selected(65_535, false),
            ],
            2,
            511,
            255,
            1,
        ),
        (vec![selected(65_535, false); 256], 0, 0, 0, 0),
    ];
    for (id, (fields, count, sum, low, high)) in cases.into_iter().enumerate() {
        exact_age18(&fields);
        let prepared = owner
            .prepare_exact_index_aggregate_for_experiment(context(id as u8), &fields)
            .unwrap();
        let result = peer
            .evaluate_exact_index_aggregate_for_experiment(&prepared.request)
            .unwrap();
        assert_eq!(
            (
                result.stats.ct_ct_multiplications,
                result.stats.rotations,
                result.stats.multiplicative_depth
            ),
            (0, 8, 0)
        );
        let actual = owner
            .decrypt_exact_index_unverified_for_experiment(prepared.pending, &result.output)
            .unwrap();
        assert_eq!(
            (
                actual.count,
                actual.sum,
                actual.low_limb_sum,
                actual.high_limb_sum
            ),
            (count, sum, low, high)
        );
        assert_eq!(actual.proof, ProofStatus::Unavailable);
    }
}

#[test]
fn identical_context_uses_fresh_ciphertexts_including_empty_and_retains_full_setup() {
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let before = setup.to_bytes().unwrap();
    let digest: [u8; 32] = Sha256::digest(&before).into();
    let counts = setup.byte_counts().unwrap();
    assert!(counts.relinearization_key > 0 && counts.rotation_keys > 0);
    assert_eq!(owner.profile().degree, 8192);
    assert_eq!(owner.profile().plaintext_modulus, 114_689);
    for fields in [vec![], vec![selected(256, true); 16]] {
        exact_age18(&fields);
        let a = owner
            .prepare_exact_index_aggregate_for_experiment(context(4), &fields)
            .unwrap();
        let b = owner
            .prepare_exact_index_aggregate_for_experiment(context(4), &fields)
            .unwrap();
        assert_eq!(a.pending.keyset_id(), digest);
        assert_eq!(a.pending.context(), &context(4));
        assert_ne!(
            a.ciphertext_payload_bytes().unwrap(),
            b.ciphertext_payload_bytes().unwrap()
        );
    }
    assert_eq!(setup.to_bytes().unwrap(), before);
    let roundtrip = PublicSetup::from_bytes(&before).unwrap();
    assert_eq!(roundtrip.to_bytes().unwrap(), before);
}

#[test]
fn a_different_owner_or_public_keyset_cannot_complete_the_bound_operation() {
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let (other, other_setup) = Owner::generate(Geometry::Rows256).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let other_peer = PeerEvaluator::from_public_setup(&other_setup).unwrap();
    let prepared = owner
        .prepare_exact_index_aggregate_for_experiment(context(5), &[selected(255, true)])
        .unwrap();
    assert!(matches!(
        other_peer.evaluate_exact_index_aggregate_for_experiment(&prepared.request),
        Err(Error::BindingMismatch)
    ));
    let result = peer
        .evaluate_exact_index_aggregate_for_experiment(&prepared.request)
        .unwrap();
    assert!(matches!(
        other.decrypt_exact_index_unverified_for_experiment(prepared.pending, &result.output),
        Err(Error::BindingMismatch)
    ));
}

#[test]
fn operation_domains_and_trailing_wire_are_rejected() {
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let fields = [selected(255, true)];
    let exact = owner
        .prepare_exact_index_aggregate_for_experiment(context(6), &fields)
        .unwrap();
    let legacy = owner
        .prepare(context(6), &fields, Predicate::Equal(18))
        .unwrap();
    assert!(peer.evaluate(&exact.request).is_err());
    assert!(
        peer.evaluate_exact_index_aggregate_for_experiment(&legacy.request)
            .is_err()
    );
    let exact_output = peer
        .evaluate_exact_index_aggregate_for_experiment(&exact.request)
        .unwrap();
    let legacy_output = peer.evaluate(&legacy.request).unwrap();
    assert!(
        owner
            .decrypt_unverified(legacy.pending, &exact_output.output)
            .is_err()
    );
    assert!(
        owner
            .decrypt_exact_index_unverified_for_experiment(exact.pending, &legacy_output.output)
            .is_err()
    );
    let again = owner
        .prepare_exact_index_aggregate_for_experiment(context(6), &fields)
        .unwrap();
    let mut trailing = again.request.clone();
    trailing.push(0);
    assert!(
        peer.evaluate_exact_index_aggregate_for_experiment(&trailing)
            .is_err()
    );
    let mut output = exact_output.output;
    output.push(0);
    assert!(
        owner
            .decrypt_exact_index_unverified_for_experiment(again.pending, &output)
            .is_err()
    );
}

#[test]
fn exact_operation_rejects_other_geometry_and_over_limit_before_encryption() {
    let (small, _) = Owner::generate(Geometry::Rows16).unwrap();
    assert!(matches!(
        small.prepare_exact_index_aggregate_for_experiment(context(7), &[]),
        Err(Error::GeometryLimit)
    ));
    let (owner, _) = Owner::generate(Geometry::Rows256).unwrap();
    assert!(matches!(
        owner.prepare_exact_index_aggregate_for_experiment(
            context(7),
            &vec![selected(1, true); 257]
        ),
        Err(Error::GeometryLimit)
    ));
}
