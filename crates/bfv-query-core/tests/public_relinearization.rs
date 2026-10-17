//! Public fixtures are non-secret and exercise only the owning material view.
use bfv_fixed_geometry::{DEGREE, MODULI, PLAINTEXT};
use bfv_query_core::{Geometry, Owner, PeerEvaluator, PublicSetup};
use fhe::bfv::{BfvParametersBuilder, RelinearizationKey};
use fhe_traits::{DeserializeParametrized, Serialize};
use sha2::{Digest, Sha256};

fn public_parameters() -> Vec<u8> {
    BfvParametersBuilder::new()
        .set_degree(DEGREE)
        .set_plaintext_modulus(PLAINTEXT)
        .set_moduli(&MODULI)
        .set_variance(10)
        .build_arc()
        .unwrap()
        .to_bytes()
}

#[test]
fn owner_setup_and_roundtrip_expose_the_original_public_key_and_complete_identity() {
    // This test-only key is non-secret; no raw secret leaves Owner.
    let (_owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let original = setup.to_bytes().unwrap();
    let view = setup.relinearization_material().unwrap();
    let another_view = setup.relinearization_material().unwrap();
    let parameters = BfvParametersBuilder::new()
        .set_degree(DEGREE)
        .set_plaintext_modulus(PLAINTEXT)
        .set_moduli(&MODULI)
        .set_variance(10)
        .build_arc()
        .unwrap();

    assert_eq!(view.parameters(), parameters.to_bytes());
    assert_eq!(view.geometry(), Geometry::Rows16);
    assert_eq!(
        view.keyset_id(),
        <[u8; 32]>::from(Sha256::digest(&original))
    );
    assert_eq!(
        view.parameters().as_ptr(),
        another_view.parameters().as_ptr()
    );
    assert_eq!(
        view.relinearization_key().as_ptr(),
        another_view.relinearization_key().as_ptr()
    );
    // Decoding is an explicit caller operation, never part of the view accessor.
    let key = RelinearizationKey::from_bytes(view.relinearization_key(), &parameters).unwrap();
    assert_eq!(key.to_bytes(), view.relinearization_key());

    let restored = PublicSetup::from_bytes(&original).unwrap();
    let restored_view = restored.relinearization_material().unwrap();
    assert_eq!(restored.to_bytes().unwrap(), original);
    assert_eq!(restored_view.parameters(), view.parameters());
    assert_eq!(
        restored_view.relinearization_key(),
        view.relinearization_key()
    );
    assert_eq!(restored_view.keyset_id(), view.keyset_id());
}

#[test]
fn complete_identity_changes_for_geometry_either_key_blob_and_original_rotation_order() {
    let parameters = public_parameters();
    let original = PublicSetup::from_public_material(
        Geometry::Rows16,
        &parameters,
        &[11, 12, 13],
        &[21, 22, 23],
    )
    .unwrap();
    let baseline = original.relinearization_material().unwrap();
    let cases = [
        (Geometry::Rows256, vec![11, 12, 13], vec![21, 22, 23]),
        (Geometry::Rows16, vec![11, 12, 14], vec![21, 22, 23]),
        (Geometry::Rows16, vec![11, 12, 13], vec![21, 22, 24]),
        (Geometry::Rows16, vec![11, 12, 13], vec![23, 22, 21]),
    ];
    for (geometry, relinearization, rotations) in cases {
        let other =
            PublicSetup::from_public_material(geometry, &parameters, &relinearization, &rotations)
                .unwrap();
        let view = other.relinearization_material().unwrap();
        assert_eq!(view.parameters(), parameters);
        assert_eq!(view.relinearization_key(), relinearization);
        assert_eq!(view.geometry(), geometry);
        assert_ne!(view.keyset_id(), baseline.keyset_id());
        assert_eq!(
            view.keyset_id(),
            <[u8; 32]>::from(Sha256::digest(other.to_bytes().unwrap()))
        );
    }
    assert_eq!(
        original.relinearization_material().unwrap().keyset_id(),
        baseline.keyset_id()
    );
}

#[test]
fn opaque_invalid_key_material_roundtrips_but_cannot_initialize_a_full_evaluator() {
    let parameters = public_parameters();
    let key = [0xff, 0, 1, 0xff];
    let rotations = [0xff, 9, 0xff];
    let setup =
        PublicSetup::from_public_material(Geometry::Rows16, &parameters, &key, &rotations).unwrap();
    let original = setup.to_bytes().unwrap();

    let view = setup.relinearization_material().unwrap();
    assert_eq!(view.parameters(), parameters);
    assert_eq!(view.relinearization_key(), key);
    assert_eq!(
        view.keyset_id(),
        <[u8; 32]>::from(Sha256::digest(&original))
    );
    assert!(PeerEvaluator::from_public_setup(&setup).is_err());

    let restored = PublicSetup::from_bytes(&original).unwrap();
    assert_eq!(restored.to_bytes().unwrap(), original);
    let restored_view = restored.relinearization_material().unwrap();
    assert_eq!(restored_view.relinearization_key(), key);
    assert_eq!(restored_view.keyset_id(), view.keyset_id());
}
