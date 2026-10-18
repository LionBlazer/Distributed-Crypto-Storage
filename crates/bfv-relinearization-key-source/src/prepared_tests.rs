//! PUBLIC NONSECRET Owner/SDK oracles. No probe supplies production key authority.
use super::*;
use bfv_query_core::{Geometry, Owner, PublicSetup};
use fhe::bfv::{BfvParameters, BfvParametersBuilder, Ciphertext, RelinearizationKey};
use fhe_math::rq::{Poly, Representation, traits::TryConvertFrom};
use fhe_traits::DeserializeParametrized;
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};

fn setup() -> &'static PublicSetup {
    static SETUP: OnceLock<PublicSetup> = OnceLock::new();
    SETUP.get_or_init(|| Owner::generate(Geometry::Rows16).unwrap().1)
}
fn id(setup: &PublicSetup) -> [u8; 32] {
    Sha256::digest(setup.to_bytes().unwrap()).into()
}
fn parameters() -> Arc<BfvParameters> {
    BfvParametersBuilder::new()
        .set_degree(DEGREE)
        .set_moduli(&MODULI)
        .set_plaintext_modulus(bfv_fixed_geometry::PLAINTEXT)
        .set_variance(10)
        .build_arc()
        .unwrap()
}
fn changed_setup(key: &[u8], rotations: &[u8]) -> PublicSetup {
    let original = setup().relinearization_material().unwrap();
    PublicSetup::from_public_material(original.geometry(), original.parameters(), key, rotations)
        .unwrap()
}

#[test]
fn prepared_public_key_matches_all_fifty_sdk_rows_and_rejects_invalid_component_indices() {
    let setup = setup();
    let prepared = PreparedKey::from_original(setup, id(setup)).unwrap();
    let parameters = parameters();
    let key = RelinearizationKey::from_bytes(
        setup
            .relinearization_material()
            .unwrap()
            .relinearization_key(),
        &parameters,
    )
    .unwrap();
    let context = parameters.context_at_level(0).unwrap();
    for source in 0..5 {
        let mut spike = vec![0; 5 * DEGREE];
        spike[source * DEGREE] = 1;
        let mut c2 =
            Poly::try_convert_from(spike, context, true, Representation::PowerBasis).unwrap();
        c2.change_representation(Representation::Ntt);
        let zero = Poly::zero(context, Representation::Ntt);
        let mut probe = Ciphertext::new(vec![zero.clone(), zero, c2], &parameters).unwrap();
        key.relinearizes(&mut probe).unwrap();
        for (component, polynomial) in probe.iter().enumerate() {
            let oracle = Vec::<u64>::from(polynomial);
            let actual = prepared.component(component, source).unwrap();
            assert_eq!(actual.len(), 5 * DEGREE);
            assert_eq!(
                actual, oracle,
                "component {component}, decomposition {source}"
            );
        }
    }
    assert_eq!(prepared.keyset_id(), id(setup));
    assert_eq!(
        prepared.original_setup_digest(),
        <[u8; 64]>::from(Sha512::digest(setup.to_bytes().unwrap()))
    );
    assert!(prepared.component(2, 0).is_none());
    assert!(prepared.component(0, 5).is_none());
    assert!(prepared.component(usize::MAX, usize::MAX).is_none());
}

#[test]
fn prepared_original_pin_covers_rotations_and_seed_without_claiming_same_secret() {
    let setup = setup();
    let original = PreparedKey::from_original(setup, id(setup)).unwrap();
    let material = setup.relinearization_material().unwrap();
    let rotated = changed_setup(
        material.relinearization_key(),
        b"PUBLIC alternate rotations",
    );
    assert!(matches!(
        PreparedKey::from_original(&rotated, id(setup)),
        Err(PreparedKeyError::KeySource(crate::Error::SetupMismatch))
    ));
    let other = PreparedKey::from_original(&rotated, id(&rotated)).unwrap();
    assert_ne!(
        other.original_setup_digest(),
        original.original_setup_digest()
    );
    for component in 0..2 {
        for source in 0..5 {
            assert_eq!(
                other.component(component, source),
                original.component(component, source)
            );
        }
    }
    let mut bytes = material.relinearization_key().to_vec();
    *bytes.last_mut().unwrap() ^= 1;
    let changed = changed_setup(&bytes, b"PUBLIC alternate rotations");
    assert!(PreparedKey::from_original(&changed, id(&rotated)).is_err());
    let own = PreparedKey::from_original(&changed, id(&changed)).unwrap();
    for source in 0..5 {
        assert_eq!(own.component(0, source), other.component(0, source));
        assert_ne!(own.component(1, source), other.component(1, source));
    }
}

#[test]
fn malformed_original_keys_reject_in_source_before_public_ntt_preprocessing() {
    let original = setup().relinearization_material().unwrap();
    let key = original.relinearization_key();
    let mut unknown = key.to_vec();
    unknown.extend([0x10, 1]);
    let mut trailing = key.to_vec();
    trailing.push(0);
    for bytes in [
        Vec::new(),
        key[..key.len() - 1].to_vec(),
        unknown,
        trailing,
        vec![0; crate::MAX_KEY_BYTES + 1],
    ] {
        let candidate = changed_setup(&bytes, b"PUBLIC malformed key fixture");
        assert!(matches!(
            PreparedKey::from_original(&candidate, id(&candidate)),
            Err(PreparedKeyError::KeySource(_))
        ));
        // The independent pin still wins even when the peer also supplies bad bytes.
        assert!(matches!(
            PreparedKey::from_original(&candidate, id(setup())),
            Err(PreparedKeyError::KeySource(crate::Error::SetupMismatch))
        ));
    }
}
