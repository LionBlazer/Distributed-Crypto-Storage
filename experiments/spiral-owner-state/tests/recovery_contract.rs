//! All seeds and images here are explicitly public non-secret fixtures.
use sha2::{Digest, Sha256};
use spiral_owner_state::{profile_params, OwnerState, RecoveryError, OWNER_STATE_BYTES};
use zeroize::Zeroizing;
const DOMAIN: [u8; 32] = [0x61; 32];
fn fixture() -> (
    spiral_rs::params::Params,
    Zeroizing<[u8; OWNER_STATE_BYTES]>,
    Vec<u8>,
) {
    let params = profile_params();
    let setup =
        OwnerState::create_with_seed_for_experiment(&params, DOMAIN, Zeroizing::new([0x42; 32]))
            .unwrap();
    let image = setup.owner.encode_secret_for_experiment();
    let public_wire = setup.public_wire;
    drop(setup.client);
    (params, image, public_wire)
}
#[test]
fn restored_owner_keeps_original_public_setup_byte_for_byte() {
    let (params, image, public_wire) = fixture();
    let restored = OwnerState::restore(&params, DOMAIN, image.as_ref(), &public_wire).unwrap();
    assert_eq!(restored.public.serialize(), public_wire);
    assert_eq!(
        restored.owner.encode_secret_for_experiment().as_ref(),
        image.as_ref()
    );
    assert_eq!(image.len(), 336);
    assert_eq!(public_wire.len(), 6_029_344);
}
#[test]
fn restoration_rejects_another_owner_domain_and_a_different_parameter_profile() {
    let (mut params, image, public_wire) = fixture();
    assert!(matches!(
        OwnerState::restore(&params, [0x62; 32], image.as_ref(), &public_wire),
        Err(RecoveryError::DomainMismatch)
    ));
    params.db_dim_1 = 6;
    assert!(matches!(
        OwnerState::restore(&params, DOMAIN, image.as_ref(), &public_wire),
        Err(RecoveryError::ProfileMismatch)
    ));
}
#[test]
fn restoration_rejects_changed_truncated_and_extended_public_setup() {
    let (params, image, mut public_wire) = fixture();
    public_wire[100] ^= 1;
    assert!(matches!(
        OwnerState::restore(&params, DOMAIN, image.as_ref(), &public_wire),
        Err(RecoveryError::PublicSetupMismatch)
    ));
    public_wire.pop();
    assert!(matches!(
        OwnerState::restore(&params, DOMAIN, image.as_ref(), &public_wire),
        Err(RecoveryError::PublicSetupLength)
    ));
    public_wire.extend([0, 0]);
    assert!(matches!(
        OwnerState::restore(&params, DOMAIN, image.as_ref(), &public_wire),
        Err(RecoveryError::PublicSetupLength)
    ));
}
#[test]
fn restoration_rejects_missing_extra_and_corrupted_secret_image_bytes() {
    let (params, mut image, public_wire) = fixture();
    assert!(matches!(
        OwnerState::restore(&params, DOMAIN, &image[..335], &public_wire),
        Err(RecoveryError::OwnerImageLength)
    ));
    let mut extended = Zeroizing::new(image.to_vec());
    extended.push(0);
    assert!(matches!(
        OwnerState::restore(&params, DOMAIN, &extended, &public_wire),
        Err(RecoveryError::OwnerImageLength)
    ));
    image[272] ^= 1; // controlled corruption of an explicitly public fixture seed
    assert!(matches!(
        OwnerState::restore(&params, DOMAIN, image.as_ref(), &public_wire),
        Err(RecoveryError::OwnerImageCorrupt)
    ));
}
#[test]
fn restoration_rejects_other_sdk_rng_and_encoded_profile_contracts() {
    let (params, image, public_wire) = fixture();
    for offset in [12, 32, 96] {
        let mut changed = Zeroizing::new(*image);
        changed[offset] ^= 1;
        let checksum = Sha256::digest(&changed[..304]);
        changed[304..].copy_from_slice(&checksum);
        let result = OwnerState::restore(&params, DOMAIN, changed.as_ref(), &public_wire);
        if offset == 96 {
            assert!(matches!(result, Err(RecoveryError::ProfileMismatch)));
        } else {
            assert!(matches!(result, Err(RecoveryError::OwnerImageHeader)));
        }
    }
}
#[test]
fn restored_client_uses_fresh_query_randomness_instead_of_reusing_owner_seed() {
    let (params, image, public_wire) = fixture();
    let restored = OwnerState::restore(&params, DOMAIN, image.as_ref(), &public_wire).unwrap();
    let first = restored.client.generate_query(17).serialize();
    let second = restored.client.generate_query(17).serialize();
    assert_ne!(first, second);
}
#[test]
fn same_secret_seed_produces_new_public_setup_and_is_not_a_public_backup() {
    let (params, _, original_public) = fixture();
    let second =
        OwnerState::create_with_seed_for_experiment(&params, DOMAIN, Zeroizing::new([0x42; 32]))
            .unwrap();
    assert_ne!(second.public_wire, original_public);
}
