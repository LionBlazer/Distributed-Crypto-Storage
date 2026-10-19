//! PUBLIC NONSECRET generated Owner material; claim decoding supplies no authority.
use super::*;
use p3_field::PrimeField64;
use std::sync::OnceLock;

fn fixture() -> &'static (PublicSetup, BfvKeyAnchor) {
    static PUBLIC: OnceLock<(PublicSetup, BfvKeyAnchor)> = OnceLock::new();
    PUBLIC.get_or_init(|| {
        let (owner, setup) = Owner::generate(crate::Geometry::Rows16).unwrap();
        let anchor = owner
            .key_anchor(
                &setup,
                KeyScope {
                    database: [0x42; 16],
                    bfv_key_domain: [0x71; 16],
                    epoch: u32::MAX,
                },
            )
            .unwrap()
            .public_anchor()
            .clone();
        (setup, anchor)
    })
}

#[test]
fn public_anchor_claim_roundtrips_actual_owner_metadata_without_minting_authority() {
    let (setup, anchor) = fixture();
    let bytes = anchor.encode_claim().unwrap();
    assert_eq!(bytes.len(), BfvKeyAnchor::CLAIM_BYTES);
    let decoded = setup.decode_key_anchor_claim(&bytes).unwrap();
    assert_eq!(&decoded, anchor);
    assert_eq!(decoded.encode_claim().unwrap(), bytes);
    // A different canonical Cs is a different UNVERIFIED claim, not an Owner
    // signature or a reason to replace the independently retained original pin.
    let mut foreign = bytes;
    let next = if anchor.coefficients[3] == 0 {
        1u64
    } else {
        0u64
    };
    foreign[132..140].copy_from_slice(&next.to_le_bytes());
    let decoded = setup.decode_key_anchor_claim(&foreign).unwrap();
    assert_ne!(&decoded, anchor);
    assert_eq!(
        anchor.coefficient_commitment(),
        fixture().1.coefficient_commitment()
    );
}

#[test]
fn public_anchor_claim_rejects_noncanonical_roots_lengths_and_other_installed_setup() {
    let (setup, anchor) = fixture();
    let bytes = anchor.encode_claim().unwrap();
    for length in [0, 7, BfvKeyAnchor::CLAIM_BYTES - 1] {
        assert!(matches!(
            setup.decode_key_anchor_claim(&bytes[..length]),
            Err(Error::InvalidShape)
        ));
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(
        setup.decode_key_anchor_claim(&trailing),
        Err(Error::InvalidShape)
    ));
    let mut magic = bytes.clone();
    magic[0] ^= 1;
    assert!(matches!(
        setup.decode_key_anchor_claim(&magic),
        Err(Error::InvalidShape)
    ));
    for offset in [108, 116, 124, 132] {
        let mut alias = bytes.clone();
        alias[offset..offset + 8].copy_from_slice(&bfv_hiding_stark::Val::ORDER_U64.to_le_bytes());
        assert!(matches!(
            setup.decode_key_anchor_claim(&alias),
            Err(Error::InvalidShape)
        ));
    }
    for offset in [44, 75, 76, 107] {
        let mut wrong = bytes.clone();
        wrong[offset] ^= 1;
        assert!(matches!(
            setup.decode_key_anchor_claim(&wrong),
            Err(Error::BindingMismatch)
        ));
    }
    // Rotation-only full-setup change, with unchanged parameters and RK.
    let mut rotations = setup.rotation_keys.clone();
    rotations.push(0);
    let different = PublicSetup::from_public_material(
        setup.geometry,
        &setup.parameters,
        &setup.relinearization_key,
        &rotations,
    )
    .unwrap();
    assert!(matches!(
        different.decode_key_anchor_claim(&bytes),
        Err(Error::BindingMismatch)
    ));
}
