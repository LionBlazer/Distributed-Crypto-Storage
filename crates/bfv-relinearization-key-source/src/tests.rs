//! All keys, setup buffers and arithmetic probes here are explicitly non-secret fixtures.
use super::*;
use bfv_query_core::{Geometry, Owner, PublicSetup};
use fhe::bfv::{BfvParameters, BfvParametersBuilder, Ciphertext, RelinearizationKey};
use fhe::proto::bfv::RelinearizationKey as KeyProto;
use fhe_math::rq::{Poly, Representation, traits::TryConvertFrom};
use fhe_traits::{DeserializeParametrized, Serialize};
use prost::Message;
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};

fn fixture() -> &'static PublicSetup {
    static SETUP: OnceLock<PublicSetup> = OnceLock::new();
    SETUP.get_or_init(|| {
        let (_owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
        setup
    })
}
fn parameters() -> Arc<BfvParameters> {
    BfvParametersBuilder::new()
        .set_degree(DEGREE)
        .set_plaintext_modulus(bfv_fixed_geometry::PLAINTEXT)
        .set_moduli(&MODULI)
        .set_variance(10)
        .build_arc()
        .unwrap()
}
fn expected(setup: &PublicSetup) -> [u8; 32] {
    Sha256::digest(setup.to_bytes().unwrap()).into()
}
fn parse(setup: &PublicSetup) -> UnverifiedSeededRelinearizationKey<'_> {
    decode_seeded(setup.relinearization_material().unwrap(), expected(setup)).unwrap()
}
fn setup_with_key(bytes: &[u8]) -> PublicSetup {
    PublicSetup::from_public_material(
        Geometry::Rows16,
        fixture().relinearization_material().unwrap().parameters(),
        bytes,
        b"opaque public rotation fixture",
    )
    .unwrap()
}
fn original_proto() -> KeyProto {
    KeyProto::decode(
        fixture()
            .relinearization_material()
            .unwrap()
            .relinearization_key(),
    )
    .unwrap()
}
fn rejects_key(bytes: &[u8]) -> bool {
    let setup = setup_with_key(bytes);
    decode_seeded(setup.relinearization_material().unwrap(), expected(&setup)).is_err()
}
fn false_bool_proto() -> KeyProto {
    let mut key = original_proto();
    for rq in &mut key.ksk.as_mut().unwrap().c0 {
        assert_eq!(&rq[rq.len() - 2..], &[0x20, 1]);
        rq.truncate(rq.len() - 2);
    }
    key
}
fn varint(mut value: u64) -> Vec<u8> {
    let mut result = Vec::new();
    while value >= 128 {
        result.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    result.push(value as u8);
    result
}
fn wrap_ksk(payload: &[u8]) -> Vec<u8> {
    let mut wire = vec![0x0a];
    wire.extend(varint(payload.len() as u64));
    wire.extend_from_slice(payload);
    wire
}
// Locate a real SDK packed payload for mutations; expected coefficient values
// come only from the public SDK oracle, never from this framing helper.
fn payload_offset(rq: &[u8]) -> usize {
    let mut cursor = cursor::Cursor::new(rq);
    cursor.tag(0x08).unwrap();
    assert_eq!(cursor.varint().unwrap(), 3);
    cursor.tag(0x10).unwrap();
    assert_eq!(cursor.varint().unwrap(), DEGREE as u64);
    cursor.tag(0x1a).unwrap();
    let packed = cursor.delimited(PACKED_POLYNOMIAL_BYTES).unwrap();
    packed.as_ptr() as usize - rq.as_ptr() as usize
}
fn set_last_residue(rq: &mut [u8], basis: usize, value: u64) {
    let first = payload_offset(rq);
    let row_start = MODULI[..basis]
        .iter()
        .map(|q| (u64::BITS - (q - 1).leading_zeros()) as usize * DEGREE)
        .sum::<usize>();
    let width = (u64::BITS - (MODULI[basis] - 1).leading_zeros()) as usize;
    for bit in 0..width {
        let offset = row_start + (DEGREE - 1) * width + bit;
        let byte = &mut rq[first + offset / 8];
        let mask = 1u8 << (offset % 8);
        *byte = (*byte & !mask) | (((value >> bit) as u8 & 1) * mask);
    }
}

#[test]
fn all_five_public_impulses_match_every_c0_and_seeded_c1_sdk_residue_without_private_access() {
    let setup = fixture();
    let decoded = parse(setup);
    let expanded = decoded.expand_c1_ntt().unwrap();
    let par = parameters();
    assert_eq!(par.to_bytes(), decoded.parameters());
    let key = RelinearizationKey::from_bytes(decoded.relinearization_key(), &par).unwrap();
    let ctx = par.context_at_level(0).unwrap();
    for decomposition in 0..KEY_COMPONENTS {
        let mut impulse = vec![0u64; COEFFICIENTS];
        impulse[decomposition * DEGREE] = 1;
        let mut c2 =
            Poly::try_convert_from(impulse, ctx, false, Representation::PowerBasis).unwrap();
        c2.change_representation(Representation::Ntt);
        let zero = Poly::zero(ctx, Representation::Ntt);
        let mut probe = Ciphertext::new(vec![zero.clone(), zero, c2], &par).unwrap();

        key.relinearizes(&mut probe).unwrap();

        let mut c0 = Poly::try_convert_from(
            decoded.c0_power_basis(decomposition).unwrap().to_vec(),
            ctx,
            false,
            Representation::PowerBasis,
        )
        .unwrap();
        c0.change_representation(Representation::Ntt);
        assert_eq!(probe.len(), 2);
        assert_eq!(probe[0].coefficients(), c0.coefficients());
        assert_eq!(
            probe[1].coefficients().as_slice().unwrap(),
            expanded.c1_ntt(decomposition).unwrap()
        );
        assert_eq!(
            decoded.c0_power_basis(decomposition).unwrap().len(),
            COEFFICIENTS
        );
        assert_eq!(expanded.c1_ntt(decomposition).unwrap().len(), COEFFICIENTS);
    }
    assert!(decoded.c0_power_basis(5).is_none());
    assert!(expanded.c1_ntt(5).is_none());
    assert_eq!(expanded.keyset_id(), expected(setup));
}

#[test]
fn original_owner_bytes_seed_and_full_setup_identity_are_preserved_without_a_new_wire() {
    let setup = fixture();
    let view = setup.relinearization_material().unwrap();
    let original = view.relinearization_key();
    assert_eq!(original.len(), MAX_KEY_BYTES);
    let pointer = original.as_ptr();
    let decoded = decode_seeded(view, expected(setup)).unwrap();
    assert_eq!(decoded.parameters(), parameters().to_bytes());
    assert_eq!(decoded.relinearization_key(), original);
    assert_eq!(decoded.relinearization_key().as_ptr(), pointer);
    assert_eq!(decoded.geometry(), Geometry::Rows16);
    assert_eq!(decoded.keyset_id(), expected(setup));
    assert_eq!(
        decoded.seed().as_slice(),
        original_proto().ksk.unwrap().seed
    );
}

#[test]
fn sdk_canonical_omitted_false_flags_are_accepted_but_explicit_false_aliases_are_rejected() {
    let key = false_bool_proto();
    let wire = key.encode_to_vec();
    let par = parameters();
    let sdk = RelinearizationKey::from_bytes(&wire, &par).unwrap();
    assert_eq!(sdk.to_bytes(), wire);
    let setup = setup_with_key(&wire);
    let decoded = parse(&setup);
    let original = parse(fixture());
    for i in 0..KEY_COMPONENTS {
        assert_eq!(decoded.c0_power_basis(i), original.c0_power_basis(i));
    }
    let mut alias = key;
    alias.ksk.as_mut().unwrap().c0[4].extend_from_slice(&[0x20, 0]);
    let alias = alias.encode_to_vec();
    assert!(RelinearizationKey::from_bytes(&alias, &par).is_ok());
    assert!(rejects_key(&alias));
}

#[test]
fn independent_expected_identity_is_checked_before_parsing_and_covers_rotation_bytes() {
    let setup = setup_with_key(&[0xff]);
    let mut foreign = expected(&setup);
    foreign[31] ^= 1;
    assert!(matches!(
        decode_seeded(setup.relinearization_material().unwrap(), foreign),
        Err(Error::SetupMismatch)
    ));
    assert!(matches!(
        decode_seeded(setup.relinearization_material().unwrap(), expected(&setup)),
        Err(Error::CanonicalEncoding)
    ));

    let original = parse(fixture());
    let changed_rotations = PublicSetup::from_public_material(
        Geometry::Rows16,
        original.parameters(),
        original.relinearization_key(),
        b"different rotations",
    )
    .unwrap();
    assert!(matches!(
        decode_seeded(
            changed_rotations.relinearization_material().unwrap(),
            original.keyset_id()
        ),
        Err(Error::SetupMismatch)
    ));
}

#[test]
fn all_decomposition_and_target_rows_reject_a_noncanonical_last_power_basis_residue() {
    for decomposition in 0..KEY_COMPONENTS {
        for (basis, modulus) in MODULI.into_iter().enumerate() {
            let mut key = original_proto();
            set_last_residue(
                &mut key.ksk.as_mut().unwrap().c0[decomposition],
                basis,
                modulus,
            );
            let setup = setup_with_key(&key.encode_to_vec());
            assert!(
                matches!(
                    decode_seeded(setup.relinearization_material().unwrap(), expected(&setup)),
                    Err(Error::Residue)
                ),
                "source {decomposition}, target {basis}"
            );
        }
    }
}

#[test]
fn seed_count_level_representation_and_degree_cannot_select_a_different_key_language() {
    for count in [0, 1, 4, 6] {
        let mut key = original_proto();
        let rq = key.ksk.as_ref().unwrap().c0[0].clone();
        key.ksk.as_mut().unwrap().c0 = vec![rq; count];
        assert!(rejects_key(&key.encode_to_vec()));
    }
    for length in [0, 1, 31, 33] {
        let mut key = original_proto();
        key.ksk.as_mut().unwrap().seed = vec![7; length];
        assert!(rejects_key(&key.encode_to_vec()));
    }
    for field in 0..3 {
        let mut key = original_proto();
        let ksk = key.ksk.as_mut().unwrap();
        match field {
            0 => ksk.ciphertext_level = 1,
            1 => ksk.ksk_level = 1,
            _ => ksk.log_base = 1,
        }
        assert!(rejects_key(&key.encode_to_vec()));
    }
    for (offset, value) in [(1, 2), (3, 0xff)] {
        let mut key = original_proto();
        key.ksk.as_mut().unwrap().c0[0][offset] = value;
        assert!(rejects_key(&key.encode_to_vec()));
    }
    let mut unseeded = original_proto();
    let ksk = unseeded.ksk.as_mut().unwrap();
    ksk.seed.clear();
    ksk.c1 = ksk.c0.clone();
    assert!(unseeded.encode_to_vec().len() > MAX_KEY_BYTES);
    assert!(rejects_key(&unseeded.encode_to_vec()));
}

#[test]
fn sdk_ignored_seeded_c1_and_explicit_zero_defaults_are_not_canonical_sources() {
    let original = false_bool_proto();
    let par = parameters();
    let mut extra_c1 = original.clone();
    extra_c1.ksk.as_mut().unwrap().c1 = vec![vec![]];
    let wire = extra_c1.encode_to_vec();
    assert!(wire.len() <= MAX_KEY_BYTES);
    let sdk = RelinearizationKey::from_bytes(&wire, &par).unwrap();
    assert_eq!(sdk.to_bytes(), original.encode_to_vec());
    assert!(rejects_key(&wire));
    for explicit_default in [[0x20, 0], [0x28, 0], [0x30, 0]] {
        let mut ksk = original.ksk.as_ref().unwrap().encode_to_vec();
        ksk.extend_from_slice(&explicit_default);
        assert!(rejects_key(&wrap_ksk(&ksk)));
    }
}

#[test]
fn nonminimal_lengths_duplicate_fields_unknown_tags_truncation_and_caps_reject() {
    let key = false_bool_proto();
    let wire = key.encode_to_vec();
    let mut nonminimal = wire.clone();
    let mut end = 1;
    while nonminimal[end] & 0x80 != 0 {
        end += 1;
    }
    nonminimal[end] |= 0x80;
    nonminimal.insert(end + 1, 0);
    assert!(rejects_key(&nonminimal));
    for suffix in [&[0x0a, 0][..], &[0x38, 1][..], &[0x1a, 0][..]] {
        let mut ksk = key.ksk.as_ref().unwrap().encode_to_vec();
        ksk.extend_from_slice(suffix);
        assert!(rejects_key(&wrap_ksk(&ksk)));
    }
    let mut duplicate = wire.clone();
    duplicate.extend_from_slice(&[0x0a, 0]);
    assert!(duplicate.len() <= MAX_KEY_BYTES);
    assert!(rejects_key(&duplicate));
    let ksk = key.ksk.as_ref().unwrap();
    let mut out_of_order = vec![0x1a, 32];
    out_of_order.extend_from_slice(&ksk.seed);
    for rq in &ksk.c0 {
        out_of_order.push(0x0a);
        out_of_order.extend(varint(rq.len() as u64));
        out_of_order.extend_from_slice(rq);
    }
    assert!(rejects_key(&wrap_ksk(&out_of_order)));
    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(rejects_key(&trailing));
    for length in [0, 1, 2, wire.len() / 2, wire.len() - 1] {
        assert!(rejects_key(&wire[..length]));
    }
    assert!(rejects_key(&vec![0; MAX_KEY_BYTES + 1]));
    // Overflow and overlong varints never index or allocate using attacker lengths.
    assert!(rejects_key(&[
        0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2
    ]));
}

#[test]
fn a_changed_public_seed_has_a_distinct_source_identity_and_different_full_ntt_expansion() {
    let baseline_setup = setup_with_key(&original_proto().encode_to_vec());
    let original = parse(&baseline_setup);
    let first = original.expand_c1_ntt().unwrap();
    let mut key = original_proto();
    key.ksk.as_mut().unwrap().seed[31] ^= 1;
    let setup = setup_with_key(&key.encode_to_vec());
    let changed = parse(&setup);
    assert_ne!(changed.keyset_id(), original.keyset_id());
    let second = changed.expand_c1_ntt().unwrap();
    for i in 0..KEY_COMPONENTS {
        assert_eq!(changed.c0_power_basis(i), original.c0_power_basis(i));
        assert_ne!(second.c1_ntt(i), first.c1_ntt(i));
        for (basis, q) in MODULI.into_iter().enumerate() {
            assert!(
                second.c1_ntt(i).unwrap()[basis * DEGREE..(basis + 1) * DEGREE]
                    .iter()
                    .all(|x| *x < q)
            );
        }
    }
}
