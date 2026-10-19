//! PUBLIC NONSECRET keys and rows for the caller-owned key API.
use crate::{EncryptedSnapshot, Error, Layout, Limits, Owner};
use zeroize::Zeroizing;

const DATABASE: [u8; 16] = [0x31; 16];
const DOMAIN: [u8; 16] = [0x52; 16];
const KEY: [u8; 32] = [0x73; 32];
const PLAIN: [u8; 9] = [1, 0, 0, 255, 255, 255, 42, 0x34, 0x12];
const LAYOUT: Layout = Layout {
    schema: [0x94; 16],
    row_width: 3,
    rows_per_page: 2,
    row_count: 3,
};

#[test]
fn caller_owned_key_reopens_every_sealed_page_without_the_original_owner() {
    // Arrange: retain public fixture key material, not an Owner key accessor.
    let limits = Limits::default();
    let original_owner = Owner::from_key(DATABASE, DOMAIN, Zeroizing::new(KEY));
    let image = original_owner.seal(LAYOUT, &PLAIN, limits).unwrap();
    let expected = image.commitment().clone();
    let bytes = image.encode();
    drop(image);
    drop(original_owner);
    let owner = Owner::from_key(DATABASE, DOMAIN, Zeroizing::new(KEY));

    // Act: audit the complete saved ciphertext and decrypt both actual pages.
    let restored = EncryptedSnapshot::decode_for_head(&bytes, &expected, limits).unwrap();
    let mut opened = Zeroizing::new(Vec::new());
    for page in 0..LAYOUT.page_count().unwrap() {
        let verified = restored
            .lookup(page as u64, limits)
            .unwrap()
            .verify(&expected, page as u64, limits)
            .unwrap();
        opened.extend_from_slice(owner.decrypt(&verified).unwrap().as_bytes());
    }

    // Assert: caller-selected identity and the final partial page survive.
    assert_eq!(expected.database(), DATABASE);
    assert_eq!(expected.key_domain(), DOMAIN);
    assert_eq!(opened.as_slice(), &PLAIN);
    assert_eq!(restored.encode(), bytes);
}

#[test]
fn matching_metadata_with_another_key_fails_authentication() {
    let limits = Limits::default();
    let owner = Owner::from_key(DATABASE, DOMAIN, Zeroizing::new(KEY));
    let image = owner.seal(LAYOUT, &PLAIN, limits).unwrap();
    let verified = image
        .lookup(0, limits)
        .unwrap()
        .verify(image.commitment(), 0, limits)
        .unwrap();
    let wrong_key = Owner::from_key(DATABASE, DOMAIN, Zeroizing::new([0x75; 32]));

    assert!(matches!(
        wrong_key.decrypt(&verified),
        Err(Error::Authentication)
    ));
    assert_eq!(owner.decrypt(&verified).unwrap().as_bytes(), &PLAIN[..6]);
}

#[test]
fn same_key_with_another_database_or_domain_is_not_owner_authority() {
    let limits = Limits::default();
    let owner = Owner::from_key(DATABASE, DOMAIN, Zeroizing::new(KEY));
    let image = owner.seal(LAYOUT, &PLAIN, limits).unwrap();
    let verified = image
        .lookup(0, limits)
        .unwrap()
        .verify(image.commitment(), 0, limits)
        .unwrap();
    let other_database = Owner::from_key([0x32; 16], DOMAIN, Zeroizing::new(KEY));
    let other_domain = Owner::from_key(DATABASE, [0x53; 16], Zeroizing::new(KEY));

    for other in [other_database, other_domain] {
        assert!(matches!(other.decrypt(&verified), Err(Error::WrongOwner)));
    }
    assert_eq!(owner.decrypt(&verified).unwrap().as_bytes(), &PLAIN[..6]);
}
