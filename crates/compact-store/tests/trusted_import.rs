use compact_store::{EncryptedSnapshot, Error, Layout, Limits, MANIFEST_BYTES, Owner};

fn layout() -> Layout {
    Layout {
        schema: *b"public-import-v1",
        row_width: 3,
        rows_per_page: 2,
        row_count: 3,
    }
}

#[test]
fn trusted_import_preserves_complete_ciphertext_and_owner_readability() {
    let limits = Limits::default();
    let owner = Owner::generate([71; 16]).unwrap();
    // Public synthetic rows, never participant data.
    let rows = [17, 10, 0, 18, 20, 0, 42, 30, 0];
    let source = owner.seal(layout(), &rows, limits).unwrap();
    let head = source.commitment().clone();

    let imported = EncryptedSnapshot::decode_for_head(&source.encode(), &head, limits).unwrap();

    assert_eq!(imported.encode(), source.encode());
    for (index, expected) in [(0, &rows[..6]), (1, &rows[6..])] {
        let page = imported
            .lookup(index, limits)
            .unwrap()
            .verify(&head, index, limits)
            .unwrap();
        assert_eq!(owner.decrypt(&page).unwrap().as_bytes(), expected);
    }
}

#[test]
fn intact_stale_image_fails_current_head_but_remains_valid_for_an_explicit_old_read() {
    let limits = Limits::default();
    let owner = Owner::generate([72; 16]).unwrap();
    let mut source = owner.seal(layout(), &[1; 9], limits).unwrap();
    let old_head = source.commitment().clone();
    let old_image = source.encode();
    let current = owner
        .replace_page(&mut source, &old_head, 0, &[2; 6], limits)
        .unwrap();

    assert!(matches!(
        EncryptedSnapshot::decode_for_head(&old_image, &current, limits),
        Err(Error::WrongVersion)
    ));
    assert!(EncryptedSnapshot::decode_for_head(&old_image, &old_head, limits).is_ok());
    assert!(EncryptedSnapshot::decode_for_head(&source.encode(), &current, limits).is_ok());
}

#[test]
fn self_consistent_other_owner_or_schema_is_not_the_requested_image() {
    let limits = Limits::default();
    let owner = Owner::generate([73; 16]).unwrap();
    let requested = owner.seal(layout(), &[1; 9], limits).unwrap();
    let other_owner = Owner::generate([73; 16]).unwrap();
    let other_domain = other_owner.seal(layout(), &[1; 9], limits).unwrap();
    let mut other_layout = layout();
    other_layout.schema = [9; 16];
    let other_schema = owner.seal(other_layout, &[1; 9], limits).unwrap();

    for image in [other_domain, other_schema] {
        assert!(EncryptedSnapshot::decode(&image.encode(), limits).is_ok());
        assert!(matches!(
            EncryptedSnapshot::decode_for_head(&image.encode(), requested.commitment(), limits),
            Err(Error::WrongVersion)
        ));
    }
}

#[test]
fn matching_manifest_cannot_hide_changed_payload_or_a_truncated_page() {
    let limits = Limits::default();
    let owner = Owner::generate([74; 16]).unwrap();
    let source = owner.seal(layout(), &[1; 9], limits).unwrap();
    let head = source.commitment();
    let mut corrupt = source.encode();
    corrupt[MANIFEST_BYTES + 32] ^= 1;

    assert!(matches!(
        EncryptedSnapshot::decode_for_head(&corrupt, head, limits),
        Err(Error::InvalidProof)
    ));
    assert!(matches!(
        EncryptedSnapshot::decode_for_head(
            &source.encode()[..source.encoded_len() - 1],
            head,
            limits
        ),
        Err(Error::InvalidFormat)
    ));
}

#[test]
fn import_enforces_caps_and_rejects_short_headers_and_trailing_bytes() {
    let limits = Limits::default();
    let owner = Owner::generate([75; 16]).unwrap();
    let source = owner.seal(layout(), &[1; 9], limits).unwrap();
    let image = source.encode();
    let head = source.commitment();
    let restricted = Limits {
        max_image_bytes: image.len() - 1,
        ..limits
    };

    assert!(matches!(
        EncryptedSnapshot::decode_for_head(&image, head, restricted),
        Err(Error::ResourceLimit)
    ));
    for length in 0..MANIFEST_BYTES {
        assert!(matches!(
            EncryptedSnapshot::decode_for_head(&image[..length], head, limits),
            Err(Error::InvalidFormat)
        ));
    }
    let mut extra = image;
    extra.push(0);
    assert!(matches!(
        EncryptedSnapshot::decode_for_head(&extra, head, limits),
        Err(Error::InvalidFormat)
    ));
}
