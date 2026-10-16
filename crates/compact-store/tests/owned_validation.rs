use compact_store::{EncryptedSnapshot, Error, Layout, Limits, OwnedVerifiedSnapshotBytes, Owner};

fn image(owner: &Owner, pages: usize) -> EncryptedSnapshot {
    let rows = if pages == 0 { 0 } else { (pages - 1) * 4 + 1 };
    owner
        .seal(
            Layout {
                schema: [82; 16],
                row_width: 3,
                rows_per_page: 4,
                row_count: rows as u64,
            },
            &vec![19; rows * 3],
            Limits::default(),
        )
        .unwrap()
}

#[test]
fn consuming_an_owned_audit_returns_the_original_allocation_and_bytes() {
    let owner = Owner::generate([81; 16]).unwrap();
    for pages in [0, 1, 2, 3, 5, 8, 9, 16, 17] {
        let source = image(&owner, pages);
        let expected = source.encode();
        let mut bytes = expected.clone();
        bytes.reserve_exact(73);
        let pointer = bytes.as_ptr();
        let capacity = bytes.capacity();

        let checked = OwnedVerifiedSnapshotBytes::decode_for_head(
            bytes,
            source.commitment(),
            Limits::default(),
        )
        .unwrap();
        assert_eq!(checked.commitment(), source.commitment());
        let returned = checked.into_bytes();

        assert_eq!(returned.as_ptr(), pointer);
        assert_eq!(returned.capacity(), capacity);
        assert_eq!(returned, expected);
    }
}

#[test]
fn owned_odd_even_empty_and_partial_images_lookup_and_materialize_exactly() {
    let owner = Owner::generate([83; 16]).unwrap();
    for pages in [0, 1, 2, 3, 5, 8, 9, 16, 17] {
        let source = image(&owner, pages);
        let checked = OwnedVerifiedSnapshotBytes::decode_for_head(
            source.encode(),
            source.commitment(),
            Limits::default(),
        )
        .unwrap();
        for page in 0..pages as u64 {
            let response = checked.lookup(page, Limits::default()).unwrap();
            assert_eq!(
                response.encode(),
                source.lookup(page, Limits::default()).unwrap().encode()
            );
            let verified = response
                .verify(source.commitment(), page, Limits::default())
                .unwrap();
            assert_eq!(
                owner.decrypt(&verified).unwrap().as_bytes(),
                vec![19; if page + 1 == pages as u64 { 3 } else { 12 }]
            );
        }
        assert!(matches!(
            checked.lookup(pages as u64, Limits::default()),
            Err(Error::InvalidPage)
        ));

        let materialized = checked.into_snapshot();

        assert_eq!(materialized.commitment(), source.commitment());
        assert_eq!(materialized.encode(), source.encode());
        assert_eq!(materialized.index_hash_bytes(), source.index_hash_bytes());
        for page in 0..pages as u64 {
            assert_eq!(
                materialized
                    .lookup(page, Limits::default())
                    .unwrap()
                    .encode(),
                source.lookup(page, Limits::default()).unwrap().encode()
            );
        }
    }
}

#[test]
fn an_owned_audit_does_not_bypass_lower_lookup_limits() {
    let owner = Owner::generate([84; 16]).unwrap();
    let source = image(&owner, 5);
    let encoded = source.encode();
    let response = source.lookup(0, Limits::default()).unwrap();
    let checked = OwnedVerifiedSnapshotBytes::decode_for_head(
        encoded.clone(),
        source.commitment(),
        Limits::default(),
    )
    .unwrap();
    for restricted in [
        Limits {
            max_response_bytes: response.encoded_len() - 1,
            ..Limits::default()
        },
        Limits {
            max_pages: 4,
            ..Limits::default()
        },
        Limits {
            max_image_bytes: encoded.len() - 1,
            ..Limits::default()
        },
    ] {
        assert!(matches!(
            checked.lookup(0, restricted),
            Err(Error::ResourceLimit)
        ));
    }
    assert!(matches!(
        checked.lookup(
            99,
            Limits {
                max_pages: 4,
                ..Limits::default()
            }
        ),
        Err(Error::ResourceLimit)
    ));
}
