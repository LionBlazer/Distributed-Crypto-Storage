use compact_store::{
    EncryptedSnapshot, Error, Layout, Limits, MANIFEST_BYTES, OwnedVerifiedSnapshotBytes, Owner,
    VerifiedSnapshotBytes,
};

fn image(owner: &Owner, pages: usize) -> EncryptedSnapshot {
    let rows = if pages == 0 { 0 } else { (pages - 1) * 4 + 1 };
    owner
        .seal(
            Layout {
                schema: [69; 16],
                row_width: 3,
                rows_per_page: 4,
                row_count: rows as u64,
            },
            &vec![7; rows * 3],
            Limits::default(),
        )
        .unwrap()
}

#[test]
fn borrowed_odd_even_empty_and_partial_images_lookup_and_materialize_exactly() {
    let owner = Owner::generate([68; 16]).unwrap();
    for pages in [0, 1, 2, 3, 5, 8, 9, 16, 17] {
        let source = image(&owner, pages);
        let encoded = source.encode();
        let checked = VerifiedSnapshotBytes::decode_for_head(
            &encoded,
            source.commitment(),
            Limits::default(),
        )
        .unwrap();
        assert_eq!(checked.commitment(), source.commitment());
        for page in 0..pages as u64 {
            let response = checked.lookup(page, Limits::default()).unwrap();
            assert_eq!(
                response.encode(),
                source.lookup(page, Limits::default()).unwrap().encode()
            );
            let verified = response
                .verify(source.commitment(), page, Limits::default())
                .unwrap();
            let plain = owner.decrypt(&verified).unwrap();
            assert_eq!(
                plain.as_bytes(),
                vec![7; if page + 1 == pages as u64 { 3 } else { 12 }]
            );
        }
        assert!(matches!(
            checked.lookup(pages as u64, Limits::default()),
            Err(Error::InvalidPage)
        ));
        let materialized = checked.into_snapshot();
        assert_eq!(materialized.commitment(), source.commitment());
        assert_eq!(materialized.encode(), encoded);
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
fn borrowed_and_owned_imports_keep_canonical_rejection_and_check_order() {
    let owner = Owner::generate([70; 16]).unwrap();
    let source = image(&owner, 3);
    let encoded = source.encode();
    for (name, changed, expected) in [
        (
            "bad magic",
            {
                let mut b = encoded.clone();
                b[0] ^= 1;
                b
            },
            Error::InvalidFormat,
        ),
        (
            "zero row width",
            {
                let mut b = encoded.clone();
                b[64..68].fill(0);
                b
            },
            Error::InvalidFormat,
        ),
        (
            "overlong geometry",
            {
                let mut b = encoded.clone();
                b[72..80].copy_from_slice(&1_000_001u64.to_le_bytes());
                b
            },
            Error::ResourceLimit,
        ),
        (
            "truncated tail",
            encoded[..encoded.len() - 1].to_vec(),
            Error::InvalidFormat,
        ),
        (
            "trailing byte",
            {
                let mut b = encoded.clone();
                b.push(0);
                b
            },
            Error::InvalidFormat,
        ),
        (
            "future packet revision",
            {
                let mut b = encoded.clone();
                b[MANIFEST_BYTES..MANIFEST_BYTES + 8].copy_from_slice(&1u64.to_le_bytes());
                b
            },
            Error::InvalidFormat,
        ),
        (
            "corrupt unseen tail",
            {
                let mut b = encoded.clone();
                *b.last_mut().unwrap() ^= 1;
                b
            },
            Error::InvalidProof,
        ),
        (
            "bad earlier packet plus later future revision",
            {
                let mut b = encoded.clone();
                b[MANIFEST_BYTES + 32] ^= 1;
                let later = MANIFEST_BYTES + 2 * (12 + 48);
                b[later..later + 8].copy_from_slice(&1u64.to_le_bytes());
                b
            },
            Error::InvalidFormat,
        ),
    ] {
        assert_eq!(
            VerifiedSnapshotBytes::decode_for_head(
                &changed,
                source.commitment(),
                Limits::default()
            )
            .err(),
            Some(expected),
            "borrowed: {name}"
        );
        assert_eq!(
            OwnedVerifiedSnapshotBytes::decode_for_head(
                changed.clone(),
                source.commitment(),
                Limits::default(),
            )
            .err(),
            Some(expected),
            "owned bytes: {name}"
        );
        assert_eq!(
            EncryptedSnapshot::decode_for_head(&changed, source.commitment(), Limits::default())
                .err(),
            Some(expected),
            "owned: {name}"
        );
        assert_eq!(
            EncryptedSnapshot::decode(&changed, Limits::default()).err(),
            Some(expected),
            "embedded: {name}"
        );
    }
    let other = image(&owner, 2);
    let truncated = &encoded[..encoded.len() - 1];
    assert_eq!(
        VerifiedSnapshotBytes::decode_for_head(truncated, other.commitment(), Limits::default())
            .err(),
        Some(Error::WrongVersion)
    );
    assert_eq!(
        EncryptedSnapshot::decode_for_head(truncated, other.commitment(), Limits::default()).err(),
        Some(Error::WrongVersion)
    );
    assert_eq!(
        OwnedVerifiedSnapshotBytes::decode_for_head(
            truncated.to_vec(),
            other.commitment(),
            Limits::default(),
        )
        .err(),
        Some(Error::WrongVersion)
    );
    let restricted = Limits {
        max_image_bytes: 1,
        ..Limits::default()
    };
    assert_eq!(
        VerifiedSnapshotBytes::decode_for_head(truncated, other.commitment(), restricted).err(),
        Some(Error::ResourceLimit)
    );
    assert_eq!(
        EncryptedSnapshot::decode_for_head(truncated, other.commitment(), restricted).err(),
        Some(Error::ResourceLimit)
    );
    assert_eq!(
        OwnedVerifiedSnapshotBytes::decode_for_head(
            truncated.to_vec(),
            other.commitment(),
            restricted,
        )
        .err(),
        Some(Error::ResourceLimit)
    );
    for length in 0..MANIFEST_BYTES {
        assert_eq!(
            OwnedVerifiedSnapshotBytes::decode_for_head(
                encoded[..length].to_vec(),
                source.commitment(),
                Limits::default(),
            )
            .err(),
            Some(Error::InvalidFormat)
        );
        assert_eq!(
            VerifiedSnapshotBytes::decode_for_head(
                &encoded[..length],
                source.commitment(),
                Limits::default()
            )
            .err(),
            Some(Error::InvalidFormat)
        );
    }
}

#[test]
fn a_borrowed_audit_does_not_bypass_lower_lookup_limits() {
    let owner = Owner::generate([71; 16]).unwrap();
    let source = image(&owner, 5);
    let encoded = source.encode();
    let checked =
        VerifiedSnapshotBytes::decode_for_head(&encoded, source.commitment(), Limits::default())
            .unwrap();
    let response = checked.lookup(0, Limits::default()).unwrap();
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
        assert!(matches!(
            source.lookup(0, restricted),
            Err(Error::ResourceLimit)
        ));
    }
    let restricted = Limits {
        max_pages: 4,
        ..Limits::default()
    };
    assert!(matches!(
        checked.lookup(99, restricted),
        Err(Error::ResourceLimit)
    ));
    assert!(matches!(
        source.lookup(99, restricted),
        Err(Error::ResourceLimit)
    ));
}
