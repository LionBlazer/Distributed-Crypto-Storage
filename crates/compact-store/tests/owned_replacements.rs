//! Public ciphertext fixtures compare both checked reconstruction representations.
use compact_store::{
    EncryptedSnapshot, Error, Layout, Limits, MANIFEST_BYTES, OwnedVerifiedSnapshotBytes, Owner,
    PAGE_OVERHEAD, VerifiedPage,
};

fn fixture(count: usize) -> (Owner, EncryptedSnapshot, EncryptedSnapshot, Vec<u64>) {
    let owner = Owner::generate([87; 16]).unwrap();
    let rows = if count == 0 { 0 } else { (count - 1) * 2 + 1 };
    let original = owner
        .seal(
            Layout {
                schema: [88; 16],
                row_width: 3,
                rows_per_page: 2,
                row_count: rows as u64,
            },
            &vec![7; rows * 3],
            Limits::default(),
        )
        .unwrap();
    let mut next = original.clone();
    let indices = match count {
        0 => vec![],
        1 => vec![0],
        _ => vec![0, count as u64 - 1],
    };
    let values: Vec<_> = indices
        .iter()
        .map(|index| {
            (
                *index,
                vec![9; if *index + 1 == count as u64 { 3 } else { 6 }],
            )
        })
        .collect();
    let replacements: Vec<_> = values
        .iter()
        .map(|(index, bytes)| (*index, bytes.as_slice()))
        .collect();
    if !replacements.is_empty() {
        owner
            .replace_pages(
                &mut next,
                original.commitment(),
                &replacements,
                Limits::default(),
            )
            .unwrap();
    }
    (owner, original, next, indices)
}
fn verified(image: &EncryptedSnapshot, indices: &[u64]) -> Vec<VerifiedPage> {
    indices
        .iter()
        .map(|index| {
            image
                .lookup(*index, Limits::default())
                .unwrap()
                .verify(image.commitment(), *index, Limits::default())
                .unwrap()
        })
        .collect()
}
fn owned(image: &EncryptedSnapshot) -> OwnedVerifiedSnapshotBytes {
    OwnedVerifiedSnapshotBytes::decode_for_head(
        image.encode(),
        image.commitment(),
        Limits::default(),
    )
    .unwrap()
}

#[test]
fn owned_reconstruction_keeps_its_allocation_and_exact_odd_even_partial_target() {
    for count in [1, 2, 3, 5, 8, 9, 16, 17] {
        let (owner, original, next, indices) = fixture(count);
        let before = original.encode();
        let mut bytes = before.clone();
        bytes.reserve_exact(71);
        let pointer = bytes.as_ptr();
        let capacity = bytes.capacity();
        let base = OwnedVerifiedSnapshotBytes::decode_for_head(
            bytes,
            original.commitment(),
            Limits::default(),
        )
        .unwrap();

        let rebuilt = base
            .apply_verified_replacements(
                original.commitment(),
                next.commitment(),
                verified(&next, &indices),
                Limits::default(),
            )
            .unwrap();

        assert_eq!(rebuilt.commitment(), next.commitment());
        for page in 0..count as u64 {
            let response = rebuilt.lookup(page, Limits::default()).unwrap();
            let actual = response
                .verify(next.commitment(), page, Limits::default())
                .unwrap();
            let expected = next
                .lookup(page, Limits::default())
                .unwrap()
                .verify(next.commitment(), page, Limits::default())
                .unwrap();
            assert_eq!(
                owner.decrypt(&actual).unwrap().as_bytes(),
                owner.decrypt(&expected).unwrap().as_bytes()
            );
        }
        let result = rebuilt.into_bytes();
        assert_eq!(result.as_ptr(), pointer);
        assert_eq!(result.capacity(), capacity);
        assert_eq!(result, next.encode());
        assert_eq!(&result[..MANIFEST_BYTES], &next.commitment().encode());
        for page in (0..count as u64).filter(|page| !indices.contains(page)) {
            let start = MANIFEST_BYTES + page as usize * (6 + PAGE_OVERHEAD);
            let end = start + if page + 1 == count as u64 { 3 } else { 6 } + PAGE_OVERHEAD;
            assert_eq!(&result[start..end], &before[start..end]);
        }
        let snapshot = original
            .clone()
            .apply_verified_replacements(
                original.commitment(),
                next.commitment(),
                verified(&next, &indices),
                Limits::default(),
            )
            .unwrap();
        assert_eq!(result, snapshot.encode());
        assert_eq!(original.encode(), before);
    }
}

#[test]
fn exact_unchanged_empty_or_populated_images_need_no_packet_or_revision_rewrite() {
    for count in [0, 1, 5] {
        let (_, original, _, _) = fixture(count);
        let bytes = original.encode();
        let pointer = bytes.as_ptr();
        let capacity = bytes.capacity();
        let base = OwnedVerifiedSnapshotBytes::decode_for_head(
            bytes,
            original.commitment(),
            Limits::default(),
        )
        .unwrap();

        let same = base
            .apply_verified_replacements(
                original.commitment(),
                original.commitment(),
                vec![],
                Limits::default(),
            )
            .unwrap()
            .into_bytes();

        assert_eq!(same.as_ptr(), pointer);
        assert_eq!(same.capacity(), capacity);
        assert_eq!(same, original.encode());
        assert!(matches!(
            owned(&original).apply_verified_replacements(
                original.commitment(),
                original.commitment(),
                vec![],
                Limits {
                    max_image_bytes: original.encoded_len() - 1,
                    ..Limits::default()
                },
            ),
            Err(Error::ResourceLimit)
        ));
    }
}

#[test]
fn rejected_targets_match_snapshot_errors_and_never_change_the_external_base() {
    let (owner, original, mut next, _) = fixture(5);
    let before = original.encode();
    for (indices, expected) in [
        (vec![], Error::InvalidPage),
        (vec![0], Error::InvalidProof),
        (vec![4], Error::InvalidProof),
        (vec![0, 0], Error::InvalidPage),
    ] {
        let actual = owned(&original).apply_verified_replacements(
            original.commitment(),
            next.commitment(),
            verified(&next, &indices),
            Limits::default(),
        );
        assert_eq!(actual.err(), Some(expected));
        assert_eq!(
            original
                .clone()
                .apply_verified_replacements(
                    original.commitment(),
                    next.commitment(),
                    verified(&next, &indices),
                    Limits::default(),
                )
                .err(),
            Some(expected)
        );
        assert_eq!(original.encode(), before);
    }
    assert!(matches!(
        owned(&original).apply_verified_replacements(
            next.commitment(),
            next.commitment(),
            vec![],
            Limits {
                max_image_bytes: 0,
                ..Limits::default()
            },
        ),
        Err(Error::WrongVersion)
    ));
    assert!(matches!(
        owned(&original).apply_verified_replacements(
            original.commitment(),
            next.commitment(),
            verified(&next, &[0, 4]),
            Limits {
                max_pages: 4,
                ..Limits::default()
            },
        ),
        Err(Error::ResourceLimit)
    ));
    assert!(matches!(
        owned(&original).apply_verified_replacements(
            original.commitment(),
            next.commitment(),
            verified(&original, &[0, 4]),
            Limits::default(),
        ),
        Err(Error::WrongVersion)
    ));
    let (_, _, foreign, _) = fixture(5);
    assert!(matches!(
        owned(&original).apply_verified_replacements(
            original.commitment(),
            next.commitment(),
            verified(&foreign, &[0, 4]),
            Limits::default(),
        ),
        Err(Error::WrongVersion)
    ));
    assert!(matches!(
        owned(&original).apply_verified_replacements(
            original.commitment(),
            original.commitment(),
            verified(&original, &[0]),
            Limits::default(),
        ),
        Err(Error::WrongVersion)
    ));
    // A valid first replacement cannot make a later foreign proof acceptable.
    let mut mixed = verified(&next, &[0]);
    mixed.extend(verified(&foreign, &[4]));
    assert!(matches!(
        owned(&original).apply_verified_replacements(
            original.commitment(),
            next.commitment(),
            mixed,
            Limits::default(),
        ),
        Err(Error::WrongVersion)
    ));
    let wrong_layout = owner
        .seal(
            Layout {
                schema: [89; 16],
                ..original.commitment().layout()
            },
            &[7; 27],
            Limits::default(),
        )
        .unwrap();
    assert!(matches!(
        owned(&original).apply_verified_replacements(
            original.commitment(),
            wrong_layout.commitment(),
            vec![],
            Limits::default(),
        ),
        Err(Error::WrongVersion)
    ));
    let first = next.commitment().clone();
    owner
        .replace_page(&mut next, &first, 2, &[5; 6], Limits::default())
        .unwrap();
    assert!(matches!(
        owned(&original).apply_verified_replacements(
            original.commitment(),
            next.commitment(),
            verified(&next, &[0, 2, 4]),
            Limits::default(),
        ),
        Err(Error::WrongVersion)
    ));
    assert_eq!(original.encode(), before);
}

#[test]
fn unique_page_order_and_extra_valid_target_members_keep_the_existing_core_contract() {
    let (_, original, next, _) = fixture(5);
    // The outer delta wire owns canonical ordering. This generic primitive has
    // always accepted reordered unique members and unchanged target members.
    let actual = owned(&original)
        .apply_verified_replacements(
            original.commitment(),
            next.commitment(),
            verified(&next, &[4, 2, 0]),
            Limits::default(),
        )
        .unwrap();
    let snapshot = original
        .clone()
        .apply_verified_replacements(
            original.commitment(),
            next.commitment(),
            verified(&next, &[4, 2, 0]),
            Limits::default(),
        )
        .unwrap();
    assert_eq!(actual.into_bytes(), snapshot.encode());
    assert_eq!(snapshot.encode(), next.encode());
}

#[test]
fn one_two_64_256_and_257_owned_replacements_preserve_exact_target_bytes() {
    for count in [1, 2, 64, 256, 257] {
        let owner = Owner::generate([90; 16]).unwrap();
        let original = owner
            .seal(
                Layout {
                    schema: [91; 16],
                    row_width: 1,
                    rows_per_page: 1,
                    row_count: 300,
                },
                &[7; 300],
                Limits::default(),
            )
            .unwrap();
        let mut next = original.clone();
        let replacements: Vec<_> = (0..count).map(|index| (index as u64, &[9][..])).collect();
        owner
            .replace_pages(
                &mut next,
                original.commitment(),
                &replacements,
                Limits::default(),
            )
            .unwrap();
        let indices: Vec<_> = (0..count as u64).collect();

        let actual = owned(&original)
            .apply_verified_replacements(
                original.commitment(),
                next.commitment(),
                verified(&next, &indices),
                Limits::default(),
            )
            .unwrap();

        assert_eq!(actual.into_bytes(), next.encode());
        assert_eq!(original.commitment().revision(), 0);
    }
}
