//! Public synthetic ciphertext fixtures; clone ownership must preserve value semantics.
use compact_store::{Commitment, EncryptedSnapshot, Error, Layout, Limits, Owner};

fn fixture() -> (Owner, EncryptedSnapshot, Vec<u8>) {
    let owner = Owner::generate([61; 16]).unwrap();
    let bytes = (0..33).collect::<Vec<u8>>();
    let snapshot = owner
        .seal(
            Layout {
                schema: [62; 16],
                row_width: 3,
                rows_per_page: 4,
                row_count: 11,
            },
            &bytes,
            Limits::default(),
        )
        .unwrap();
    (owner, snapshot, bytes)
}
fn assert_readable(owner: &Owner, image: &EncryptedSnapshot, head: &Commitment, expected: &[u8]) {
    let limits = Limits::default();
    assert_eq!(image.commitment(), head);
    let restored = EncryptedSnapshot::decode_for_head(&image.encode(), head, limits).unwrap();
    let mut actual = Vec::new();
    for index in 0..head.layout().page_count().unwrap() {
        let page = restored
            .lookup(index as u64, limits)
            .unwrap()
            .verify(head, index as u64, limits)
            .unwrap();
        actual.extend_from_slice(owner.decrypt(&page).unwrap().as_bytes());
    }
    assert_eq!(actual, expected);
}

#[test]
fn single_and_batch_replacements_on_a_clone_keep_both_versions_independent() {
    let (owner, mut original, bytes) = fixture();
    let limits = Limits::default();
    let old = original.commitment().clone();
    let original_encoded = original.encode();
    let mut changed = original.clone();
    let last = [91; 9];
    let first = [92; 12];

    let single = owner
        .replace_page(&mut changed, &old, 2, &last, limits)
        .unwrap();
    let next = owner
        .replace_pages(&mut changed, &single, &[(0, &first), (2, &last)], limits)
        .unwrap();

    let mut changed_bytes = bytes.clone();
    changed_bytes[..12].copy_from_slice(&first);
    changed_bytes[24..].copy_from_slice(&last);
    assert_ne!(next.root(), old.root());
    assert_eq!(next.revision(), old.revision() + 2);
    assert_eq!(original.encode(), original_encoded);
    assert_readable(&owner, &original, &old, &bytes);
    assert_readable(&owner, &changed, &next, &changed_bytes);

    // Editing the original in turn cannot alter the clone's slots or Merkle path.
    let changed_encoded = changed.encode();
    let middle = [93; 12];
    let original_next = owner
        .replace_page(&mut original, &old, 1, &middle, limits)
        .unwrap();
    let mut original_bytes = bytes;
    original_bytes[12..24].copy_from_slice(&middle);
    assert_eq!(changed.encode(), changed_encoded);
    assert_readable(&owner, &original, &original_next, &original_bytes);
    assert_readable(&owner, &changed, &next, &changed_bytes);
}

#[test]
fn verified_reconstruction_of_a_clone_preserves_original_and_target_images() {
    let (owner, original, bytes) = fixture();
    let limits = Limits::default();
    let old = original.commitment().clone();
    let original_encoded = original.encode();
    let mut target = original.clone();
    let first = [81; 12];
    let last = [82; 9];
    let next = owner
        .replace_pages(&mut target, &old, &[(0, &first), (2, &last)], limits)
        .unwrap();
    let target_encoded = target.encode();
    let proof = |index| {
        target
            .lookup(index, limits)
            .unwrap()
            .verify(&next, index, limits)
            .unwrap()
    };

    assert!(matches!(
        original
            .clone()
            .apply_verified_replacements(&old, &next, vec![proof(0)], limits),
        Err(Error::InvalidProof)
    ));
    let reconstructed = original
        .clone()
        .apply_verified_replacements(&old, &next, vec![proof(0), proof(2)], limits)
        .unwrap();

    let mut target_bytes = bytes.clone();
    target_bytes[..12].copy_from_slice(&first);
    target_bytes[24..].copy_from_slice(&last);
    assert_ne!(old.root(), next.root());
    assert_eq!(reconstructed.encode(), target_encoded);
    assert_eq!(target.encode(), target_encoded);
    assert_eq!(original.encode(), original_encoded);
    assert_readable(&owner, &original, &old, &bytes);
    assert_readable(&owner, &target, &next, &target_bytes);
    assert_readable(&owner, &reconstructed, &next, &target_bytes);
}

#[test]
fn invalid_later_pages_or_duplicate_addresses_roll_back_without_touching_shared_sources() {
    let (owner, original, bytes) = fixture();
    let limits = Limits::default();
    let old = original.commitment().clone();
    let before = original.encode();
    let valid = [71; 12];
    let short = [72; 8];
    for replacements in [
        vec![(0, &valid[..]), (2, &short[..])],
        vec![(0, &valid[..]), (0, &valid[..])],
        vec![(0, &valid[..]), (3, &valid[..])],
    ] {
        let mut changed = original.clone();

        assert!(matches!(
            owner.replace_pages(&mut changed, &old, &replacements, limits),
            Err(Error::InvalidPage)
        ));

        assert_eq!(changed.encode(), before);
        assert_eq!(original.encode(), before);
        assert_readable(&owner, &changed, &old, &bytes);
        assert_readable(&owner, &original, &old, &bytes);
    }
}
