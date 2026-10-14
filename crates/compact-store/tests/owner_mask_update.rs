use compact_store::{Error, Layout, Limits, Owner};

#[test]
fn owner_mask_reconstructs_authenticated_ciphertext_range_without_key_export() {
    let limits = Limits::default();
    let owner = Owner::generate([91; 16]).unwrap();
    let layout = Layout {
        schema: [3; 16],
        row_width: 3,
        rows_per_page: 2,
        row_count: 2,
    };
    let snapshot = owner.seal(layout, &[1, 2, 3, 4, 5, 6], limits).unwrap();
    let verified = snapshot
        .lookup(0, limits)
        .unwrap()
        .verify(snapshot.commitment(), 0, limits)
        .unwrap();
    let mask = owner.derive_keystream_range(&verified, 3..6).unwrap();
    let restored: Vec<_> = verified.ciphertext()[3..6]
        .iter()
        .zip(mask.as_bytes())
        .map(|(c, p)| c ^ p)
        .collect();
    assert_eq!(restored, [4, 5, 6]);
    assert!(matches!(
        owner.derive_keystream_range(&verified, 5..7),
        Err(Error::InvalidPage)
    ));
    let foreign = Owner::generate([91; 16]).unwrap();
    assert!(matches!(
        foreign.derive_keystream_range(&verified, 0..3),
        Err(Error::WrongOwner)
    ));
}
#[test]
fn batch_invalid_later_page_or_duplicate_leaves_every_encrypted_page_intact() {
    let limits = Limits::default();
    let owner = Owner::generate([92; 16]).unwrap();
    let layout = Layout {
        schema: [3; 16],
        row_width: 3,
        rows_per_page: 1,
        row_count: 2,
    };
    let mut snapshot = owner.seal(layout, &[1, 2, 3, 4, 5, 6], limits).unwrap();
    let head = snapshot.commitment().clone();
    let original = snapshot.encode();
    for replacements in [
        vec![(0, &[7, 8, 9][..]), (1, &[1, 2][..])],
        vec![(0, &[7, 8, 9][..]), (0, &[7, 8, 9][..])],
    ] {
        assert!(matches!(
            owner.replace_pages(&mut snapshot, &head, &replacements, limits),
            Err(Error::InvalidPage)
        ));
        assert_eq!(snapshot.encode(), original);
    }
    let next = owner
        .replace_pages(
            &mut snapshot,
            &head,
            &[(0, &[7, 8, 9]), (1, &[10, 11, 12])],
            limits,
        )
        .unwrap();
    assert_eq!(next.revision(), 1);
    assert_eq!(snapshot.encoded_len(), original.len());
    for (page, expected) in [(0, &[7, 8, 9][..]), (1, &[10, 11, 12][..])] {
        let verified = snapshot
            .lookup(page, limits)
            .unwrap()
            .verify(&next, page, limits)
            .unwrap();
        assert_eq!(owner.decrypt(&verified).unwrap().as_bytes(), expected);
        assert_eq!(verified.page_revision(), 1);
    }
}
