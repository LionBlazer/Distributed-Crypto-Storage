//! Actual encrypted public fixtures; path reissue grants no SQL/head authority.
use compact_store::{
    EncryptedSnapshot, Error, Layout, Limits, LookupResponse, MANIFEST_BYTES, Owner, PAGE_OVERHEAD,
};
use std::collections::BTreeSet;

fn fixture(pages: usize) -> (Owner, EncryptedSnapshot) {
    let owner = Owner::generate([81; 16]).unwrap();
    let rows = if pages == 0 { 0 } else { (pages - 1) * 4 + 3 };
    let bytes = (0..rows * 3).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    let snapshot = owner
        .seal(
            Layout {
                schema: [82; 16],
                row_width: 3,
                rows_per_page: 4,
                row_count: rows as u64,
            },
            &bytes,
            Limits::default(),
        )
        .unwrap();
    (owner, snapshot)
}

#[test]
fn empty_image_has_no_reissuable_page() {
    let (_, image) = fixture(0);
    assert!(matches!(
        image.lookup(0, Limits::default()),
        Err(Error::InvalidPage)
    ));
}

#[test]
fn odd_even_and_partial_page_paths_match_full_reconstruction_of_the_same_packet() {
    let limits = Limits::default();
    for pages in [1, 2, 3, 5, 8, 9, 16, 17] {
        let (owner, original) = fixture(pages);
        let old = original.commitment().clone();
        let original_bytes = original.encode();
        for index in BTreeSet::from([0, pages / 2, pages - 1]) {
            let index = index as u64;
            let response = original.lookup(index, limits).unwrap();
            let old_page = response.verify(&old, index, limits).unwrap();
            let original_plain = owner.decrypt(&old_page).unwrap();
            let replacement = vec![71; original_plain.as_bytes().len()];
            let source = response.verify_for_reissue(&old, index, limits).unwrap();
            assert_eq!(source.commitment(), &old);
            assert_eq!(source.page_index(), index);

            let (next, replacement_proof) = owner
                .reissue_page(source, &old, &replacement, limits)
                .unwrap();

            assert_eq!(next.layout(), old.layout());
            assert_eq!(next.revision(), old.revision() + 1);
            assert_ne!(next.root(), old.root());
            let checked = replacement_proof.verify(&next, index, limits).unwrap();
            assert_eq!(checked.page_revision(), next.revision());
            assert_ne!(checked.nonce(), old_page.nonce());
            assert_eq!(owner.decrypt(&checked).unwrap().as_bytes(), replacement);
            assert!(replacement_proof.verify(&old, index, limits).is_err());
            assert!(response.verify(&next, index, limits).is_err());
            let rebuilt = original
                .clone()
                .apply_verified_replacements(&old, &next, vec![checked], limits)
                .unwrap();

            // Independently replace exactly the returned canonical packet in the
            // full original wire image, then rebuild EVERY leaf from those bytes.
            let wire = replacement_proof.encode();
            let length = u32::from_le_bytes(wire[8..12].try_into().unwrap()) as usize;
            let offset = MANIFEST_BYTES + index as usize * (4 * 3 + PAGE_OVERHEAD);
            let mut expected_bytes = original_bytes.clone();
            expected_bytes[..MANIFEST_BYTES].copy_from_slice(&next.encode());
            expected_bytes[offset..offset + length].copy_from_slice(&wire[16..16 + length]);
            let decoded =
                EncryptedSnapshot::decode_for_head(&expected_bytes, &next, limits).unwrap();
            assert_eq!(
                rebuilt.encode(),
                expected_bytes,
                "pages {pages}, index {index}"
            );
            assert_eq!(decoded.commitment(), &next);
            assert_eq!(original.encode(), original_bytes);
            assert_eq!(original.commitment(), &old);
            assert_eq!(
                owner.decrypt(&old_page).unwrap().as_bytes(),
                original_plain.as_bytes()
            );
        }
    }
}

#[test]
fn wrong_address_packet_path_or_expected_head_cannot_create_a_reissue_capability() {
    let (_, image) = fixture(5);
    let (_, other) = fixture(5);
    let head = image.commitment();
    let limits = Limits::default();
    let response = image.lookup(4, limits).unwrap();
    assert!(response.verify_for_reissue(head, 0, limits).is_err());
    assert!(
        response
            .verify_for_reissue(other.commitment(), 4, limits)
            .is_err()
    );
    let wire = response.encode();
    let packet_len = u32::from_le_bytes(wire[8..12].try_into().unwrap()) as usize;
    for offset in [0, 16, 16 + 32, 16 + packet_len - 1, 16 + packet_len] {
        let mut bad = wire.clone();
        bad[offset] ^= 1;
        let parsed = LookupResponse::decode(&bad, limits).unwrap();
        assert!(
            parsed.verify_for_reissue(head, 4, limits).is_err(),
            "offset {offset}"
        );
    }
    let low = Limits {
        max_response_bytes: wire.len() - 1,
        ..limits
    };
    assert!(matches!(
        response.verify_for_reissue(head, 4, low),
        Err(Error::ResourceLimit)
    ));
}

#[test]
fn reissue_rechecks_owner_current_head_length_and_lower_resource_limits() {
    let (owner, image) = fixture(3);
    let foreign = Owner::generate([81; 16]).unwrap();
    let head = image.commitment();
    let limits = Limits::default();
    let before = image.encode();
    let response = image.lookup(2, limits).unwrap();
    let source = || response.verify_for_reissue(head, 2, limits).unwrap();
    assert!(matches!(
        foreign.reissue_page(source(), head, &[1; 9], limits),
        Err(Error::WrongOwner)
    ));
    assert!(matches!(
        owner.reissue_page(source(), head, &[1; 8], limits),
        Err(Error::InvalidPage)
    ));
    for low in [
        Limits {
            max_pages: 2,
            ..limits
        },
        Limits {
            max_image_bytes: before.len() - 1,
            ..limits
        },
        Limits {
            max_response_bytes: response.encoded_len() - 1,
            ..limits
        },
    ] {
        assert!(matches!(
            owner.reissue_page(source(), head, &[1; 9], low),
            Err(Error::ResourceLimit)
        ));
    }
    let (next, _) = owner.reissue_page(source(), head, &[1; 9], limits).unwrap();
    assert!(matches!(
        owner.reissue_page(source(), &next, &[1; 9], limits),
        Err(Error::WrongVersion)
    ));
    assert_eq!(image.encode(), before);
    assert_eq!(image.commitment(), head);
}
