use compact_store::{
    Commitment, EncryptedSnapshot, Error, Layout, Limits, LookupResponse, MANIFEST_BYTES, Owner,
    PAGE_OVERHEAD,
};

// Explicitly public synthetic fixture: the existing age:u8 + amount:u16 schema.
fn rows(count: usize) -> Vec<u8> {
    (0..count)
        .flat_map(|i| {
            let amount = ((i * 719 + 123) % 65_536) as u16;
            [
                ((i * 37 + 11) % 256) as u8,
                amount as u8,
                (amount >> 8) as u8,
            ]
        })
        .collect()
}

fn layout(count: u64, rows_per_page: u32) -> Layout {
    Layout {
        schema: *b"age8/amount16-v1",
        row_width: 3,
        rows_per_page,
        row_count: count,
    }
}

#[test]
fn opaque_peer_round_trip_returns_every_exact_page_including_short_last_page() {
    let limits = Limits::default();
    let plaintext = rows(9);
    let owner = Owner::generate([1; 16]).unwrap();
    let snapshot = owner.seal(layout(9, 4), &plaintext, limits).unwrap();
    let trusted = snapshot.commitment().clone();

    let peer = EncryptedSnapshot::decode(&snapshot.encode(), limits).unwrap();

    for index in 0..3 {
        let wire = peer.lookup(index, limits).unwrap().encode();
        let untrusted = LookupResponse::decode(&wire, limits).unwrap();
        let verified = untrusted.verify(&trusted, index, limits).unwrap();
        let page = owner.decrypt(&verified).unwrap();
        let start = index as usize * 12;
        let end = (start + 12).min(plaintext.len());
        assert_eq!(page.as_bytes(), &plaintext[start..end]);
        assert_eq!(verified.ciphertext().len(), end - start);
    }
    assert_eq!(peer.encoded_len(), MANIFEST_BYTES + 27 + 3 * PAGE_OVERHEAD);
    assert!(matches!(peer.lookup(3, limits), Err(Error::InvalidPage)));
}

#[test]
fn known_logical_row_address_selects_the_matching_row_bytes() {
    let limits = Limits::default();
    let plaintext = rows(17);
    let owner = Owner::generate([2; 16]).unwrap();
    let snapshot = owner.seal(layout(17, 4), &plaintext, limits).unwrap();
    let address = snapshot.commitment().layout().address_of(13).unwrap();

    let response = snapshot.lookup(address.page_index, limits).unwrap();
    let verified = response
        .verify(snapshot.commitment(), address.page_index, limits)
        .unwrap();
    let page = owner.decrypt(&verified).unwrap();

    assert_eq!(
        &page.as_bytes()[address.byte_offset..address.byte_offset + 3],
        &plaintext[39..42]
    );
    assert!(matches!(
        layout(17, 4).address_of(17),
        Err(Error::InvalidPage)
    ));
}

#[test]
fn empty_snapshot_is_canonical_and_cannot_return_a_page() {
    let limits = Limits::default();
    let owner = Owner::generate([3; 16]).unwrap();

    let snapshot = owner.seal(layout(0, 4), &[], limits).unwrap();
    let restored = EncryptedSnapshot::decode(&snapshot.encode(), limits).unwrap();

    assert_eq!(restored.commitment(), snapshot.commitment());
    assert_eq!(restored.encoded_len(), MANIFEST_BYTES);
    assert!(matches!(
        restored.lookup(0, limits),
        Err(Error::InvalidPage)
    ));
}

#[test]
fn tampering_nonce_ciphertext_tag_or_merkle_sibling_is_rejected_before_decryption() {
    let limits = Limits::default();
    let owner = Owner::generate([4; 16]).unwrap();
    let snapshot = owner.seal(layout(9, 4), &rows(9), limits).unwrap();
    let wire = snapshot.lookup(0, limits).unwrap().encode();
    let packet_len = u32::from_le_bytes(wire[8..12].try_into().unwrap()) as usize;

    for offset in [16 + 8, 16 + 32, 16 + packet_len - 1, wire.len() - 1] {
        let mut forged = wire.clone();
        forged[offset] ^= 1;
        let response = LookupResponse::decode(&forged, limits).unwrap();
        assert!(matches!(
            response.verify(snapshot.commitment(), 0, limits),
            Err(Error::InvalidProof)
        ));
    }
}

#[test]
fn another_valid_page_cannot_substitute_for_the_requested_address() {
    let limits = Limits::default();
    let owner = Owner::generate([5; 16]).unwrap();
    let snapshot = owner.seal(layout(12, 4), &rows(12), limits).unwrap();

    let response = snapshot.lookup(1, limits).unwrap();

    assert!(matches!(
        response.verify(snapshot.commitment(), 0, limits),
        Err(Error::InvalidProof)
    ));
}

#[test]
fn omitted_or_extra_proof_nodes_cannot_establish_membership() {
    let limits = Limits::default();
    let owner = Owner::generate([6; 16]).unwrap();
    let snapshot = owner.seal(layout(9, 4), &rows(9), limits).unwrap();
    let wire = snapshot.lookup(2, limits).unwrap().encode();
    let old_count = u32::from_le_bytes(wire[12..16].try_into().unwrap());

    let mut omitted = wire[..wire.len() - 32].to_vec();
    omitted[12..16].copy_from_slice(&(old_count - 1).to_le_bytes());
    let response = LookupResponse::decode(&omitted, limits).unwrap();

    assert!(matches!(
        response.verify(snapshot.commitment(), 2, limits),
        Err(Error::InvalidProof)
    ));
    let mut extra = wire;
    extra.extend_from_slice(&[0; 32]);
    extra[12..16].copy_from_slice(&(old_count + 1).to_le_bytes());
    let response = LookupResponse::decode(&extra, limits).unwrap();
    assert!(matches!(
        response.verify(snapshot.commitment(), 2, limits),
        Err(Error::InvalidProof)
    ));
}

#[test]
fn replayed_page_or_proof_is_rejected_against_the_current_head() {
    let limits = Limits::default();
    let owner = Owner::generate([7; 16]).unwrap();
    let mut snapshot = owner.seal(layout(9, 4), &rows(9), limits).unwrap();
    let old_head = snapshot.commitment().clone();
    let old_changed_page = snapshot.lookup(0, limits).unwrap();
    let old_unchanged_page = snapshot.lookup(2, limits).unwrap();

    let current = owner
        .replace_page(&mut snapshot, &old_head, 0, &rows(4), limits)
        .unwrap();

    assert_eq!(current.revision(), old_head.revision() + 1);
    assert_ne!(current.root(), old_head.root());
    for (index, response) in [(0, old_changed_page), (2, old_unchanged_page)] {
        assert!(response.verify(&current, index, limits).is_err());
        assert!(response.verify(&old_head, index, limits).is_ok());
    }
    assert!(matches!(
        owner.replace_page(&mut snapshot, &old_head, 0, &rows(4), limits),
        Err(Error::WrongVersion)
    ));
}

#[test]
fn thousand_replacements_retain_constant_live_storage_and_current_readability() {
    let limits = Limits::default();
    let owner = Owner::generate([8; 16]).unwrap();
    let mut snapshot = owner.seal(layout(257, 16), &rows(257), limits).unwrap();
    let before = snapshot.encoded_len();
    let index_before = snapshot.index_hash_bytes();
    let initial_nonce = snapshot
        .lookup(0, limits)
        .unwrap()
        .verify(snapshot.commitment(), 0, limits)
        .unwrap()
        .nonce();
    let mut replacement = rows(16);

    for revision in 1..=1000 {
        replacement[0] = revision as u8;
        let previous = snapshot.commitment().clone();
        let current = owner
            .replace_page(&mut snapshot, &previous, 0, &replacement, limits)
            .unwrap();
        assert_eq!(current.revision(), revision);
        assert_eq!(snapshot.encoded_len(), before);
        assert_eq!(snapshot.index_hash_bytes(), index_before);
    }
    let restored = EncryptedSnapshot::decode(&snapshot.encode(), limits).unwrap();
    assert_eq!(restored.commitment(), snapshot.commitment());
    let page = restored
        .lookup(0, limits)
        .unwrap()
        .verify(snapshot.commitment(), 0, limits)
        .unwrap();
    assert_ne!(page.nonce(), initial_nonce);
    assert_eq!(owner.decrypt(&page).unwrap().as_bytes(), replacement);
    assert_eq!(before, MANIFEST_BYTES + 257 * 3 + 17 * PAGE_OVERHEAD);
}

#[test]
fn another_owner_cannot_decrypt_or_replace_a_verified_page() {
    let limits = Limits::default();
    let owner = Owner::generate([9; 16]).unwrap();
    let other = Owner::generate([9; 16]).unwrap();
    let mut snapshot = owner.seal(layout(4, 4), &rows(4), limits).unwrap();
    let trusted = snapshot.commitment().clone();
    let page = snapshot
        .lookup(0, limits)
        .unwrap()
        .verify(&trusted, 0, limits)
        .unwrap();

    assert!(matches!(other.decrypt(&page), Err(Error::WrongOwner)));
    assert!(matches!(
        other.replace_page(&mut snapshot, &trusted, 0, &rows(4), limits),
        Err(Error::WrongOwner)
    ));
    assert_eq!(snapshot.commitment(), &trusted);
}

#[test]
fn different_database_schema_geometry_or_revision_cannot_reuse_a_proof() {
    let limits = Limits::default();
    let owner = Owner::generate([10; 16]).unwrap();
    let snapshot = owner.seal(layout(12, 4), &rows(12), limits).unwrap();
    let response = snapshot.lookup(0, limits).unwrap();

    for offset in [8, 24, 40, 56, 68, 72] {
        let mut bytes = snapshot.commitment().encode();
        bytes[offset] ^= 1;
        if let Ok(forged) = Commitment::decode(&bytes, limits) {
            assert!(response.verify(&forged, 0, limits).is_err());
        }
    }
}

#[test]
fn malformed_and_over_quota_storage_is_rejected_before_import() {
    let limits = Limits::default();
    let owner = Owner::generate([11; 16]).unwrap();
    let snapshot = owner.seal(layout(9, 4), &rows(9), limits).unwrap();
    let wire = snapshot.encode();
    let restricted = Limits {
        max_image_bytes: wire.len() - 1,
        ..limits
    };

    assert!(matches!(
        EncryptedSnapshot::decode(&wire, restricted),
        Err(Error::ResourceLimit)
    ));
    assert!(EncryptedSnapshot::decode(&wire[..wire.len() - 1], limits).is_err());
    let mut extra = wire.clone();
    extra.push(0);
    assert!(EncryptedSnapshot::decode(&extra, limits).is_err());
    let mut forged_count = wire;
    forged_count[72..80].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(matches!(
        EncryptedSnapshot::decode(&forged_count, limits),
        Err(Error::ResourceLimit)
    ));
    assert!(matches!(
        owner.seal(
            layout(9, 4),
            &rows(9),
            Limits {
                max_pages: 2,
                ..limits
            }
        ),
        Err(Error::ResourceLimit)
    ));
    assert!(matches!(
        owner.seal(
            layout(9, 4),
            &rows(9),
            Limits {
                max_page_plaintext_bytes: 11,
                ..limits
            }
        ),
        Err(Error::ResourceLimit)
    ));
}

#[test]
fn malformed_or_over_quota_response_is_rejected_before_allocating_payload() {
    let limits = Limits::default();
    let owner = Owner::generate([12; 16]).unwrap();
    let snapshot = owner.seal(layout(9, 4), &rows(9), limits).unwrap();
    let wire = snapshot.lookup(0, limits).unwrap().encode();

    assert!(matches!(
        LookupResponse::decode(
            &wire,
            Limits {
                max_response_bytes: wire.len() - 1,
                ..limits
            }
        ),
        Err(Error::ResourceLimit)
    ));
    let mut declared_huge = wire.clone();
    declared_huge[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        LookupResponse::decode(&declared_huge, limits),
        Err(Error::ResourceLimit)
    ));
    let mut huge_proof = wire.clone();
    huge_proof[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        LookupResponse::decode(&huge_proof, limits),
        Err(Error::ResourceLimit)
    ));
    assert!(LookupResponse::decode(&wire[..wire.len() - 1], limits).is_err());
}

#[test]
fn failed_replacement_preserves_the_previous_version_and_payload() {
    let limits = Limits::default();
    let owner = Owner::generate([13; 16]).unwrap();
    let mut snapshot = owner.seal(layout(9, 4), &rows(9), limits).unwrap();
    let before = snapshot.encode();
    let trusted = snapshot.commitment().clone();

    assert!(matches!(
        owner.replace_page(&mut snapshot, &trusted, 0, &[1], limits),
        Err(Error::InvalidPage)
    ));

    assert_eq!(snapshot.encode(), before);
}

#[test]
fn overflowing_or_unrepresentable_layouts_fail_before_sealing() {
    let limits = Limits {
        max_rows: u64::MAX,
        max_pages: u32::MAX,
        max_page_plaintext_bytes: usize::MAX,
        max_image_bytes: usize::MAX,
        max_response_bytes: usize::MAX,
    };
    let overflowing_rows = Layout {
        schema: [0; 16],
        row_width: 3,
        rows_per_page: 256,
        row_count: u64::MAX,
    };
    let oversized_packet = Layout {
        schema: [0; 16],
        row_width: u32::MAX,
        rows_per_page: u32::MAX,
        row_count: 1,
    };

    assert!(matches!(
        overflowing_rows.validate(limits),
        Err(Error::ResourceLimit)
    ));
    assert!(matches!(
        oversized_packet.validate(limits),
        Err(Error::ResourceLimit)
    ));
}

#[test]
fn all_short_headers_are_rejected_without_panicking() {
    let limits = Limits::default();
    let owner = Owner::generate([14; 16]).unwrap();
    let snapshot = owner.seal(layout(4, 4), &rows(4), limits).unwrap();
    let image = snapshot.encode();
    let response = snapshot.lookup(0, limits).unwrap().encode();

    for prefix_len in 0..MANIFEST_BYTES {
        assert!(Commitment::decode(&image[..prefix_len], limits).is_err());
        assert!(EncryptedSnapshot::decode(&image[..prefix_len], limits).is_err());
    }
    for prefix_len in 0..16 {
        assert!(LookupResponse::decode(&response[..prefix_len], limits).is_err());
    }
}

#[test]
fn corrupted_version_root_or_future_page_revision_cannot_be_imported() {
    let limits = Limits::default();
    let owner = Owner::generate([15; 16]).unwrap();
    let snapshot = owner.seal(layout(4, 4), &rows(4), limits).unwrap();
    let mut corrupted_root = snapshot.encode();
    let mut future_page = corrupted_root.clone();

    corrupted_root[80] ^= 1;
    future_page[MANIFEST_BYTES..MANIFEST_BYTES + 8].copy_from_slice(&1u64.to_le_bytes());

    assert!(matches!(
        EncryptedSnapshot::decode(&corrupted_root, limits),
        Err(Error::InvalidProof)
    ));
    assert!(matches!(
        EncryptedSnapshot::decode(&future_page, limits),
        Err(Error::InvalidFormat)
    ));
}

#[test]
fn peer_refuses_to_construct_a_response_above_its_response_quota() {
    let limits = Limits::default();
    let owner = Owner::generate([16; 16]).unwrap();
    let snapshot = owner.seal(layout(4, 4), &rows(4), limits).unwrap();
    let response_len = snapshot.lookup(0, limits).unwrap().encoded_len();

    let result = snapshot.lookup(
        0,
        Limits {
            max_response_bytes: response_len - 1,
            ..limits
        },
    );

    assert!(matches!(result, Err(Error::ResourceLimit)));
}
