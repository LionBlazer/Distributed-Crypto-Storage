use compact_store::{
    AuditWorkers, Commitment, EncryptedSnapshot, Error, Layout, Limits, MANIFEST_BYTES,
    OwnedVerifiedSnapshotBytes, Owner, PAGE_OVERHEAD, VerifiedSnapshotBytes,
};

fn limits() -> Limits {
    Limits {
        max_rows: 64 * 1024 * 1024,
        ..Limits::default()
    }
}

fn image(owner: &Owner, pages: usize, width: u32, per_page: u32) -> EncryptedSnapshot {
    let rows = if pages == 0 {
        0
    } else {
        (pages - 1) * per_page as usize + 1
    };
    owner
        .seal(
            Layout {
                schema: [164; 16],
                row_width: width,
                rows_per_page: per_page,
                row_count: rows as u64,
            },
            &vec![41; rows * width as usize],
            limits(),
        )
        .unwrap()
}

fn assert_rejected(bytes: &[u8], head: &Commitment, caps: Limits, expected: Error) {
    for workers in [AuditWorkers::One, AuditWorkers::Two] {
        assert_eq!(
            VerifiedSnapshotBytes::decode_for_head_with_workers(bytes, head, caps, workers).err(),
            Some(expected),
            "borrowed {workers:?}"
        );
        assert_eq!(
            OwnedVerifiedSnapshotBytes::decode_for_head_with_workers(
                bytes.to_vec(),
                head,
                caps,
                workers,
            )
            .err(),
            Some(expected),
            "{workers:?}"
        );
    }
}

#[test]
fn serial_and_optional_two_worker_audits_preserve_canonical_bytes_membership_and_plaintext() {
    assert_eq!(AuditWorkers::default(), AuditWorkers::One);
    let owner = Owner::generate([163; 16]).unwrap();
    // Empty, odd/even, partial tails, above-threshold images, and the page cap.
    for (pages, width, per_page) in [
        (0, 3, 4),
        (1, 3, 4),
        (2, 3, 4),
        (3, 3, 4),
        (5, 3, 4),
        (65, 1, 65_536),
        (66, 1, 65_536),
        (65_536, 16, 1),
    ] {
        let source = image(&owner, pages, width, per_page);
        let expected = source.encode();
        for workers in [AuditWorkers::One, AuditWorkers::Two] {
            let borrowed = VerifiedSnapshotBytes::decode_for_head_with_workers(
                &expected,
                source.commitment(),
                limits(),
                workers,
            )
            .unwrap();
            assert_eq!(borrowed.commitment(), source.commitment());
            let mut bytes = expected.clone();
            bytes.reserve_exact(37);
            let pointer = bytes.as_ptr();
            let capacity = bytes.capacity();
            let checked = OwnedVerifiedSnapshotBytes::decode_for_head_with_workers(
                bytes,
                source.commitment(),
                limits(),
                workers,
            )
            .unwrap();
            assert_eq!(checked.commitment(), source.commitment());
            let returned = checked.into_bytes();
            assert_eq!(returned.as_ptr(), pointer);
            assert_eq!(returned.capacity(), capacity);
            assert_eq!(returned, expected);

            let checked = OwnedVerifiedSnapshotBytes::decode_for_head_with_workers(
                returned,
                source.commitment(),
                limits(),
                workers,
            )
            .unwrap();
            if pages > 0 {
                for page in [0, pages / 2, pages - 1] {
                    let response = checked.lookup(page as u64, limits()).unwrap();
                    assert_eq!(
                        borrowed.lookup(page as u64, limits()).unwrap().encode(),
                        response.encode()
                    );
                    assert_eq!(
                        response.encode(),
                        source.lookup(page as u64, limits()).unwrap().encode()
                    );
                    let verified = response
                        .verify(source.commitment(), page as u64, limits())
                        .unwrap();
                    let plain = owner.decrypt(&verified).unwrap();
                    let rows = if page + 1 == pages {
                        1
                    } else {
                        per_page as usize
                    };
                    assert_eq!(plain.as_bytes(), vec![41; rows * width as usize]);
                }
            }
            assert!(matches!(
                checked.lookup(pages as u64, limits()),
                Err(Error::InvalidPage)
            ));
            let materialized = checked.into_snapshot();
            let borrowed_materialized = borrowed.into_snapshot();
            assert_eq!(materialized.encode(), expected);
            assert_eq!(borrowed_materialized.encode(), expected);
            assert_eq!(
                borrowed_materialized.index_hash_bytes(),
                source.index_hash_bytes()
            );
            assert_eq!(materialized.index_hash_bytes(), source.index_hash_bytes());
        }
    }
}

#[test]
fn complete_audits_reject_corrupt_first_middle_and_unrequested_tail_packets() {
    let owner = Owner::generate([165; 16]).unwrap();
    let source = image(&owner, 65, 1, 65_536);
    let bytes = source.encode();
    assert!(bytes.len() >= 4 * 1024 * 1024);
    let capacity = 65_536 + PAGE_OVERHEAD;
    for offset in [
        MANIFEST_BYTES + 32,
        MANIFEST_BYTES + 32 * capacity + 32,
        bytes.len() - 1,
    ] {
        let mut damaged = bytes.clone();
        damaged[offset] ^= 1;
        assert_rejected(&damaged, source.commitment(), limits(), Error::InvalidProof);
    }
    for page in [0, 32, 64] {
        let mut damaged = bytes.clone();
        let start = MANIFEST_BYTES + page * capacity;
        damaged[start..start + 8].copy_from_slice(&1u64.to_le_bytes());
        assert_rejected(
            &damaged,
            source.commitment(),
            limits(),
            Error::InvalidFormat,
        );
    }
    let mut earlier_corruption_later_revision = bytes.clone();
    earlier_corruption_later_revision[MANIFEST_BYTES + 32] ^= 1;
    let last = MANIFEST_BYTES + 64 * capacity;
    earlier_corruption_later_revision[last..last + 8].copy_from_slice(&1u64.to_le_bytes());
    assert_rejected(
        &earlier_corruption_later_revision,
        source.commitment(),
        limits(),
        Error::InvalidFormat,
    );
}

#[test]
fn optional_workers_preserve_header_head_length_revision_and_root_error_precedence() {
    let owner = Owner::generate([166; 16]).unwrap();
    let source = image(&owner, 65, 1, 65_536);
    let other = image(&owner, 66, 1, 65_536);
    let bytes = source.encode();
    let truncated = &bytes[..bytes.len() - 1];
    assert_rejected(
        truncated,
        source.commitment(),
        limits(),
        Error::InvalidFormat,
    );
    assert_rejected(truncated, other.commitment(), limits(), Error::WrongVersion);
    assert_rejected(
        truncated,
        other.commitment(),
        Limits {
            max_image_bytes: 1,
            ..limits()
        },
        Error::ResourceLimit,
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_rejected(
        &trailing,
        source.commitment(),
        limits(),
        Error::InvalidFormat,
    );
    let mut malformed = bytes.clone();
    malformed[0] ^= 1;
    assert_rejected(
        &malformed,
        source.commitment(),
        limits(),
        Error::InvalidFormat,
    );
    let mut zero_width = bytes.clone();
    zero_width[64..68].fill(0);
    assert_rejected(
        &zero_width,
        source.commitment(),
        limits(),
        Error::InvalidFormat,
    );
    let mut excessive_rows = bytes.clone();
    excessive_rows[72..80].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_rejected(
        &excessive_rows,
        source.commitment(),
        limits(),
        Error::ResourceLimit,
    );
    let mut bad_root = bytes.clone();
    bad_root[80] ^= 1;
    let malformed_head = Commitment::decode(&bad_root[..MANIFEST_BYTES], limits()).unwrap();
    assert_rejected(&bad_root, &malformed_head, limits(), Error::InvalidProof);
    let last = MANIFEST_BYTES + 64 * (65_536 + PAGE_OVERHEAD);
    bad_root[last..last + 8].copy_from_slice(&1u64.to_le_bytes());
    assert_rejected(&bad_root, &malformed_head, limits(), Error::InvalidFormat);
    for caps in [
        Limits {
            max_rows: source.commitment().layout().row_count - 1,
            ..limits()
        },
        Limits {
            max_pages: 64,
            ..limits()
        },
        Limits {
            max_page_plaintext_bytes: 65_535,
            ..limits()
        },
        Limits {
            max_image_bytes: bytes.len() - 1,
            ..limits()
        },
    ] {
        assert_rejected(&bytes, source.commitment(), caps, Error::ResourceLimit);
    }
}

#[test]
fn a_two_worker_audit_keeps_current_lookup_caps_and_address_guards() {
    let owner = Owner::generate([167; 16]).unwrap();
    let source = image(&owner, 65, 1, 65_536);
    let encoded = source.encode();
    let borrowed = VerifiedSnapshotBytes::decode_for_head_with_workers(
        &encoded,
        source.commitment(),
        limits(),
        AuditWorkers::Two,
    )
    .unwrap();
    let checked = OwnedVerifiedSnapshotBytes::decode_for_head_with_workers(
        encoded.clone(),
        source.commitment(),
        limits(),
        AuditWorkers::Two,
    )
    .unwrap();
    let response = checked.lookup(0, limits()).unwrap();
    let restricted = Limits {
        max_response_bytes: response.encoded_len() - 1,
        ..limits()
    };
    assert!(matches!(
        checked.lookup(0, restricted),
        Err(Error::ResourceLimit)
    ));
    assert!(matches!(
        borrowed.lookup(0, restricted),
        Err(Error::ResourceLimit)
    ));
    assert!(matches!(
        checked.lookup(
            999,
            Limits {
                max_pages: 64,
                ..limits()
            }
        ),
        Err(Error::ResourceLimit)
    ));
    assert!(matches!(
        borrowed.lookup(
            999,
            Limits {
                max_pages: 64,
                ..limits()
            }
        ),
        Err(Error::ResourceLimit)
    ));
    let verified = response.verify(source.commitment(), 0, limits()).unwrap();
    assert_eq!(
        owner.decrypt(&verified).unwrap().as_bytes(),
        vec![41; 65_536]
    );
    assert!(matches!(
        response.verify(source.commitment(), 1, limits()),
        Err(Error::InvalidProof)
    ));
}
