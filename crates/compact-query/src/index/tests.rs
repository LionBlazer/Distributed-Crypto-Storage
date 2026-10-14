//! Public synthetic rows and malformed public index fixtures; no participant data.
use super::*;
use crate::{MAX_ROWS, ROW_BYTES, SCHEMA};

fn seal_data(owner: &compact_store::Owner, rows: &[PlainRow]) -> EncryptedSnapshot {
    let mut bytes = Vec::with_capacity(rows.len() * ROW_BYTES as usize);
    for row in rows {
        bytes.push(row.age);
        bytes.extend_from_slice(&row.amount.to_le_bytes());
    }
    owner
        .seal(
            Layout {
                schema: SCHEMA,
                row_width: ROW_BYTES,
                rows_per_page: 256,
                row_count: rows.len() as u64,
            },
            &bytes,
            Limits::default(),
        )
        .unwrap()
}

fn seal_index(owner: &compact_store::Owner, bytes: &[u8]) -> EncryptedSnapshot {
    owner
        .seal(
            Layout {
                schema: INDEX_SCHEMA,
                row_width: 1,
                rows_per_page: INDEX_PAGE_BYTES as u32,
                row_count: bytes.len() as u64,
            },
            bytes,
            index_limits(),
        )
        .unwrap()
}

fn raw_index(
    owner: &compact_store::Owner,
    head: &Commitment,
    buckets: &[(u8, u32, &[u8])],
) -> EncryptedSnapshot {
    let mut bytes = vec![0; INDEX_HEADER_BYTES];
    bytes[..MANIFEST_BYTES].copy_from_slice(&head.encode());
    for age in 0..AGE_BUCKETS {
        if let Some((_, count, payload)) = buckets.iter().find(|entry| entry.0 as usize == age) {
            let start = COUNTS_START + age * 4;
            bytes[start..start + 4].copy_from_slice(&count.to_le_bytes());
            bytes.extend_from_slice(payload);
        }
        let offset = (bytes.len() - INDEX_HEADER_BYTES) as u32;
        let start = OFFSETS_START + (age + 1) * 4;
        bytes[start..start + 4].copy_from_slice(&offset.to_le_bytes());
    }
    let padded_len = INDEX_HEADER_BYTES + posting_capacity(head.layout().row_count).unwrap();
    if bytes.len() < padded_len {
        bytes.resize(padded_len, 0);
    }
    seal_index(owner, &bytes)
}

fn plaintext(owner: &compact_store::Owner, index: &EncryptedSnapshot) -> Vec<u8> {
    let mut bytes = Vec::new();
    for page in 0..index.commitment().layout().page_count().unwrap() {
        bytes.extend_from_slice(
            page_bytes_counted(owner, index, page as u64, &mut 0)
                .unwrap()
                .as_bytes(),
        );
    }
    bytes
}

fn selected(
    owner: &compact_store::Owner,
    index: &EncryptedSnapshot,
    head: &Commitment,
    range: AgeRange,
) -> Result<Vec<u64>> {
    select(owner, index, head, range, MAX_ROWS, &mut 0)
}

#[test]
fn complete_selection_matches_uniform_skew_random_and_one_age_fixtures() {
    let owner = compact_store::Owner::generate([61; 16]).unwrap();
    let mut expected_index_bytes = None;
    for pattern in 0..4 {
        let mut random = 0x4271_caf0_99bd_3721_u64;
        let rows: Vec<_> = (0..4096)
            .map(|ordinal| {
                random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
                let age = match pattern {
                    0 => ordinal as u8,
                    1 if ordinal % 10 != 0 => 42,
                    1 => (ordinal / 10) as u8,
                    2 => (random >> 32) as u8,
                    _ => 42,
                };
                PlainRow {
                    age,
                    amount: ordinal as u16,
                }
            })
            .collect();
        let data = seal_data(&owner, &rows);
        let index = build(&owner, &rows, data.commitment()).unwrap();
        assert_eq!(
            index.commitment().layout().row_count,
            (INDEX_HEADER_BYTES + posting_capacity(rows.len() as u64).unwrap()) as u64
        );
        let same_size = expected_index_bytes.get_or_insert(index.encoded_len());
        assert_eq!(index.encoded_len(), *same_size);
        for range in [
            AgeRange::equal(0),
            AgeRange::equal(42),
            AgeRange::equal(255),
            AgeRange {
                lower: 41,
                upper: 43,
            },
        ] {
            let expected: Vec<_> = rows
                .iter()
                .enumerate()
                .filter(|(_, row)| range.contains(row.age))
                .map(|(ordinal, _)| ordinal as u64)
                .collect();
            if expected.len() > MAX_ROWS {
                assert_eq!(
                    selected(&owner, &index, data.commitment(), range),
                    Err(Error::SelectionBudget {
                        selected: expected.len(),
                        budget: MAX_ROWS
                    }),
                );
            } else {
                assert_eq!(
                    selected(&owner, &index, data.commitment(), range).unwrap(),
                    expected
                );
            }
        }
    }
}

#[test]
fn selected_varint_can_straddle_an_authenticated_page_boundary() {
    let owner = compact_store::Owner::generate([62; 16]).unwrap();
    // Header 2164 + 1931 dense ordinals = byte 4095: the final two-byte
    // absolute ordinal begins at the last byte of page zero.
    let mut rows = vec![PlainRow { age: 0, amount: 1 }; 1932];
    rows[1931].age = 1;
    let data = seal_data(&owner, &rows);
    let index = build(&owner, &rows, data.commitment()).unwrap();
    let mut transferred = 0;
    assert_eq!(
        select(
            &owner,
            &index,
            data.commitment(),
            AgeRange::equal(1),
            1,
            &mut transferred
        )
        .unwrap(),
        vec![1931],
    );
    let expected_bytes = index.lookup(0, index_limits()).unwrap().encoded_len()
        + index.lookup(1, index_limits()).unwrap().encoded_len();
    assert_eq!(transferred, expected_bytes);
}

#[test]
fn selective_read_skips_unselected_pages_and_reuses_header_page() {
    let owner = compact_store::Owner::generate([63; 16]).unwrap();
    let mut rows = vec![PlainRow { age: 0, amount: 1 }; 30_000];
    rows[29_999].age = 255;
    let data = seal_data(&owner, &rows);
    let index = build(&owner, &rows, data.commitment()).unwrap();
    let mut transferred = 0;
    assert_eq!(
        select(
            &owner,
            &index,
            data.commitment(),
            AgeRange::equal(255),
            1,
            &mut transferred
        )
        .unwrap(),
        vec![29_999],
    );
    let posting_page = (INDEX_HEADER_BYTES + 29_999) / INDEX_PAGE_BYTES;
    assert_eq!(
        transferred,
        index.lookup(0, index_limits()).unwrap().encoded_len()
            + index
                .lookup(posting_page as u64, index_limits())
                .unwrap()
                .encoded_len(),
    );
    let tiny = seal_data(&owner, &[PlainRow { age: 42, amount: 1 }]);
    let tiny_index = build(
        &owner,
        &[PlainRow { age: 42, amount: 1 }],
        tiny.commitment(),
    )
    .unwrap();
    transferred = 0;
    assert_eq!(
        select(
            &owner,
            &tiny_index,
            tiny.commitment(),
            AgeRange::equal(42),
            1,
            &mut transferred
        )
        .unwrap(),
        vec![0],
    );
    assert_eq!(
        transferred,
        tiny_index.lookup(0, index_limits()).unwrap().encoded_len()
    );
}

#[test]
fn complete_count_preflight_rejects_before_reading_posting_pages() {
    let owner = compact_store::Owner::generate([64; 16]).unwrap();
    let rows = vec![PlainRow { age: 42, amount: 1 }; 5000];
    let data = seal_data(&owner, &rows);
    let index = build(&owner, &rows, data.commitment()).unwrap();
    for budget in [0, 5, usize::MAX] {
        let mut transferred = 0;
        assert_eq!(
            select(
                &owner,
                &index,
                data.commitment(),
                AgeRange::equal(42),
                budget,
                &mut transferred
            ),
            Err(Error::SelectionBudget {
                selected: 5000,
                budget: budget.min(MAX_ROWS)
            }),
        );
        assert_eq!(
            transferred,
            index.lookup(0, index_limits()).unwrap().encoded_len()
        );
    }
}

#[test]
fn malformed_postings_are_rejected_at_the_selected_bucket_boundary() {
    let owner = compact_store::Owner::generate([65; 16]).unwrap();
    for (count, payload) in [
        (1, vec![0x80]),                            // truncated continuation
        (1, vec![0x80, 0]),                         // noncanonical zero
        (1, vec![0x81, 0]),                         // noncanonical one
        (1, vec![0x80, 0x80, 0x80, 0x80, 0x80, 0]), // more than five groups
        (1, vec![0xff, 0xff, 0xff, 0xff, 0x10]),    // u32 overflow
        (1, vec![0xff, 0xff, 0xff, 0xff, 0x8f]),    // continued fifth group
        (1, vec![8]),                               // ordinal outside table
        (1, vec![0, 1]),                            // trailing bytes after exact count
        (2, vec![0, 0]),                            // zero delta / duplicate ordinal
        (2, vec![0, 8]),                            // delta outside table
        (2, vec![1, 0xff, 0xff, 0xff, 0xff, 0x0f]), // ordinal addition overflow
    ] {
        let rows = vec![PlainRow { age: 42, amount: 1 }; 8];
        let data = seal_data(&owner, &rows);
        let mut filler = vec![1; 8 - count as usize];
        filler[0] = 0;
        let index = raw_index(
            &owner,
            data.commitment(),
            &[(0, 8 - count, &filler), (42, count, &payload)],
        );
        assert_eq!(
            selected(&owner, &index, data.commitment(), AgeRange::equal(42)),
            Err(Error::InvalidIndex)
        );
    }
    let data = seal_data(
        &owner,
        &[
            PlainRow { age: 41, amount: 1 },
            PlainRow { age: 42, amount: 1 },
        ],
    );
    let index = raw_index(
        &owner,
        data.commitment(),
        &[(41, 1, &[0x80]), (42, 1, &[0])],
    );
    assert_eq!(
        selected(
            &owner,
            &index,
            data.commitment(),
            AgeRange {
                lower: 41,
                upper: 42
            }
        ),
        Err(Error::InvalidIndex),
    );
}

#[test]
fn duplicate_addresses_across_distinct_age_buckets_are_rejected() {
    let owner = compact_store::Owner::generate([66; 16]).unwrap();
    let data = seal_data(
        &owner,
        &[
            PlainRow { age: 41, amount: 1 },
            PlainRow { age: 42, amount: 1 },
        ],
    );
    let index = raw_index(&owner, data.commitment(), &[(41, 1, &[0]), (42, 1, &[0])]);
    assert_eq!(
        selected(
            &owner,
            &index,
            data.commitment(),
            AgeRange {
                lower: 41,
                upper: 42
            }
        ),
        Err(Error::DuplicateAddress),
    );
}

#[test]
fn corrupt_authenticated_counts_offsets_and_binding_are_rejected() {
    let owner = compact_store::Owner::generate([67; 16]).unwrap();
    let rows = [PlainRow { age: 42, amount: 1 }; 2];
    let data = seal_data(&owner, &rows);
    let index = build(&owner, &rows, data.commitment()).unwrap();
    let valid = plaintext(&owner, &index);
    for (offset, value) in [
        (COUNTS_START + 42 * 4, 3),   // wrong total
        (OFFSETS_START, 1),           // first offset is not zero
        (OFFSETS_START + 256 * 4, 3), // wrong final byte count
        (OFFSETS_START + 42 * 4, 3),  // descending offsets
        (OFFSETS_START + 4, 1),       // bytes for an empty age bucket
    ] {
        let mut corrupted = valid.clone();
        corrupted[offset..offset + 4].copy_from_slice(&u32::to_le_bytes(value));
        let index = seal_index(&owner, &corrupted);
        assert!(matches!(
            check_binding(&owner, &index, data.commitment()),
            Err(Error::InvalidIndex)
        ));
    }
    let mut old_layout = index.commitment().layout();
    old_layout.schema = *b"CQAGEINDEX000001";
    let old_format = owner.seal(old_layout, &valid, index_limits()).unwrap();
    assert!(matches!(
        check_binding(&owner, &old_format, data.commitment()),
        Err(Error::InvalidIndex)
    ));
    let mut wrong_head = valid.clone();
    wrong_head[80] ^= 1;
    let index = seal_index(&owner, &wrong_head);
    assert!(matches!(
        check_binding(&owner, &index, data.commitment()),
        Err(Error::WrongVersion)
    ));
    let too_short = seal_index(&owner, &valid[..INDEX_HEADER_BYTES - 1]);
    assert!(matches!(
        check_binding(&owner, &too_short, data.commitment()),
        Err(Error::InvalidIndex)
    ));
}

#[test]
fn canonical_varint_encodings_cover_every_u32_byte_width() {
    let owner = compact_store::Owner::generate([68; 16]).unwrap();
    let data = seal_data(&owner, &[PlainRow { age: 42, amount: 1 }]);
    for (value, expected) in [
        (0, vec![0]),
        (127, vec![127]),
        (128, vec![0x80, 1]),
        (16383, vec![0xff, 0x7f]),
        (16384, vec![0x80, 0x80, 1]),
        (1 << 21, vec![0x80, 0x80, 0x80, 1]),
        (u32::MAX, vec![0xff, 0xff, 0xff, 0xff, 0x0f]),
    ] {
        let mut encoded = Vec::new();
        write_varint(value, &mut encoded);
        assert_eq!(encoded, expected);
        let index = raw_index(&owner, data.commitment(), &[(42, 1, &expected)]);
        let first_page = page_bytes_counted(&owner, &index, 0, &mut 0).unwrap();

        let mut transferred = 0;
        let mut reader = PostingReader {
            owner: &owner,
            snapshot: &index,
            position: INDEX_HEADER_BYTES,
            page_index: 0,
            page: first_page,
            transferred: &mut transferred,
        };
        assert_eq!(
            reader.varint(INDEX_HEADER_BYTES + expected.len()).unwrap(),
            value
        );
    }
}

#[test]
fn restart_and_amount_only_rebinding_preserve_all_posting_ciphertext_pages() {
    let owner = compact_store::Owner::generate([69; 16]).unwrap();
    let mut rows = vec![PlainRow { age: 0, amount: 1 }; 9000];
    rows[8999].age = 255;
    let mut data = seal_data(&owner, &rows);
    let index = build(&owner, &rows, data.commitment()).unwrap();
    let restored = EncryptedSnapshot::decode(&index.encode(), index_limits()).unwrap();
    assert_eq!(restored.commitment(), index.commitment());
    assert_eq!(
        selected(&owner, &restored, data.commitment(), AgeRange::equal(255)).unwrap(),
        vec![8999]
    );
    let old_data_head = data.commitment().clone();
    let old_index_bytes = index.encode();
    let page = data
        .lookup(0, Limits::default())
        .unwrap()
        .verify(&old_data_head, 0, Limits::default())
        .unwrap();
    let mut new_page = owner.decrypt(&page).unwrap().as_bytes().to_vec();
    new_page[1..3].copy_from_slice(&2_u16.to_le_bytes());
    let new_head = owner
        .replace_page(&mut data, &old_data_head, 0, &new_page, Limits::default())
        .unwrap();
    let mut rebound_index = rebound(&owner, &restored, &old_data_head, &new_head).unwrap();
    assert_eq!(rebound_index.encoded_len(), index.encoded_len());
    let unchanged_start = MANIFEST_BYTES + INDEX_PAGE_BYTES + compact_store::PAGE_OVERHEAD;
    assert_eq!(
        &rebound_index.encode()[unchanged_start..],
        &old_index_bytes[unchanged_start..]
    );
    assert!(matches!(
        check_binding(&owner, &index, &new_head),
        Err(Error::WrongVersion)
    ));
    assert!(matches!(
        check_binding(&owner, &rebound_index, &old_data_head),
        Err(Error::WrongVersion)
    ));
    for amount in 3_u16..=10 {
        let old_head = data.commitment().clone();
        let old_index = rebound_index.encode();
        let verified = data
            .lookup(0, Limits::default())
            .unwrap()
            .verify(&old_head, 0, Limits::default())
            .unwrap();
        let mut page = owner.decrypt(&verified).unwrap().as_bytes().to_vec();
        page[1..3].copy_from_slice(&amount.to_le_bytes());
        let new_head = owner
            .replace_page(&mut data, &old_head, 0, &page, Limits::default())
            .unwrap();
        rebound_index = rebound(&owner, &rebound_index, &old_head, &new_head).unwrap();
        assert_eq!(rebound_index.encoded_len(), old_index.len());
        assert_eq!(
            &rebound_index.encode()[unchanged_start..],
            &old_index[unchanged_start..]
        );
        data = EncryptedSnapshot::decode(&data.encode(), Limits::default()).unwrap();
        rebound_index = EncryptedSnapshot::decode(&rebound_index.encode(), index_limits()).unwrap();
        assert_eq!(
            selected(
                &owner,
                &rebound_index,
                data.commitment(),
                AgeRange::equal(255)
            )
            .unwrap(),
            vec![8999]
        );
    }
    let new_head = data.commitment().clone();
    let restarted = EncryptedSnapshot::decode(&rebound_index.encode(), index_limits()).unwrap();
    assert_eq!(
        selected(&owner, &restarted, &new_head, AgeRange::equal(255)).unwrap(),
        vec![8999]
    );
}

#[test]
fn empty_table_and_empty_buckets_have_no_posting_reads() {
    let owner = compact_store::Owner::generate([70; 16]).unwrap();
    let data = seal_data(&owner, &[]);
    let index = build(&owner, &[], data.commitment()).unwrap();
    let mut transferred = 0;
    assert!(
        select(
            &owner,
            &index,
            data.commitment(),
            AgeRange {
                lower: 0,
                upper: 255
            },
            0,
            &mut transferred
        )
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        transferred,
        index.lookup(0, index_limits()).unwrap().encoded_len()
    );
    assert_eq!(
        selected(
            &owner,
            &index,
            data.commitment(),
            AgeRange { lower: 2, upper: 1 }
        ),
        Err(Error::InvalidRange)
    );
}

#[test]
fn fixed_padding_is_not_posting_data_and_its_ciphertext_is_authenticated() {
    let owner = compact_store::Owner::generate([71; 16]).unwrap();
    let rows = [PlainRow { age: 42, amount: 1 }; 10];
    let data = seal_data(&owner, &rows);
    let index = build(&owner, &rows, data.commitment()).unwrap();
    let bytes = plaintext(&owner, &index);
    assert_eq!(bytes.len(), INDEX_HEADER_BYTES + 20);
    assert_eq!(
        u32::from_le_bytes(
            bytes[OFFSETS_START + 256 * 4..OFFSETS_START + 257 * 4]
                .try_into()
                .unwrap()
        ),
        10
    );
    assert!(
        bytes[INDEX_HEADER_BYTES + 10..]
            .iter()
            .all(|byte| *byte == 0)
    );
    assert_eq!(
        selected(&owner, &index, data.commitment(), AgeRange::equal(42)).unwrap(),
        (0..10).collect::<Vec<u64>>()
    );

    // Moving one padding byte into the real bucket is trailing posting data,
    // even though the total fixed-capacity image length is unchanged.
    let mut extra_real_byte = bytes.clone();
    for offset in 43..=256 {
        let start = OFFSETS_START + offset * 4;
        extra_real_byte[start..start + 4].copy_from_slice(&11_u32.to_le_bytes());
    }
    let invalid = seal_index(&owner, &extra_real_byte);
    assert_eq!(
        selected(&owner, &invalid, data.commitment(), AgeRange::equal(42)),
        Err(Error::InvalidIndex)
    );
    let wrong_capacity = seal_index(&owner, &bytes[..bytes.len() - 1]);
    assert!(matches!(
        check_binding(&owner, &wrong_capacity, data.commitment()),
        Err(Error::InvalidIndex)
    ));

    let mut corrupt_padding_ciphertext = index.encode();
    let padding_ciphertext_byte = MANIFEST_BYTES + 32 + INDEX_HEADER_BYTES + 10;
    corrupt_padding_ciphertext[padding_ciphertext_byte] ^= 1;
    assert!(EncryptedSnapshot::decode(&corrupt_padding_ciphertext, index_limits()).is_err());
    assert_eq!(posting_capacity(0).unwrap(), 0);
    assert_eq!(posting_capacity(1_000_000).unwrap(), 2_015_624);
    assert!(matches!(
        posting_capacity(1_000_001),
        Err(Error::InvalidIndex)
    ));
}
