use super::*;
use crate::wire::{self, Request, WireRequest};
use compact_store::{Layout, Limits, Owner};

fn bundle(data: &EncryptedSnapshot, index: &EncryptedSnapshot) -> Bundle {
    Bundle {
        data_head: data.commitment().encode().to_vec(),
        index_head: index.commitment().encode().to_vec(),
        data: data.encode(),
        index: index.encode(),
    }
}
fn fixture(
    count: usize,
) -> (
    EncryptedSnapshot,
    EncryptedSnapshot,
    Bundle,
    StoreDeltaRequest,
) {
    let owner = Owner::generate([61; 16]).unwrap();
    let layout = Layout {
        schema: [1; 16],
        row_width: 1,
        rows_per_page: 4096,
        row_count: 300 * 4096 - 3,
    };
    let original_data = owner
        .seal(
            layout,
            &vec![7; layout.row_count as usize],
            custody_limits(),
        )
        .unwrap();
    let original_index = owner
        .seal(
            Layout {
                schema: [2; 16],
                ..layout
            },
            &vec![8; layout.row_count as usize],
            custody_limits(),
        )
        .unwrap();
    let base = bundle(&original_data, &original_index);
    let mut data = original_data.clone();
    let mut index = original_index.clone();
    if count > 1 {
        let replacements: Vec<_> = (0..count - 1)
            .map(|page| (page as u64, &[9; 4096][..]))
            .collect();
        owner
            .replace_pages(
                &mut data,
                original_data.commitment(),
                &replacements,
                custody_limits(),
            )
            .unwrap();
    }
    owner
        .replace_page(
            &mut index,
            original_index.commitment(),
            299,
            &[10; 4093],
            custody_limits(),
        )
        .unwrap();
    let next = bundle(&data, &index);
    let mut pages: Vec<_> = (0..count.saturating_sub(1))
        .map(|page| {
            (
                PageAddress {
                    image: PageImage::Data,
                    index: page as u64,
                },
                data.lookup(page as u64, custody_limits()).unwrap(),
            )
        })
        .collect();
    pages.push((
        PageAddress {
            image: PageImage::Index,
            index: 299,
        },
        index.lookup(299, custody_limits()).unwrap(),
    ));
    let delta = StoreDeltaRequest::new(
        base.id(),
        original_data.commitment(),
        original_index.commitment(),
        &next,
        &pages,
    )
    .unwrap();
    (original_data, original_index, next, delta)
}
#[test]
fn one_two_64_256_and_257_replacements_have_identical_complete_wire_lengths() {
    let mut expected = None;
    for count in [1, 2, 64, 256, 257] {
        let (data, index, next, delta) = fixture(count);
        let fixed = delta.request_bytes();
        assert_eq!(*expected.get_or_insert(fixed), fixed);
        let wire_bytes = wire::encode(&WireRequest {
            version: 1,
            id: 7,
            request: Request::StoreDelta(delta),
        })
        .unwrap();
        assert_eq!(wire_bytes.len(), fixed);
        assert_eq!(
            u32::from_le_bytes(wire_bytes[10..14].try_into().unwrap()),
            19
        );
        let decoded: WireRequest = wire::decode(&wire_bytes).unwrap();
        let Request::StoreDelta(delta) = decoded.request else {
            panic!("exact delta request")
        };
        let checked = delta.verify_pages().unwrap();
        assert_eq!(delta.reconstruct(data, index, checked).unwrap(), next);
    }
}
#[test]
fn actual_million_row_images_have_the_pinned_public_footprint_and_full_request_geometry() {
    let owner = Owner::generate([62; 16]).unwrap();
    let data = owner
        .seal(
            Layout {
                schema: [3; 16],
                row_width: 3,
                rows_per_page: 256,
                row_count: 1_000_000,
            },
            &vec![0; 3_000_000],
            custody_limits(),
        )
        .unwrap();
    let index = owner
        .seal(
            Layout {
                schema: [4; 16],
                row_width: 1,
                rows_per_page: 4096,
                row_count: 34_017_824,
            },
            &vec![0; 34_017_824],
            custody_limits(),
        )
        .unwrap();
    assert_eq!(data.encoded_len(), 3_187_648);
    assert_eq!(index.encoded_len(), 34_416_624);
    let base = bundle(&data, &index);
    let mut next_data = data.clone();
    let mut next_index = index.clone();
    owner
        .replace_page(
            &mut next_data,
            data.commitment(),
            0,
            &[1; 768],
            custody_limits(),
        )
        .unwrap();
    owner
        .replace_page(
            &mut next_index,
            index.commitment(),
            0,
            &[2; 4096],
            custody_limits(),
        )
        .unwrap();
    let next = bundle(&next_data, &next_index);
    let pages = [
        (
            PageAddress {
                image: PageImage::Data,
                index: 0,
            },
            next_data.lookup(0, custody_limits()).unwrap(),
        ),
        (
            PageAddress {
                image: PageImage::Index,
                index: 0,
            },
            next_index.lookup(0, custody_limits()).unwrap(),
        ),
    ];
    let delta = StoreDeltaRequest::new(
        base.id(),
        data.commitment(),
        index.commitment(),
        &next,
        &pages,
    )
    .unwrap();
    let actual_delta = wire::encode(&WireRequest {
        version: 1,
        id: 1,
        request: Request::StoreDelta(delta.clone()),
    })
    .unwrap();
    let actual_full = wire::encode(&WireRequest {
        version: 1,
        id: 1,
        request: Request::Store(next.clone()),
    })
    .unwrap();
    assert_eq!(actual_delta.len(), 1_188_143);
    assert_eq!(actual_full.len(), 37_604_542);
    let checked = delta.verify_pages().unwrap();
    assert_eq!(delta.reconstruct(data, index, checked).unwrap(), next);
}
#[test]
fn conservative_limits_bound_is_below_32mib_and_small_geometry_chooses_full() {
    let limits = Limits::default();
    let mut pages = limits.max_pages as usize;
    let mut height = 0;
    while pages > 1 {
        pages = pages.div_ceil(2);
        height += 1;
    }
    let bound = HEADER_BYTES
        + REQUEST_ENVELOPE_BYTES
        + MAX_STORE_DELTA_PAGES
            * (13
                + 16
                + compact_store::PAGE_OVERHEAD
                + limits.max_page_plaintext_bytes
                + height * 32);
    assert_eq!(bound, 16_994_671);
    assert!(bound < MAX_STORE_DELTA_REQUEST_BYTES);
    let owner = Owner::generate([63; 16]).unwrap();
    let small = owner
        .seal(
            Layout {
                schema: [1; 16],
                row_width: 3,
                rows_per_page: 256,
                row_count: 2,
            },
            &[0; 6],
            custody_limits(),
        )
        .unwrap();
    assert_eq!(
        StoreDeltaPlan::for_heads(small.commitment(), small.commitment())
            .unwrap()
            .padded_request_bytes(),
        None
    );
}
#[test]
fn noncanonical_padding_lengths_counts_addresses_and_unbounded_serde_lengths_reject() {
    let (_, _, _, delta) = fixture(2);
    let correct = delta.encode();
    for mutation in 0..8 {
        let mut bad = correct.clone();
        match mutation {
            0 => *bad.last_mut().unwrap() = 1,
            1 => {
                bad.pop();
            }
            2 => bad.push(0),
            3 => bad[..8].fill(0),
            4 => bad[8..10].copy_from_slice(&2_u16.to_le_bytes()),
            5 => bad[522..524].copy_from_slice(&258_u16.to_le_bytes()),
            6 => bad[HEADER_BYTES] = 2,
            _ => bad[HEADER_BYTES + 1..HEADER_BYTES + 9].copy_from_slice(&u64::MAX.to_le_bytes()),
        }
        assert!(
            StoreDeltaRequest::decode(&bad).is_err(),
            "mutation {mutation}"
        );
    }
    assert!(wire::decode::<StoreDeltaRequest>(&u64::MAX.to_le_bytes()).is_err());
    assert!(
        wire::decode::<StoreDeltaRequest>(&((MAX_BODY_BYTES + 1) as u64).to_le_bytes()).is_err()
    );
}
#[test]
fn omitted_pages_tampered_membership_and_wrong_full_object_identity_never_reconstruct() {
    let (data, index, _, delta) = fixture(2);
    let mut omitted = delta.clone();
    omitted.pages.pop();
    let omitted = StoreDeltaRequest::decode(&omitted.encode()).unwrap();
    let checked = omitted.verify_pages().unwrap();
    assert!(
        omitted
            .reconstruct(data.clone(), index.clone(), checked)
            .is_err()
    );
    let mut tampered = delta.encode();
    tampered[HEADER_BYTES + 13 + 16 + 32] ^= 1;
    let tampered = StoreDeltaRequest::decode(&tampered).unwrap();
    assert!(tampered.verify_pages().is_err());
    let mut wrong = delta.clone();
    wrong.binding.next.object[0] ^= 1;
    let checked = wrong.verify_pages().unwrap();
    assert!(
        wrong
            .reconstruct(data.clone(), index.clone(), checked)
            .is_err()
    );
    let mut duplicate = delta.clone();
    duplicate.pages[1] = duplicate.pages[0].clone();
    assert!(StoreDeltaRequest::decode(&duplicate.encode()).is_err());
    let mut wrong_head = delta;
    wrong_head.binding.base.object[0] ^= 1;
    // Base object custody is checked by Store; the codec cannot establish it.
    assert_ne!(wrong_head.base_object(), &bundle(&data, &index).id());
}
