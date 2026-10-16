//! Only raw codec acceptance is tested here; full custody remains independent.
use super::*;
use crate::{
    objects,
    wire::{self, Request, Response, WireRequest, WireResponse},
};
use peer_transport::MAX_FRAME_BYTES;

fn raw() -> RawBundle {
    RawBundle {
        version: 3,
        nonce: [27; 32],
        data_head: vec![1; 111],
        index_head: vec![2; 113],
        data: (0u8..=255).cycle().take(4097).collect(),
        index: vec![4; 65],
    }
}
#[test]
fn every_payload_borrows_the_original_slice_until_complete_preflight() {
    let expected = raw();
    let bytes = wire::encode(&expected).unwrap();
    let borrowed = RawBundleSlice::parse(&bytes).unwrap();
    let mut position = 34;
    for (actual, original) in [
        (borrowed.data_head, expected.data_head.as_slice()),
        (borrowed.index_head, expected.index_head.as_slice()),
        (borrowed.data, expected.data.as_slice()),
        (borrowed.index, expected.index.as_slice()),
    ] {
        position += 8;
        assert_eq!(actual, original);
        assert_eq!(actual.as_ptr(), bytes[position..].as_ptr());
        position += original.len();
    }
    assert_eq!(position, bytes.len());
    assert_eq!(borrowed.into_owned(), expected);
    // Parsing preserves invalid inner metadata; it does not grant custody.
    assert!(objects::CheckedObject::audit(decode(&bytes).unwrap()).is_err());
}

#[test]
fn late_fourth_length_and_trailing_bytes_reject_in_the_borrow_only_stage() {
    let mut expected = raw();
    expected.data = vec![7; 2 * 1024 * 1024 + 3];
    let bytes = wire::encode(&expected).unwrap();
    let fourth =
        34 + 3 * 8 + expected.data_head.len() + expected.index_head.len() + expected.data.len();
    for length in [expected.index.len() as u64 + 1, u64::MAX] {
        let mut malformed = bytes.clone();
        malformed[fourth..fourth + 8].copy_from_slice(&length.to_le_bytes());
        // This type has only borrowed slices: no payload Vec exists to allocate
        // before the invalid last length is discovered.
        assert!(RawBundleSlice::parse(&malformed).is_err());
        assert!(wire::decode::<RawBundle>(&malformed).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(RawBundleSlice::parse(&trailing).is_err());
    assert!(wire::decode::<RawBundle>(&trailing).is_err());
}

#[derive(Clone, Copy)]
enum Envelope {
    Disk,
    Store,
    Reply,
}
impl Envelope {
    fn empty(self) -> Vec<u8> {
        let empty = RawBundle {
            version: 1,
            nonce: [0; 32],
            data_head: vec![],
            index_head: vec![],
            data: vec![],
            index: vec![],
        };
        match self {
            Self::Disk => objects::encode_disk(&empty).unwrap(),
            Self::Store => wire::encode(&WireRequest {
                version: 2,
                id: 91,
                request: Request::Store(empty),
            })
            .unwrap(),
            Self::Reply => wire::encode(&WireResponse {
                version: 2,
                id: 91,
                result: Ok(Response::RawBundle(empty)),
            })
            .unwrap(),
        }
    }
    fn decode(self, bytes: &[u8]) -> io::Result<RawBundle> {
        match self {
            Self::Disk => objects::decode_disk(bytes),
            Self::Store => match wire::decode_request(bytes)?.request {
                Request::Store(raw) => Ok(raw),
                _ => panic!("Store expected"),
            },
            Self::Reply => match wire::decode_response(bytes)?.result {
                Ok(Response::RawBundle(raw)) => Ok(raw),
                _ => panic!("RawBundle expected"),
            },
        }
    }
}
#[test]
fn actual_whole_caps_include_disk_store_and_reply_headers() {
    for (envelope, outer) in [
        (Envelope::Disk, 40),
        (Envelope::Store, 14),
        (Envelope::Reply, 18),
    ] {
        let mut bytes = envelope.empty();
        assert_eq!(bytes.len(), outer + 66);
        let index_length = bytes.len() - 8;
        // One allocation per envelope, reused at actual cap-1/cap/cap+1 lengths.
        bytes.reserve(MAX_FRAME_BYTES + 1 - bytes.len());
        for size in [MAX_FRAME_BYTES - 1, MAX_FRAME_BYTES, MAX_FRAME_BYTES + 1] {
            bytes.resize(size, 0);
            bytes[index_length..index_length + 8]
                .copy_from_slice(&((size - outer - 66) as u64).to_le_bytes());
            match envelope.decode(&bytes) {
                Ok(raw) => {
                    assert!(size <= MAX_FRAME_BYTES);
                    assert_eq!(raw.index.len(), size - outer - 66);
                    assert_eq!(raw.version, 1);
                    if matches!(envelope, Envelope::Store) {
                        assert!(
                            raw.check_frame().is_err(),
                            "Raw disk admission is later than Store authorization"
                        );
                    }
                }
                Err(_) => assert_eq!(size, MAX_FRAME_BYTES + 1),
            }
        }
    }
}

#[test]
fn rpc_wrappers_keep_versions_tags_ids_and_generic_variants_exact() {
    let expected = raw();
    let store = wire::encode(&WireRequest {
        version: 2,
        id: u64::MAX,
        request: Request::Store(expected.clone()),
    })
    .unwrap();
    let reply = wire::encode(&WireResponse {
        version: 2,
        id: u64::MAX,
        result: Ok(Response::RawBundle(expected.clone())),
    })
    .unwrap();
    let actual = wire::decode_request(&store).unwrap();
    assert_eq!(actual.id, u64::MAX);
    assert!(matches!(actual.request, Request::Store(raw) if raw == expected));
    let actual = wire::decode_response(&reply).unwrap();
    assert_eq!(actual.id, u64::MAX);
    assert!(matches!(actual.result, Ok(Response::RawBundle(raw)) if raw == expected));
    for original in [&store, &reply] {
        for version in [1u16, 3] {
            let mut old = original.to_vec();
            old[..2].copy_from_slice(&version.to_le_bytes());
            assert!(wire::decode_request(&old).is_err());
            assert!(wire::decode_response(&old).is_err());
        }
    }
    for boundary in [0, 1, 2, 9, 10, 13, 14, store.len() - 1] {
        assert!(wire::decode_request(&store[..boundary]).is_err());
    }
    for boundary in [0, 1, 2, 9, 10, 13, 14, 17, 18, reply.len() - 1] {
        assert!(wire::decode_response(&reply[..boundary]).is_err());
    }
    let probe = wire::encode(&WireRequest {
        version: 2,
        id: 3,
        request: Request::Probe,
    })
    .unwrap();
    assert!(matches!(
        wire::decode_request(&probe).unwrap().request,
        Request::Probe
    ));
    let denied = wire::encode(&WireResponse {
        version: 2,
        id: 4,
        result: Err(crate::RemoteError::Unauthorized),
    })
    .unwrap();
    assert!(matches!(
        wire::decode_response(&denied).unwrap().result,
        Err(crate::RemoteError::Unauthorized)
    ));
    let mut unknown = store.clone();
    unknown[10..14].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(wire::decode_request(&unknown).is_err());
    let mut unknown = reply.clone();
    unknown[14..18].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(wire::decode_response(&unknown).is_err());
    let mut unknown = reply.clone();
    unknown[10..14].copy_from_slice(&2u32.to_le_bytes());
    assert!(wire::decode_response(&unknown).is_err());
    for mut malformed in [store, reply] {
        malformed.push(0);
        assert!(wire::decode_request(&malformed).is_err());
        assert!(wire::decode_response(&malformed).is_err());
    }
}

#[test]
fn complete_custody_still_rejects_same_head_tail_corruption_after_bulk_decode() {
    let owner = compact_store::Owner::generate([41; 16]).unwrap();
    let image = owner
        .seal(
            compact_store::Layout {
                schema: [42; 16],
                row_width: 1,
                rows_per_page: 3,
                row_count: 7,
            },
            &[9; 7],
            compact_store::Limits::default(),
        )
        .unwrap();
    let raw = RawBundle::from_snapshots(&image, &image).unwrap();
    let original = *raw.target_version().unwrap().object();
    let decoded = objects::decode_disk(&objects::encode_disk(&raw).unwrap()).unwrap();
    assert_eq!(decoded, raw);
    assert!(objects::CheckedObject::audit(decoded).is_ok());
    for data in [true, false] {
        let mut malformed = raw.clone();
        let image = if data {
            &mut malformed.data
        } else {
            &mut malformed.index
        };
        *image.last_mut().unwrap() ^= 1;
        let disk = objects::encode_disk(&malformed).unwrap();
        let decoded = objects::decode_disk(&disk).unwrap();
        assert_eq!(decoded.target_version().unwrap().object(), &original);
        assert!(objects::CheckedObject::audit(decoded).is_err());
    }
}

#[test]
fn public_generic_deserialization_keeps_the_original_ioreader_limit_path() {
    use bincode::Options;
    let expected = raw();
    let bytes = wire::encode(&expected).unwrap();
    let options = |limit| {
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(limit)
    };
    let decoded: RawBundle = options(bytes.len() as u64)
        .deserialize_from(bytes.as_slice())
        .unwrap();
    assert_eq!(decoded, expected);
    let rejected =
        options(bytes.len() as u64 - 1).deserialize_from::<_, RawBundle>(bytes.as_slice());
    assert!(matches!(
        *rejected.unwrap_err(),
        bincode::ErrorKind::SizeLimit
    ));
}
