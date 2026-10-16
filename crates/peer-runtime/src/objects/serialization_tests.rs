//! The pinned plain-Vec codec is the byte contract, not another admission path.
use super::*;
use crate::wire::{self, Request, Response, WireRequest, WireResponse};
use bincode::Options;

#[derive(Serialize, Deserialize)]
struct PlainVecBundle {
    version: u16,
    nonce: [u8; 32],
    data_head: Vec<u8>,
    index_head: Vec<u8>,
    data: Vec<u8>,
    index: Vec<u8>,
}
impl From<&RawBundle> for PlainVecBundle {
    fn from(raw: &RawBundle) -> Self {
        Self {
            version: raw.version,
            nonce: raw.nonce,
            data_head: raw.data_head.clone(),
            index_head: raw.index_head.clone(),
            data: raw.data.clone(),
            index: raw.index.clone(),
        }
    }
}
impl From<PlainVecBundle> for RawBundle {
    fn from(raw: PlainVecBundle) -> Self {
        Self {
            version: raw.version,
            nonce: raw.nonce,
            data_head: raw.data_head,
            index_head: raw.index_head,
            data: raw.data,
            index: raw.index,
        }
    }
}
fn binary(length: usize) -> Vec<u8> {
    (0u8..=255).cycle().take(length).collect()
}
fn untrusted(length: usize) -> RawBundle {
    RawBundle {
        version: 2,
        nonce: [31; 32],
        data_head: binary(112),
        index_head: binary(112),
        data: binary(length),
        index: binary(length / 2),
    }
}

#[test]
fn raw_store_fetch_and_disk_keep_plain_vec_bytes_and_mutual_decoding() {
    let mut cases: Vec<_> = [0, 1, 255, 256, 65_536].map(untrusted).into();
    let mut empty = untrusted(0);
    empty.data_head.clear();
    empty.index_head.clear();
    cases.push(empty);
    // Serialization must not turn an untrusted envelope into an admitted object.
    let mut malformed = untrusted(17);
    malformed.version = 1;
    malformed.data_head.pop();
    malformed.index_head.push(0xff);
    cases.push(malformed);

    for raw in cases {
        let plain = PlainVecBundle::from(&raw);
        let raw_bytes = wire::encode(&raw).unwrap();
        let plain_bytes = wire::encode(&plain).unwrap();
        assert_eq!(raw_bytes, plain_bytes);
        assert_eq!(wire::decode::<RawBundle>(&plain_bytes).unwrap(), raw);
        assert_eq!(
            RawBundle::from(wire::decode::<PlainVecBundle>(&raw_bytes).unwrap()),
            raw
        );

        let store = wire::encode(&WireRequest {
            version: 2,
            id: 19,
            request: Request::Store(raw.clone()),
        })
        .unwrap();
        // Fixed tuple fields encode the actual v2 envelope and Store tag 2.
        let plain_store = wire::encode(&(2u16, 19u64, 2u32, &plain)).unwrap();
        assert_eq!(store, plain_store);
        let decoded: WireRequest = wire::decode(&plain_store).unwrap();
        assert!(matches!(decoded.request, Request::Store(actual) if actual == raw));
        let (version, id, tag, actual): (u16, u64, u32, PlainVecBundle) =
            wire::decode(&store).unwrap();
        assert_eq!((version, id, tag), (2, 19, 2));
        assert_eq!(RawBundle::from(actual), raw);

        let fetch = wire::encode(&WireResponse {
            version: 2,
            id: 19,
            result: Ok(Response::RawBundle(raw.clone())),
        })
        .unwrap();
        let plain_fetch = wire::encode(&(2u16, 19u64, 0u32, 3u32, &plain)).unwrap();
        assert_eq!(fetch, plain_fetch);
        let decoded: WireResponse = wire::decode(&plain_fetch).unwrap();
        assert!(matches!(decoded.result, Ok(Response::RawBundle(actual)) if actual == raw));
        let (version, id, result, tag, actual): (u16, u64, u32, u32, PlainVecBundle) =
            wire::decode(&fetch).unwrap();
        assert_eq!((version, id, result, tag), (2, 19, 0, 3));
        assert_eq!(RawBundle::from(actual), raw);

        let disk = encode_disk(&raw).unwrap();
        let mut plain_disk = DISK_MAGIC.to_vec();
        plain_disk.extend_from_slice(&OBJECT_PROFILE_ID);
        plain_disk.extend_from_slice(&plain_bytes);
        assert_eq!(disk, plain_disk);
        assert_eq!(decode_disk(&plain_disk).unwrap(), raw);
        assert_eq!(
            RawBundle::from(wire::decode::<PlainVecBundle>(&disk[DISK_HEADER_BYTES..]).unwrap()),
            raw
        );
        assert!(CheckedObject::audit(raw).is_err());
    }
}

#[test]
fn bounded_serialization_keeps_exact_size_and_rejects_before_any_write() {
    let raw = untrusted(4096);
    let plain = PlainVecBundle::from(&raw);
    let exact = wire::encode(&plain).unwrap().len() as u64;
    for limit in [exact, exact - 1] {
        let options = || {
            bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .with_limit(limit)
        };
        let current = options().serialize(&raw);
        let original = options().serialize(&plain);
        assert_eq!(current.is_ok(), limit == exact);
        assert_eq!(original.is_ok(), limit == exact);
        let mut current_writer = Vec::new();
        let mut original_writer = Vec::new();
        let current_write = options().serialize_into(&mut current_writer, &raw);
        let original_write = options().serialize_into(&mut original_writer, &plain);
        if limit == exact {
            assert_eq!(current.unwrap(), original.unwrap());
            current_write.unwrap();
            original_write.unwrap();
            assert_eq!(current_writer, original_writer);
            assert_eq!(current_writer.len() as u64, exact);
        } else {
            assert!(matches!(
                *current.unwrap_err(),
                bincode::ErrorKind::SizeLimit
            ));
            assert!(matches!(
                *original.unwrap_err(),
                bincode::ErrorKind::SizeLimit
            ));
            assert!(matches!(
                *current_write.unwrap_err(),
                bincode::ErrorKind::SizeLimit
            ));
            assert!(matches!(
                *original_write.unwrap_err(),
                bincode::ErrorKind::SizeLimit
            ));
            assert!(current_writer.is_empty());
            assert!(original_writer.is_empty());
        }
    }
}

#[test]
fn unchanged_decoder_rejects_truncation_trailing_and_hostile_field_lengths() {
    let raw = untrusted(257);
    let bytes = wire::encode(&PlainVecBundle::from(&raw)).unwrap();
    for boundary in [0, 1, 33, 34, 41, 153, bytes.len() - 1] {
        assert!(wire::decode::<RawBundle>(&bytes[..boundary]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(wire::decode::<RawBundle>(&trailing).is_err());
    // All four existing fixint length slots reject without trusting their claims.
    let lengths = [
        34,
        34 + 8 + 112,
        34 + 2 * (8 + 112),
        34 + 2 * (8 + 112) + 8 + 257,
    ];
    for offset in lengths {
        let mut announced = bytes.clone();
        announced[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(wire::decode::<RawBundle>(&announced).is_err());
    }
}
