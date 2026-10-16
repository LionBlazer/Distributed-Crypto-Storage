//! Original-frame ownership and raw syntax, independently of custody admission.
use super::*;
use crate::wire::{Response, WireResponse};
use peer_transport::MAX_FRAME_BYTES;

fn raw() -> RawBundle {
    RawBundle {
        version: 3,
        nonce: [29; 32],
        data_head: vec![1; 111],
        index_head: vec![2; 113],
        data: (0..=255).cycle().take(4097).collect(),
        index: vec![4; 65],
    }
}
fn reply(raw: RawBundle) -> Vec<u8> {
    wire::encode(&WireResponse {
        version: 2,
        id: 91,
        result: Ok(Response::RawBundle(raw)),
    })
    .unwrap()
}

#[test]
fn received_fields_keep_the_one_original_frame_allocation_and_untrusted_metadata() {
    let expected = raw();
    let bytes = reply(expected.clone());
    let pointer = bytes.as_ptr();
    let capacity = bytes.capacity();
    let received = receive_version(bytes, 91).unwrap().unwrap();

    assert_eq!(received.frame.as_ptr(), pointer);
    assert_eq!(received.frame.capacity(), capacity);
    assert_eq!(received.version, expected.version);
    assert_eq!(received.nonce, expected.nonce);
    let decoded = RawBundleSlice::parse(&received.frame[18..]).unwrap();
    for (range, field) in received.fields.iter().zip([
        decoded.data_head,
        decoded.index_head,
        decoded.data,
        decoded.index,
    ]) {
        assert_eq!(received.frame[range.clone()].as_ptr(), field.as_ptr());
        assert_eq!(&received.frame[range.clone()], field);
    }
    assert_eq!(
        received.encoded_images(),
        (&*expected.data, &*expected.index)
    );
    assert!(
        received.target_version().is_err(),
        "Raw version is not admitted by parsing"
    );
    assert_eq!(decoded.into_owned(), expected);
    let generic: WireResponse = wire::decode(&received.frame).unwrap();
    assert!(matches!(generic.result, Ok(Response::RawBundle(raw)) if raw == expected));
}

#[test]
fn binding_and_image_admission_remain_separate_for_a_genuine_reply() {
    let owner = compact_store::Owner::generate([31; 16]).unwrap();
    let image = owner
        .seal(
            compact_store::Layout {
                schema: [32; 16],
                row_width: 1,
                rows_per_page: 3,
                row_count: 7,
            },
            &[8; 7],
            compact_store::Limits::default(),
        )
        .unwrap();
    let raw = RawBundle::from_snapshots(&image, &image).unwrap();
    let expected = raw.target_version().unwrap();
    for corrupt_data in [None, Some(true), Some(false)] {
        let mut altered = raw.clone();
        if let Some(data) = corrupt_data {
            let bytes = if data {
                &mut altered.data
            } else {
                &mut altered.index
            };
            *bytes.last_mut().unwrap() ^= 1;
        }
        let received = receive_version(reply(altered.clone()), 91)
            .unwrap()
            .unwrap();
        assert!(received.target_version().unwrap() == expected);
        assert_eq!(received.encoded_images(), (&*altered.data, &*altered.index));
        assert_eq!(
            super::super::CheckedObject::audit(altered).is_ok(),
            corrupt_data.is_none()
        );
    }
}

#[test]
fn known_unexpected_success_is_none_but_errors_and_unknown_tags_are_not() {
    let bytes = wire::encode(&WireResponse {
        version: 2,
        id: 91,
        result: Ok(Response::Done),
    })
    .unwrap();
    assert!(receive_version(bytes.clone(), 91).unwrap().is_none());
    assert_eq!(
        receive_version(bytes, 92).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    let bytes = wire::encode(&WireResponse {
        version: 2,
        id: 91,
        result: Err(RemoteError::NotFound),
    })
    .unwrap();
    let error = receive_version(bytes, 91).unwrap_err();
    assert!(matches!(
        error.get_ref().unwrap().downcast_ref(),
        Some(RemoteError::NotFound)
    ));
    let mut unknown = reply(raw());
    unknown[14..18].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(receive_version(unknown, 91).is_err());
    let mut unknown = reply(raw());
    unknown[10..14].copy_from_slice(&2u32.to_le_bytes());
    assert!(receive_version(unknown, 91).is_err());
}

#[test]
fn received_raw_specialization_never_falls_back_on_malformed_body_or_envelope() {
    let bytes = reply(raw());
    for version in [1u16, 3] {
        let mut altered = bytes.clone();
        altered[..2].copy_from_slice(&version.to_le_bytes());
        assert!(receive_version(altered, 91).is_err());
    }
    assert_eq!(
        receive_version(bytes.clone(), 92).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    for end in [0, 1, 2, 9, 10, 13, 14, 17, 18, 51, 52, bytes.len() - 1] {
        assert!(receive_version(bytes[..end].to_vec(), 91).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(receive_version(trailing, 91).is_err());
    let last_length = bytes.len() - raw().index.len() - 8;
    for length in [66u64, u64::MAX] {
        let mut altered = bytes.clone();
        altered[last_length..last_length + 8].copy_from_slice(&length.to_le_bytes());
        assert!(receive_version(altered.clone(), 91).is_err());
        assert!(wire::decode_response(&altered).is_err());
    }
}

#[test]
fn received_whole_frame_cap_includes_all_eighteen_outer_bytes() {
    let empty = RawBundle {
        version: 1,
        nonce: [0; 32],
        data_head: vec![],
        index_head: vec![],
        data: vec![],
        index: vec![],
    };
    for size in [MAX_FRAME_BYTES - 1, MAX_FRAME_BYTES, MAX_FRAME_BYTES + 1] {
        let mut bytes = reply(empty.clone());
        assert_eq!(bytes.len(), 18 + 66);
        let last_length = bytes.len() - 8;
        bytes.resize(size, 0);
        bytes[last_length..last_length + 8]
            .copy_from_slice(&((size - 18 - 66) as u64).to_le_bytes());
        let expected = wire::decode_response(&bytes).is_ok();
        let pointer = bytes.as_ptr();
        match receive_version(bytes, 91) {
            Ok(Some(received)) => {
                assert!(expected && size <= MAX_FRAME_BYTES);
                assert_eq!(received.frame.as_ptr(), pointer);
                assert_eq!(received.encoded_images().1.len(), size - 18 - 66);
                assert!(received.target_version().is_err());
            }
            Err(_) => assert!(!expected && size > MAX_FRAME_BYTES),
            Ok(None) => panic!("A raw reply is never an unexpected success"),
        }
    }
}
