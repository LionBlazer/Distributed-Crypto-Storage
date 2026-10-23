//! Public nonsecret byte vectors, captured independently with .NET SHA256.HashData.

use super::*;
use p3_field::{PackedValue, PrimeCharacteristicRing};

#[test]
fn scalar_leaf_and_byte_digest_types_have_the_same_single_sdk_lane() {
    assert_eq!(<Val as PackedValue>::WIDTH, 1);
    assert_eq!(<u8 as PackedValue>::WIDTH, 1);
}

#[test]
fn empty_and_canonical_boundary_leaves_match_independent_byte_vectors() {
    let empty = [
        0xb7, 0x2b, 0x9b, 0x8c, 0xdb, 0x55, 0xce, 0x78, 0xaa, 0x56, 0x78, 0xe5, 0xa6, 0xae, 0x64,
        0xc2, 0x0d, 0x16, 0x2c, 0x30, 0x39, 0xc8, 0x0f, 0x97, 0xf3, 0x38, 0xcd, 0xe6, 0xb1, 0xad,
        0xbf, 0x68,
    ];
    let boundary = [
        0x09, 0xce, 0xa6, 0x20, 0x22, 0xf5, 0x14, 0x01, 0x59, 0x07, 0x8c, 0xfa, 0xf4, 0x94, 0xf5,
        0x5a, 0x15, 0x8c, 0x88, 0x9c, 0x76, 0x92, 0xa3, 0x0a, 0xa3, 0x81, 0x8b, 0x52, 0xa8, 0x02,
        0x6c, 0x5b,
    ];
    let mut empty_bytes =
        b"DCS/research/hash-hiding-FRI/SHA256/leaf/ValLE8/countLE64/v1\0".to_vec();
    empty_bytes.extend_from_slice(&[0; 8]);
    assert_eq!(<[u8; 32]>::from(Sha256::digest(&empty_bytes)), empty);
    let mut boundary_bytes =
        b"DCS/research/hash-hiding-FRI/SHA256/leaf/ValLE8/countLE64/v1\0".to_vec();
    boundary_bytes.extend_from_slice(&[
        0, 0, 0, 0, 0, 0, 0, 0, // Zero.
        1, 0, 0, 0, 0, 0, 0, 0, // One.
        0, 0, 0, 0, 255, 255, 255, 255, // Goldilocks p-1, canonical LE8.
        3, 0, 0, 0, 0, 0, 0, 0, // Three fields, LE64.
    ]);
    assert_eq!(<[u8; 32]>::from(Sha256::digest(&boundary_bytes)), boundary);

    assert_eq!(LeafHash.hash_iter(core::iter::empty()), empty);
    // A filtered stream has no exact-length contract; hashing must consume it once.
    let values = [Val::ZERO, Val::ONE, Val::from_u64(Val::ORDER_U64 - 1)];
    assert_eq!(
        LeafHash.hash_iter(values.into_iter().filter(|_| true)),
        boundary
    );
}

#[test]
fn canonical_field_values_lengths_and_order_determine_leaf_bytes() {
    let zero = Val::from_u64(Val::ORDER_U64);
    let one = Val::from_u64(Val::ORDER_U64 + 1);
    assert_eq!(zero, Val::ZERO);
    assert_eq!(one, Val::ONE);
    assert_eq!(
        LeafHash.hash_iter([zero, one]),
        LeafHash.hash_iter([Val::ZERO, Val::ONE])
    );
    assert_ne!(LeafHash.hash_iter([]), LeafHash.hash_iter([Val::ZERO]));
    assert_ne!(
        LeafHash.hash_iter([Val::ONE]),
        LeafHash.hash_iter([Val::ONE, Val::ZERO])
    );
    assert_ne!(
        LeafHash.hash_iter([Val::ONE, Val::from_u8(2)]),
        LeafHash.hash_iter([Val::from_u8(2), Val::ONE])
    );
}

#[test]
fn binary_nodes_match_independent_bytes_and_keep_order_and_leaf_domain_distinct() {
    let payload: [u8; 64] = core::array::from_fn(|index| u8::try_from(index).unwrap());
    let left: [u8; 32] = payload[..32].try_into().unwrap();
    let right: [u8; 32] = payload[32..].try_into().unwrap();
    let expected = [
        0xac, 0xf6, 0xf7, 0xd3, 0x3e, 0x64, 0xfb, 0xf4, 0x46, 0xd3, 0x53, 0xf0, 0xfa, 0xd1, 0x81,
        0x2c, 0x86, 0x08, 0xf2, 0xd2, 0xd0, 0xe2, 0x66, 0x79, 0x06, 0xe5, 0x82, 0x69, 0x93, 0x54,
        0xef, 0xd7,
    ];
    let mut bytes = b"DCS/research/hash-hiding-FRI/SHA256/node/binary32/v1\0".to_vec();
    bytes.extend(payload);
    assert_eq!(<[u8; 32]>::from(Sha256::digest(&bytes)), expected);

    assert_eq!(NodeCompress.compress([left, right]), expected);
    assert_ne!(NodeCompress.compress([right, left]), expected);
    assert_eq!((LEAF_DOMAIN.len(), NODE_DOMAIN.len()), (61, 53));
    assert!(!LEAF_DOMAIN.starts_with(NODE_DOMAIN));
    assert!(!NODE_DOMAIN.starts_with(LEAF_DOMAIN));
    let fields: [Val; 8] = core::array::from_fn(|index| {
        let chunk: [u8; 8] = payload[8 * index..8 * (index + 1)].try_into().unwrap();
        Val::from_u64(u64::from_le_bytes(chunk))
    });
    assert_ne!(LeafHash.hash_iter(fields), expected);
}

#[test]
fn unrepresentable_leaf_counts_reject_before_any_count_or_sha_length_wrap() {
    let domain_bytes = u64::try_from(LEAF_DOMAIN.len()).unwrap();
    let max = (u64::MAX / 8 - domain_bytes - 8) / 8;
    assert_eq!(checked_leaf_count(max - 1, 1), max);
    assert_eq!(checked_leaf_count(max - 64, 64), max);
    assert_eq!(checked_leaf_count(max, 0), max);
    // Partial/full blocks must reject the first excessive total, while both
    // count-addition overflow and encoded-byte overflow remain hard failures.
    for (count, additional) in [
        (max, 1),
        (max - 63, 64),
        (u64::MAX, 1),
        (u64::MAX - 63, 64),
        (u64::MAX / 8, 0),
    ] {
        assert!(std::panic::catch_unwind(|| checked_leaf_count(count, additional)).is_err());
    }
}

fn one_shot_leaf_bytes(fields: &[Val]) -> [u8; 32] {
    // Independently encode one complete finite message, with no chunked writes
    // or production counter helper. Allocation is restricted to this test oracle.
    let mut bytes = b"DCS/research/hash-hiding-FRI/SHA256/leaf/ValLE8/countLE64/v1\0".to_vec();
    for field in fields {
        bytes.extend_from_slice(&field.as_canonical_u64().to_le_bytes());
    }
    bytes.extend_from_slice(&u64::try_from(fields.len()).unwrap().to_le_bytes());
    Sha256::digest(bytes).into()
}

#[test]
fn full_and_partial_stack_blocks_match_the_complete_one_shot_byte_stream() {
    for length in [
        0, 1, 7, 8, 9, 63, 64, 65, 127, 128, 129, 184, 419, 425, 429, 512, 521, 549, 577, 672, 718,
        7170,
    ] {
        let fields: Vec<Val> = (0..length)
            .map(|index| match index % 7 {
                0 => Val::ZERO,
                1 => Val::ONE,
                2 => Val::from_u64(Val::ORDER_U64 - 1),
                3 => Val::from_u64(Val::ORDER_U64),
                4 => Val::from_u64(Val::ORDER_U64 + 1),
                5 => Val::from_u64(u64::MAX),
                _ => Val::from_u64(u64::try_from(index).unwrap() * 0x0102_0304_0506),
            })
            .collect();
        let expected = one_shot_leaf_bytes(&fields);

        let actual = LeafHash.hash_iter(fields.iter().copied());

        assert_eq!(actual, expected, "field count {length}");
    }
}

#[test]
fn unknown_length_iterators_are_consumed_once_through_the_first_end_marker() {
    for length in [0, 1, 63, 64, 65, 127, 128, 129] {
        let fields: Vec<Val> = (0..length).map(Val::from_usize).collect();
        let expected = one_shot_leaf_bytes(&fields);
        let mut remaining = fields.iter().copied();
        let mut visits = 0;
        let stream = core::iter::from_fn(|| {
            visits += 1;
            remaining.next()
        });

        let actual = LeafHash.hash_iter(stream);

        assert_eq!(actual, expected, "unknown field count {length}");
        assert_eq!(visits, length + 1, "unknown field count {length}");
    }
}
