//! Public nonsecret SDK transcript diagnostics; no proving or native setup.

use super::*;
use crate::Challenge;
use p3_challenger::fs::{Hierarchy, Interaction, InteractionPattern, Kind, Length};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_symmetric::{CryptographicHasher, Permutation, PseudoCompressionFunction};

#[test]
fn actual_leaf_and_node_interfaces_are_not_independent_random_oracles() {
    let permutation = p3_goldilocks::default_goldilocks_poseidon2_12();
    let hash = crate::Hash::new(permutation.clone());
    let compression = crate::Compress::new(permutation);
    let input: [Val; 8] = core::array::from_fn(|i| Val::from_usize(i + 1));
    let children = [
        input[..4].try_into().unwrap(),
        input[4..].try_into().unwrap(),
    ];
    assert_eq!(hash.hash_iter(input), compression.compress(children));
}

#[test]
fn distinct_fixed_matrix_widths_can_share_the_same_padding_free_leaf_hash() {
    // Actual fused Query salted MAIN/AUX lengths are425 and429. This is a
    // cross-width mode correlation, not a same-width MMCS forgery or SQL proof.
    let permutation = p3_goldilocks::default_goldilocks_poseidon2_12();
    let hash = crate::Hash::new(permutation.clone());
    let mut short: Vec<Val> = (0..425).map(|i| Val::from_usize(i + 1)).collect();
    let mut before_last = [Val::ZERO; 12];
    for block in short[..424].as_chunks::<8>().0 {
        before_last[..8].copy_from_slice(block);
        permutation.permute_mut(&mut before_last);
    }
    let short_hash = hash.hash_iter(short.iter().copied());
    // Partial sponge absorption keeps the unoverwritten rate tail. Extending
    // with those exact known words creates the same final permutation input.
    short.extend_from_slice(&before_last[1..5]);
    assert_eq!(short.len(), 429);
    assert_eq!(short_hash, hash.hash_iter(short));
}

fn pattern(public_count: usize) -> InteractionPattern {
    InteractionPattern::new(vec![
        Interaction::algebra::<Val, Val>(
            Hierarchy::Atomic,
            Kind::Public,
            "public-values",
            Length::Fixed(public_count),
        ),
        Interaction::algebra::<Val, Challenge>(
            Hierarchy::Atomic,
            Kind::Challenge,
            "extension-challenge",
            Length::Scalar,
        ),
    ])
    .unwrap()
}

#[test]
fn actual_seed_fields_decode_to_independent_protocol_and_chunk_framing() {
    let pattern = pattern(1);
    let pattern_hash = pattern.pattern_hash();
    let mut separator = DomainSeparator::<FieldUnit<Val>>::new(0x2a, b"seed", pattern);
    separator
        .instance(&[0x01, 0x80, 0xff, 0x00, 0x02, 0x03, 0x04, 0x05])
        .instance(&[])
        .instance(&[0x00]);

    let binding = inspect_separator(&separator);

    let mut protocol_id = [0u8; 64];
    protocol_id[..5].copy_from_slice(&[0x2a, b's', b'e', b'e', b'd']);
    protocol_id[63] = 4;
    let label = [
        0, 0, 0, 8, 0x01, 0x80, 0xff, 0x00, 0x02, 0x03, 0x04, 0x05, 0, 0, 0, 0, 0, 0, 0, 1, 0,
    ];
    assert_eq!(binding.protocol_id(), &protocol_id);
    assert_eq!(binding.pattern_hash(), &pattern_hash);
    assert_eq!(binding.instance_label(), &label);
    let mut expected_bytes = Vec::new();
    expected_bytes.extend_from_slice(&protocol_id);
    expected_bytes.extend_from_slice(&pattern_hash);
    expected_bytes.extend_from_slice(&21u32.to_be_bytes());
    expected_bytes.extend_from_slice(&label);
    expected_bytes.push(0x80);
    assert_eq!(expected_bytes.len(), 122);

    let fields = binding.observed_fields();
    assert_eq!(fields.len(), 19);
    assert_eq!(fields[0], Val::from_u64(122));
    assert_eq!(
        fields[1],
        Val::from_u64(u64::from_le_bytes([0x2a, b's', b'e', b'e', b'd', 0, 0, 0]))
    );
    assert_eq!(fields.last(), Some(&Val::from_u64(0x80_00_01)));
    // Independent inverse: each canonical Gold value carries at most seven
    // bytes, then the separate length element removes final zero padding.
    let mut unpacked = Vec::new();
    for value in &fields[1..] {
        let word = value.as_canonical_u64();
        assert!(word < (1u64 << 56));
        unpacked.extend_from_slice(&word.to_le_bytes()[..7]);
    }
    assert_eq!(&unpacked[..122], expected_bytes.as_slice());
    assert!(unpacked[122..].iter().all(|&byte| byte == 0));
}

#[test]
fn protocol_version_and_zero_padded_name_remain_distinct_in_actual_seed() {
    let mut original = DomainSeparator::<FieldUnit<Val>>::new(1, b"seed", pattern(1));
    original.instance(b"instance");
    let baseline = inspect_separator(&original);
    for mut changed in [
        DomainSeparator::<FieldUnit<Val>>::new(2, b"seed", pattern(1)),
        DomainSeparator::<FieldUnit<Val>>::new(1, b"seed\0", pattern(1)),
    ] {
        changed.instance(b"instance");
        let changed = inspect_separator(&changed);
        assert_ne!(changed.protocol_id(), baseline.protocol_id());
        assert_eq!(changed.pattern_hash(), baseline.pattern_hash());
        assert_eq!(changed.instance_label(), baseline.instance_label());
        assert_ne!(changed.observed_fields(), baseline.observed_fields());
    }
}

#[test]
fn instance_chunk_boundaries_empty_chunks_and_trailing_zero_change_actual_seed() {
    let mut split = DomainSeparator::<FieldUnit<Val>>::new(1, b"seed", pattern(1));
    split.instance(b"ab").instance(b"c");
    let baseline = inspect_separator(&split);
    let mut joined = DomainSeparator::<FieldUnit<Val>>::new(1, b"seed", pattern(1));
    joined.instance(b"abc");
    let mut resplit = DomainSeparator::<FieldUnit<Val>>::new(1, b"seed", pattern(1));
    resplit.instance(b"a").instance(b"bc");
    let mut empty = split.clone();
    empty.instance(&[]);
    let mut padded = DomainSeparator::<FieldUnit<Val>>::new(1, b"seed", pattern(1));
    padded.instance(b"ab").instance(b"c\0");

    for changed in [joined, resplit, empty, padded] {
        let changed = inspect_separator(&changed);
        assert_eq!(changed.protocol_id(), baseline.protocol_id());
        assert_eq!(changed.pattern_hash(), baseline.pattern_hash());
        assert_ne!(changed.instance_label(), baseline.instance_label());
        assert_ne!(changed.observed_fields(), baseline.observed_fields());
    }
}

#[test]
fn changed_typed_pattern_changes_actual_seed_without_changing_instance_or_protocol() {
    let mut original = DomainSeparator::<FieldUnit<Val>>::new(1, b"seed", pattern(1));
    original.instance(b"instance");
    let baseline = inspect_separator(&original);
    let mut changed = DomainSeparator::<FieldUnit<Val>>::new(1, b"seed", pattern(2));
    changed.instance(b"instance");

    let changed = inspect_separator(&changed);

    assert_eq!(changed.protocol_id(), baseline.protocol_id());
    assert_eq!(changed.instance_label(), baseline.instance_label());
    assert_ne!(changed.pattern_hash(), baseline.pattern_hash());
    assert_ne!(changed.observed_fields(), baseline.observed_fields());
    let repeated = inspect_separator(&original);
    assert_eq!(repeated.observed_fields(), baseline.observed_fields());
}
