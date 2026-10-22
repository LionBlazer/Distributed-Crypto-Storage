//! Public nonsecret transcript vectors, independently captured with .NET SHA512.HashData.

use super::{Challenger, rejection_sample};
use crate::{Challenge, Val};
use p3_challenger::{CanObserve, CanSample, CanSampleBits, GrindingChallenger};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_symmetric::MerkleCap;
use sha2::{Digest, Sha512};

// These are complete byte inputs, not finalized hash states or outputs fed back
// as a substitute for the prefix. Tags, counters and canonical words are literal.
const FIRST_DRAW_BYTES: &str = concat!(
    "4443532f72657365617263682f686173682d686964696e672d4652492f46532d5348413531322f",
    "66756c6c2d7072656669782f763100", // Fixed domain, including its terminating zero.
    "010000000000000000",             // FIELD zero.
    "010100000000000000",             // FIELD one.
    "0100000000ffffffff",             // FIELD p-1.
    "020200000000000000",             // CAP, two roots.
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "0400000000000000000000000000000000", // DRAW counter zero, retry zero.
);
const FIRST_DRAW_SHA512: &str = concat!(
    "ae8d18466318e2b4dc597a040f8b42e6c1ecd83ebac9370c0c82ee632adf6246",
    "477768cf5175856463e63c5a46ba6bd07b8afddec51784c410c9ae1c16692cd4",
);
const NEXT_DRAW_BYTES: &str = concat!(
    "4443532f72657365617263682f686173682d686964696e672d4652492f46532d5348413531322f",
    "66756c6c2d7072656669782f763100",
    "010000000000000000",
    "010100000000000000",
    "0100000000ffffffff",
    "020200000000000000",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "030000000000000000ae8d18466318e2b4", // SAMPLE zero, accepted canonical word.
    "010900000000000000",                 // Newly observed FIELD nine, after that sample.
    "0401000000000000000000000000000000", // DRAW counter one, retry zero.
);
const NEXT_DRAW_SHA512: &str = concat!(
    "8b816fa2b0d08455cd115357f5326b93dbbca8fe2fb571e90468bf2e3c291421d",
    "063d4da509c941584467a4e9a454036b764f3dc19381217476f90c211e31457",
);

fn hex_bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
        .collect()
}

fn public_cap() -> MerkleCap<Val, [u8; 32]> {
    MerkleCap::new(vec![
        [0xff; 32],
        core::array::from_fn(|index| u8::try_from(index).unwrap()),
    ])
}

fn public_events() -> Challenger {
    let mut challenger = Challenger::new();
    challenger.observe(Val::ZERO);
    challenger.observe(Val::ONE);
    challenger.observe(Val::from_u64(Val::ORDER_U64 - 1));
    challenger.observe(public_cap());
    challenger
}

#[test]
fn public_fields_raw_cap_and_first_draw_match_independent_full_prefix_sha512_bytes() {
    let bytes = hex_bytes(FIRST_DRAW_BYTES);
    let expected_hash = hex_bytes(FIRST_DRAW_SHA512);
    assert_eq!(bytes.len(), 171);
    let hash: [u8; 64] = Sha512::digest(bytes).into();
    assert_eq!(hash.as_slice(), expected_hash.as_slice());

    let actual: Val = public_events().sample();

    assert_eq!(actual.as_canonical_u64(), 13_034_007_086_220_479_918);
    assert_eq!(&actual.as_canonical_u64().to_le_bytes(), &hash[..8]);
}

#[test]
fn sample_then_observation_preserves_the_full_original_prefix_and_event_order() {
    let bytes = hex_bytes(NEXT_DRAW_BYTES);
    let expected_hash = hex_bytes(NEXT_DRAW_SHA512);
    assert_eq!(bytes.len(), 197);
    let hash: [u8; 64] = Sha512::digest(bytes).into();
    assert_eq!(hash.as_slice(), expected_hash.as_slice());
    let mut challenger = public_events();
    let first: Val = challenger.sample();
    assert_eq!(first.as_canonical_u64(), 13_034_007_086_220_479_918);
    challenger.observe(Val::from_u8(9));

    let actual: Val = challenger.sample();

    assert_eq!(actual.as_canonical_u64(), 6_162_279_647_207_719_307);
    assert_eq!(&actual.as_canonical_u64().to_le_bytes(), &hash[..8]);
    let mut reordered = public_events();
    reordered.observe(Val::from_u8(9));
    let reordered: Val = reordered.sample();
    assert_ne!(actual, reordered);
    let mut restarted = Challenger::new();
    restarted.observe(Val::from_u8(9));
    let restarted: Val = restarted.sample();
    assert_ne!(actual, restarted);
    let mut omitted_observation = public_events();
    let _: Val = omitted_observation.sample();
    let omitted_observation: Val = omitted_observation.sample();
    assert_ne!(actual, omitted_observation);
}

#[test]
fn scalar_and_slice_observations_have_the_same_canonical_field_event_stream() {
    let fields = [Val::ZERO, Val::ONE, Val::from_u64(Val::ORDER_U64 - 1)];
    let mut scalar = Challenger::new();
    for value in fields {
        scalar.observe(value);
    }
    let mut sliced = Challenger::new();
    sliced.observe_slice(&fields);
    sliced.observe_slice(&[] as &[Val]);

    let scalar_values: [Val; 3] = scalar.sample_array();
    let sliced_values: [Val; 3] = sliced.sample_array();

    assert_eq!(scalar_values, sliced_values);
    let mut reduced = Challenger::new();
    reduced.observe(Val::from_u64(Val::ORDER_U64));
    reduced.observe(Val::from_u64(Val::ORDER_U64 + 1));
    let mut canonical = Challenger::new();
    canonical.observe_slice(&[Val::ZERO, Val::ONE]);
    let reduced_value: Val = reduced.sample();
    let canonical_value: Val = canonical.sample();
    assert_eq!(reduced_value, canonical_value);
}

#[test]
fn owned_and_borrowed_caps_preserve_every_raw_digest_byte() {
    let cap = public_cap();
    let mut borrowed = Challenger::new();
    borrowed.observe(&cap);
    let mut owned = Challenger::new();
    owned.observe(cap);

    let borrowed_values: [Val; 3] = borrowed.sample_array();
    let owned_values: [Val; 3] = owned.sample_array();

    assert_eq!(borrowed_values, owned_values);
    let mut changed_byte = public_cap().into_roots();
    changed_byte[0][31] ^= 0x80;
    let mut changed = Challenger::new();
    changed.observe(MerkleCap::new(changed_byte));
    let changed_value: Val = changed.sample();
    assert_ne!(borrowed_values[0], changed_value);
}

#[test]
fn cap_roots_order_boundaries_and_field_type_have_distinct_transcripts() {
    let mut original = Challenger::new();
    original.observe(public_cap());
    let expected: Val = original.sample();

    let mut reversed_roots = public_cap().into_roots();
    reversed_roots.reverse();
    let mut reversed = Challenger::new();
    reversed.observe(MerkleCap::new(reversed_roots));
    let reversed: Val = reversed.sample();
    assert_ne!(expected, reversed);

    let mut split = Challenger::new();
    for root in public_cap().into_roots() {
        split.observe(MerkleCap::new(vec![root]));
    }
    let split: Val = split.sample();
    assert_ne!(expected, split);

    let mut raw_cap = Challenger::new();
    raw_cap.observe(MerkleCap::new(vec![[0xff; 32]]));
    let mut fields = Challenger::new();
    fields.observe_slice(&[Val::from_u64(u64::MAX); 4]);
    let raw_cap: Val = raw_cap.sample();
    let fields: Val = fields.sample();
    assert_ne!(raw_cap, fields);
}

#[test]
fn extension_sample_uses_five_consecutive_base_samples_and_advances_identically() {
    let mut extension = public_events();
    let mut base = public_events();

    let actual: Challenge = extension.sample();
    let expected: [Val; 5] = base.sample_array();

    assert_eq!(
        <Challenge as BasedVectorSpace<Val>>::as_basis_coefficients_slice(&actual),
        expected.as_slice()
    );
    let next_extension: Val = extension.sample();
    let next_base: Val = base.sample();
    assert_eq!(next_extension, next_base);
}

#[test]
fn actual_rejection_sampler_retries_modulus_and_max_then_accepts_canonical_boundary() {
    let candidates = [Val::ORDER_U64, u64::MAX, Val::ORDER_U64 - 1];
    let mut retries = Vec::new();

    let actual = rejection_sample(|retry| {
        retries.push(retry);
        candidates[usize::try_from(retry).unwrap()]
    });

    assert_eq!(retries, [0, 1, 2]);
    assert_eq!(actual.as_canonical_u64(), Val::ORDER_U64 - 1);
}

#[test]
fn sample_bits_uses_canonical_gold_low_bits_and_consumes_one_base_sample() {
    for bits in [0, 1, 13, 31, usize::BITS as usize - 1] {
        let mut actual = public_events();
        let mut reference = public_events();
        let field: Val = reference.sample();

        let sampled = actual.sample_bits(bits);

        let expected = field.as_canonical_u64() & ((1u64 << bits) - 1);
        assert_eq!(sampled, usize::try_from(expected).unwrap());
        let next_actual: Val = actual.sample();
        let next_reference: Val = reference.sample();
        assert_eq!(next_actual, next_reference);
    }
    // A uniform Gold sample has one more preimage for low-bits zero here.
    // This contract deliberately does not claim exactly uniform bit sampling.
    assert_eq!(Val::ORDER_U64 % (1u64 << 13), 1);
}

#[test]
fn zero_grinding_requires_the_canonical_witness_without_advancing_the_transcript() {
    let mut challenger = public_events();
    let mut reference = public_events();

    assert_eq!(challenger.grind(0), Val::ZERO);
    assert!(challenger.check_witness(0, Val::ZERO));
    assert!(!challenger.check_witness(0, Val::ONE));
    assert!(!challenger.check_witness(1, Val::ZERO));
    assert!(!challenger.check_witness(1, Val::ONE));

    let actual: Val = challenger.sample();
    let expected: Val = reference.sample();
    assert_eq!(actual, expected);
}

#[test]
#[should_panic(expected = "candidate supports only zero grinding")]
fn positive_grinding_is_rejected() {
    let _ = Challenger::new().grind(1);
}
