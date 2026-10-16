//! The public domain value has no SQL/parser or proof authority.
use compact_query::{AgeRange, AgeSet256};
#[test]
fn canonical_mask_preserves_every_bit_and_iterates_unique_ages_in_order() {
    let mut bytes = [0; 32];
    for age in [0u8, 7, 8, 63, 64, 127, 128, 254, 255] {
        bytes[usize::from(age) / 8] |= 1 << (age % 8);
    }
    let set = AgeSet256::from_bytes(bytes);
    assert_eq!(set.to_bytes(), bytes);
    assert_eq!(
        set.ages().collect::<Vec<_>>(),
        vec![0, 7, 8, 63, 64, 127, 128, 254, 255]
    );
    for age in 0..=u8::MAX {
        assert_eq!(
            set.contains(age),
            [0, 7, 8, 63, 64, 127, 128, 254, 255].contains(&age)
        );
    }
    assert_eq!(AgeSet256::all().ages().count(), 256);
    assert_eq!(AgeSet256::empty().ages().count(), 0);
    assert_eq!(AgeSet256::equal(255).ages().collect::<Vec<_>>(), vec![255]);
    assert!(
        AgeSet256::try_from(AgeRange {
            lower: 42,
            upper: 18
        })
        .is_err()
    );
    assert_eq!(
        AgeSet256::try_from(AgeRange {
            lower: 18,
            upper: 42
        })
        .unwrap()
        .ages()
        .collect::<Vec<_>>(),
        (18..=42).collect::<Vec<_>>()
    );
}
