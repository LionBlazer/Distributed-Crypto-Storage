//! Local support/accounting examples. No test here produces a cryptographic proof.
use super::*;
use p3_air::{check_all_constraints, symbolic::AirLayout};
use p3_lookup::InteractionSymbolicBuilder;
const ALL: [Range; 6] = [
    Range::R2,
    Range::R9,
    Range::R13,
    Range::R14,
    Range::R15,
    Range::R16,
];

#[test]
fn fixed_supports_pin_every_value_and_provided_counts_have_zero_query_weight() {
    let namespace = Namespace::new([0x31; 32]);
    for range in ALL {
        let shape = RangeAir::shape(namespace, range);
        assert!(!shape.is_prepared());
        assert!(shape.preprocessed_trace().is_none());
        let air = RangeAir::prepare(namespace, range);
        let public = air.preprocessed_trace().unwrap();
        assert_eq!(public.values.len(), range.height());
        for (index, &value) in public.values.iter().enumerate() {
            assert_eq!(
                value.as_canonical_u64(),
                (index % range.domain_size()) as u64
            );
        }
        let symbols = InteractionSymbolicBuilder::<Val>::from_air(&air, AirLayout::from_air(&air));
        assert_eq!(symbols.base_constraints().len(), 1);
        assert_eq!(symbols.global_interactions().len(), 1);
        let interaction = &symbols.global_interactions()[0];
        assert_eq!(interaction.bus_name, bus(namespace, range));
        assert_eq!(interaction.fields.len(), 1);
        assert_eq!(interaction.count_weight, 0);
        assert_eq!(air.width(), 2);
        assert_eq!(air.preprocessed_width(), 1);
        assert_eq!(air.num_public_values(), 0);
        assert!(air.main_next_row_columns().is_empty());
    }
    assert_ne!(
        bus(namespace, Range::R16),
        bus(Namespace::new([0x32; 32]), Range::R16)
    );
    assert_ne!(bus(namespace, Range::R16), bus(namespace, Range::R15));
}
#[test]
fn histogram_rejects_aliases_and_merges_subsets_atomically_without_field_reduction() {
    assert!(matches!(
        Histogram::new(&[Range::R2, Range::R2]),
        Err(Error::DuplicateRange)
    ));
    let mut total = Histogram::new(&ALL).unwrap();
    let mut part = Histogram::new(&[Range::R2, Range::R16]).unwrap();
    part.add(Range::R2, 3).unwrap();
    part.add(Range::R16, 65535).unwrap();
    assert_eq!(part.add(Range::R16, 65536), Err(Error::OutOfRange));
    assert_eq!(part.add(Range::R9, 0), Err(Error::MissingRange));
    total.merge(&part).unwrap();
    total.merge(&part).unwrap();
    assert_eq!(total.count(Range::R2, 3), Some(2));
    assert_eq!(total.count(Range::R16, 65535), Some(2));
    let mut small = Histogram::new(&[Range::R2]).unwrap();
    small.add(Range::R2, 3).unwrap();
    assert_eq!(small.merge(&part), Err(Error::MissingRange));
    assert_eq!(small.count(Range::R2, 3), Some(1));
    small.entries[0].1[3] = Val::ORDER_U64 - 1;
    let mut one = Histogram::new(&[Range::R2]).unwrap();
    one.add(Range::R2, 3).unwrap();
    assert_eq!(small.merge(&one), Err(Error::MultiplicityOverflow));
    assert_eq!(small.count(Range::R2, 3), Some(Val::ORDER_U64 - 1));
    assert_eq!(small.add(Range::R2, 3), Err(Error::MultiplicityOverflow));
}
#[test]
fn repeated_small_support_uses_one_frequency_copy_and_local_fixed_value_tampering_rejects() {
    let namespace = Namespace::new([0x33; 32]);
    let air = RangeAir::prepare(namespace, Range::R2);
    let mut counts = Histogram::new(&[Range::R2]).unwrap();
    counts.add(Range::R2, 3).unwrap();
    let trace = counts.trace(Range::R2).unwrap();
    assert_eq!(trace.values.len(), 32);
    for (index, row) in trace.values.as_chunks::<2>().0.iter().enumerate() {
        assert_eq!(row[0].as_canonical_u64(), (index % 4) as u64);
        assert_eq!(row[1], if index == 3 { Val::ONE } else { Val::ZERO });
    }
    assert!(check_all_constraints(&air, &trace, &[], Some(1)).is_ok());
    let mut bad = trace;
    bad.values[30] = Val::ONE;
    assert!(!check_all_constraints(&air, &bad, &[], Some(1)).is_ok());
    // Debug builders ignore interaction messages. This checks the fixed value
    // constraint only; range inclusion must be proved by a real LogUp consumer.
}
