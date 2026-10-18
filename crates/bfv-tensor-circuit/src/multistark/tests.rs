//! Local equations/range obligations only; actual LogUp proofs belong to a consumer.
use super::*;
use p3_air::{check_all_constraints, symbolic::AirLayout};
use p3_field::PrimeField64;
use p3_lookup::InteractionSymbolicBuilder;
fn request(index: u8, operands: [u64; 4]) -> Request {
    let basis = Basis::new(index).unwrap();
    let input: Vec<_> = operands
        .into_iter()
        .flat_map(|v| core::iter::repeat_n(v, DEGREE))
        .collect();
    crate::decode_request(&crate::encode_request(basis, [0x51; 32], &input).unwrap()).unwrap()
}
fn prepared(index: u8, operands: [u64; 4]) -> (Request, crate::Evaluation, PreparedMachine) {
    let r = request(index, operands);
    let e = crate::evaluate_with_certificate(&r).unwrap();
    let p = prepare_public(&r, &e.output, Namespace::new([0x52; 32])).unwrap();
    (r, e, p)
}
fn integer(values: &[Val]) -> u64 {
    values
        .iter()
        .enumerate()
        .map(|(i, v)| v.as_canonical_u64() << (16 * i))
        .sum()
}

#[test]
fn all_ten_sealed_shapes_expose24_equations54_ranges_and_no_auxiliary_public_cells() {
    for index in 0..10 {
        let basis = Basis::new(index).unwrap();
        let namespace = Namespace::new([0x52; 32]);
        let s = shape(basis, namespace);
        assert_eq!(s.basis(), basis);
        assert_eq!(s.namespace(), namespace);
        assert_eq!(s.tables().len(), 3);
        assert_eq!(s.tables()[0].main_width(), 54);
        assert_eq!(s.tables()[0].preprocessed_width(), 28);
        assert_eq!(s.total_lookup_count_weight(), 54 * DEGREE);
        for (air, table) in s.airs().iter().zip(s.tables()) {
            assert!(!air.is_prepared());
            assert!(air.preprocessed_trace().is_none());
            assert_eq!(air.num_public_values(), 0);
            assert!(air.main_next_row_columns().is_empty());
            let symbols =
                InteractionSymbolicBuilder::<Val>::from_air(air, AirLayout::from_air(air));
            assert_eq!(
                symbols.base_constraints().len(),
                air.num_constraints().unwrap()
            );
            assert_eq!(
                symbols.global_interactions().len(),
                table.lookup_contributions_per_row()
            );
            assert_eq!(
                symbols
                    .global_interactions()
                    .iter()
                    .map(|x| x.count_weight as usize)
                    .sum::<usize>(),
                table.lookup_count_weight_per_row()
            );
        }
        let symbols = InteractionSymbolicBuilder::<Val>::from_air(
            &s.airs()[0],
            AirLayout::from_air(&s.airs()[0]),
        );
        for (column, interaction) in symbols.global_interactions().iter().enumerate() {
            assert_eq!(
                interaction.bus_name,
                limb_range_air::bus(namespace, column_range(column).unwrap())
            );
            assert_eq!(interaction.count_weight, 1);
        }
        assert_ne!(
            profile_digest(basis, namespace),
            crate::profile_digest(basis)
        );
        assert_ne!(
            profile_digest(basis, namespace),
            profile_digest(basis, Namespace::new([0x53; 32]))
        );
    }
}
#[test]
fn all_moduli_maximum_products_preserve_full_high_limbs_quotients_and_zero_end_carries() {
    for index in 0..10 {
        let modulus = Basis::new(index).unwrap().modulus();
        let (_, e, p) = prepared(index, [modulus - 1; 4]);
        let traces = p.witness(&e.aux).unwrap().into_traces().unwrap();
        for (component, wanted) in [1, 2, 1].into_iter().enumerate() {
            assert!(
                e.output.coefficients()[component * DEGREE..(component + 1) * DEGREE]
                    .iter()
                    .all(|&v| v == wanted)
            );
        }
        for index in [0, DEGREE - 1] {
            let row = &traces[0].values[index * MAIN_WIDTH..(index + 1) * MAIN_WIDTH];
            for (component, wanted) in [modulus - 2, 2 * modulus - 4, modulus - 2]
                .into_iter()
                .enumerate()
            {
                assert_eq!(integer(&row[4 * component..4 * component + 4]), wanted);
            }
            for (column, value) in row.iter().enumerate() {
                assert!(value.as_canonical_u64() < (1u64 << column_range(column).unwrap().bits()));
            }
        }
        for (air, trace) in p.airs().iter().zip(&traces) {
            assert!(air.is_prepared());
            assert!(check_all_constraints(air, trace, &[], Some(1)).is_ok());
        }
        let queries: u64 = traces[1..]
            .iter()
            .flat_map(|t| {
                t.values
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|r| r[1].as_canonical_u64())
            })
            .sum();
        assert_eq!(queries, (54 * DEGREE) as u64);
    }
}
#[test]
fn both_asymmetric_cross_terms_are_required_and_public_preparation_never_multiplies_them() {
    let (r, mut e, p) = prepared(9, [2, 3, 5, 7]);
    for (component, wanted) in [10, 29, 21].into_iter().enumerate() {
        assert!(
            e.output.coefficients()[component * DEGREE..(component + 1) * DEGREE]
                .iter()
                .all(|&v| v == wanted)
        );
    }
    let traces = p.witness(&e.aux).unwrap().into_traces().unwrap();
    assert!(check_all_constraints(p.arithmetic_air(), &traces[0], &[], Some(1)).is_ok());
    // This is exactly the first cross term2*7; the omitted3*5 must still reject.
    e.output.coefficients[2 * DEGREE - 1] = 14;
    let wrong = prepare_public(&r, &e.output, Namespace::new([0x52; 32])).unwrap();
    assert!(matches!(wrong.witness(&e.aux), Err(Error::Binding)));
    e.aux.output_digest = codec::digest(&e.output.encode());
    let traces = wrong.witness(&e.aux).unwrap().into_traces().unwrap();
    assert!(!check_all_constraints(wrong.arithmetic_air(), &traces[0], &[], Some(1)).is_ok());
    let mut foreign = r;
    foreign.binding[31] ^= 1;
    assert!(matches!(
        prepare_public(&foreign, &e.output, Namespace::new([0x52; 32])),
        Err(Error::Binding)
    ));
}
#[test]
fn canonical_last_coefficient_quotient_and_every_endpoint_carry_chain_reach_actual_equations() {
    let modulus = Basis::new(9).unwrap().modulus();
    let (r, e, p) = prepared(9, [modulus - 1; 4]);
    let traces = p.witness(&e.aux).unwrap().into_traces().unwrap();
    for component in 0..3 {
        for column in [
            4 * component,
            4 * component + 3,
            12 + 7 * component,
            18 + 7 * component,
            33 + 7 * component,
            39 + 7 * component,
        ] {
            let mut bad = traces[0].clone();
            let at = (DEGREE - 1) * MAIN_WIDTH + column;
            let value = bad.values[at].as_canonical_u64() ^ 1;
            assert!(value < (1u64 << column_range(column).unwrap().bits()));
            bad.values[at] = Val::from_u64(value);
            assert!(
                !check_all_constraints(p.arithmetic_air(), &bad, &[], Some(1)).is_ok(),
                "component{component} column{column}"
            );
        }
        let mut output = e.output.clone();
        output.coefficients[(component + 1) * DEGREE - 1] ^= 1;
        let mut aux = e.aux.clone();
        aux.output_digest = codec::digest(&output.encode());
        let claimed = prepare_public(&r, &output, Namespace::new([0x52; 32])).unwrap();
        let wrong = claimed.witness(&aux).unwrap().into_traces().unwrap();
        assert!(!check_all_constraints(claimed.arithmetic_air(), &wrong[0], &[], Some(1)).is_ok());
    }
}
#[test]
fn split_carry_field_alias_does_not_remove_the_declared_integer_range_obligation() {
    let (_, e, p) = prepared(0, [0; 4]);
    let (mut trace, _) = p.witness(&e.aux).unwrap().into_parts();
    let at = (DEGREE - 1) * MAIN_WIDTH;
    let before = trace.values[at + 12] + trace.values[at + 33] * Val::from_u32(1 << 16);
    trace.values[at + 12] += Val::from_u32(1 << 16);
    trace.values[at + 33] -= Val::ONE;
    assert_eq!(
        before,
        trace.values[at + 12] + trace.values[at + 33] * Val::from_u32(1 << 16)
    );
    assert!(check_all_constraints(p.arithmetic_air(), &trace, &[], Some(1)).is_ok());
    let mut counts = Histogram::new(&RANGES).unwrap();
    assert_eq!(
        counts.add(Range::R16, trace.values[at + 12].as_canonical_u64()),
        Err(limb_range_air::Error::OutOfRange)
    );
    // DebugConstraintBuilder ignores LogUp, so its success is not proof acceptance.
    // A genuine consumer must reject this mandatory out-of-support message.
}
#[cfg(feature = "plonky3")]
#[test]
fn compact_and_legacy_public_aux_layouts_feed_the_identical_private_integer_kernel() {
    let modulus = Basis::new(9).unwrap().modulus();
    let (r, e, p) = prepared(9, [modulus - 1; 4]);
    let old = crate::plonky3::prepare(&r, &e.output, &e.aux).unwrap();
    let traces = p.witness(&e.aux).unwrap().into_traces().unwrap();
    let pp = p.arithmetic_air().preprocessed_trace().unwrap();
    for index in [0, DEGREE - 1] {
        let row = &traces[0].values[index * MAIN_WIDTH..(index + 1) * MAIN_WIDTH];
        let mut rebuilt = pp.values[index * PUBLIC_WIDTH..(index + 1) * PUBLIC_WIDTH].to_vec();
        rebuilt.extend_from_slice(&row[..12]);
        for i in 0..3 * CARRIES {
            rebuilt.push(row[12 + i] + row[33 + i] * Val::from_u32(1 << 16));
        }
        assert_eq!(old.coefficient_row(index).unwrap(), rebuilt);
    }
}
