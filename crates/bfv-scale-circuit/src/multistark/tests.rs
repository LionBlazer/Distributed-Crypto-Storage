//! Owning local equations/layout/range obligations, not genuine LogUp proof tests.
use super::*;
use p3_air::{check_all_constraints, symbolic::AirLayout};
use p3_field::PrimeField64;
use p3_lookup::InteractionSymbolicBuilder;
fn request(role: Role, largest: bool) -> Request {
    let input: Vec<_> = role
        .input_moduli()
        .iter()
        .flat_map(|&p| core::iter::repeat_n(if largest { p - 1 } else { 0 }, DEGREE))
        .collect();
    crate::decode_request(&crate::encode_request(role, [0x41; 32], &input).unwrap()).unwrap()
}
fn integer(values: &[Val]) -> u128 {
    values
        .iter()
        .enumerate()
        .map(|(i, v)| (v.as_canonical_u64() as u128) << (16 * i))
        .sum()
}
fn prepared(role: Role, largest: bool) -> (Request, crate::Evaluation, PreparedMachine) {
    let r = request(role, largest);
    let e = crate::evaluate_with_certificate(&r).unwrap();
    let p = prepare_public(&r, &e.output, Namespace::new([0x42; 32])).unwrap();
    (r, e, p)
}

#[test]
fn shape_is_unprepared_and_all63_equations_and160_range_queries_are_declared() {
    for role in [Role::Extend5To10, Role::Scale10To5] {
        let namespace = Namespace::new([0x42; 32]);
        let s = shape(role, namespace);
        assert_eq!(s.role(), role);
        assert_eq!(s.namespace(), namespace);
        assert_eq!(s.tables().len(), 1 + ranges(role).len());
        assert_eq!(s.tables()[0].main_width(), 160);
        assert_eq!(
            s.tables()[0].preprocessed_width(),
            if role == Role::Extend5To10 { 40 } else { 60 }
        );
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
                    .map(|i| i.count_weight as usize)
                    .sum::<usize>(),
                table.lookup_count_weight_per_row()
            );
        }
        assert_eq!(s.total_lookup_count_weight(), 160 * DEGREE);
        assert_ne!(profile_digest(role, namespace), crate::profile_digest(role));
        assert_ne!(
            profile_digest(role, namespace),
            profile_digest(role, Namespace::new([0x43; 32]))
        );
        let symbols = InteractionSymbolicBuilder::<Val>::from_air(
            &s.airs()[0],
            AirLayout::from_air(&s.airs()[0]),
        );
        for (column, interaction) in symbols.global_interactions().iter().enumerate() {
            assert_eq!(
                interaction.bus_name,
                limb_range_air::bus(namespace, column_range(role, column).unwrap())
            );
            assert_eq!(interaction.count_weight, 1);
        }
    }
}
#[test]
fn centered_zero_and_minus_one_have_independent_exact_outputs_and_complete_ranged_rows() {
    for role in [Role::Extend5To10, Role::Scale10To5] {
        for largest in [false, true] {
            let (_, e, p) = prepared(role, largest);
            for (poly, &modulus) in role.output_moduli().iter().enumerate() {
                let expected = if largest && role == Role::Extend5To10 {
                    modulus - 1
                } else {
                    0
                };
                assert!(
                    e.output.coefficients()[poly * DEGREE..(poly + 1) * DEGREE]
                        .iter()
                        .all(|&v| v == expected)
                );
            }
            let traces = p.witness(&e.aux).unwrap().into_traces().unwrap();
            assert_eq!(traces.len(), p.airs().len());
            for (air, trace) in p.airs().iter().zip(&traces) {
                assert!(air.is_prepared());
                assert!(check_all_constraints(air, trace, &[], Some(1)).is_ok());
            }
            for row in traces[0].values.as_chunks::<MAIN_WIDTH>().0 {
                for (column, value) in row.iter().enumerate() {
                    assert!(
                        value.as_canonical_u64()
                            < (1u64 << column_range(role, column).unwrap().bits())
                    );
                }
            }
            let total: u64 = traces[1..]
                .iter()
                .flat_map(|t| {
                    t.values
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|r| r[1].as_canonical_u64())
                })
                .sum();
            assert_eq!(total, (160 * DEGREE) as u64);
            if !largest {
                let row = &traces[0].values[..MAIN_WIDTH];
                assert_eq!(integer(&row[..4]), 0);
                assert_eq!(
                    integer(&row[4..12]),
                    1u128 << (crate::constants(role).garner_shift() - 1)
                );
                assert_eq!(integer(&row[12..15]), 1u128 << 45);
                assert_eq!(integer(&row[15..23]), 1u128 << 126);
                for q in row[23..48].as_chunks::<5>().0 {
                    assert_eq!(integer(q), 1u128 << 64);
                }
            }
        }
    }
}
#[test]
fn public_preparation_accepts_a_claim_without_aux_but_actual_last_row_math_rejects_it() {
    let (r, mut e, _) = prepared(Role::Scale10To5, false);
    e.output.coefficients[5 * DEGREE - 1] = 1;
    let p = prepare_public(&r, &e.output, Namespace::new([0x42; 32])).unwrap();
    assert!(matches!(p.witness(&e.aux), Err(Error::Binding)));
    e.aux.output_digest = codec::digest(&e.output.encode());
    let traces = p.witness(&e.aux).unwrap().into_traces().unwrap();
    assert!(!check_all_constraints(p.arithmetic_air(), &traces[0], &[], Some(1)).is_ok());
    let mut foreign = r.clone();
    foreign.binding[31] ^= 1;
    assert!(matches!(
        prepare_public(&foreign, &e.output, Namespace::new([0x42; 32])),
        Err(Error::Binding)
    ));
}
#[test]
fn canonical_last_row_scalar_quotient_and_both_carry_halves_cannot_bypass_integer_equations() {
    for role in [Role::Extend5To10, Role::Scale10To5] {
        let (_, e, p) = prepared(role, true);
        let traces = p.witness(&e.aux).unwrap().into_traces().unwrap();
        for column in [0, 4, 12, 15, 23, 47, 48, 103, 104, 159] {
            let mut bad = traces[0].clone();
            let at = (DEGREE - 1) * MAIN_WIDTH + column;
            let value = bad.values[at].as_canonical_u64() ^ 1;
            assert!(value < (1u64 << column_range(role, column).unwrap().bits()));
            bad.values[at] = Val::from_u64(value);
            assert!(
                !check_all_constraints(p.arithmetic_air(), &bad, &[], Some(1)).is_ok(),
                "role{role:?} column{column}"
            );
        }
    }
}
#[test]
fn split_carry_alias_is_locally_equal_but_outside_its_mandatory_range_message() {
    let (_, e, p) = prepared(Role::Extend5To10, false);
    let (mut trace, _) = p.witness(&e.aux).unwrap().into_parts();
    let at = (DEGREE - 1) * MAIN_WIDTH;
    let before = trace.values[at + 48] + trace.values[at + 104] * Val::from_u32(1 << 16);
    trace.values[at + 48] += Val::from_u32(1 << 16);
    trace.values[at + 104] -= Val::ONE;
    assert_eq!(
        before,
        trace.values[at + 48] + trace.values[at + 104] * Val::from_u32(1 << 16)
    );
    assert!(check_all_constraints(p.arithmetic_air(), &trace, &[], Some(1)).is_ok());
    let mut counts = Histogram::new(ranges(p.role())).unwrap();
    assert_eq!(
        counts.add(Range::R16, trace.values[at + 48].as_canonical_u64()),
        Err(limb_range_air::Error::OutOfRange)
    );
    // Local debug success deliberately proves nothing about LogUp. The actual
    // consumer must reject this emitted out-of-support message cryptographically.
}
#[test]
fn batch_histograms_merge_without_duplicating_the_shared_provided_support() {
    let (_, e, p) = prepared(Role::Extend5To10, true);
    let (_, h0) = p.witness(&e.aux).unwrap().into_parts();
    let mut merged = Histogram::new(&SCALE_RANGES).unwrap();
    merged.merge(&h0).unwrap();
    merged.merge(&h0).unwrap();
    let count: u64 = merged
        .ranges()
        .map(|r| {
            merged
                .trace(r)
                .unwrap()
                .values
                .as_chunks::<2>()
                .0
                .iter()
                .map(|row| row[1].as_canonical_u64())
                .sum::<u64>()
        })
        .sum();
    assert_eq!(count, (2 * 160 * DEGREE) as u64);
    assert_eq!(merged.count(Range::R13, 0), Some(0));
}
#[cfg(feature = "plonky3")]
#[test]
fn both_optional_layouts_reconstruct_the_same_complete_private_kernel_row() {
    for role in [Role::Extend5To10, Role::Scale10To5] {
        let (r, e, p) = prepared(role, true);
        let old = crate::plonky3::prepare(&r, &e.output, &e.aux).unwrap();
        let traces = p.witness(&e.aux).unwrap().into_traces().unwrap();
        let pp = p.arithmetic_air().preprocessed_trace().unwrap();
        let width = pp.width;
        for index in [0, DEGREE - 1] {
            let row = &traces[0].values[index * MAIN_WIDTH..(index + 1) * MAIN_WIDTH];
            let mut rebuilt = pp.values[index * width..(index + 1) * width].to_vec();
            rebuilt.extend_from_slice(&row[..48]);
            for i in 0..CARRIES {
                rebuilt.push(row[48 + i] + row[104 + i] * Val::from_u32(1 << 16));
            }
            assert_eq!(old.coefficient_row(index).unwrap(), rebuilt);
        }
    }
}
