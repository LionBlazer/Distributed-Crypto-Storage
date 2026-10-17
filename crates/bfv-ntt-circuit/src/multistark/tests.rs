//! These owning checks cover local constraints/layout only, never LogUp proof acceptance.
use super::*;
use crate::{
    Error, decode_aux, decode_request, encode_request, evaluate_with_certificate, parameters,
};
use p3_air::{BaseAir, symbolic::AirLayout};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_lookup::InteractionSymbolicBuilder;

fn request(direction: Direction, basis: u8) -> Request {
    decode_request(
        &encode_request(
            direction,
            Basis::new(basis).unwrap(),
            [71; 32],
            &vec![0; DEGREE],
        )
        .unwrap(),
    )
    .unwrap()
}
fn symbolic(air: &ProgramAir) -> InteractionSymbolicBuilder<Val> {
    InteractionSymbolicBuilder::from_air(air, AirLayout::from_air(air))
}
fn integer(row: &[Val]) -> u128 {
    row.iter()
        .enumerate()
        .map(|(i, v)| (v.as_canonical_u64() as u128) << (16 * i))
        .sum()
}

#[test]
fn every_fixed_machine_shape_exposes_complete_unprepared_tables_and_actual_interaction_counts() {
    for direction in [Direction::Forward, Direction::Inverse] {
        for index in 0..10 {
            let shape = shape(direction, Basis::new(index).unwrap());
            assert_eq!(shape.tables().len(), direction.stages() + 5);
            assert_eq!(shape.direction(), direction);
            assert_eq!(shape.basis().index(), index);
            for (air, table) in shape.airs().iter().zip(shape.tables()) {
                assert!(!air.is_prepared());
                assert!(air.preprocessed_trace().is_none());
                assert_eq!(air.height(), table.height());
                assert_eq!(air.width(), table.main_width());
                assert_eq!(air.preprocessed_width(), table.preprocessed_width());
                assert_eq!(air.num_public_values(), 0);
                let symbols = symbolic(air);
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
                assert_eq!(
                    symbols.base_constraints().len(),
                    air.num_constraints().unwrap()
                );
            }
            let expected = if direction == Direction::Forward {
                (3_900_448, 1_327_632, 3_293_712, 3_317_760)
            } else {
                (4_187_168, 1_417_744, 3_531_280, 3_555_328)
            };
            assert_eq!(
                (
                    shape.total_main_cells(),
                    shape.total_preprocessed_cells(),
                    shape.total_lookup_contributions(),
                    shape.total_lookup_count_weight()
                ),
                expected
            );
            assert_eq!(shape.tables()[direction.stages()].kind(), TableKind::Io);
            for (table, range) in shape.tables()[direction.stages() + 1..].iter().zip(RANGES) {
                assert_eq!(table.kind(), TableKind::Range(range));
                assert_eq!(table.height(), range.height());
            }
        }
    }
}

#[test]
fn public_preparation_pins_first_last_gathers_weights_and_the_fourteenth_inverse_normalization() {
    let r = request(Direction::Inverse, 9);
    let e = evaluate_with_certificate(&r).unwrap();
    let machine = prepare_public(&r, &e.output).unwrap();
    assert!(machine.airs().iter().all(ProgramAir::is_prepared));
    let first = machine.airs()[0].preprocessed_trace().unwrap();
    let row = &first.values[(DEGREE - 1) * 11..DEGREE * 11];
    let p = r.basis().modulus();
    assert_eq!(
        row[..3],
        [
            Val::from_usize(DEGREE - 1),
            Val::from_usize(DEGREE - 2),
            Val::from_usize(DEGREE - 1)
        ]
    );
    let w = parameters(r.basis()).inverse_twiddles()[4095];
    assert_eq!(integer(&row[3..7]), w as u128);
    assert_eq!(integer(&row[7..11]), (p - w) as u128);
    let last = machine.airs()[13].preprocessed_trace().unwrap();
    let row = &last.values[(DEGREE - 1) * 11..DEGREE * 11];
    assert_eq!(row[..3], [Val::from_usize(DEGREE - 1); 3]);
    assert_eq!(
        integer(&row[3..7]),
        parameters(r.basis()).inverse_size() as u128
    );
    assert_eq!(integer(&row[7..11]), 0);
    let forward = request(Direction::Forward, 0);
    let f = evaluate_with_certificate(&forward).unwrap();
    let machine = prepare_public(&forward, &f.output).unwrap();
    let first = machine.airs()[0].preprocessed_trace().unwrap();
    assert_eq!(
        first.values[..3],
        [Val::ZERO, Val::ZERO, Val::from_usize(DEGREE / 2)]
    );
}

#[test]
fn verifier_public_preparation_needs_no_aux_and_does_not_reexecute_a_claimed_ntt() {
    let r = request(Direction::Forward, 0);
    let e = evaluate_with_certificate(&r).unwrap();
    let mut foreign = e.output.clone();
    foreign.binding[31] ^= 1;
    assert!(matches!(prepare_public(&r, &foreign), Err(Error::Binding)));
    let mut claimed = e.output.clone();
    claimed.coefficients[DEGREE - 1] = 1;
    let machine = prepare_public(&r, &claimed).unwrap();
    let io = machine.airs()[r.direction().stages()]
        .preprocessed_trace()
        .unwrap();
    assert_eq!(integer(&io.values[(DEGREE - 1) * 9 + 5..DEGREE * 9]), 1);
    // Preparation builds the claimed statement; the old witness is NOT a proof for it.
    assert!(matches!(machine.witness(&e.aux), Err(Error::Binding)));
}

#[test]
fn full_aux_witness_covers_every_table_and_builds_exact_provided_range_frequencies() {
    let basis = Basis::new(9).unwrap();
    let input: Vec<_> = (0..DEGREE)
        .map(|index| match index % 4 {
            0 => 0,
            1 => 1,
            2 => basis.modulus() / 2,
            _ => basis.modulus() - 1,
        })
        .collect();
    let r = decode_request(&encode_request(Direction::Forward, basis, [71; 32], &input).unwrap())
        .unwrap();
    let e = evaluate_with_certificate(&r).unwrap();
    let machine = prepare_public(&r, &e.output).unwrap();
    let traces = machine.witness(&e.aux).unwrap();
    assert_eq!(traces.len(), machine.airs().len());
    for ((air, table), trace) in machine
        .airs()
        .iter()
        .zip(machine.shape().tables())
        .zip(&traces)
    {
        assert_eq!(trace.width, table.main_width());
        assert_eq!(trace.values.len(), table.height() * table.main_width());
        assert!(p3_air::check_all_constraints(air, trace, &[], Some(1)).is_ok());
    }
    for (offset, range) in RANGES.into_iter().enumerate() {
        let trace = &traces[r.direction().stages() + 1 + offset];
        let expected = [17, 2, 7, 1][range.index()] * DEGREE * r.direction().stages();
        let actual = trace
            .values
            .as_chunks::<2>()
            .0
            .iter()
            .map(|r| r[1].as_canonical_u64())
            .sum::<u64>();
        assert_eq!(actual, expected as u64);
        for (index, row) in trace.values.as_chunks::<2>().0.iter().enumerate() {
            assert_eq!(
                row[0].as_canonical_u64(),
                (index % range.domain_size()) as u64
            );
            if range == RangeKind::R2 && index >= 4 {
                assert_eq!(row[1], Val::ZERO);
            }
        }
    }
}

#[test]
fn normalization_has_one_input_read_zero_y_and_one_use_of_every_preceding_output() {
    let r = request(Direction::Inverse, 0);
    let e = evaluate_with_certificate(&r).unwrap();
    let machine = prepare_public(&r, &e.output).unwrap();
    let traces = machine.witness(&e.aux).unwrap();
    let s12 = symbolic(&machine.airs()[12]);
    let s13 = symbolic(&machine.airs()[13]);
    assert_eq!(s12.global_interactions()[2].count_weight, 1);
    assert_eq!(s13.global_interactions().len(), 29);
    assert_eq!(s13.global_interactions()[0].fields.len(), 5);
    assert_eq!(s13.global_interactions()[1].count_weight, 1);
    for row in traces[13].values.as_chunks::<35>().0 {
        assert_eq!(row[4..8], [Val::ZERO; 4]);
    }
    let mut bad = traces[13].clone();
    bad.values[(DEGREE - 1) * 35 + 4] = Val::ONE;
    assert!(!p3_air::check_all_constraints(&machine.airs()[13], &bad, &[], Some(1)).is_ok());
}

#[test]
fn last_row_quotient_carry_and_canonical_slack_forgeries_reach_the_local_integer_constraints() {
    let r = request(Direction::Forward, 9);
    let e = evaluate_with_certificate(&r).unwrap();
    let machine = prepare_public(&r, &e.output).unwrap();
    let traces = machine.witness(&e.aux).unwrap();
    let last = r.direction().stages() - 1;
    for column in [16, 21, 28, 12] {
        let mut bad = traces[last].clone();
        bad.values[(DEGREE - 1) * 35 + column] += Val::ONE;
        assert!(
            !p3_air::check_all_constraints(&machine.airs()[last], &bad, &[], Some(1)).is_ok(),
            "column {column}"
        );
    }
}

#[test]
fn canonical_auxiliary_forgery_builds_prover_rows_but_is_not_accepted_as_an_arithmetic_proof() {
    let r = request(Direction::Inverse, 9);
    let e = evaluate_with_certificate(&r).unwrap();
    let machine = prepare_public(&r, &e.output).unwrap();
    let mut wrong = e.aux.clone();
    wrong.stages[13].rows[DEGREE - 1].biased_quotient ^= 1;
    let wrong = decode_aux(&wrong.encode()).unwrap();
    let traces = machine.witness(&wrong).unwrap();
    assert!(!p3_air::check_all_constraints(&machine.airs()[13], &traces[13], &[], Some(1)).is_ok());
    let foreign = request(Direction::Forward, 9);
    let f = evaluate_with_certificate(&foreign).unwrap();
    assert!(matches!(machine.witness(&f.aux), Err(Error::Binding)));
}

#[test]
fn public_io_zero_and_fixed_range_value_copies_have_owning_local_rejection_checks() {
    let r = request(Direction::Forward, 0);
    let e = evaluate_with_certificate(&r).unwrap();
    let machine = prepare_public(&r, &e.output).unwrap();
    let traces = machine.witness(&e.aux).unwrap();
    let io = r.direction().stages();
    let mut bad = traces[io].clone();
    bad.values[DEGREE - 1] = Val::ONE;
    assert!(!p3_air::check_all_constraints(&machine.airs()[io], &bad, &[], Some(1)).is_ok());
    for (table, trace) in traces.iter().enumerate().skip(io + 1) {
        let mut bad = trace.clone();
        let last = bad.values.len() - 2;
        bad.values[last] += Val::ONE;
        assert!(!p3_air::check_all_constraints(&machine.airs()[table], &bad, &[], Some(1)).is_ok());
        let symbols = symbolic(&machine.airs()[table]);
        assert_eq!(symbols.global_interactions()[0].count_weight, 0);
    }
    // These checks deliberately do not claim cross-AIR copy/range inclusion:
    // DebugConstraintBuilder discards lookup messages; the genuine consumer must verify LogUp.
}

#[cfg(feature = "plonky3")]
#[test]
fn both_optional_air_layouts_feed_the_exact_same_private_eight_digit_kernel() {
    let r = request(Direction::Inverse, 9);
    let e = evaluate_with_certificate(&r).unwrap();
    let machine = prepare_public(&r, &e.output).unwrap();
    let traces = machine.witness(&e.aux).unwrap();
    let old = crate::plonky3::prepare(&r, &e.output, &e.aux).unwrap();
    for index in [0, DEGREE - 1] {
        let public = old.coefficient_row(index).unwrap();
        for stage in 0..r.direction().stages() {
            let row = &traces[stage].values[index * 35..(index + 1) * 35];
            let pp = machine.airs()[stage].preprocessed_trace().unwrap();
            let weights = &pp.values[index * 11 + 3..(index + 1) * 11];
            let mut rebuilt = row[..12].to_vec();
            rebuilt.extend_from_slice(weights);
            rebuilt.extend_from_slice(&row[16..21]);
            for i in 0..7 {
                rebuilt.push(row[21 + i] + row[28 + i] * Val::from_u64(1 << 16));
            }
            assert_eq!(&public[stage * 32..(stage + 1) * 32], rebuilt);
        }
    }
}
