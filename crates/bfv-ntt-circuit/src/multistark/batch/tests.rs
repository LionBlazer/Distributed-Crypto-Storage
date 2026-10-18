//! Local/layout owning checks; actual cross-table proof acceptance belongs to the consumer.
use super::*;
use crate::{decode_request, encode_request, evaluate_with_certificate};
use p3_air::symbolic::AirLayout;
use p3_lookup::InteractionSymbolicBuilder;
fn request(direction: Direction, basis: u8, instance: u8) -> Request {
    let b = Basis::new(basis).unwrap();
    let values = (0..DEGREE)
        .map(|j| ((j as u128 * 13 + u128::from(instance) + 1) % u128::from(b.modulus())) as u64)
        .collect::<Vec<_>>();
    decode_request(&encode_request(direction, b, [instance; 32], &values).unwrap()).unwrap()
}
#[test]
fn complete_batch_shapes_namespace_every_data_edge_and_share_only_four_range_providers() {
    for count in [2, 4, 8] {
        let specs = (0..count)
            .map(|i| BatchSpec {
                direction: if i % 2 == 0 {
                    Direction::Forward
                } else {
                    Direction::Inverse
                },
                basis: Basis::new(i as u8).unwrap(),
            })
            .collect::<Vec<_>>();
        let shape = batch_shape(&specs).unwrap();
        assert_eq!(
            shape.tables.len(),
            specs
                .iter()
                .map(|s| s.direction.stages() + 1)
                .sum::<usize>()
                + 4
        );
        assert_eq!(
            shape.tables.iter().filter(|t| t.instance.is_none()).count(),
            4
        );
        for (air, table) in shape.airs.iter().zip(&shape.tables) {
            assert!(!air.is_prepared());
            let symbolic =
                InteractionSymbolicBuilder::<Val>::from_air(air, AirLayout::from_air(air));
            for atom in symbolic.global_interactions() {
                if let Some(i) = table.instance {
                    assert!(
                        atom.bus_name
                            .starts_with(&format!("dcs/bfv-ntt-witness/batch/{i}/data/"))
                            || atom.bus_name.starts_with("dcs/bfv-ntt-witness/range/")
                    );
                } else {
                    assert!(atom.bus_name.starts_with("dcs/bfv-ntt-witness/range/"));
                }
            }
        }
    }
    let old = shape(Direction::Forward, Basis::new(0).unwrap());
    let old_stage = InteractionSymbolicBuilder::<Val>::from_air(
        &old.airs[0],
        AirLayout::from_air(&old.airs[0]),
    );
    assert_eq!(
        old_stage.global_interactions()[0].bus_name,
        "dcs/bfv-ntt-witness/data/0"
    );
    let old_io = InteractionSymbolicBuilder::<Val>::from_air(
        &old.airs[13],
        AirLayout::from_air(&old.airs[13]),
    );
    assert_eq!(
        old_io.global_interactions()[0].bus_name,
        "dcs/bfv-ntt-witness/data/0"
    );
    for n in [0, 1, 3, 9] {
        assert!(
            batch_shape(&vec![
                BatchSpec {
                    direction: Direction::Forward,
                    basis: Basis::new(0).unwrap()
                };
                n
            ])
            .is_err()
        );
    }
}
#[test]
fn mixed_native_targets_reuse_all_integer_rows_and_sum_every_shared_range_frequency() {
    let requests = [
        request(Direction::Forward, 0, 1),
        request(Direction::Inverse, 9, 2),
    ];
    let evaluations = requests
        .iter()
        .map(|r| evaluate_with_certificate(r).unwrap())
        .collect::<Vec<_>>();
    let outputs = evaluations
        .iter()
        .map(|e| e.output.clone())
        .collect::<Vec<_>>();
    let aux = evaluations
        .iter()
        .map(|e| e.aux.clone())
        .collect::<Vec<_>>();
    let machine = prepare_batch(&requests, &outputs).unwrap();
    let traces = machine.witness(&aux).unwrap();
    assert_eq!(traces.len(), machine.airs.len());
    for (air, trace) in machine.airs.iter().zip(&traces) {
        assert!(p3_air::check_all_constraints(air, trace, &[], Some(1)).is_ok());
    }
    let mut offset = 0;
    for ((request, output), aux) in requests.iter().zip(&outputs).zip(&aux) {
        let old = prepare_public(request, output).unwrap();
        let old_traces = old.witness(aux).unwrap();
        let end = request.direction().stages() + 1;
        for (old, new) in old_traces[..end].iter().zip(&traces[offset..offset + end]) {
            assert_eq!(old.values, new.values);
        }
        offset += end;
    }
    for (range, trace) in RANGES.into_iter().zip(&traces[offset..]) {
        let total = trace
            .values
            .as_chunks::<2>()
            .0
            .iter()
            .map(|r| r[1].as_canonical_u64())
            .sum::<u64>();
        assert_eq!(total, ([17, 2, 7, 1][range.index()] * DEGREE * 27) as u64);
        if range == RangeKind::R2 {
            assert!(
                trace.values.as_chunks::<2>().0[4..]
                    .iter()
                    .all(|r| r[1] == Val::ZERO)
            );
        }
    }
    assert!(machine.witness(&aux[..1]).is_err());
    assert!(prepare_batch(&requests, &outputs[..1]).is_err());
    assert!(
        prepare_batch(
            &[requests[0].clone(), requests[0].clone()],
            &[outputs[0].clone(), outputs[0].clone()]
        )
        .is_err()
    );
    let mut crossed = aux;
    crossed.swap(0, 1);
    assert!(machine.witness(&crossed).is_err());
}
