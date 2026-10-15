//! Explicit public test fixtures; fresh secret keys remain in memory only.
use super::*;

fn context() -> QueryContext {
    QueryContext::new([19; 16], [2; HEAD_BYTES], [3; HEAD_BYTES])
}
fn fields(count: usize) -> Vec<SelectedField> {
    (0..count)
        .map(|slot| SelectedField {
            age: if slot == 0 { 255 } else { slot as u8 },
            amount: if slot % 2 == 0 { 65535 } else { 256 },
            active: true,
        })
        .collect()
}
fn evaluator(setup: &PublicSetup) -> PublicUpdateEvaluator {
    PublicUpdateEvaluator::from_parameters(&setup.update_parameters().unwrap()).unwrap()
}

#[test]
fn canonical_products_match_actual_upstream_projection_for_both_geometries_and_every_column() {
    for geometry in [Geometry::Rows16, Geometry::Rows256] {
        let (owner, setup) = Owner::generate(geometry).unwrap();
        let peer = evaluator(&setup);
        for projection in [
            RowProjection::Age,
            RowProjection::Amount,
            RowProjection::AgeAmount,
        ] {
            for count in [0, 1, geometry.slots()] {
                let original = fields(count);
                let prepared = owner
                    .prepare_exact_select_for_experiment(context(), &original, projection)
                    .unwrap();

                let canonical = peer.select_circuit_request(&prepared.request).unwrap();
                let computed = bfv_product_circuit::evaluate(&canonical).unwrap();
                let restored = peer
                    .restore_select_circuit_output(&prepared.request, &computed)
                    .unwrap();
                let upstream = peer.evaluate_exact_select(&prepared.request).unwrap();

                assert!(
                    restored == upstream,
                    "Canonical product and upstream ciphertext bytes differ"
                );
                let result = owner
                    .decrypt_indexed_select_unverified_for_experiment(prepared.pending, &restored)
                    .unwrap();
                assert_eq!(result.proof, ProofStatus::Unavailable);
                assert_eq!(result.rows.len(), count);
                for (row, field) in result.rows.iter().zip(original) {
                    assert_eq!(row.age, projection.age().then_some(field.age));
                    assert_eq!(row.amount, projection.amount().then_some(field.amount));
                }
            }
        }
    }
}

#[test]
fn original_fields_are_encrypted_before_projection_and_count_never_changes_public_mask_or_wire_size()
 {
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let peer = evaluator(&setup);
    let mut sizes = Vec::new();
    let mut masks = Vec::new();
    for count in [0, 1, 256] {
        let prepared = owner
            .prepare_exact_select_for_experiment(context(), &fields(count), RowProjection::Age)
            .unwrap();
        sizes.push(prepared.request.len());
        let request: Request = decode(&prepared.request).unwrap();
        assert!(request.mask.is_empty());
        let rows = checked_ciphertext(&request.rows, &owner.parameters).unwrap();
        let plaintext = Zeroizing::new(owner.key.try_decrypt(&rows).unwrap());
        let decoded = Zeroizing::new(Vec::<u64>::try_decode(&plaintext, Encoding::simd()).unwrap());
        if count > 0 {
            // Amount is not requested, but the original encrypted input must retain it.
            assert_eq!(
                (decoded[0], decoded[DEGREE / 2], decoded[VALIDITY_START]),
                (255, 65535, 1)
            );
        }
        let circuit = peer.select_circuit_request(&prepared.request).unwrap();
        masks.push(circuit[40 + bfv_product_circuit::COEFFICIENTS * 8..].to_vec());
    }
    assert!(sizes.windows(2).all(|pair| pair[0] == pair[1]));
    assert!(masks.windows(2).all(|pair| pair[0] == pair[1]));
    // The public mask is fixed over all 256 possible rows, including encrypted padding.
    let mask = public_projection(&owner.parameters, RowProjection::Age).unwrap();
    let slots = Vec::<u64>::try_decode(&mask, Encoding::simd()).unwrap();
    assert!(slots[..MAX_ROWS].iter().all(|value| *value == 1));
    assert!(
        slots[VALIDITY_START..VALIDITY_START + MAX_ROWS]
            .iter()
            .all(|value| *value == 1)
    );
    assert!(
        slots[DEGREE / 2..DEGREE / 2 + MAX_ROWS]
            .iter()
            .all(|value| *value == 0)
    );
}

#[test]
fn private_active_holes_cannot_use_public_projection_and_operation_domains_do_not_mix() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let peer = evaluator(&setup);
    let full = PeerEvaluator::from_public_setup(&setup).unwrap();
    let hole = SelectedField {
        age: 255,
        amount: 65535,
        active: false,
    };
    assert!(matches!(
        owner.prepare_exact_select_for_experiment(context(), &[hole], RowProjection::Age),
        Err(Error::InvalidShape)
    ));
    assert!(matches!(
        owner.prepare_exact_select_for_experiment(context(), &fields(17), RowProjection::Age),
        Err(Error::GeometryLimit)
    ));
    let private = owner
        .prepare_indexed_select_for_experiment(context(), &[hole], RowProjection::AgeAmount)
        .unwrap();
    assert!(peer.select_circuit_request(&private.request).is_err());
    assert!(peer.request_context(&private.request).is_err());
    assert!(peer.evaluate_exact_select(&private.request).is_err());
    let exact = owner
        .prepare_exact_select_for_experiment(context(), &fields(1), RowProjection::AgeAmount)
        .unwrap();
    assert!(
        full.evaluate_indexed_select_for_experiment(&exact.request)
            .is_err()
    );
    let exact_output = peer.evaluate_exact_select(&exact.request).unwrap();
    assert!(matches!(
        owner.decrypt_indexed_select_unverified_for_experiment(private.pending, &exact_output),
        Err(Error::BindingMismatch)
    ));
    let again = owner
        .prepare_exact_select_for_experiment(context(), &fields(1), RowProjection::AgeAmount)
        .unwrap();
    assert_ne!(
        again.ciphertext_payload_bytes().unwrap(),
        exact.ciphertext_payload_bytes().unwrap()
    );
}

#[test]
fn exact_query_and_both_heads_are_bound_even_when_ciphertexts_are_identical() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let peer = evaluator(&setup);
    let prepared = owner
        .prepare_exact_select_for_experiment(context(), &fields(2), RowProjection::AgeAmount)
        .unwrap();
    let output =
        bfv_product_circuit::evaluate(&peer.select_circuit_request(&prepared.request).unwrap())
            .unwrap();
    for fault in 0..7 {
        let mut request: Request = decode(&prepared.request).unwrap();
        match fault {
            0 => request.context.query_id[0] ^= 1,
            1 => request.context.data_head[HEAD_BYTES - 1] ^= 1,
            2 => request.context.index_head[HEAD_BYTES - 1] ^= 1,
            3 => request.projection = RowProjection::Age,
            4 => request.geometry = Geometry::Rows256,
            5 => request.keyset_id[0] ^= 1,
            6 => request.mask.push(1),
            _ => unreachable!(),
        }
        assert!(
            peer.restore_select_circuit_output(&encode(&request).unwrap(), &output)
                .is_err()
        );
    }
}

#[test]
fn malformed_originals_and_metadata_are_rejected_before_conversion_or_restoration() {
    use fhe_math::rq::Representation;
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let peer = evaluator(&setup);
    let prepared = owner
        .prepare_exact_select_for_experiment(context(), &fields(2), RowProjection::AgeAmount)
        .unwrap();
    let honest: Request = decode(&prepared.request).unwrap();
    let fresh = checked_ciphertext(&honest.rows, &owner.parameters).unwrap();
    let explicit = Ciphertext::new(fresh.to_vec(), &owner.parameters).unwrap();
    let mut bad_wires = vec![Vec::new()];
    for component in 0..2 {
        let mut bad = explicit.clone();
        bad[component].change_representation(Representation::PowerBasis);
        bad_wires.push(bad.to_bytes());
    }
    let mut lower = explicit.clone();
    lower.switch_to_level(1).unwrap();
    bad_wires.push(lower.to_bytes());
    bad_wires.push(
        Ciphertext::new(
            vec![fresh[0].clone(), fresh[1].clone(), fresh[1].clone()],
            &owner.parameters,
        )
        .unwrap()
        .to_bytes(),
    );
    for rows in bad_wires {
        let mut request: Request = decode(&prepared.request).unwrap();
        request.rows = rows;
        let wire = encode(&request).unwrap();
        let zeros = vec![0; bfv_product_circuit::COEFFICIENTS];
        let output = bfv_product_circuit::evaluate(
            &bfv_product_circuit::encode_request(Sha256::digest(&wire).into(), &zeros, &zeros)
                .unwrap(),
        )
        .unwrap();
        assert!(peer.evaluate_exact_select(&wire).is_err());
        assert!(peer.request_context(&wire).is_err());
        assert!(peer.select_circuit_request(&wire).is_err());
        assert!(peer.restore_select_circuit_output(&wire, &output).is_err());
    }
    for fault in 0..5 {
        let mut request: Request = decode(&prepared.request).unwrap();
        match fault {
            0 => request.magic[0] ^= 1,
            1 => request.version += 1,
            2 => {
                request.context.data_head.pop();
            }
            3 => {
                request.context.index_head.pop();
            }
            4 => request.operation = Operation::IndexedMaskedSelect,
            _ => unreachable!(),
        }
        assert!(
            peer.select_circuit_request(&encode(&request).unwrap())
                .is_err()
        );
        assert!(peer.request_context(&encode(&request).unwrap()).is_err());
    }
    let mut trailing = prepared.request.clone();
    trailing.push(0);
    assert!(peer.select_circuit_request(&trailing).is_err());
    assert!(
        peer.select_circuit_request(&prepared.request[..prepared.request.len() - 1])
            .is_err()
    );
}
