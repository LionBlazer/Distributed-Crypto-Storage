use super::*;

fn context() -> QueryContext {
    QueryContext::new([7; 16], [2; HEAD_BYTES], [3; HEAD_BYTES])
}
fn fields(amounts: impl IntoIterator<Item = u16>) -> Vec<SelectedField> {
    amounts
        .into_iter()
        .map(|amount| SelectedField {
            age: 18,
            amount,
            active: true,
        })
        .collect()
}
fn evaluate(
    owner: &Owner,
    evaluator: &PublicUpdateEvaluator,
    source: &[SelectedField],
) -> UnverifiedPolynomialAggregate {
    let prepared = owner
        .prepare_polynomial_aggregate(context(), source)
        .unwrap();
    let input = evaluator
        .aggregate_circuit_request(&prepared.request)
        .unwrap();
    let output = bfv_product_circuit::evaluate(&input).unwrap();
    let restored = evaluator
        .restore_aggregate_circuit_output(&prepared.request, &output)
        .unwrap();
    owner
        .decrypt_polynomial_aggregate_unverified(prepared.pending, &restored)
        .unwrap()
}

#[test]
fn original_coefficients_and_fixed_width_convolution_cover_all_ten_extreme_bands() {
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let evaluator =
        PublicUpdateEvaluator::from_parameters(&setup.update_parameters().unwrap()).unwrap();
    let source = fields([u16::MAX; POLYNOMIAL_AGGREGATE_CAPACITY]);
    let prepared = owner
        .prepare_polynomial_aggregate(context(), &source)
        .unwrap();
    let request: Request = decode(&prepared.request).unwrap();
    let original = checked_ciphertext(&request.original, &owner.parameters).unwrap();
    let plaintext = owner.key.try_decrypt(&original).unwrap();
    let coefficients = Vec::<u64>::try_decode(&plaintext, Encoding::poly()).unwrap();
    assert_eq!(
        &coefficients[..2 * POLYNOMIAL_AGGREGATE_CAPACITY],
        &[255; 2 * POLYNOMIAL_AGGREGATE_CAPACITY]
    );
    assert_eq!(
        &coefficients[2 * POLYNOMIAL_AGGREGATE_CAPACITY..3 * POLYNOMIAL_AGGREGATE_CAPACITY],
        &[1; POLYNOMIAL_AGGREGATE_CAPACITY]
    );
    assert!(
        coefficients[3 * POLYNOMIAL_AGGREGATE_CAPACITY..]
            .iter()
            .all(|value| *value == 0)
    );
    let input = evaluator
        .aggregate_circuit_request(&prepared.request)
        .unwrap();
    let output = bfv_product_circuit::evaluate(&input).unwrap();
    let restored = evaluator
        .restore_aggregate_circuit_output(&prepared.request, &output)
        .unwrap();
    let answer = owner
        .decrypt_polynomial_aggregate_unverified(prepared.pending, &restored)
        .unwrap();
    assert_eq!(
        answer,
        UnverifiedPolynomialAggregate {
            count: 2560,
            sum: 167_769_600
        }
    );
}

#[test]
fn partial_bands_preserve_distinct_source_limbs_and_reduce_actual_peer_coefficients() {
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let evaluator =
        PublicUpdateEvaluator::from_parameters(&setup.update_parameters().unwrap()).unwrap();
    for len in [0, 255, 256, 257, 511, 512, 513, 2559, 2560] {
        let source = fields((0..len).map(|slot| {
            let band = slot / WINDOW;
            ((band * 23 + slot % WINDOW) as u16) | (((band * 19 + 7) as u16) << 8)
        }));
        let prepared = owner
            .prepare_polynomial_aggregate(context(), &source)
            .unwrap();
        let request: Request = decode(&prepared.request).unwrap();
        let ciphertext = checked_ciphertext(&request.original, &owner.parameters).unwrap();
        let plaintext = owner.key.try_decrypt(&ciphertext).unwrap();
        let coefficients = Vec::<u64>::try_decode(&plaintext, Encoding::poly()).unwrap();
        for (slot, field) in source.iter().enumerate() {
            assert_eq!(coefficients[slot], u64::from(field.amount & 255));
            assert_eq!(
                coefficients[POLYNOMIAL_AGGREGATE_CAPACITY + slot],
                u64::from(field.amount >> 8)
            );
            assert_eq!(coefficients[2 * POLYNOMIAL_AGGREGATE_CAPACITY + slot], 1);
        }
        let answer = evaluate(&owner, &evaluator, &source);
        assert_eq!(answer.count as usize, len);
        assert_eq!(
            answer.sum,
            source.iter().map(|row| u32::from(row.amount)).sum::<u32>()
        );
    }
    assert_eq!(
        evaluate(&owner, &evaluator, &fields([0; 257])),
        UnverifiedPolynomialAggregate { count: 257, sum: 0 }
    );
}

#[test]
fn decoder_rejects_impossible_partial_counts_limb_bounds_presence_shape_and_raw_tail() {
    let (owner, _) = Owner::generate(Geometry::Rows256).unwrap();
    let source = fields([0; 257]);
    // Independently construct the mathematically valid zero-amount convolution.
    let mut correct = vec![0; DEGREE];
    for row in 0..source.len() {
        for kernel in 0..WINDOW {
            correct[2 * POLYNOMIAL_AGGREGATE_CAPACITY + row + kernel] += 1;
        }
    }
    for (coefficient, value) in [
        (2 * POLYNOMIAL_AGGREGATE_CAPACITY + WINDOW, 255), // pure count, not a band endpoint
        (POLYNOMIAL_AGGREGATE_CAPACITY + 2 * WINDOW - 1, 256), // one-row high limb
        (WINDOW - 1, 65_281),                              // full-band byte bound
        (2 * WINDOW + 1, 1),                               // unused gap after amount support
        (OUTPUT_COEFFICIENTS, 1),
        (DEGREE - 1, 1),
        (WINDOW - 1, PLAINTEXT - 1),
        (2 * POLYNOMIAL_AGGREGATE_CAPACITY + 3 * WINDOW - 1, 1), // empty band
    ] {
        let prepared = owner
            .prepare_polynomial_aggregate(context(), &source)
            .unwrap();
        let mut malformed = correct.clone();
        malformed[coefficient] = value;
        let plaintext =
            Plaintext::try_encode(&malformed, Encoding::poly(), &owner.parameters).unwrap();
        let ciphertext: Ciphertext = owner.key.try_encrypt(&plaintext, &mut rand::rng()).unwrap();
        let response = encode(&Response {
            magic: RESPONSE_MAGIC,
            version: AGGREGATE_VERSION,
            keyset_id: owner.keyset_id,
            context: context(),
            geometry: Geometry::Rows256,
            aggregated: ciphertext.to_bytes(),
        })
        .unwrap();
        assert!(
            matches!(
                owner.decrypt_polynomial_aggregate_unverified(prepared.pending, &response),
                Err(Error::AggregateBounds)
            ),
            "coefficient {coefficient}"
        );
    }
}

#[test]
fn old_wires_wrong_context_geometry_and_sources_over_the_aggregate_capacity_fail_closed() {
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let evaluator =
        PublicUpdateEvaluator::from_parameters(&setup.update_parameters().unwrap()).unwrap();
    let prepared = owner
        .prepare_polynomial_aggregate(context(), &fields([1]))
        .unwrap();
    for mutation in 0..5 {
        let mut request: Request = decode(&prepared.request).unwrap();
        match mutation {
            0 => request.magic = *b"BFVPAGQ1",
            1 => request.version = 1,
            2 => request.geometry = Geometry::Rows16,
            3 => request.keyset_id[0] ^= 1,
            _ => request.context.data_head.clear(),
        }
        let wire = encode(&request).unwrap();
        assert!(evaluator.aggregate_circuit_request(&wire).is_err());
        assert!(evaluator.request_context(&wire).is_err());
    }
    let input = evaluator
        .aggregate_circuit_request(&prepared.request)
        .unwrap();
    let output = bfv_product_circuit::evaluate(&input).unwrap();
    let restored = evaluator
        .restore_aggregate_circuit_output(&prepared.request, &output)
        .unwrap();
    for mutation in 0..5 {
        let pending = owner
            .prepare_polynomial_aggregate(context(), &fields([1]))
            .unwrap()
            .pending;
        let mut response: Response = decode(&restored).unwrap();
        match mutation {
            0 => response.magic = *b"BFVPAGR1",
            1 => response.version = 1,
            2 => response.geometry = Geometry::Rows16,
            3 => response.keyset_id[0] ^= 1,
            _ => response.context = QueryContext::new([8; 16], [2; HEAD_BYTES], [3; HEAD_BYTES]),
        }
        assert!(matches!(
            owner.decrypt_polynomial_aggregate_unverified(pending, &encode(&response).unwrap()),
            Err(Error::BindingMismatch)
        ));
    }
    assert!(matches!(
        owner.prepare_polynomial_aggregate(
            context(),
            &fields(vec![0; POLYNOMIAL_AGGREGATE_CAPACITY + 1])
        ),
        Err(Error::GeometryLimit)
    ));
    assert!(matches!(
        evaluator.aggregate_circuit_request(&vec![0; MAX_AGGREGATE_WIRE + 1]),
        Err(Error::WireLimit)
    ));
    let mut inactive = fields([1]);
    inactive[0].active = false;
    assert!(
        owner
            .prepare_polynomial_aggregate(context(), &inactive)
            .is_err()
    );
}
