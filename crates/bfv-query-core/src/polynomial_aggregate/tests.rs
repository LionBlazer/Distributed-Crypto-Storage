use super::*;
fn context() -> QueryContext {
    QueryContext::new([7; 16], [2; HEAD_BYTES], [3; HEAD_BYTES])
}

#[test]
fn original_coefficients_and_convolution_produce_full_unsigned_limb_sums() {
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let evaluator =
        PublicUpdateEvaluator::from_parameters(&setup.update_parameters().unwrap()).unwrap();
    let fields = vec![
        SelectedField {
            age: 255,
            amount: 65535,
            active: true
        };
        MAX_ROWS
    ];
    let prepared = owner
        .prepare_polynomial_aggregate(context(), &fields)
        .unwrap();
    let request: Request = decode(&prepared.request).unwrap();
    let original = checked_ciphertext(&request.original, &owner.parameters).unwrap();
    let plaintext = owner.key.try_decrypt(&original).unwrap();
    let coefficients = Vec::<u64>::try_decode(&plaintext, Encoding::poly()).unwrap();
    assert_eq!(&coefficients[..2 * MAX_ROWS], &[255; 2 * MAX_ROWS]);
    assert_eq!(&coefficients[2 * MAX_ROWS..3 * MAX_ROWS], &[1; MAX_ROWS]);
    assert!(coefficients[3 * MAX_ROWS..].iter().all(|value| *value == 0));
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
            count: 256,
            sum: 16_776_960
        }
    );
}
#[test]
fn empty_and_nonuniform_sources_reduce_without_wrap_and_wrong_geometry_rejects() {
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let evaluator =
        PublicUpdateEvaluator::from_parameters(&setup.update_parameters().unwrap()).unwrap();
    for (amounts, expected) in [(vec![], (0, 0)), (vec![255, 256, 65535], (3, 66046))] {
        let fields: Vec<_> = amounts
            .into_iter()
            .map(|amount| SelectedField {
                age: 18,
                amount,
                active: true,
            })
            .collect();
        let prepared = owner
            .prepare_polynomial_aggregate(context(), &fields)
            .unwrap();
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
        assert_eq!((answer.count, answer.sum), expected);
        let mut request: Request = decode(&prepared.request).unwrap();
        request.geometry = Geometry::Rows16;
        assert!(
            evaluator
                .aggregate_circuit_request(&encode(&request).unwrap())
                .is_err()
        );
    }
    assert!(
        owner
            .prepare_polynomial_aggregate(
                context(),
                &vec![
                    SelectedField {
                        age: 0,
                        amount: 0,
                        active: true
                    };
                    MAX_ROWS + 1
                ]
            )
            .is_err()
    );
    assert!(matches!(
        evaluator.aggregate_circuit_request(&vec![0; MAX_AGGREGATE_WIRE + 1]),
        Err(Error::WireLimit)
    ));
}
