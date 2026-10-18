//! PUBLIC NONSECRET codec examples. These tests do not manufacture proof acceptance.
use super::*;

#[test]
fn exact_public_response_decodes_with_original_owner_and_rejects_changed_context_or_key() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let context = QueryContext::new([7; 16], [8; 112], [9; 112]);
    let fields = [SelectedField {
        age: 255,
        amount: 65535,
        active: true,
    }];
    let prepared = owner
        .prepare_exact_select_for_experiment(context.clone(), &fields, RowProjection::Amount)
        .unwrap();
    let parameters = setup.update_parameters().unwrap();
    let evaluator = PublicUpdateEvaluator::from_parameters(&parameters).unwrap();
    let canonical = evaluator.select_circuit_request(&prepared.request).unwrap();
    let output = bfv_product_circuit::evaluate(&canonical).unwrap();
    let response = evaluator
        .restore_select_circuit_output(&prepared.request, &output)
        .unwrap();

    let slots = owner
        .decrypt_public_select_unverified_for_experiment(&prepared.request, &response)
        .unwrap();
    let mut expected = vec![0; DEGREE];
    expected[DEGREE / 2] = 65535;
    expected[VALIDITY_START] = 1;
    assert_eq!(slots, expected);

    let mut wrong: Response = decode(&response).unwrap();
    wrong.context = QueryContext::new([6; 16], [8; 112], [9; 112]);
    assert!(
        owner
            .decrypt_public_select_unverified_for_experiment(
                &prepared.request,
                &encode(&wrong).unwrap(),
            )
            .is_err()
    );
    let (foreign, _) = Owner::generate(Geometry::Rows16).unwrap();
    assert!(
        foreign
            .decrypt_public_select_unverified_for_experiment(&prepared.request, &response,)
            .is_err()
    );
    assert!(
        owner
            .decrypt_public_select_unverified_for_experiment(
                &prepared.request,
                &vec![0; MAX_PUBLIC_SELECT_CIPHERTEXT_BYTES + 513],
            )
            .is_err()
    );
}
