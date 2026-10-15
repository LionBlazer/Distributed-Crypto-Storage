use super::*;
use bfv_query_core::{Geometry, QueryContext};

fn context() -> QueryContext {
    QueryContext::new(
        [1; 16],
        [2; bfv_query_core::HEAD_BYTES],
        [3; bfv_query_core::HEAD_BYTES],
    )
}

#[test]
fn genuine_serialized_product_proof_completes_the_actual_generic_byte_projection() {
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let evaluator =
        PublicUpdateEvaluator::from_parameters(&setup.update_parameters().unwrap()).unwrap();
    let prepared = owner
        .prepare_byte_select(
            context(),
            [4; 32],
            b"ALFKI\0Berlin\0\xff",
            &[
                true, true, true, true, true, false, false, false, false, false, false, false,
                false, true,
            ],
        )
        .unwrap();
    let input = evaluator
        .byte_select_circuit_request(&prepared.request)
        .unwrap();
    let generated = bfv_query_proof::prove(&input).unwrap();

    let checked = check(&evaluator, &prepared, generated.output(), generated.proof()).unwrap();

    let selected =
        complete_checked(&owner, &evaluator, prepared, generated.output(), checked).unwrap();
    assert_eq!(selected.bytes(), b"ALFKI\0\0\0\0\0\0\0\0\xff");
    assert_eq!(
        selected.evidence().operation(),
        Operation::PublicPolynomialProduct
    );
}

#[test]
fn changed_output_proof_and_another_prepared_chunk_never_complete() {
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let evaluator =
        PublicUpdateEvaluator::from_parameters(&setup.update_parameters().unwrap()).unwrap();
    let prepared = owner
        .prepare_byte_select(context(), [4; 32], b"abc", &[true; 3])
        .unwrap();
    let input = evaluator
        .byte_select_circuit_request(&prepared.request)
        .unwrap();
    let generated = bfv_query_proof::prove(&input).unwrap();
    let mut output = generated.output().to_vec();
    *output.last_mut().unwrap() ^= 1;
    assert!(check(&evaluator, &prepared, &output, generated.proof()).is_err());
    let mut proof = generated.proof().to_vec();
    let middle = proof.len() / 2;
    proof[middle] ^= 1;
    assert!(check(&evaluator, &prepared, generated.output(), &proof).is_err());
    let checked = check(&evaluator, &prepared, generated.output(), generated.proof()).unwrap();
    let other = owner
        .prepare_byte_select(context(), [5; 32], b"abc", &[true; 3])
        .unwrap();

    let completed = complete_checked(&owner, &evaluator, other, generated.output(), checked);

    assert!(matches!(completed, Err(Error::ComputationProof(_))));
}
