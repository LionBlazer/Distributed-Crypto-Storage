use super::*;

fn context() -> QueryContext {
    QueryContext::new([5; 16], [6; HEAD_BYTES], [7; HEAD_BYTES])
}
fn roles() -> (Owner, PublicUpdateEvaluator) {
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let evaluator =
        PublicUpdateEvaluator::from_parameters(&setup.update_parameters().unwrap()).unwrap();
    (owner, evaluator)
}

#[test]
fn byte_projection_preserves_arbitrary_encoding_and_homomorphically_zeros_unrequested_columns() {
    let (owner, evaluator) = roles();
    // Public fixture: UTF-8, nullable marker, binary bytes and a four-byte integer.
    let original = b"ALFKI\0Alfreds\xC3\xA4\0\x00\xff\x00\x40\x00\x00\x00";
    let project: Vec<_> = (0..original.len())
        .map(|slot| !(5..=16).contains(&slot))
        .collect();
    let prepared = owner
        .prepare_byte_select(context(), [8; 32], original, &project)
        .unwrap();

    let output = evaluator.evaluate_byte_select(&prepared.request).unwrap();

    assert_eq!(
        evaluator.request_context(&prepared.request).unwrap(),
        context()
    );
    let selected = owner
        .decrypt_byte_select_unverified(prepared.pending, &output)
        .unwrap();
    let expected: Vec<_> = original
        .iter()
        .zip(&project)
        .map(|(value, selected)| if *selected { *value } else { 0 })
        .collect();
    assert_eq!(selected.bytes, expected);
    assert_eq!(selected.proof, ProofStatus::Unavailable);
}

#[test]
fn a_full_chunk_can_contain_thousands_of_rows_and_matches_the_canonical_product() {
    let (owner, evaluator) = roles();
    // Public fixed-width fixture: 2,730 three-byte rows, exceeding the old 128-row limit.
    let original: Vec<_> = (0..BYTE_SELECT_CAPACITY).map(|slot| slot as u8).collect();
    let prepared = owner
        .prepare_byte_select(context(), [9; 32], &original, &vec![true; original.len()])
        .unwrap();
    let input = evaluator
        .byte_select_circuit_request(&prepared.request)
        .unwrap();

    let circuit_output = bfv_product_circuit::evaluate(&input).unwrap();

    let restored = evaluator
        .restore_byte_select_circuit_output(&prepared.request, &circuit_output)
        .unwrap();
    assert_eq!(
        restored,
        evaluator.evaluate_byte_select(&prepared.request).unwrap()
    );
    let request: Request = decode(&prepared.request).unwrap();
    let response: Response = decode(&restored).unwrap();
    assert_ne!(
        response.projected, request.original,
        "The guard mask prevents an echo"
    );
    let selected = owner
        .decrypt_byte_select_unverified(prepared.pending, &restored)
        .unwrap();
    assert_eq!(selected.bytes, original);
}

#[test]
fn shape_keyset_and_changed_schema_query_chunk_binding_are_rejected() {
    let (owner, evaluator) = roles();
    assert!(matches!(
        owner.prepare_byte_select(context(), [9; 32], &[1, 2], &[true]),
        Err(Error::GeometryLimit)
    ));
    assert!(matches!(
        owner.prepare_byte_select(
            context(),
            [9; 32],
            &vec![1; BYTE_SELECT_CAPACITY + 1],
            &vec![true; BYTE_SELECT_CAPACITY + 1]
        ),
        Err(Error::GeometryLimit)
    ));
    let prepared = owner
        .prepare_byte_select(context(), [9; 32], &[1, 2], &[true, true])
        .unwrap();
    let input = evaluator
        .byte_select_circuit_request(&prepared.request)
        .unwrap();
    let output = bfv_product_circuit::evaluate(&input).unwrap();
    let mut changed: Request = decode(&prepared.request).unwrap();
    changed.binding[0] ^= 1;
    let changed_wire = encode(&changed).unwrap();
    assert!(matches!(
        evaluator.restore_byte_select_circuit_output(&changed_wire, &output),
        Err(Error::BindingMismatch)
    ));
    let (_, other) = roles();
    assert!(matches!(
        other.byte_select_circuit_request(&prepared.request),
        Err(Error::BindingMismatch)
    ));
    let mut response: Response =
        decode(&evaluator.evaluate_byte_select(&prepared.request).unwrap()).unwrap();
    response.projection[0] = false;
    assert!(matches!(
        owner.decrypt_byte_select_unverified(prepared.pending, &encode(&response).unwrap()),
        Err(Error::BindingMismatch)
    ));
}

#[test]
fn empty_selection_has_real_ciphertext_projection_and_only_zero_decoded_slots() {
    let (owner, evaluator) = roles();
    let prepared = owner
        .prepare_byte_select(context(), [10; 32], &[], &[])
        .unwrap();

    let output = evaluator.evaluate_byte_select(&prepared.request).unwrap();

    let selected = owner
        .decrypt_byte_select_unverified(prepared.pending, &output)
        .unwrap();
    assert_eq!(selected.bytes, Vec::<u8>::new());
}
