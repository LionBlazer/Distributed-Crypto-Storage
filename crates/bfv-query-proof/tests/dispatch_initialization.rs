#![cfg(feature = "runtime-dispatch")]

use bfv_query_core::{
    Geometry, HEAD_BYTES, Owner, PublicUpdateEvaluator, QueryContext, SelectedField,
};
use bfv_query_proof::{backend_kind, compiled_kind, initialize_backend, prove, verify};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn missing_optional_kernels_select_one_linked_backend_for_genuine_proofs() {
    // A separate integration-test executable owns this process-wide initialization.
    let absent = std::env::temp_dir().join(format!(
        "dcs-proof-absent-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    assert_eq!(backend_kind(), compiled_kind());
    assert_eq!(initialize_backend(&absent).unwrap(), compiled_kind());
    assert_eq!(
        initialize_backend(&absent.join("second-call")).unwrap(),
        compiled_kind()
    );

    // Explicitly public fixture; its fresh owner secret never crosses the kernel.
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let peer = PublicUpdateEvaluator::from_parameters(&setup.update_parameters().unwrap()).unwrap();
    let prepared = owner
        .prepare_indexed_update_for_experiment(
            QueryContext::new([7; 16], [2; HEAD_BYTES], [3; HEAD_BYTES]),
            &[SelectedField {
                age: 18,
                amount: 20,
                active: true,
            }],
            5,
        )
        .unwrap();
    let input = peer.circuit_request(&prepared.request).unwrap();

    let generated = prove(&input).unwrap();
    let checked = verify(&input, generated.output(), generated.proof()).unwrap();

    assert!(checked.matches_statement(&input, generated.output()));
    assert_eq!(backend_kind(), compiled_kind());
    let mut changed = input;
    changed[8] ^= 1;
    assert!(!checked.matches_statement(&changed, generated.output()));
}
