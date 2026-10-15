//! Separate process: exercise application startup selection before any proof call.
use bfv_query_core::{
    Geometry, HEAD_BYTES, Owner, PublicUpdateEvaluator, QueryContext, SelectedField,
};
use bfv_query_proof::{backend_kind, initialize_backend, prove, verify};
use proof_acceleration::Kernel;
use std::path::PathBuf;

#[test]
#[ignore = "requires kernels built by dcs-launch; set DCS_TEST_KERNEL_DIR"]
fn startup_retains_the_supported_backend_for_genuine_proofs() {
    let directory =
        PathBuf::from(std::env::var_os("DCS_TEST_KERNEL_DIR").expect("set DCS_TEST_KERNEL_DIR"));
    let expected = Kernel::select(&directory)
        .unwrap()
        .expect("installed SIMD kernel")
        .kind();
    assert_eq!(initialize_backend(&directory).unwrap(), expected);
    assert_eq!(backend_kind(), expected);
    // Once selected, a subsequent caller cannot replace the backend or cause
    // another directory/CPU search by passing a different installation path.
    assert_eq!(
        initialize_backend(&directory.join("not-an-installation")).unwrap(),
        expected
    );

    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let peer = PublicUpdateEvaluator::from_parameters(&setup.update_parameters().unwrap()).unwrap();
    let context = QueryContext::new([7; 16], [2; HEAD_BYTES], [3; HEAD_BYTES]);
    let prepared = owner
        .prepare_indexed_update_for_experiment(
            context,
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
    assert_eq!(backend_kind(), expected);
    eprintln!("startup selected {expected}; genuine proof and verification completed");
}
