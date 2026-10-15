use bfv_addition_proof::{Error, MAX_PROOF_BYTES, prove, verify};
use bfv_query_core::{
    Geometry, HEAD_BYTES, Owner, PublicUpdateEvaluator, QueryContext, SelectedField,
};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

struct Fixture {
    input: Vec<u8>,
    output: Vec<u8>,
    proof: Vec<u8>,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        // Explicitly public records, fresh keys only in memory. All failure cases
        // reuse this one genuine full-profile proof; no reduced FRI test settings.
        let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
        let pending = owner
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
        let evaluator =
            PublicUpdateEvaluator::from_parameters(&setup.update_parameters().unwrap()).unwrap();
        let input = evaluator.circuit_request(&pending.request).unwrap();
        let generated = prove(&input).unwrap();
        Fixture {
            input,
            output: generated.output().to_vec(),
            proof: generated.proof().to_vec(),
        }
    })
}

#[test]
fn serialized_real_proof_checks_the_exact_public_ciphertext_arrays() {
    let fixture = fixture();

    let checked = verify(&fixture.input, &fixture.output, &fixture.proof).unwrap();

    assert_eq!(
        checked.input_digest(),
        <[u8; 32]>::from(Sha256::digest(&fixture.input))
    );
    assert_eq!(
        checked.output_digest(),
        <[u8; 32]>::from(Sha256::digest(&fixture.output))
    );
    assert!(checked.timings().total >= checked.timings().public_preprocessing);
}

#[test]
fn missing_truncated_and_corrupted_serialized_proofs_are_rejected() {
    let fixture = fixture();
    let mut corrupted = fixture.proof.clone();
    *corrupted.last_mut().unwrap() ^= 1;

    assert_eq!(
        verify(&fixture.input, &fixture.output, &[]).unwrap_err(),
        Error::ProofLength
    );
    assert!(
        verify(
            &fixture.input,
            &fixture.output,
            &fixture.proof[..fixture.proof.len() - 1]
        )
        .is_err()
    );
    assert!(verify(&fixture.input, &fixture.output, &corrupted).is_err());
}

#[test]
fn trailing_bytes_and_frames_above_the_fixed_cap_are_rejected() {
    let fixture = fixture();
    let mut trailing = fixture.proof.clone();
    trailing.push(0);
    let oversized = vec![0; MAX_PROOF_BYTES + 1];

    assert_eq!(
        verify(&fixture.input, &fixture.output, &trailing).unwrap_err(),
        Error::TrailingProofBytes
    );
    assert_eq!(
        verify(&fixture.input, &fixture.output, &oversized).unwrap_err(),
        Error::ProofLength
    );
}

#[test]
fn changing_the_last_canonical_output_residue_invalidates_the_real_proof() {
    let fixture = fixture();
    let mut output = fixture.output.clone();
    let offset = output.len() - 8;
    let last = u64::from_le_bytes(output[offset..].try_into().unwrap());
    let changed = (last + 1) % bfv_linear_circuit::MODULI[4];
    output[offset..].copy_from_slice(&changed.to_le_bytes());

    assert_eq!(
        verify(&fixture.input, &output, &fixture.proof).unwrap_err(),
        Error::Verification
    );
}

#[test]
fn omitting_output_data_is_rejected_before_any_arithmetic_result_is_accepted() {
    let fixture = fixture();

    let result = verify(
        &fixture.input,
        &fixture.output[..fixture.output.len() - 8],
        &fixture.proof,
    );

    assert_eq!(result.unwrap_err(), Error::StatementShape);
}

#[test]
fn rebinding_both_matching_headers_cannot_replay_an_old_proof() {
    let fixture = fixture();
    let mut input = fixture.input.clone();
    let mut output = fixture.output.clone();
    input[8] ^= 1;
    output[8] ^= 1;

    assert_eq!(
        verify(&input, &output, &fixture.proof).unwrap_err(),
        Error::Verification
    );
}
