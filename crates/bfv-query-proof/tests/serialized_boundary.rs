use bfv_query_core::{
    Geometry, HEAD_BYTES, Owner, PublicUpdateEvaluator, QueryContext, RowProjection, SelectedField,
    UnverifiedUpdateOutcome,
};
use bfv_query_proof::{Error, MAX_PROOF_BYTES, Operation, prove, verify};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

struct Fixture {
    input: Vec<u8>,
    output: Vec<u8>,
    proof: Vec<u8>,
}

fn fixture(operation: Operation) -> &'static Fixture {
    static ADD: OnceLock<Fixture> = OnceLock::new();
    static PRODUCT: OnceLock<Fixture> = OnceLock::new();
    let cell = match operation {
        Operation::Addition => &ADD,
        Operation::PublicPolynomialProduct => &PRODUCT,
    };
    cell.get_or_init(|| {
        // Explicitly public fixture, fresh secret key held only in this process.
        // Every real coefficient and the production-strength proof profile remain.
        let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
        let peer = PublicUpdateEvaluator::from_parameters(&setup.update_parameters().unwrap()).unwrap();
        let context = QueryContext::new([7;16], [2;HEAD_BYTES], [3;HEAD_BYTES]);
        let fields = [SelectedField { age:18, amount:20, active:true },
            SelectedField { age:42, amount:30, active:true }];
        let (input, generated) = match operation {
            Operation::Addition => {
                let prepared = owner.prepare_indexed_update_for_experiment(context, &fields, 5).unwrap();
                let input = peer.circuit_request(&prepared.request).unwrap();
                let generated = prove(&input).unwrap();
                verify(&input,generated.output(),generated.proof()).unwrap();
                let response = peer.restore_circuit_output(&prepared.request,generated.output()).unwrap();
                let UnverifiedUpdateOutcome::Values(actual) = owner.decrypt_indexed_update_unverified_for_experiment(prepared.pending,&response).unwrap() else { panic!("public fixture must not overflow"); };
                assert_eq!(actual.rows.iter().map(|row|row.amount).collect::<Vec<_>>(),vec![25,35]);
                (input,generated)
            }
            Operation::PublicPolynomialProduct => {
                let prepared = owner.prepare_exact_select_for_experiment(context, &fields, RowProjection::AgeAmount).unwrap();
                let input = peer.select_circuit_request(&prepared.request).unwrap();
                let generated = prove(&input).unwrap();
                verify(&input,generated.output(),generated.proof()).unwrap();
                let response = peer.restore_select_circuit_output(&prepared.request,generated.output()).unwrap();
                let actual = owner.decrypt_indexed_select_unverified_for_experiment(prepared.pending,&response).unwrap();
                assert_eq!(actual.rows.iter().map(|row|(row.age,row.amount)).collect::<Vec<_>>(),vec![(Some(18),Some(20)),(Some(42),Some(30))]);
                (input,generated)
            }
        };
        let t = generated.timings();
        eprintln!("{operation:?}: encrypted={:?}, prep={:?}, proving+encoding={:?}, prover={:?}, proof={}B",
            t.encrypted_operation,t.public_preprocessing,t.proving_and_encoding,t.total,generated.proof().len());
        Fixture { input, output: generated.output().to_vec(), proof: generated.proof().to_vec() }
    })
}

fn operations() -> [Operation; 2] {
    [Operation::Addition, Operation::PublicPolynomialProduct]
}

#[test]
fn genuine_serialized_full_profile_addition_and_product_check_all_operands() {
    for operation in operations() {
        let f = fixture(operation);
        let checked = verify(&f.input, &f.output, &f.proof).unwrap();
        assert_eq!(checked.operation(), operation);
        assert_eq!(
            checked.input_digest(),
            <[u8; 32]>::from(Sha256::digest(&f.input))
        );
        assert_eq!(
            checked.output_digest(),
            <[u8; 32]>::from(Sha256::digest(&f.output))
        );
        let t = checked.timings();
        eprintln!(
            "{operation:?}: independentprep={:?}, verification={:?}, fullverify={:?}",
            t.public_preprocessing, t.proof_verification, t.total
        );
        assert!(t.total >= t.public_preprocessing + t.proof_verification);
    }
}

#[test]
fn changing_the_final_residue_of_either_operation_invalidates_its_proof() {
    for operation in operations() {
        let f = fixture(operation);
        let mut output = f.output.clone();
        let offset = output.len() - 8;
        let last = u64::from_le_bytes(output[offset..].try_into().unwrap());
        let changed = (last + 1) % bfv_linear_circuit::MODULI[4];
        output[offset..].copy_from_slice(&changed.to_le_bytes());
        assert_eq!(
            verify(&f.input, &output, &f.proof).unwrap_err(),
            Error::Verification
        );
    }
}

#[test]
fn matching_rebound_headers_cannot_replay_either_arithmetic_proof() {
    for operation in operations() {
        let f = fixture(operation);
        let mut input = f.input.clone();
        let mut output = f.output.clone();
        input[8] ^= 1;
        output[8] ^= 1;
        assert_eq!(
            verify(&input, &output, &f.proof).unwrap_err(),
            Error::Verification
        );
    }
}

#[test]
fn changed_trusted_operand_is_rejected_even_when_its_binding_is_unchanged() {
    for operation in operations() {
        let f = fixture(operation);
        let mut input = f.input.clone();
        let offset = input.len() - 8;
        let residue = u64::from_le_bytes(input[offset..].try_into().unwrap());
        input[offset..]
            .copy_from_slice(&((residue + 1) % bfv_linear_circuit::MODULI[4]).to_le_bytes());
        assert_eq!(
            verify(&input, &f.output, &f.proof).unwrap_err(),
            Error::Verification
        );
    }
}

#[test]
fn missing_truncated_corrupt_and_oversized_proof_frames_are_rejected() {
    for operation in operations() {
        let f = fixture(operation);
        let mut corrupt = f.proof.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert_eq!(
            verify(&f.input, &f.output, &[]).unwrap_err(),
            Error::ProofLength
        );
        assert!(verify(&f.input, &f.output, &f.proof[..f.proof.len() - 1]).is_err());
        assert!(verify(&f.input, &f.output, &corrupt).is_err());
        assert_eq!(
            verify(&f.input, &f.output, &vec![0; MAX_PROOF_BYTES + 1]).unwrap_err(),
            Error::ProofLength
        );
    }
}

#[test]
fn trailing_data_omitted_coefficients_and_noncanonical_residues_are_rejected() {
    for operation in operations() {
        let f = fixture(operation);
        let mut proof = f.proof.clone();
        proof.push(0);
        assert_eq!(
            verify(&f.input, &f.output, &proof).unwrap_err(),
            Error::TrailingProofBytes
        );
        assert_eq!(
            verify(&f.input, &f.output[..f.output.len() - 8], &f.proof).unwrap_err(),
            Error::StatementShape
        );
        let mut output = f.output.clone();
        output[40..48].copy_from_slice(&bfv_linear_circuit::MODULI[0].to_le_bytes());
        assert_eq!(
            verify(&f.input, &output, &f.proof).unwrap_err(),
            Error::NonCanonicalResidue
        );
    }
}

#[test]
fn an_addition_proof_cannot_be_used_for_a_product_statement() {
    let addition = fixture(Operation::Addition);
    let product = fixture(Operation::PublicPolynomialProduct);
    assert_eq!(
        verify(&product.input, &product.output, &addition.proof).unwrap_err(),
        Error::ProofEncoding
    );
}

#[test]
fn changed_public_quotient_or_carry_certificate_requires_a_different_valid_proof() {
    let f = fixture(Operation::PublicPolynomialProduct);
    // All edits remain within their canonical public ranges. Alter the final
    // residue's auxiliary quotient/carries: the old serialized proof must fail.
    let last = 8 + (bfv_linear_circuit::COEFFICIENTS - 1) * 12;
    for offset in [last, last + 6, last + 9] {
        let mut proof = f.proof.clone();
        proof[offset] ^= 1;
        assert_eq!(
            verify(&f.input, &f.output, &proof).unwrap_err(),
            Error::Verification
        );
    }
}

#[test]
fn out_of_range_or_truncated_auxiliary_certificates_and_legacy_product_magic_are_rejected() {
    let f = fixture(Operation::PublicPolynomialProduct);
    for offset in [8 + 5, 8 + 8] {
        let mut proof = f.proof.clone();
        proof[offset] |= 0x80;
        assert_eq!(
            verify(&f.input, &f.output, &proof).unwrap_err(),
            Error::NonCanonicalResidue
        );
    }
    let end = 8 + 12 * bfv_linear_circuit::COEFFICIENTS;
    assert_eq!(
        verify(&f.input, &f.output, &f.proof[..end - 1]).unwrap_err(),
        Error::ProofLength
    );
    let mut old = f.proof.clone();
    old[7] = b'1';
    assert_eq!(
        verify(&f.input, &f.output, &old).unwrap_err(),
        Error::ProofEncoding
    );
}
