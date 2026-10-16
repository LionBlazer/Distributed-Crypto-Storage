use core::borrow::{Borrow, BorrowMut};
use p3_air::BaseAir;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::Pcs;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_fri::HidingFriProverError;
use p3_matrix::dense::RowMajorMatrix;
use p3_sha256_air::{NUM_SHA256_COLS, SHA256_IV, Sha256Cols};
use p3_uni_stark::StarkGenericConfig;

use crate::air::CompressionAir;
use crate::backend::{
    self, AllocationEstimate, Backend, Challenge, Error, PROOF_DEGREE_BITS, RANDOM_CODEWORDS,
    TRACE_HEIGHT, Val,
};
use crate::statement::{Statement, reference_output};

#[test]
fn public_compression_matches_independent_oracle_at_word_boundaries() {
    for (block, state) in [
        ([0; 16], SHA256_IV),
        ([u32::MAX; 16], [u32::MAX; 8]),
        (core::array::from_fn(|i| 1 << i), SHA256_IV),
    ] {
        let statement = Statement {
            block,
            state,
            output: reference_output(block, state),
            ..Statement::fixture()
        };
        let trace = CompressionAir::trace(&statement);
        for row in trace.values.as_chunks::<NUM_SHA256_COLS>().0 {
            let columns: &Sha256Cols<Val> = row.as_slice().borrow();
            let output: [u32; 8] = core::array::from_fn(|i| {
                columns.h_out[i]
                    .iter()
                    .enumerate()
                    .fold(0, |word, (bit, value)| {
                        word | ((value.as_canonical_u64() as u32) << bit)
                    })
            });
            assert_eq!(output, statement.output);
        }
    }
}

#[test]
fn final_wrapper_uses_both_security_bounds_and_explicit_public_shape() {
    let statement = Statement::fixture();
    let air = CompressionAir::new(&statement);
    let (parameters, report) = backend::analyze(&air).unwrap();
    report.require_target().unwrap();
    assert_eq!(BaseAir::<Val>::width(&air), 7728);
    assert_eq!(BaseAir::<Val>::preprocessed_width(&air), 0);
    assert!(BaseAir::<Val>::main_next_row_columns(&air).is_empty());
    assert_eq!(parameters.max_combo, 1);
    assert_eq!(report.degree, 3);
    assert_eq!(parameters.fri_num_queries, 192);
    assert_eq!(PROOF_DEGREE_BITS, 10);
    assert_eq!(report.constraints, parameters.num_constraints);
    assert!(report.unique_decoding_bits >= 128);
    assert!(report.list_decoding_bits >= 128);
    let weak = backend::SecurityReport {
        unique_decoding_bits: 127,
        ..report
    };
    assert_eq!(weak.require_target().unwrap_err(), Error::SecurityProfile);
    let weak = backend::SecurityReport {
        list_decoding_bits: 127,
        ..report
    };
    assert_eq!(weak.require_target().unwrap_err(), Error::SecurityProfile);
}

#[test]
fn genuine_proof_binds_input_output_identity_height_and_randomization() {
    let statement = Statement::fixture();
    let backend = Backend::new(&statement).unwrap();

    let mut proof = backend.prove(&statement).unwrap();

    let independent_verifier = Backend::new(&statement).unwrap();
    independent_verifier.verify(&statement, &proof).unwrap();
    let mut wrong_identity = statement.public_values();
    wrong_identity[0] += Val::ONE;
    assert!(
        p3_uni_stark::verify(
            &backend.config,
            &CompressionAir::new(&statement),
            &proof,
            &wrong_identity
        )
        .is_err()
    );
    let exposed = proof.opened_values.trace_local.len()
        + proof
            .opened_values
            .quotient_chunks
            .iter()
            .map(Vec::len)
            .sum::<usize>()
        + proof.opened_values.random.as_ref().unwrap().len();
    let masking = proof
        .opening_proof
        .0
        .iter()
        .flatten()
        .flatten()
        .map(Vec::len)
        .sum::<usize>();
    assert_eq!(backend.report.batched_functions, exposed + masking);
    for changed in [
        Statement {
            request: [0x43; 32],
            ..statement.clone()
        },
        Statement {
            output: [0; 8],
            ..statement.clone()
        },
        Statement {
            block: [0; 16],
            ..statement.clone()
        },
        Statement {
            state: [0; 8],
            ..statement.clone()
        },
    ] {
        assert!(backend.verify(&changed, &proof).is_err());
    }
    proof.degree_bits = usize::MAX;
    assert_eq!(backend.verify(&statement, &proof), Err(Error::Shape));
    proof.degree_bits = PROOF_DEGREE_BITS;
    proof.opened_values.random.as_mut().unwrap()[0] += Challenge::ONE;
    assert!(backend.verify(&statement, &proof).is_err());
}

#[test]
fn adversarial_prover_cannot_change_an_internal_schedule_bit_in_the_last_padding_row() {
    let statement = Statement::fixture();
    let mut trace = CompressionAir::trace(&statement);
    let last = trace
        .values
        .as_chunks_mut::<NUM_SHA256_COLS>()
        .0
        .last_mut()
        .unwrap();
    let columns: &mut Sha256Cols<Val> = last.as_mut_slice().borrow_mut();
    // The wrapper binds w[0..16], input state and output only. This bit is
    // checked by the upstream SHA schedule constraints, not by the wrapper.
    columns.w[16][0] = Val::ONE - columns.w[16][0];

    assert_rebuilt_trace_is_rejected(&statement, trace);
}

#[test]
fn rebuilt_proof_cannot_claim_wrong_output_for_the_same_genuine_input() {
    let mut wrong_claim = Statement::fixture();
    wrong_claim.output[0] ^= 1;
    // The upstream trace generator reads only the block and initial state. Its
    // compression rows therefore contain the true output, not this false claim.
    let genuine_trace = CompressionAir::trace(&wrong_claim);

    assert_rebuilt_trace_is_rejected(&wrong_claim, genuine_trace);
}

#[test]
fn rebuilt_proof_rejects_a_valid_alternate_input_or_state_in_the_last_row() {
    let statement = Statement::fixture();
    let mut changed_input = statement.clone();
    changed_input.block[0] ^= 1;
    let mut changed_state = statement.clone();
    changed_state.state[0] ^= 1;
    for alternate in [changed_input, changed_state] {
        let alternate_row =
            p3_sha256_air::generate_trace_rows::<Val>(vec![alternate.trace_input()], 0);
        // Validate this row against the unwrapped primitive. Rejection below
        // must come from the wrapper's public statement binding, not bad SHA.
        p3_air::check_constraints(&p3_sha256_air::Sha256Air, &alternate_row, &[]);
        let mut trace = CompressionAir::trace(&statement);
        trace.values[(TRACE_HEIGHT - 1) * NUM_SHA256_COLS..].copy_from_slice(&alternate_row.values);

        assert_rebuilt_trace_is_rejected(&statement, trace);
    }
}

fn assert_rebuilt_trace_is_rejected(statement: &Statement, trace: RowMajorMatrix<Val>) {
    let backend = Backend::new(statement).unwrap();
    // Invoke the actual prover under the claimed statement, bypassing the
    // honest generator. No previously valid proof or transcript is replayed.
    // Release mode reaches proof creation; SDK debug builds assert bad traces.
    let result = p3_uni_stark::prove(
        &backend.config,
        &CompressionAir::new(statement),
        trace,
        &statement.public_values(),
    );
    if let Ok(forgery) = result {
        assert!(backend.verify(statement, &forgery).is_err());
    }
}

#[test]
fn pcs_rejects_too_short_masks_and_too_few_random_codewords() {
    let pcs = backend::contract_pcs(RANDOM_CODEWORDS).unwrap();
    let domain =
        <backend::Pcs as Pcs<Challenge, backend::Challenger>>::natural_domain_for_degree(&pcs, 512);
    let result = <backend::Pcs as Pcs<Challenge, backend::Challenger>>::commit(
        &pcs,
        [(domain, RowMajorMatrix::new(vec![Val::ONE; 256], 1))],
    );
    assert!(matches!(
        result,
        Err(HidingFriProverError::HidingBudgetExceeded {
            mask_height: 256,
            ..
        })
    ));

    let pcs = backend::contract_pcs(RANDOM_CODEWORDS - 1).unwrap();
    let domain = <backend::Pcs as Pcs<Challenge, backend::Challenger>>::natural_domain_for_degree(
        &pcs,
        2 * TRACE_HEIGHT,
    );
    let result = <backend::Pcs as Pcs<Challenge, backend::Challenger>>::commit(
        &pcs,
        [(domain, RowMajorMatrix::new(vec![Val::ONE; TRACE_HEIGHT], 1))],
    );
    assert!(matches!(
        result,
        Err(HidingFriProverError::InsufficientRandomCodewords {
            required: 5,
            got: 4
        })
    ));
}

#[test]
fn cloned_private_prover_data_cannot_reuse_the_single_opening_budget() {
    let config = backend::config().unwrap();
    let pcs = config.pcs();
    let domain = <backend::Pcs as Pcs<Challenge, backend::Challenger>>::natural_domain_for_degree(
        pcs,
        2 * TRACE_HEIGHT,
    );
    let (commitment, data) = <backend::Pcs as Pcs<Challenge, backend::Challenger>>::commit(
        pcs,
        [(domain, RowMajorMatrix::new(vec![Val::ONE; TRACE_HEIGHT], 1))],
    )
    .unwrap();
    let cloned = data.clone();
    let mut challenger = config.initialise_challenger();
    challenger.observe(commitment);
    let point: Challenge = challenger.sample_algebra_element();
    <backend::Pcs as Pcs<Challenge, backend::Challenger>>::open(
        pcs,
        vec![(&data, vec![vec![point]]).into()],
        &mut challenger,
    )
    .unwrap();

    let repeated = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        <backend::Pcs as Pcs<Challenge, backend::Challenger>>::open(
            pcs,
            vec![(&cloned, vec![vec![point]]).into()],
            &mut challenger,
        )
    }));

    let panic = repeated
        .err()
        .expect("SDK must reject an already opened private commitment");
    let message = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .unwrap_or("");
    assert!(message.contains("already opened"));
}

#[test]
fn cloned_configuration_forks_the_mask_and_salt_streams() {
    let original = backend::config().unwrap();
    let cloned = original.clone();
    let commit = |config: &backend::Config| {
        let domain =
            <backend::Pcs as Pcs<Challenge, backend::Challenger>>::natural_domain_for_degree(
                config.pcs(),
                2 * TRACE_HEIGHT,
            );
        <backend::Pcs as Pcs<Challenge, backend::Challenger>>::commit(
            config.pcs(),
            [(domain, RowMajorMatrix::new(vec![Val::ONE; TRACE_HEIGHT], 1))],
        )
        .unwrap()
        .0
    };

    assert_ne!(commit(&original), commit(&cloned));
}

#[test]
fn allocation_estimates_name_only_the_arrays_they_actually_count() {
    let estimate = AllocationEstimate::fixed();
    assert_eq!(estimate.trace_bytes, 31_653_888);
    assert_eq!(estimate.masked_trace_bytes, 63_348_736);
    assert_eq!(estimate.main_lde_bytes, 506_789_888);
}
