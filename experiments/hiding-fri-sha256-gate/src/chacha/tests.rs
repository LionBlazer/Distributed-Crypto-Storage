use p3_air::{BaseAir, check_constraints};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;

use super::air::{ADD, CARRY, ChaChaAir, FEEDFORWARD_CARRY, WIDTH, XOR, schedule_columns};
use super::statement::{Statement, reference_output};
use super::{BITS, HCHACHA_OUTPUT, QUARTER_ROUNDS, SCHEDULE, WORDS};
use crate::backend::{self, AllocationEstimate, Backend, Challenge, Error, TRACE_HEIGHT, Val};
use crate::primitive::{Kind, PrimitiveStatement, PublicStatement};

fn fixtures() -> [Statement; 2] {
    [Statement::hchacha_fixture(), Statement::chacha_fixture()]
}

#[test]
fn public_rfc_and_draft_vectors_match_independent_rustcrypto_and_actual_trace() {
    let expected = [
        [
            0x423b_4182,
            0xfe7b_b227,
            0x5042_0ed3,
            0x737d_878a,
            0xd5e4_f9a0,
            0x53a8_748a,
            0x13c4_2ec1,
            0xdcec_d326,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ],
        [
            0xe4e7_f110,
            0x1559_3bd1,
            0x1fdd_0f50,
            0xc471_20a3,
            0xc7f4_d1c7,
            0x0368_c033,
            0x9aaa_2204,
            0x4e6c_d4c3,
            0x4664_82d2,
            0x09aa_9f07,
            0x05d7_c214,
            0xa202_8bd9,
            0xd19c_12b5,
            0xb94e_16de,
            0xe883_d0cb,
            0x4e3c_50a2,
        ],
    ];
    for (statement, expected) in fixtures().into_iter().zip(expected) {
        assert_eq!(statement.output, expected);
        let trace = statement.trace();
        assert_eq!(claimed_output(&statement, &trace), expected);
        check_constraints(&statement.air(), &trace, &statement.public_values());
    }
}

#[test]
fn full_twenty_rounds_match_the_oracle_for_zero_all_one_and_boundary_words() {
    for fixture in fixtures() {
        for fill in [0, u32::MAX, 0x8000_0001] {
            let mut statement = fixture.clone();
            statement.input[4..].fill(fill);
            if statement.kind == Kind::ChaCha20 {
                statement.input[12] = 1;
            }
            statement.output = reference_output(&statement);
            let trace = statement.trace();
            assert_eq!(claimed_output(&statement, &trace), statement.output);
            check_constraints(&statement.air(), &trace, &statement.public_values());
        }
    }
}

#[test]
fn fixed_schedule_boundary_openings_and_both_security_reports_cover_the_entire_air() {
    let schedule = schedule_columns();
    assert_eq!(schedule.len(), 8);
    for row in 0..TRACE_HEIGHT {
        for (step, column) in schedule.iter().enumerate() {
            assert_eq!(column[row], Val::from_bool(row < 80 && row % 8 == step));
        }
    }
    assert_eq!(SCHEDULE.len() * 10, QUARTER_ROUNDS);
    for statement in fixtures() {
        let air = statement.air();
        assert_eq!(air.width(), 788);
        assert_eq!(air.preprocessed_width(), 0);
        assert_eq!(air.main_next_row_columns(), (0..512).collect::<Vec<_>>());
        assert_eq!(air.num_periodic_columns(), 8);
        let (parameters, report) = backend::analyze(&air).unwrap();
        report.require_target().unwrap();
        assert_eq!(parameters.max_combo, 2);
        assert_eq!(parameters.fri_num_queries, 192);
        assert_eq!(report.constraints, 1492);
        assert_eq!(report.degree, 3);
        assert_eq!(
            report.batched_functions,
            2 * (WIDTH + 5) + report.quotient_chunks * 10 + 10,
        );
    }
    let arrays = AllocationEstimate::for_width(WIDTH);
    assert_eq!(arrays.trace_bytes, 3_227_648);
    assert_eq!(arrays.masked_trace_bytes, 6_496_256);
    assert_eq!(arrays.main_lde_bytes, 51_970_048);
}

#[test]
fn genuine_proofs_bind_the_public_words_kind_request_shape_and_randomization() {
    for statement in fixtures() {
        let backend = Backend::new(&statement).unwrap();
        let mut proof = backend.prove(&statement).unwrap();
        Backend::new(&statement)
            .unwrap()
            .verify(&statement, &proof)
            .unwrap();

        let mut changed = statement.clone();
        changed.request[0] ^= 1;
        assert!(backend.verify(&changed, &proof).is_err());
        assert!(
            Backend::new(&changed)
                .unwrap()
                .verify(&changed, &proof)
                .is_err()
        );
        changed = statement.clone();
        changed.input[4] ^= 1;
        assert!(backend.verify(&changed, &proof).is_err());
        assert!(
            Backend::new(&changed)
                .unwrap()
                .verify(&changed, &proof)
                .is_err()
        );
        changed = statement.clone();
        changed.output[0] ^= 1;
        assert!(backend.verify(&changed, &proof).is_err());
        assert!(
            Backend::new(&changed)
                .unwrap()
                .verify(&changed, &proof)
                .is_err()
        );
        changed = statement.clone();
        changed.kind = if statement.kind == Kind::HChaCha20 {
            Kind::ChaCha20
        } else {
            Kind::HChaCha20
        };
        assert_eq!(backend.verify(&changed, &proof), Err(Error::Shape));
        assert!(
            Backend::new(&changed)
                .unwrap()
                .verify(&changed, &proof)
                .is_err()
        );

        let next = proof.opened_values.trace_next.take().unwrap();
        assert_eq!(next.len(), WIDTH); // SDK 0.8 opens the complete next width.
        assert_eq!(backend.verify(&statement, &proof), Err(Error::Shape));
        proof.opened_values.trace_next = Some(next);
        proof.opened_values.random.as_mut().unwrap()[0] += Challenge::ONE;
        assert!(backend.verify(&statement, &proof).is_err());
    }
}

#[test]
fn rebuilt_proofs_reject_wrong_output_for_the_same_genuine_public_input() {
    for mut statement in fixtures() {
        statement.output[0] ^= 1;
        let trace = statement.trace(); // Does not read claimed output.
        assert_rebuilt_rejected(&statement, trace);
    }
}

#[test]
fn rebuilt_proofs_reject_internal_xor_carry_and_nonboolean_mutations() {
    let statement = Statement::hchacha_fixture();
    let genuine = statement.trace();
    let mut internal = genuine.clone();
    let offset = 37 * WIDTH + XOR + 2 * BITS + 5;
    internal.values[offset] = Val::ONE - internal.values[offset];
    assert_rebuilt_rejected(&statement, internal);

    let mut carry = genuine.clone();
    let offset = (0..QUARTER_ROUNDS)
        .flat_map(|row| (0..4).map(move |operation| row * WIDTH + CARRY + operation))
        .find(|offset| carry.values[*offset] == Val::ONE)
        .expect("public draft fixture exercises an actual overflowing addition");
    carry.values[offset] = Val::ZERO;
    assert_rebuilt_rejected(&statement, carry);

    let mut nonboolean = genuine;
    nonboolean.values[(TRACE_HEIGHT - 1) * WIDTH + 5] = Val::TWO;
    assert_rebuilt_rejected(&statement, nonboolean);
}

#[test]
fn rebuilt_proof_cannot_skip_the_last_quarter_round_even_with_a_matching_false_claim() {
    for mut statement in fixtures() {
        let mut trace = statement.trace();
        let before_last =
            trace.values[(QUARTER_ROUNDS - 1) * WIDTH..(QUARTER_ROUNDS - 1) * WIDTH + ADD].to_vec();
        for row in QUARTER_ROUNDS..TRACE_HEIGHT {
            trace.values[row * WIDTH..row * WIDTH + ADD].copy_from_slice(&before_last);
        }
        // Rebind the false public output AND final feedforward carries to the
        // skipped-round state. Only the enforced round-79 transition exposes it.
        rebind_claim_and_final_carries(&mut statement, &mut trace);
        assert_rebuilt_rejected(&statement, trace);
    }
}

#[test]
fn rebuilt_proofs_enforce_no_hchacha_feedforward_and_normal_chacha_feedforward() {
    let mut hchacha = Statement::hchacha_fixture();
    let trace = hchacha.trace();
    for (output, word) in HCHACHA_OUTPUT.into_iter().enumerate() {
        hchacha.output[output] = hchacha.output[output].wrapping_add(hchacha.input[word]);
    }
    assert_rebuilt_rejected(&hchacha, trace);

    let mut chacha = Statement::chacha_fixture();
    let mut trace = chacha.trace();
    chacha.output = final_state(&trace);
    trace.values[(TRACE_HEIGHT - 1) * WIDTH + FEEDFORWARD_CARRY] =
        Val::ONE - trace.values[(TRACE_HEIGHT - 1) * WIDTH + FEEDFORWARD_CARRY];
    assert_rebuilt_rejected(&chacha, trace);
}

#[test]
fn rebuilt_proof_cannot_replace_a_valid_entire_trace_under_the_original_public_input() {
    let statement = Statement::hchacha_fixture();
    let mut alternate = statement.clone();
    alternate.input[4] = alternate.input[4].swap_bytes();
    alternate.output = reference_output(&alternate);
    let alternate_trace = alternate.trace();
    check_constraints(
        &alternate.air(),
        &alternate_trace,
        &alternate.public_values(),
    );

    assert_rebuilt_rejected(&statement, alternate_trace);
}

fn final_state(trace: &RowMajorMatrix<Val>) -> [u32; WORDS] {
    let last = &trace.values[(TRACE_HEIGHT - 1) * WIDTH..];
    core::array::from_fn(|word| {
        last[word * BITS..(word + 1) * BITS]
            .iter()
            .enumerate()
            .fold(0, |sum, (bit, value)| {
                sum | ((value.as_canonical_u64() as u32) << bit)
            })
    })
}

fn claimed_output(statement: &Statement, trace: &RowMajorMatrix<Val>) -> [u32; WORDS] {
    let state = final_state(trace);
    match statement.kind {
        Kind::HChaCha20 => core::array::from_fn(|word| {
            if word < 8 {
                state[HCHACHA_OUTPUT[word]]
            } else {
                0
            }
        }),
        Kind::ChaCha20 => {
            core::array::from_fn(|word| state[word].wrapping_add(statement.input[word]))
        }
        Kind::Sha256
        | Kind::Poly1305Raw
        | Kind::Poly1305Padded
        | Kind::PairOpening
        | Kind::CanonicalIndexOpening
        | Kind::SelectionOpening
        | Kind::PackedCanonicalIndexOpening
        | Kind::FactorizedPackedCanonicalIndexOpening
        | Kind::StateCertificate
        | Kind::VersionSelection
        | Kind::SelectedEncoding
        | Kind::LockingSelection
        | Kind::VersionLockingSelection
        | Kind::BfvKeyTransform
        | Kind::BfvBasisConvolution
        | Kind::BfvCiphertextFormation
        | Kind::BfvLocalFormation
        | Kind::LockReturnedEncoding
        | Kind::BfvLockReturnedFormation
        | Kind::RegistryLifecycleBootstrap
        | Kind::RegistryLifecycle
        | Kind::RegistryLifecycleEncoding
        | Kind::RegistryBootstrap => {
            unreachable!()
        }
    }
}

fn rebind_claim_and_final_carries(statement: &mut Statement, trace: &mut RowMajorMatrix<Val>) {
    statement.output = claimed_output(statement, trace);
    if statement.kind == Kind::ChaCha20 {
        let state = final_state(trace);
        for (word, value) in state.iter().enumerate() {
            trace.values[(TRACE_HEIGHT - 1) * WIDTH + FEEDFORWARD_CARRY + word] =
                Val::from_bool(value.overflowing_add(statement.input[word]).1);
        }
    }
}

fn assert_rebuilt_rejected(statement: &Statement, trace: RowMajorMatrix<Val>) {
    let backend = Backend::new(statement).unwrap();
    // These are real rebuilt malicious proofs, not altered valid transcripts.
    // Run only after numerical review; SDK debug builds assert malformed traces.
    let result = p3_uni_stark::prove(
        &backend.config,
        &ChaChaAir::new(statement),
        trace,
        &statement.public_values(),
    );
    if let Ok(proof) = result {
        assert!(backend.verify(statement, &proof).is_err());
    }
}
