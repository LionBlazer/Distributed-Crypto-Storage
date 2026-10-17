//! PUBLIC NONSECRET owning-boundary native equivalence and genuine rebuilt proofs.
use super::{
    air::*,
    statement::*,
    trace::{self, Witness},
    *,
};
use crate::backend::{self, Backend, Val};
use crate::opening::poseidon;
use crate::primitive::{Kind, PublicStatement};
use p3_air::{BaseAir, check_all_constraints, check_constraints};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;

fn fixture() -> (Statement, Witness) {
    public_fixture([Val::from_u8(11); 4], [Val::from_u8(37); 4])
}
fn valid(statement: &Statement, witness: &Witness) -> RowMajorMatrix<Val> {
    Backend::new(statement).unwrap(); // Actual symbolic/hiding floor before trace allocation.
    let trace = witness.trace(statement).unwrap();
    check_constraints(&statement.air(), &trace, &statement.public_values());
    trace
}
fn reject_rebuilt(statement: &Statement, trace: RowMajorMatrix<Val>) {
    assert!(
        !check_all_constraints(
            &statement.air(),
            &trace,
            &statement.public_values(),
            Some(1)
        )
        .is_ok()
    );
    let backend = Backend::new(statement).unwrap();
    // Deliberately bypass the private witness constructor; the real SDK must reject it.
    if let Ok(proof) = p3_uni_stark::prove(
        &backend.config,
        &statement.air(),
        trace,
        &statement.public_values(),
    ) {
        assert!(backend.verify(statement, &proof).is_err());
    }
}
fn row(trace: &RowMajorMatrix<Val>, r: usize) -> &[Val] {
    &trace.values[r * WIDTH..(r + 1) * WIDTH]
}
fn row_mut(trace: &mut RowMajorMatrix<Val>, r: usize) -> &mut [Val] {
    &mut trace.values[r * WIDTH..(r + 1) * WIDTH]
}
fn finish_from(
    trace: &mut RowMajorMatrix<Val>,
    from: usize,
    statement: &Statement,
    witness: &Witness,
) {
    let mut vector = row(trace, from)[VECTOR..VECTOR + N].to_vec();
    let mut cp: [Val; 12] = row(trace, from)[CHECKPOINT..CHECKPOINT + 12]
        .try_into()
        .unwrap();
    for physical in from..TRACE_HEIGHT {
        row_mut(trace, physical).copy_from_slice(&trace::write_row(
            &vector,
            &mut cp,
            witness.salts,
            statement.contexts(),
            physical,
        ));
        trace::advance(&mut vector, physical);
    }
}
fn output_root(
    statement: &mut Statement,
    trace: &RowMajorMatrix<Val>,
    at: usize,
    witness: &Witness,
) {
    statement.transformed = trace::digest(
        statement.contexts()[1],
        witness.salts[1],
        &row(trace, at)[VECTOR..VECTOR + N],
    );
}

#[test]
fn full8192_native_odd_evaluations_match_pinned_dft_in_natural_order() {
    let (statement, witness) = fixture();
    let trace = valid(&statement, &witness);
    let input: Vec<_> = witness.coefficients.iter().copied().map(signed).collect();
    let expected = trace::oracle(&input);
    assert_eq!(
        &row(&trace, OUTPUT_ROW)[VECTOR..VECTOR + N],
        expected.as_slice()
    );
    // Independent direct polynomial values catch bit reversal, sign, twist and normalization.
    for k in [0, 1, 2, 17, 4095, 8191] {
        let x = psi().exp_u64((2 * k + 1) as u64);
        let y = input.iter().rev().fold(Val::ZERO, |sum, a| sum * x + *a);
        assert_eq!(expected[k], y);
    }
}
#[test]
fn zero_and_support_endpoints_open_all_coefficients_including_last() {
    for value in [-20, 0, 20] {
        let (_, fixture) = fixture();
        let witness = Witness::new(vec![value; N], fixture.salts[0], fixture.salts[1]).unwrap();
        let statement = witness.statement(super::fixture_descriptor_for_test());
        let trace = valid(&statement, &witness);
        assert_eq!(
            &row(&trace, OUTPUT_ROW)[..N],
            trace::oracle(&vec![signed(value); N])
        );
    }
}
#[test]
fn genuine_two_root_proof_binds_independently_fixed_setup_and_input_root() {
    let (statement, witness) = fixture();
    let backend = Backend::new(&statement).unwrap();
    let proof = backend
        .prove_with_trace(&statement, || witness.trace(&statement))
        .unwrap();
    verify(&statement.expected, &statement, &proof).unwrap();
    for change in 0..6 {
        let mut changed = statement.clone();
        match change {
            0 => changed.expected.descriptor.database[0] ^= 1,
            1 => changed.expected.descriptor.key_domain[0] ^= 1,
            2 => changed.expected.descriptor.public_setup_digest[31] ^= 1,
            3 => changed.expected.descriptor.key_epoch += 1,
            4 => changed.expected.coefficients[0] += Val::ONE,
            _ => changed.transformed[3] += Val::ONE,
        }
        if change < 5 {
            assert!(changed.require_expected(&statement.expected).is_err());
        }
        // A FRESH backend reaches SDK cryptographic binding, not only lifetime guard.
        assert!(
            Backend::new(&changed)
                .unwrap()
                .verify(&changed, &proof)
                .is_err()
        );
    }
}
#[test]
fn coherent_alternate_last_coefficient_cannot_open_original_input_anchor() {
    let (mut statement, mut witness) = fixture();
    let old = statement.expected.clone();
    witness.coefficients[N - 1] += 1;
    let alternate = witness.statement(old.descriptor.clone());
    assert_ne!(alternate.expected.coefficients, old.coefficients);
    statement.transformed = trace::digest(
        statement.contexts()[1],
        witness.salts[1],
        &trace::oracle(
            &witness
                .coefficients
                .iter()
                .copied()
                .map(signed)
                .collect::<Vec<_>>(),
        ),
    );
    let trace = witness.trace(&statement).unwrap();
    reject_rebuilt(&statement, trace);
}
#[test]
fn rebuilt_plus21_and_minus21_with_real_roots_fail_support_not_replay() {
    for value in [-21, 21] {
        let (base, mut witness) = fixture();
        witness.coefficients[N - 1] = value;
        let statement = witness.statement(base.expected.descriptor);
        reject_rebuilt(&statement, witness.trace(&statement).unwrap());
    }
}
#[test]
fn nonboolean_range_auxiliary_is_rejected_at_raw_sdk_boundary() {
    let (statement, witness) = fixture();
    let mut trace = valid(&statement, &witness);
    row_mut(&mut trace, 1)[RANGE] = Val::from_u8(2);
    reject_rebuilt(&statement, trace);
}
#[test]
fn coherent_wrong_twist_cannot_be_repaired_by_valid_later_stages_and_output_root() {
    let (mut statement, witness) = fixture();
    let mut trace = valid(&statement, &witness);
    row_mut(&mut trace, FIRST_STAGE)[123] += Val::ONE;
    finish_from(&mut trace, FIRST_STAGE, &statement, &witness);
    output_root(&mut statement, &trace, OUTPUT_ROW, &witness);
    reject_rebuilt(&statement, trace);
}
#[test]
fn coherent_wrong_twiddle_with_rebuilt_later_stages_fails() {
    let (mut statement, witness) = fixture();
    let mut trace = valid(&statement, &witness);
    let previous = row(&trace, 210);
    let base = (0..N)
        .step_by(16)
        .find(|base| previous[base + 9] != Val::ZERO)
        .unwrap();
    let a = previous[base + 1];
    let b = previous[base + 9];
    let correct = (psi() * psi()).exp_u64((N / 16) as u64);
    let wrong = correct + Val::ONE;
    row_mut(&mut trace, 211)[base + 1] = a + b * wrong;
    row_mut(&mut trace, 211)[base + 9] = a - b * wrong;
    finish_from(&mut trace, 211, &statement, &witness);
    output_root(&mut statement, &trace, OUTPUT_ROW, &witness);
    reject_rebuilt(&statement, trace);
}
#[test]
fn coherent_omitted_butterfly_stage_fails_even_with_matching_output_commitment() {
    let (mut statement, witness) = fixture();
    let mut trace = valid(&statement, &witness);
    let omitted = row(&trace, 211)[..N].to_vec();
    row_mut(&mut trace, 212)[..N].copy_from_slice(&omitted);
    finish_from(&mut trace, 212, &statement, &witness);
    output_root(&mut statement, &trace, OUTPUT_ROW, &witness);
    reject_rebuilt(&statement, trace);
}
#[test]
fn coherent_wrong_final_order_and_normalization_cannot_certify_other_transform() {
    for order in [true, false] {
        let (mut statement, witness) = fixture();
        let mut trace = valid(&statement, &witness);
        if order {
            row_mut(&mut trace, OUTPUT_ROW).swap(1, 2);
        } else {
            for v in &mut row_mut(&mut trace, OUTPUT_ROW)[..N] {
                *v *= Val::from_usize(N).inverse();
            }
        }
        finish_from(&mut trace, OUTPUT_ROW, &statement, &witness);
        output_root(&mut statement, &trace, OUTPUT_ROW, &witness);
        reject_rebuilt(&statement, trace);
    }
}
#[test]
fn input_and_output_hash_phases_cannot_change_unconsumed_last_coefficient() {
    for output in [false, true] {
        let (mut statement, witness) = fixture();
        let mut trace = valid(&statement, &witness);
        let at = if output { OUTPUT_ROW + 1 } else { 1 };
        row_mut(&mut trace, at)[N - 1] += Val::ONE;
        if !output {
            let shifted: Vec<_> = row(&trace, at)[..N]
                .iter()
                .map(|v| *v + Val::from_u8(20))
                .collect();
            statement.expected.coefficients =
                trace::digest(statement.contexts()[0], witness.salts[0], &shifted);
        }
        finish_from(&mut trace, at, &statement, &witness);
        output_root(
            &mut statement,
            &trace,
            if output { at } else { OUTPUT_ROW },
            &witness,
        );
        reject_rebuilt(&statement, trace);
    }
}
#[test]
fn inactive_gadget_inputs_and_sbox_equations_are_never_disabled() {
    for input in [true, false] {
        let (statement, witness) = fixture();
        let mut trace = valid(&statement, &witness);
        let at = P2 + poseidon::WIDTH; // last input-hash row has ONLY gadget0 active.
        if input {
            let mut false_input = [Val::ZERO; 12];
            false_input[0] = Val::ONE;
            let _ = poseidon::write(
                &mut row_mut(&mut trace, 205)[at..at + poseidon::WIDTH],
                false_input,
            );
        } else {
            row_mut(&mut trace, 205)[at + 12] += Val::ONE;
        }
        reject_rebuilt(&statement, trace);
    }
}
#[test]
fn checkpoint_uses_last_active_gadget_and_salts_and_padding_must_hold() {
    for attack in 0..3 {
        let (statement, witness) = fixture();
        let mut trace = valid(&statement, &witness);
        match attack {
            0 => {
                let wrong = poseidon::write(&mut [Val::ZERO; poseidon::WIDTH], [Val::ZERO; 12]);
                row_mut(&mut trace, 206)[CHECKPOINT..CHECKPOINT + 12].copy_from_slice(&wrong);
                finish_from(&mut trace, 206, &statement, &witness);
            }
            1 => {
                row_mut(&mut trace, 426)[SALTS] += Val::ONE;
            }
            _ => {
                row_mut(&mut trace, 511)[N - 1] += Val::ONE;
            }
        }
        reject_rebuilt(&statement, trace);
    }
}
#[test]
fn independent_salt_changes_do_not_replay_existing_coefficient_or_output_roots() {
    for role in 0..2 {
        let (statement, mut witness) = fixture();
        witness.salts[role][0] += Val::ONE;
        reject_rebuilt(&statement, witness.trace(&statement).unwrap());
    }
}
#[test]
fn exact_public_shape_keeps_hiding_budget_and_old_profiles_distinct() {
    let (statement, _) = fixture();
    let air = statement.air();
    assert_eq!(air.width(), 9932);
    assert_eq!(air.num_public_values(), 33);
    assert_eq!(air.main_next_row_columns().len(), 9932);
    assert_eq!(air.num_periodic_columns(), 512);
    assert_eq!(psi() * psi(), Val::two_adic_generator(13));
    assert_eq!(psi().exp_u64(N as u64), -Val::ONE);
    assert_eq!(psi().exp_u64((2 * N) as u64), Val::ONE);
    let (_, report) = backend::analyze(&air).unwrap();
    report.require_target().unwrap();
    let allocation = backend::AllocationEstimate::for_width(WIDTH);
    assert_eq!(
        (
            allocation.trace_bytes,
            allocation.masked_trace_bytes,
            allocation.main_lde_bytes
        ),
        (40681472, 81403904, 651231232)
    );
    for kind in [
        Kind::SelectedEncoding,
        Kind::StateCertificate,
        Kind::VersionSelection,
        Kind::PackedCanonicalIndexOpening,
        Kind::FactorizedPackedCanonicalIndexOpening,
    ] {
        assert_ne!(
            backend::profile_digest(kind),
            backend::profile_digest(Kind::BfvKeyTransform)
        );
    }
    assert_ne!(psi().as_canonical_u64(), 0);
}
