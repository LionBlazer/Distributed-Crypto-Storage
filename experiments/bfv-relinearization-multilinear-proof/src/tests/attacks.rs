//! Real SDK proofs of explicitly weakened or foreign public programs. Each
//! positively verifies with its own AIR/VK before the fixed consumer rejects it.
use super::*;
use bfv_multilinear_stark::{AirSpec, Val, config_for};
use bfv_relinearization_circuit::plonky3::{ArithmeticAir, prepare};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_multi_stark::{
    ProverInstance, ProverInstances, VerifierInstance, VerifierInstances, prove_with_security,
    setup, verify_with_security,
};
use p3_sumcheck::layout::Table;
#[derive(Clone, Copy, Debug)]
enum Attack {
    LastWord,
    Quotient,
    Carry,
    OmittedTerm,
}
struct AlteredAir {
    base: ArithmeticAir,
    skip: core::ops::Range<usize>,
}
impl BaseAir<Val> for AlteredAir {
    fn width(&self) -> usize {
        self.base.width()
    }
    fn preprocessed_width(&self) -> usize {
        self.base.preprocessed_width()
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        self.base.preprocessed_trace()
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn num_public_values(&self) -> usize {
        32
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        self.base.max_constraint_degree()
    }
}
struct Weaken<'a, AB> {
    inner: &'a mut AB,
    assertion: usize,
    skip: core::ops::Range<usize>,
}
impl<AB: AirBuilder<F = Val>> AirBuilder for Weaken<'_, AB> {
    type F = Val;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type MainWindow = AB::MainWindow;
    type PreprocessedWindow = AB::PreprocessedWindow;
    type PublicVar = AB::PublicVar;
    type PeriodicVar = AB::PeriodicVar;
    fn main(&self) -> Self::MainWindow {
        self.inner.main()
    }
    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        self.inner.preprocessed()
    }
    fn is_first_row(&self) -> Self::Expr {
        self.inner.is_first_row()
    }
    fn is_last_row(&self) -> Self::Expr {
        self.inner.is_last_row()
    }
    fn is_transition(&self) -> Self::Expr {
        self.inner.is_transition()
    }
    fn public_values(&self) -> &[Self::PublicVar] {
        self.inner.public_values()
    }
    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.inner.periodic_values()
    }
    fn assert_zero<I: Into<Self::Expr>>(&mut self, value: I) {
        let skip = self.skip.contains(&self.assertion);
        self.assertion += 1;
        if skip {
            self.inner.assert_zero(Self::Expr::ZERO)
        } else {
            self.inner.assert_zero(value)
        }
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for AlteredAir {
    fn eval(&self, b: &mut AB) {
        self.base.eval(&mut Weaken {
            inner: b,
            assertion: 0,
            skip: self.skip.clone(),
        })
    }
}
fn forged(input: &Request, attack: Attack) -> (Output, Aux) {
    let e = evaluate_with_certificate(input).unwrap();
    match attack {
        Attack::LastWord => {
            let mut values = e.output.coefficients().to_vec();
            let i = values.len() - 1;
            values[i] = (values[i] + 1) % input.role().output_moduli().last().unwrap();
            replace_outputs(e, &values)
        }
        Attack::Quotient => {
            let mut a = e.aux.encode();
            match input.role() {
                Role::Embed => {
                    let i = 176 + (DEGREE - 1) * 25 + 10;
                    assert_eq!(a[i], 2);
                    a[i] = 1;
                }
                Role::AccumulateAndAdd => {
                    let i = 176 + (DEGREE - 1) * 260 + 54;
                    let mut old = [0; 8];
                    old[..6].copy_from_slice(&a[i..i + 6]);
                    let q = u64::from_le_bytes(old);
                    a[i..i + 6]
                        .copy_from_slice(&(if q == 0 { 1 } else { q - 1 }).to_le_bytes()[..6]);
                }
            }
            (e.output, decode_aux(&a).unwrap())
        }
        Attack::Carry => {
            let mut a = e.aux.encode();
            a[176 + (DEGREE - 1) * 260 + 60 + 20 * 9 + 4 * 4] ^= 1;
            (e.output, decode_aux(&a).unwrap())
        }
        Attack::OmittedTerm => {
            let mut values = input.input().to_vec();
            for target in 0..5 {
                values[(17 * target + 2) * DEGREE..(17 * target + 3) * DEGREE].fill(0);
            }
            let r = decode_request(
                &encode_request(
                    input.role(),
                    input.binding(),
                    input.keyset_context(),
                    &values,
                )
                .unwrap(),
            )
            .unwrap();
            let result = evaluate_with_certificate(&r).unwrap();
            assert_ne!(e.output.coefficients(), result.output.coefficients());
            rebind_altered_job(input, result)
        }
    }
}
fn genuine_weaker_program_rejects(role: Role, attack: Attack) {
    let input = fixture::request(role, [0x58; 32], [0x59; 32]).unwrap();
    let (output, aux) = forged(&input, attack);
    integer_rejects(&input, &output, &aux);
    let (base, values) = prepare(&input, &output, &aux).unwrap().into_parts();
    let skip = match (role, attack) {
        (Role::Embed, Attack::LastWord) => 25..26,
        (Role::Embed, Attack::Quotient) => 11..12,
        (_, Attack::OmittedTerm) => 1..61,
        _ => 55..61,
    };
    let air = AlteredAir { base, skip };
    let (config, _) = config_for(&[AirSpec::new(&air, 13)], backend::domains()).unwrap();
    let envelope = backend::envelope(&input, &aux);
    let out = output.encode();
    let profile = backend::profile_digest(role);
    let (pk, vk) = setup(
        &config,
        &[&air],
        &mut config.challenger(profile, &envelope, &out),
    )
    .unwrap();
    let instances = ProverInstances::new(vec![ProverInstance::new(
        &air,
        Table::new(RowMajorMatrix::new(vec![Val::ZERO; DEGREE], 1).transpose()),
        &pk,
        &values,
    )]);
    let raw = prove_with_security(
        &config,
        instances,
        0,
        backend::POLICY_BITS,
        &mut config.challenger(profile, &envelope, &out),
    )
    .unwrap();
    let own = VerifierInstances::new(vec![VerifierInstance::new(&air, &vk, 13, &values)]);
    verify_with_security(
        &config,
        own,
        &raw,
        0,
        backend::POLICY_BITS,
        &mut config.challenger(profile, &envelope, &out),
    )
    .unwrap();
    let frame = proof::encode_frame(&input, &aux, &raw).unwrap();
    drop(raw);
    drop(pk);
    drop(vk);
    drop(air);
    assert!(
        verify(&input, &output, &frame).is_err(),
        "accepted {role:?}/{attack:?}"
    );
}
#[test]
fn genuine_weaker_integer_programs_cannot_certify_rebuilt_last_output_or_quotient() {
    for role in roles() {
        for attack in [Attack::LastWord, Attack::Quotient] {
            genuine_weaker_program_rejects(role, attack)
        }
    }
}
#[test]
fn genuine_removed_mac_carry_and_omitted_digit_term_programs_fail_honest_verification() {
    for attack in [Attack::Carry, Attack::OmittedTerm] {
        genuine_weaker_program_rejects(Role::AccumulateAndAdd, attack)
    }
}
#[test]
fn genuine_foreign_complete_public_preprocessing_cannot_supply_the_expected_verifier_key() {
    for role in roles() {
        let input = fixture::request(role, [0x83; 32], [0x84; 32]).unwrap();
        let e = evaluate_with_certificate(&input).unwrap();
        let (_, values) = prepare(&input, &e.output, &e.aux).unwrap().into_parts();
        let mut wrong = input.input().to_vec();
        wrong[DEGREE - 1] = (wrong[DEGREE - 1] + 1) % MODULI[0];
        let foreign = decode_request(
            &encode_request(role, input.binding(), input.keyset_context(), &wrong).unwrap(),
        )
        .unwrap();
        let f = evaluate_with_certificate(&foreign).unwrap();
        let (air, _) = prepare(&foreign, &f.output, &f.aux).unwrap().into_parts();
        let (config, _) = config_for(&[AirSpec::new(&air, 13)], backend::domains()).unwrap();
        // Keep the original complete FS envelope and PV vector while selecting foreign
        // genuine arithmetic/preprocessing. The AIR does not consume the digest PVs.
        let envelope = backend::envelope(&input, &e.aux);
        let out = e.output.encode();
        let profile = backend::profile_digest(role);
        let (pk, vk) = setup(
            &config,
            &[&air],
            &mut config.challenger(profile, &envelope, &out),
        )
        .unwrap();
        let instances = ProverInstances::new(vec![ProverInstance::new(
            &air,
            Table::new(RowMajorMatrix::new(vec![Val::ZERO; DEGREE], 1).transpose()),
            &pk,
            &values,
        )]);
        let raw = prove_with_security(
            &config,
            instances,
            0,
            backend::POLICY_BITS,
            &mut config.challenger(profile, &envelope, &out),
        )
        .unwrap();
        let own = VerifierInstances::new(vec![VerifierInstance::new(&air, &vk, 13, &values)]);
        verify_with_security(
            &config,
            own,
            &raw,
            0,
            backend::POLICY_BITS,
            &mut config.challenger(profile, &envelope, &out),
        )
        .unwrap();
        let frame = proof::encode_frame(&input, &e.aux, &raw).unwrap();
        drop(raw);
        drop(pk);
        drop(vk);
        drop(air);
        assert!(verify(&input, &e.output, &frame).is_err());
    }
}
