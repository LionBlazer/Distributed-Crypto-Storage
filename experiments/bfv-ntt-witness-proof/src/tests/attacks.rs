//! Genuine SDK proofs of explicitly weakened/foreign programs. These fixtures
//! are test-only adversaries; they never enter the consumer's sealed machine API.
use super::*;
use backend::Val;
use bfv_ntt_circuit::multistark::{ProgramAir, TableKind, prepare_public};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;
use p3_multi_stark::{
    ProverInstance, ProverInstances, VerifierInstance, VerifierInstances, prove_with_security,
    setup, verify_with_security,
};
use p3_sumcheck::layout::Table;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Attack {
    Carry,
    Quotient,
    Range,
    Routing,
    Multiplicity,
    LastButterfly,
    Normalization,
    ForeignIo,
}
struct AlteredAir {
    inner: ProgramAir,
    attack: Attack,
}
impl BaseAir<Val> for AlteredAir {
    fn width(&self) -> usize {
        self.inner.width()
    }
    fn preprocessed_width(&self) -> usize {
        self.inner.preprocessed_width()
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        self.inner.preprocessed_trace()
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn num_public_values(&self) -> usize {
        0
    }
    // No constraint-count hint: the SDK analyzes the actual test adapter.
    fn max_constraint_degree(&self) -> Option<usize> {
        self.inner.max_constraint_degree()
    }
}
struct AlteredBuilder<'a, AB> {
    inner: &'a mut AB,
    attack: Attack,
    kind: TableKind,
    assertion: usize,
    r16: usize,
}
impl<AB: AirBuilder<F = Val>> AirBuilder for AlteredBuilder<'_, AB> {
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
        let skip = match self.kind {
            TableKind::Stage(s) => {
                self.assertion < 8
                    && match self.attack {
                        Attack::Carry | Attack::Quotient => s == 0,
                        Attack::LastButterfly => s == 12,
                        Attack::Normalization => s == 13,
                        _ => false,
                    }
            }
            _ => false,
        };
        self.assertion += 1;
        if !skip {
            self.inner.assert_zero(value);
        }
    }
}
impl<AB: InteractionBuilder<F = Val>> InteractionBuilder for AlteredBuilder<'_, AB> {
    fn push_interaction<E: Into<Self::Expr>>(
        &mut self,
        bus: &str,
        fields: impl IntoIterator<Item = E>,
        count: impl Into<Count<Self::Expr>>,
    ) {
        let mut fields: Vec<Self::Expr> = fields.into_iter().map(Into::into).collect();
        let mut count = count.into();
        if self.attack == Attack::Routing && bus == "dcs/bfv-ntt-witness/data/0" {
            // An attacker removes address binding while keeping all four limbs.
            fields[0] = Self::Expr::ZERO;
        }
        if self.attack == Attack::Multiplicity && bus.starts_with("dcs/bfv-ntt-witness/data/") {
            let (value, weight) = count.into_parts();
            count = Count::bounded(value * Val::from_u8(2), weight * 2);
        }
        if bus == "dcs/bfv-ntt-witness/range/16" {
            if self.attack == Attack::Range && self.kind == TableKind::Stage(0) && self.r16 == 10 {
                count = Count::from(0);
            }
            self.r16 += 1;
        }
        self.inner.push_interaction(bus, fields, count);
    }
    fn push_local_interaction(
        &mut self,
        tuples: impl IntoIterator<Item = (Vec<Self::Expr>, Count<Self::Expr>)>,
    ) {
        self.inner.push_local_interaction(tuples);
    }
}
impl<AB: InteractionBuilder<F = Val>> Air<AB> for AlteredAir {
    fn eval(&self, builder: &mut AB) {
        self.inner.eval(&mut AlteredBuilder {
            inner: builder,
            attack: self.attack,
            kind: self.inner.table_kind(),
            assertion: 0,
            r16: 0,
        });
    }
}
fn digits(row: &mut [Val], value: u64) {
    for (i, x) in row.iter_mut().enumerate() {
        *x = Val::from_u16((value >> (16 * i)) as u16);
    }
}
fn altered_trace(
    input: &Request,
    output: &Output,
    traces: &mut [RowMajorMatrix<Val>],
    attack: Attack,
) {
    let s = input.direction().stages();
    match attack {
        Attack::Carry => {
            let x = &mut traces[0].values[(DEGREE - 1) * 35 + 21];
            *x = Val::from_u64((x.as_canonical_u64() + 1) % 65536);
        }
        Attack::Quotient => {
            let x = &mut traces[0].values[(DEGREE - 1) * 35 + 16];
            *x = Val::from_u64((x.as_canonical_u64() + 1) % 65536);
        }
        Attack::Range => {
            let row = &mut traces[0].values[(DEGREE - 1) * 35..DEGREE * 35];
            let combined = row[21] + Val::from_u64(65536) * row[28];
            assert!(row[28].as_canonical_u64() < 511);
            row[21] -= Val::from_u64(65536);
            row[28] += Val::ONE;
            assert_eq!(row[21] + Val::from_u64(65536) * row[28], combined);
            assert!(row[21].as_canonical_u64() > 65535);
        }
        Attack::LastButterfly | Attack::Normalization => {
            for (j, &z) in output.coefficients().iter().enumerate() {
                let row = &mut traces[s - 1].values[j * 35..(j + 1) * 35];
                digits(&mut row[8..12], z);
                digits(&mut row[12..16], input.basis().modulus() - 1 - z);
            }
        }
        _ => {}
    }
    // Rebuild only lookup histograms for the attacker's committed trace. This is
    // not an NTT oracle; the genuine weak proof must authenticate these columns.
    let columns: [&[usize]; 4] = [
        &[
            8, 9, 10, 12, 13, 14, 16, 17, 18, 19, 21, 22, 23, 24, 25, 26, 27,
        ],
        &[11, 15],
        &[28, 29, 30, 31, 32, 33, 34],
        &[20],
    ];
    let sizes = [65536, 16384, 512, 4];
    let mut counts: Vec<Vec<u64>> = sizes.iter().map(|&n| vec![0; n]).collect();
    for (stage, trace) in traces[..s].iter().enumerate() {
        for row in trace.values.as_chunks::<35>().0 {
            for (r, cols) in columns.iter().enumerate() {
                for &column in *cols {
                    if attack == Attack::Range && stage == 0 && column == 21 {
                        continue;
                    }
                    counts[r][row[column].as_canonical_u64() as usize] += 1;
                }
            }
        }
    }
    for (r, trace) in traces[s + 1..].iter_mut().enumerate() {
        for (j, row) in trace.values.as_chunks_mut::<2>().0.iter_mut().enumerate() {
            row[1] = Val::from_u64(if j < sizes[r] { counts[r][j] } else { 0 });
        }
    }
}
fn genuine_weak_program_is_rejected(attack: Attack) {
    let direction = if attack == Attack::Normalization {
        Direction::Inverse
    } else {
        Direction::Forward
    };
    let input = fixture::request(direction, Basis::new(0).unwrap(), [0x38; 32]).unwrap();
    let evaluation = evaluate_with_certificate(&input).unwrap();
    let original = prepare_public(&input, &evaluation.output).unwrap();
    let mut traces = original.witness(&evaluation.aux).unwrap();
    let routed_output = if attack == Attack::Routing {
        let mut permuted = input.input().to_vec();
        permuted.swap(0, DEGREE - 1);
        assert_ne!(permuted, input.input());
        let permuted = decode_request(
            &encode_request(direction, input.basis(), input.binding(), &permuted).unwrap(),
        )
        .unwrap();
        let e = evaluate_with_certificate(&permuted).unwrap();
        let m = prepare_public(&permuted, &e.output).unwrap();
        traces = m.witness(&e.aux).unwrap();
        Some(fixture::output(&input, e.output.coefficients()).unwrap())
    } else {
        None
    };
    if let Some(out) = &routed_output {
        assert_ne!(out.coefficients(), evaluation.output.coefficients());
    }
    let output = match attack {
        Attack::LastButterfly => {
            let mut values = evaluation.output.coefficients().to_vec();
            values[DEGREE - 1] = (values[DEGREE - 1] + 1) % input.basis().modulus();
            fixture::output(&input, &values).unwrap()
        }
        Attack::Routing => routed_output.unwrap(),
        Attack::Normalization => {
            fixture::output(&input, evaluation.aux.stages()[12].coefficients()).unwrap()
        }
        _ => evaluation.output,
    };
    if attack == Attack::Normalization {
        assert_ne!(output.coefficients(), original_output(&input).as_slice());
    }
    altered_trace(&input, &output, &mut traces, attack);
    let honest = backend::Backend::new(&input, &output).unwrap();
    let backend::Backend {
        config,
        machine,
        prover,
        verifier,
        ..
    } = honest;
    drop(prover);
    drop(verifier);
    if matches!(attack, Attack::Range | Attack::Routing) {
        // The honest local arithmetic equations still hold; only the global
        // range/address argument distinguishes this adversarial witness.
        for (air, trace) in machine.airs().iter().zip(&traces) {
            assert!(p3_air::check_all_constraints(air, trace, &[], Some(1)).is_ok());
        }
    }
    let source = if attack == Attack::ForeignIo {
        let foreign = fixture::request(direction, input.basis(), [0x99; 32]).unwrap();
        let mut bytes = foreign.input().to_vec();
        bytes[DEGREE - 1] = (bytes[DEGREE - 1] + 1) % input.basis().modulus();
        let foreign = decode_request(
            &encode_request(direction, input.basis(), foreign.binding(), &bytes).unwrap(),
        )
        .unwrap();
        let ev = evaluate_with_certificate(&foreign).unwrap();
        let m = prepare_public(&foreign, &ev.output).unwrap();
        traces = m.witness(&ev.aux).unwrap();
        m
    } else {
        machine
    };
    let airs: Vec<_> = source
        .airs()
        .iter()
        .cloned()
        .map(|inner| AlteredAir { inner, attack })
        .collect();
    let refs = airs.iter().collect::<Vec<_>>();
    let (key, wrong_verifier) = setup(
        &config,
        &refs,
        &mut config.challenger(
            backend::profile_digest(input.direction(), input.basis()),
            &input.encode(),
            &output.encode(),
        ),
    )
    .unwrap();
    let instances = ProverInstances::new(
        airs.iter()
            .zip(traces)
            .map(|(a, t)| ProverInstance::new(a, Table::new(t.transpose()), &key, &[]))
            .collect(),
    );
    // This is a genuine, fully analyzed SDK proof under the attacker's program,
    // with rebuilt preprocessing and an honest complete request/output FS seed.
    let raw = prove_with_security(
        &config,
        instances,
        0,
        backend::POLICY_BITS,
        &mut config.challenger(
            backend::profile_digest(input.direction(), input.basis()),
            &input.encode(),
            &output.encode(),
        ),
    )
    .unwrap();
    let own_instances = VerifierInstances::new(
        airs.iter()
            .map(|a| {
                VerifierInstance::new(a, &wrong_verifier, a.inner.height().ilog2() as usize, &[])
            })
            .collect(),
    );
    verify_with_security(
        &config,
        own_instances,
        &raw,
        0,
        backend::POLICY_BITS,
        &mut config.challenger(
            backend::profile_digest(input.direction(), input.basis()),
            &input.encode(),
            &output.encode(),
        ),
    )
    .unwrap();
    let frame = proof::encode_frame(&input, &output, &raw).unwrap();
    drop(raw);
    drop(key);
    drop(wrong_verifier);
    drop(source);
    drop(airs);
    assert!(
        verify(&input, &output, &frame).is_err(),
        "accepted {attack:?}"
    );
}
fn original_output(input: &Request) -> Vec<u64> {
    evaluate_with_certificate(input)
        .unwrap()
        .output
        .coefficients()
        .to_vec()
}
#[test]
fn genuine_prover_selected_quotient_and_carry_programs_do_not_replace_integer_constraints() {
    for attack in [Attack::Carry, Attack::Quotient] {
        genuine_weak_program_is_rejected(attack);
    }
}
#[test]
fn genuine_removed_range_query_cannot_hide_a_negative_carry_digit() {
    genuine_weak_program_is_rejected(Attack::Range);
}
#[test]
fn genuine_unaddressed_routes_and_doubled_data_multiplicities_are_not_the_fixed_machine() {
    for attack in [Attack::Routing, Attack::Multiplicity] {
        genuine_weak_program_is_rejected(attack);
    }
}
#[test]
fn genuine_omitted_last_butterfly_and_inverse_normalization_do_not_certify_rebuilt_output() {
    for attack in [Attack::LastButterfly, Attack::Normalization] {
        genuine_weak_program_is_rejected(attack);
    }
}
#[test]
fn genuine_foreign_complete_io_preprocessing_cannot_supply_the_verifiers_key() {
    genuine_weak_program_is_rejected(Attack::ForeignIo);
}
