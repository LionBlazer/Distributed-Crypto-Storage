//! Real attacker-program proofs must first pass their own actual SDK verifier.
use super::*;
use crate::machine::{self, Machine, ProgramAir};
use backend::{POLICY_BITS, Val};
use limb_range_air::Histogram;
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
    Range,
    Equation,
    ForeignPublic,
}
struct AlteredAir {
    inner: ProgramAir,
    index: usize,
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
    fn max_constraint_degree(&self) -> Option<usize> {
        self.inner.max_constraint_degree()
    }
}
struct AlteredBuilder<'a, AB> {
    inner: &'a mut AB,
    index: usize,
    attack: Attack,
    assertion: usize,
    interaction: usize,
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
        let omit = self.attack == Attack::Equation && self.index == 4 && self.assertion < 8;
        self.assertion += 1;
        if !omit {
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
        let omit = self.attack == Attack::Range && self.index == 0 && self.interaction == 48;
        self.interaction += 1;
        if !omit {
            self.inner.push_interaction(bus, fields, count);
        }
    }
    fn push_local_interaction(
        &mut self,
        tuples: impl IntoIterator<Item = (Vec<Self::Expr>, Count<Self::Expr>)>,
    ) {
        self.inner.push_local_interaction(tuples);
    }
}
impl<AB: InteractionBuilder<F = Val>> Air<AB> for AlteredAir {
    fn eval(&self, b: &mut AB) {
        self.inner.eval(&mut AlteredBuilder {
            inner: b,
            index: self.index,
            attack: self.attack,
            assertion: 0,
            interaction: 0,
        });
    }
}
fn rebuild_counts(traces: &mut [RowMajorMatrix<Val>], attack: Attack, ordinal: usize) {
    let range = statement::component_range(ordinal).unwrap();
    let supports = machine::ranges(ordinal).unwrap();
    let mut histogram = Histogram::new(supports).unwrap();
    for (local, trace) in traces[..range.len()].iter().enumerate() {
        let index = range.start + local;
        for row in trace.values.chunks_exact(trace.width) {
            for (column, value) in row.iter().enumerate() {
                if attack == Attack::Range && index == 0 && column == 48 {
                    continue;
                }
                let range = if (4..14).contains(&index) {
                    tensor::multistark::column_range(column).unwrap()
                } else {
                    scale::multistark::column_range(
                        if index < 4 {
                            scale::Role::Extend5To10
                        } else {
                            scale::Role::Scale10To5
                        },
                        column,
                    )
                    .unwrap()
                };
                histogram.add(range, value.as_canonical_u64()).unwrap();
            }
        }
    }
    for (trace, &support) in traces[range.len()..].iter_mut().zip(supports) {
        *trace = histogram.trace(support).unwrap();
    }
}
fn genuine_attacker(attack: Attack) {
    let honest = &genuine().expected;
    let ordinal = if attack == Attack::Range { 0 } else { 1 };
    let range = statement::component_range(ordinal).unwrap();
    let backend = backend::Backend::new(honest, ordinal).unwrap();
    let source = if attack == Attack::ForeignPublic {
        let mut requests = honest.requests().to_vec();
        requests[4] = changed_request(&requests[4]);
        let (outputs, aux) = proof::evaluate(&requests).unwrap();
        drop(aux);
        Expected::new(honest.context(), requests, outputs).unwrap()
    } else {
        (*honest).clone()
    };
    let (_, aux) = proof::evaluate(&source.requests()[range.clone()]).unwrap();
    let machine = Machine::new(&source, ordinal).unwrap();
    let mut traces = machine.witness(&aux).unwrap();
    drop(aux);
    if attack == Attack::Range {
        let at = 8191 * 160;
        let row = &mut traces[0].values[at..at + 160];
        let before = row[48] + row[104] * Val::from_u32(65536);
        row[48] -= Val::from_u32(65536);
        row[104] += Val::ONE;
        assert_eq!(before, row[48] + row[104] * Val::from_u32(65536));
        assert!(row[48].as_canonical_u64() > 65535);
        assert!(row[104].as_canonical_u64() < 512);
        assert!(p3_air::check_all_constraints(&machine.airs[0], &traces[0], &[], Some(1)).is_ok());
    }
    if attack == Attack::Equation {
        let at = 8191 * 54;
        let value = traces[0].values[at].as_canonical_u64() ^ 1;
        traces[0].values[at] = Val::from_u64(value);
        assert!(value < 65536);
        assert!(!p3_air::check_all_constraints(&machine.airs[0], &traces[0], &[], Some(1)).is_ok());
    }
    rebuild_counts(&mut traces, attack, ordinal);
    let backend::Backend {
        config,
        prover,
        verifier,
        machine: original,
        ..
    } = backend;
    drop(prover);
    drop(verifier);
    drop(original);
    let airs = machine
        .airs
        .into_iter()
        .enumerate()
        .map(|(local, inner)| AlteredAir {
            inner,
            index: range.start + local,
            attack,
        })
        .collect::<Vec<_>>();
    let refs = airs.iter().collect::<Vec<_>>();
    let (key, own) = setup(
        &config,
        &refs,
        &mut backend::challenger(&config, honest, ordinal).unwrap(),
    )
    .unwrap();
    let instances = ProverInstances::new(
        airs.iter()
            .zip(traces)
            .map(|(a, t)| ProverInstance::new(a, Table::new(t.transpose()), &key, &[]))
            .collect(),
    );
    let raw = prove_with_security(
        &config,
        instances,
        0,
        POLICY_BITS,
        &mut backend::challenger(&config, honest, ordinal).unwrap(),
    )
    .unwrap();
    let instances = VerifierInstances::new(
        airs.iter()
            .map(|a| VerifierInstance::new(a, &own, a.inner.height().ilog2() as usize, &[]))
            .collect(),
    );
    // This is mandatory own-verification, not conditional success or debug credit.
    verify_with_security(
        &config,
        instances,
        &raw,
        0,
        POLICY_BITS,
        &mut backend::challenger(&config, honest, ordinal).unwrap(),
    )
    .unwrap();
    let bad = postcard::to_allocvec(&raw).unwrap();
    drop(raw);
    drop(key);
    drop(own);
    drop(airs);
    drop(source);
    drop(config);
    let mut payloads = component_payloads(honest, &genuine().frame);
    payloads[ordinal] = bad;
    let frame = proof::encode_payloads(honest, &payloads).unwrap();
    assert!(
        verify(honest, &frame).is_err(),
        "accepted genuine {attack:?} program"
    );
}
#[test]
fn genuine_removed_range_query_does_not_certify_an_out_of_support_carry() {
    genuine_attacker(Attack::Range);
}
#[test]
fn genuine_removed_tensor_component_equations_do_not_certify_a_canonical_wrong_quotient() {
    genuine_attacker(Attack::Equation);
}
#[test]
fn genuine_foreign_public_preprocessing_cannot_replace_the_independently_rebuilt_union() {
    genuine_attacker(Attack::ForeignPublic);
}
