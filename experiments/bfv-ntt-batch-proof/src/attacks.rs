//! Genuine proofs under explicitly altered/foreign programs, never trusted verifier APIs.
use super::*;
use bfv_ntt_circuit::multistark::{ProgramAir, TableKind, prepare_batch};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;
use p3_multi_stark::{
    ProverInstance, ProverInstances, VerifierInstance, VerifierInstances, prove_with_security,
    setup, verify_with_security,
};
use p3_sumcheck::layout::Table;
#[derive(Clone, Copy, PartialEq, Eq)]
enum Attack {
    CollapseInstances,
    LastStage,
    Normalization,
    ForeignIo,
}
struct AlteredAir {
    inner: ProgramAir,
    instance: Option<usize>,
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
    skip: bool,
    assertion: usize,
    collapse: bool,
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
        let skip = self.skip && self.assertion < 8;
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
        if self.collapse && bus.starts_with("dcs/bfv-ntt-witness/batch/") {
            let name = format!("adversary/shared/data/{}", bus.rsplit('/').next().unwrap());
            self.inner.push_interaction(&name, fields, count);
        } else {
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
    fn eval(&self, builder: &mut AB) {
        let skip = self.instance == Some(0)
            && matches!(
                (self.attack, self.inner.table_kind()),
                (Attack::LastStage, TableKind::Stage(12))
                    | (Attack::Normalization, TableKind::Stage(13))
            );
        self.inner.eval(&mut AlteredBuilder {
            inner: builder,
            skip,
            assertion: 0,
            collapse: self.attack == Attack::CollapseInstances,
        });
    }
}
fn digits(out: &mut [Val], value: u64) {
    for (i, v) in out.iter_mut().enumerate() {
        *v = Val::from_u16((value >> (16 * i)) as u16);
    }
}
fn histograms(
    machine: &bfv_ntt_circuit::multistark::PreparedBatch,
    traces: &mut [RowMajorMatrix<Val>],
) {
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
    for (table, trace) in machine.shape().tables().iter().zip(traces.iter()) {
        if matches!(table.table().kind(), TableKind::Stage(_)) {
            for row in trace.values.as_chunks::<35>().0 {
                for (r, columns) in columns.iter().enumerate() {
                    for &c in *columns {
                        counts[r][row[c].as_canonical_u64() as usize] += 1;
                    }
                }
            }
        }
    }
    let first_provider = traces.len() - 4;
    for (r, trace) in traces[first_provider..].iter_mut().enumerate() {
        for (j, row) in trace.values.as_chunks_mut::<2>().0.iter_mut().enumerate() {
            row[1] = Val::from_u64(if j < sizes[r] { counts[r][j] } else { 0 });
        }
    }
}
fn genuine_altered_proof_is_rejected(attack: Attack) {
    let context = fixture::context();
    let direction = if attack == Attack::Normalization {
        Direction::Inverse
    } else {
        Direction::Forward
    };
    let specs = vec![
        BatchSpec {
            direction,
            basis: Basis::new(0).unwrap()
        };
        2
    ];
    let requests = fixture::requests(context, &specs).unwrap();
    let evaluations = requests
        .iter()
        .map(|r| evaluate_with_certificate(r).unwrap())
        .collect::<Vec<_>>();
    let original_outputs = evaluations
        .iter()
        .map(|e| e.output.clone())
        .collect::<Vec<_>>();
    let aux = evaluations
        .iter()
        .map(|e| e.aux.clone())
        .collect::<Vec<_>>();
    let mut outputs = original_outputs.clone();
    match attack {
        Attack::CollapseInstances => {
            outputs[0] = fixture::output(&requests[0], original_outputs[1].coefficients()).unwrap();
            outputs[1] = fixture::output(&requests[1], original_outputs[0].coefficients()).unwrap();
            assert_ne!(
                outputs[0].coefficients(),
                original_outputs[0].coefficients()
            );
        }
        Attack::LastStage => {
            let mut v = outputs[0].coefficients().to_vec();
            v[DEGREE - 1] = (v[DEGREE - 1] + 1) % requests[0].basis().modulus();
            outputs[0] = fixture::output(&requests[0], &v).unwrap();
        }
        Attack::Normalization => {
            outputs[0] =
                fixture::output(&requests[0], evaluations[0].aux.stages()[12].coefficients())
                    .unwrap();
            assert_ne!(
                outputs[0].coefficients(),
                original_outputs[0].coefficients()
            );
        }
        _ => {}
    }
    let e = Expected::new(context, requests.clone(), outputs).unwrap();
    let honest = backend::Backend::new(&e, 0).unwrap();
    let mut source = prepare_batch(&requests, &original_outputs).unwrap();
    let mut traces = source.witness(&aux).unwrap();
    if matches!(attack, Attack::LastStage | Attack::Normalization) {
        let stage = direction.stages() - 1;
        for (j, &z) in e.outputs()[0].coefficients().iter().enumerate() {
            let row = &mut traces[stage].values[j * 35..(j + 1) * 35];
            digits(&mut row[8..12], z);
            digits(&mut row[12..16], requests[0].basis().modulus() - 1 - z);
        }
        histograms(&source, &mut traces);
    }
    if attack == Attack::ForeignIo {
        let foreign = requests
            .iter()
            .map(|r| {
                let mut v = r.input().to_vec();
                v[DEGREE - 1] = (v[DEGREE - 1] + 1) % r.basis().modulus();
                decode_request(&encode_request(r.direction(), r.basis(), r.binding(), &v).unwrap())
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let ev = foreign
            .iter()
            .map(|r| evaluate_with_certificate(r).unwrap())
            .collect::<Vec<_>>();
        source = prepare_batch(
            &foreign,
            &ev.iter().map(|x| x.output.clone()).collect::<Vec<_>>(),
        )
        .unwrap();
        traces = source
            .witness(&ev.into_iter().map(|x| x.aux).collect::<Vec<_>>())
            .unwrap();
    }
    let backend::Backend {
        config,
        machine,
        prover,
        verifier,
        ..
    } = honest;
    drop(prover);
    drop(verifier);
    // False-IO programs use the honest claimed IO table, not an unbound output shadow.
    let air_source = if attack == Attack::ForeignIo {
        &source
    } else {
        &machine
    };
    let airs = air_source
        .airs()
        .iter()
        .cloned()
        .zip(air_source.shape().tables())
        .map(|(inner, t)| AlteredAir {
            inner,
            instance: t.instance(),
            attack,
        })
        .collect::<Vec<_>>();
    let refs = airs.iter().collect::<Vec<_>>();
    let (key, wrong_vk) = setup(
        &config,
        &refs,
        &mut backend::challenger(&config, &e, 0).unwrap(),
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
        backend::POLICY_BITS,
        &mut backend::challenger(&config, &e, 0).unwrap(),
    )
    .unwrap();
    let own = VerifierInstances::new(
        airs.iter()
            .map(|a| VerifierInstance::new(a, &wrong_vk, a.inner.height().ilog2() as usize, &[]))
            .collect(),
    );
    let report = bfv_multilinear_stark::assess(&config, &own).unwrap();
    report.require_security(144).unwrap();
    verify_with_security(
        &config,
        own,
        &raw,
        0,
        144,
        &mut backend::challenger(&config, &e, 0).unwrap(),
    )
    .unwrap();
    let frame = proof::encode(&e, std::slice::from_ref(&raw)).unwrap();
    drop(raw);
    drop(key);
    drop(wrong_vk);
    drop(airs);
    drop(source);
    drop(machine);
    assert!(verify(&e, &frame).is_err());
}
#[test]
fn genuine_collapsed_instance_namespaces_do_not_certify_crossed_full_outputs() {
    genuine_altered_proof_is_rejected(Attack::CollapseInstances);
}
#[test]
fn genuine_removed_last_stage_equations_do_not_certify_a_rebuilt_last_coefficient() {
    genuine_altered_proof_is_rejected(Attack::LastStage);
}
#[test]
fn genuine_removed_inverse_normalization_cannot_replace_the_fourteenth_stage() {
    genuine_altered_proof_is_rejected(Attack::Normalization);
}
#[test]
fn genuine_foreign_full_io_preprocessing_cannot_supply_a_verifier_selected_key() {
    genuine_altered_proof_is_rejected(Attack::ForeignIo);
}
