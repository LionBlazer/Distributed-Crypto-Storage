//! Isolated native Query assembly from supplied PUBLIC V/B and raw FS tape.
//! No original trace, Prepared, witness, key or production proof capability.
mod joint_public_tests;
mod shared_sessions_tests;
mod tape;
mod tests;
pub(super) use tape::TapePlan;

use super::opaque_inputs::{DenseFamily, OpaqueInputs, PrivateInput};
use super::public_deep::{Column, PublicView};
use super::research_config::{self, ChallengeMmcs, Config, Mmcs as ResearchMmcs};
use super::research_ro::{Event, Oracle, Programmer, ResearchChallenger, Walks};
use super::{Expected, public_data};
use bfv_hiding_stark::{Challenge as E, Val as F};
use p3_air::BaseAir;
use p3_batch_stark::proof::OpenedValuesWithLookups;
use p3_batch_stark::{
    BatchCommitments, BatchOpenedValues, BatchProof, BatchProverTranscript, BatchShape,
};
use p3_commit::{Mmcs, OpenedValues as PcsOpenings};
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_fri::{
    BatchMultiOpening, FriProof, PcsProverTranscript, PcsShape, TwoAdicFriFolding,
    TwoAdicFriFoldingForMmcs,
};
use p3_lookup::{Challenges, LogUpGadget, LookupTerminal};
use p3_matrix::{Matrix, bitrev::BitReversibleMatrix, dense::RowMajorMatrix};
use p3_symmetric::MerkleCap;
use p3_uni_stark::{OpenedValues, PreprocessedOpenedValues};
use rand_public_pp::rngs::StdRng;
use std::sync::Arc;

pub(super) type Result<T> = core::result::Result<T, &'static str>;
type Cap = MerkleCap<F, [u8; 32]>;
type PpData = <ResearchMmcs as Mmcs<F>>::ProverData<RowMajorMatrix<F>>;
type NativeFri = FriProof<E, ChallengeMmcs, F, Vec<BatchMultiOpening<F, ResearchMmcs>>>;
const LDE: usize = 32768;
const PP_WIDTH: usize = 545;

struct PublicPp {
    mmcs: ResearchMmcs,
    data: PpData,
    commitment: Cap,
    coefficients: Arc<Vec<Vec<F>>>,
}
impl PublicPp {
    fn new(expected: &Expected, oracle: Oracle, commitment: &Cap) -> Result<Self> {
        // Reconstruct a NORMAL native PP MMCS. Private HidingFriPcsProverData's
        // inner field is deliberately inaccessible; no witness getter is added.
        let program = super::super::public_image::QueryFoldProgram::from_expected(expected)?;
        let coefficients = Arc::new(program.public_pp_coefficients().to_vec());
        drop(program);
        if coefficients.len() != PP_WIDTH || coefficients.iter().any(|p| p.len() > 4096) {
            return Err("Query-public-PP-coefficient-shape");
        }
        let mut values = vec![F::ZERO; LDE * PP_WIDTH];
        for (column, polynomial) in coefficients.iter().enumerate() {
            for (degree, &coefficient) in polynomial.iter().enumerate() {
                values[degree * PP_WIDTH + column] = coefficient;
            }
        }
        let lde = Radix2DitParallel::<F>::default()
            .coset_dft_batch(RowMajorMatrix::new(values, PP_WIDTH), F::GENERATOR)
            .bit_reverse_rows()
            .to_row_major_matrix();
        let mmcs = research_config::mmcs(
            oracle,
            super::hash_setup::research_public_stream(expected, 0),
        );
        let (actual, data) = mmcs.commit(vec![lde]);
        if &actual != commitment {
            return Err("Query-public-PP-native-root-association");
        }
        Ok(Self {
            mmcs,
            data,
            commitment: actual,
            coefficients,
        })
    }
    fn opening(&self, indices: &[usize]) -> BatchMultiOpening<F, ResearchMmcs> {
        let (opened_values, opening_proof) = self.mmcs.open_multi_batch(indices, &self.data);
        BatchMultiOpening {
            opened_values,
            opening_proof,
        }
    }
}

/// One fresh attempt. Consuming prove owns/discards both salt streams and the
/// complete opaque forest on success OR failure. Immutable frames can be cached
/// by their caller, but this object never refreshes a second proof's masks.
pub(super) struct Inputs {
    expected: Expected,
    programmer: Programmer,
    forest: OpaqueInputs,
    opaque_salts: StdRng,
    fri_salts: Option<StdRng>,
    pp: PublicPp,
    shape: BatchShape,
    lookups: Vec<p3_lookup::Lookups<F>>,
}
impl Inputs {
    pub(super) fn new(
        expected: &Expected,
        programmer: Programmer,
        mut opaque_salts: StdRng,
        fri_salts: StdRng,
    ) -> Result<Self> {
        let oracle = programmer.oracle();
        let (air, _, public) = public_data(expected, oracle.clone());
        let common = public.common;
        // Drop the first native public PP prover data before rebuilding it as
        // directly openable native MMCS data. Both use the identical public RNG.
        drop(public.prover_only);
        let global = common
            .preprocessed
            .as_ref()
            .ok_or("Query-public-PP-missing")?;
        let meta = global.instances[0]
            .as_ref()
            .ok_or("Query-public-PP-metadata")?;
        let shape = BatchShape {
            trace_widths: vec![air.width()],
            public_value_counts: vec![air.num_public_values()],
            preprocessed_widths: vec![meta.width],
            has_preprocessed_commitment: true,
            num_lookup_instances: common.lookups.iter().filter(|l| !l.is_empty()).count(),
            lookup_pow_bits: 0,
            has_randomization_commitment: true,
            ood_pow_bits: 0,
        };
        if shape.trace_widths != [416]
            || shape.public_value_counts != [32]
            || shape.preprocessed_widths != [545]
            || shape.num_lookup_instances != 1
            || global.matrix_to_instance != [0]
            || meta.degree_bits != 12
        {
            return Err("Query-native-shape");
        }
        let pp = PublicPp::new(expected, oracle, &global.commitment)?;
        let forest = OpaqueInputs::new(DenseFamily::Query, programmer.clone(), &mut opaque_salts)
            .map_err(|_| "Query-opaque-construction")?;
        Ok(Self {
            expected: expected.clone(),
            programmer,
            forest,
            opaque_salts,
            fri_salts: Some(fri_salts),
            pp,
            shape,
            lookups: common.lookups,
        })
    }
    /// Read-only PUBLIC association data, cheaply owned outside the consuming
    /// Inputs value. This is neither original trace nor private sampler state.
    pub(super) fn public_pp_coefficients(&self) -> Arc<Vec<Vec<F>>> {
        Arc::clone(&self.pp.coefficients)
    }

    pub(super) fn prove(
        mut self,
        plan: TapePlan,
        view: &PublicView<'_>,
        b_coefficients: &[E],
        walks: Walks,
    ) -> Result<BatchProof<Config>> {
        validate_view(&self, &plan, view, b_coefficients)?;
        let pp_opening = self.pp.opening(plan.indices());
        // Exact receiver-owned PP rows, independently opened by genuine native
        // MMCS, are compared before any opaque LEAF programming.
        for (query, &row) in plan.row_for_query.iter().enumerate() {
            if pp_opening.opened_values[query].len() != 1
                || pp_opening.opened_values[query][0].len() != PP_WIDTH
                || view
                    .pp
                    .iter()
                    .zip(&pp_opening.opened_values[query][0])
                    .any(|(column, &value)| column.rows[row] != value)
            {
                return Err("Query-public-PP-row-association");
            }
        }
        let all_openings = all_openings(view);
        let mut padded = b_coefficients.to_vec();
        padded.resize(LDE, E::ZERO);
        let natural = Radix2DitParallel::<F>::default().coset_dft_algebra(padded, F::GENERATOR);
        let b_bit_reversed = (0..LDE)
            .map(|index| natural[index.reverse_bits() >> (usize::BITS - 15)])
            .collect();
        let main = self.forest.commitment(PrivateInput::Main);
        let permutation = self.forest.commitment(PrivateInput::Aux);
        let quotient = self.forest.commitment(PrivateInput::Quotient);
        let random = self.forest.commitment(PrivateInput::Random);
        let mut challenger =
            ResearchChallenger::planter(self.programmer.clone(), plan.tape.clone(), walks.clone());
        let mut batch = BatchProverTranscript::<_, F, E, Cap>::new(&mut challenger, self.shape);
        batch.instance_bindings(&[12]);
        batch.main_phase(main.clone(), &[self.expected.values()]);
        batch.preprocessed_phase(Some(self.pp.commitment.clone()));
        let lookup_refs = self.lookups.iter().map(|l| &**l).collect::<Vec<_>>();
        let (lookup_challenges, lookup_pow) = batch.lookup_phase(&lookup_refs, &LogUpGadget::new());
        let table = Challenges::new(plan.lookup_alpha(), plan.lookup_beta(), 2, 1);
        let expected_challenges = (0..83)
            .flat_map(|_| [table.bus_prefix[0], plan.lookup_beta()])
            .collect::<Vec<_>>();
        if lookup_challenges.len() != 1
            || lookup_challenges[0] != expected_challenges
            || lookup_pow != Some(F::ZERO)
        {
            batch.abort();
            return Err("Query-native-lookup-draw-association");
        }
        if batch.permutation_phase(Some(permutation.clone()), &[E::ZERO]) != plan.constraint_alpha()
        {
            batch.abort();
            return Err("Query-native-alpha-draw-association");
        }
        batch.quotient_phase(quotient.clone(), Some(random.clone()));
        let (z, ood_pow) = batch.ood_phase();
        if z != plan.z() || ood_pow != F::ZERO {
            batch.abort();
            return Err("Query-native-zeta-draw-association");
        }
        let Some(fri_salts) = self.fri_salts.take() else {
            batch.abort();
            return Err("Query-consumed-FRI-salts");
        };
        let params = research_config::fri(self.programmer.oracle(), fri_salts);
        let mut fri = match batch.delegate(|challenger| {
            let mut pcs = PcsProverTranscript::<_, F, E>::new(
                challenger,
                PcsShape::from_opened_values(&params, &all_openings),
            );
            pcs.claimed_openings(&all_openings);
            let (theta, witness) = pcs.batch_phase();
            if theta != plan.theta() || witness.is_some() {
                pcs.abort();
                return Err("Query-native-theta-draw-association");
            }
            let folding: TwoAdicFriFoldingForMmcs<F, ResearchMmcs> =
                TwoAdicFriFolding(core::marker::PhantomData);
            let result = pcs.delegate(|challenger| {
                p3_fri::prover::prove_fri(
                    &folding,
                    &params,
                    vec![b_bit_reversed],
                    challenger,
                    15,
                    &[],
                    &self.pp.mmcs,
                    F::ZERO,
                )
            });
            match result {
                Ok(proof) => {
                    pcs.finish();
                    Ok(proof)
                }
                Err(_) => {
                    pcs.abort();
                    Err("Query-native-FRI-prover")
                }
            }
        }) {
            Ok(proof) => proof,
            Err(error) => {
                batch.abort();
                return Err(error);
            }
        };
        batch.finish();
        // Native SDK performed every FIELD/CAP/SAMPLE/RAW step, including all
        // retries. Confirm the concrete walk consumed exactly the supplied tape.
        let actual = walks.with_draws();
        if actual.len() != 1 {
            return Err("Query-native-walk-count");
        }
        let samples = actual[0]
            .events
            .iter()
            .filter_map(|event| match event {
                Event::Sample { counter, value } => Some((*counter, *value)),
                _ => None,
            })
            .collect::<Vec<_>>();
        if samples.len() != 277
            || samples.iter().enumerate().any(|(i, &(counter, value))| {
                counter != i as u64 || value != plan.accepted()[i].as_canonical_u64()
            })
            || actual[0].draws.len() != plan.tape.len()
            || actual[0]
                .draws
                .iter()
                .any(|draw| plan.tape.get(&(draw.counter, draw.retry)) != Some(&draw.digest))
        {
            return Err("Query-native-complete-tape-association");
        }
        if !fri.input_openings.is_empty() {
            return Err("Query-native-inputs-not-empty-at-fill");
        }
        // Normal FRI hashes were already queried; only now plant exposed opaque
        // INPUT leaves. Shared raw aliases/conflicts remain real fail-closed events.
        let r_rows = private_rows(core::slice::from_ref(&view.r), &plan);
        let main_rows = private_rows(core::slice::from_ref(&view.main), &plan);
        let q_groups = view.quotient.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let q_rows = private_rows(&q_groups, &plan);
        let aux_rows = private_rows(core::slice::from_ref(&view.aux), &plan);
        let r = self
            .forest
            .opening(
                PrivateInput::Random,
                plan.indices(),
                &r_rows,
                &mut self.opaque_salts,
            )
            .map_err(|_| "Query-opaque-R-opening")?;
        let m = self
            .forest
            .opening(
                PrivateInput::Main,
                plan.indices(),
                &main_rows,
                &mut self.opaque_salts,
            )
            .map_err(|_| "Query-opaque-MAIN-opening")?;
        let q = self
            .forest
            .opening(
                PrivateInput::Quotient,
                plan.indices(),
                &q_rows,
                &mut self.opaque_salts,
            )
            .map_err(|_| "Query-opaque-Q-opening")?;
        let a = self
            .forest
            .opening(
                PrivateInput::Aux,
                plan.indices(),
                &aux_rows,
                &mut self.opaque_salts,
            )
            .map_err(|_| "Query-opaque-AUX-opening")?;
        fri.input_openings = vec![r, m, q, pp_opening, a];
        Ok(batch_proof(
            all_openings,
            fri,
            BatchCommitments {
                main,
                permutation: Some(permutation),
                quotient_chunks: quotient,
                random: Some(random),
            },
        ))
    }
}

fn validate_view(inputs: &Inputs, plan: &TapePlan, view: &PublicView<'_>, b: &[E]) -> Result<()> {
    if view.s != plan.positions()
        || view.z != plan.z()
        || view.theta != plan.theta()
        || view.pp_coefficients != inputs.pp.coefficients.as_slice()
        || b.len() > 4095
    {
        return Err("Query-public-V-plan-association");
    }
    if view.z == E::ZERO
        || view.z.exp_u64(2048) == E::ONE
        || (view.z / E::from(F::GENERATOR)).exp_u64(LDE as u64) == E::ONE
    {
        return Err("Query-exceptional-zeta");
    }
    if view.r.len() != 10
        || view.main.len() != 421
        || view.quotient.len() != 8
        || view.quotient.iter().any(|m| m.len() != 10)
        || view.pp.len() != 545
        || view.aux.len() != 425
    {
        return Err("Query-public-V-shape");
    }
    for (columns, next) in [
        (view.r, false),
        (view.main, true),
        (view.pp, false),
        (view.aux, true),
    ]
    .into_iter()
    .chain(view.quotient.iter().map(|m| (m.as_slice(), false)))
    {
        if columns
            .iter()
            .any(|column| column.rows.len() != view.s.len() || column.at_hz.is_some() != next)
        {
            return Err("Query-public-column-shape");
        }
    }
    for (column, polynomial) in view.pp.iter().zip(inputs.pp.coefficients.iter()) {
        let actual = polynomial
            .iter()
            .rev()
            .fold(E::ZERO, |value, &c| value * view.z + c);
        if column.at_z != actual {
            return Err("Query-public-PP-OOD-association");
        }
    }
    Ok(())
}

fn matrix_openings(columns: &[Column], next: bool) -> Vec<Vec<E>> {
    let mut points = vec![columns.iter().map(|column| column.at_z).collect()];
    if next {
        points.push(columns.iter().map(|column| column.at_hz.unwrap()).collect());
    }
    points
}
fn all_openings(view: &PublicView<'_>) -> PcsOpenings<E> {
    vec![
        vec![matrix_openings(view.r, false)],
        vec![matrix_openings(view.main, true)],
        view.quotient
            .iter()
            .map(|columns| matrix_openings(columns, false))
            .collect(),
        vec![matrix_openings(view.pp, false)],
        vec![matrix_openings(view.aux, true)],
    ]
}
fn private_rows(groups: &[&[Column]], plan: &TapePlan) -> Vec<Vec<Vec<F>>> {
    plan.row_for_query
        .iter()
        .map(|&row| {
            groups
                .iter()
                .map(|columns| columns.iter().map(|column| column.rows[row]).collect())
                .collect()
        })
        .collect()
}

fn batch_proof(
    mut opened: PcsOpenings<E>,
    fri: NativeFri,
    commitments: BatchCommitments<Cap>,
) -> BatchProof<Config> {
    // EXACT native HidingFriPcs split:5 random-codeword claims per private
    // [round][matrix][point], zero for PP. R has5 outer +5 wrapper coordinates.
    let wrappers: PcsOpenings<E> = opened
        .iter_mut()
        .enumerate()
        .map(|(round, matrices)| {
            matrices
                .iter_mut()
                .map(|points| {
                    points
                        .iter_mut()
                        .map(|values| {
                            let keep = values.len() - if round == 3 { 0 } else { 5 };
                            values.split_off(keep)
                        })
                        .collect()
                })
                .collect()
        })
        .collect();
    let base = OpenedValues {
        trace_local: opened[1][0][0].clone(),
        trace_next: Some(opened[1][0][1].clone()),
        preprocessed: Some(PreprocessedOpenedValues {
            local: opened[3][0][0].clone(),
            next: None,
        }),
        quotient_chunks: opened[2].iter().map(|points| points[0].clone()).collect(),
        random: Some(opened[0][0][0].clone()),
    };
    BatchProof {
        commitments,
        opened_values: BatchOpenedValues {
            instances: vec![OpenedValuesWithLookups {
                base_opened_values: base,
                permutation_local: opened[4][0][0].clone(),
                permutation_next: opened[4][0][1].clone(),
            }],
        },
        opening_proof: (wrappers, fri),
        lookup_terminals: vec![Some(LookupTerminal(E::ZERO))],
        degree_bits: vec![12],
        lookup_pow_witness: Some(F::ZERO),
        ood_pow_witness: F::ZERO,
    }
}
