//! Owning SourceVersion public image arithmetic, cfg(test) only.
//! Actual OpeningAir + genuine periodic512; the fold creates no witness/proof/RNG.
mod domain;
mod tests;

use super::SourceVersionExpected;
use bfv_hiding_stark::{Challenge as E, Val as F};
use domain::{DisclosureDomain, PublicResidues};
use p3_air::symbolic::{
    AirLayout, BaseEntry, BaseLeaf, SymbolicAirBuilder, SymbolicExpr, SymbolicExpression,
};
use p3_air::{Air, BaseAir};
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_matrix::Matrix;
use proof_research_support::ring::{self, Poly, Result, Ring, Tensor};
use std::collections::{HashMap, HashSet};

type BaseExpr = SymbolicExpression<F>;
const N: usize = bfv_hiding_stark::TRACE_HEIGHT;
const MAIN: usize = crate::source::layout::PACKED_WIDTH;
const PUBLIC: usize = crate::source::statement::PUBLIC_VALUES;
const INPUT_HEIGHT: usize =
    1 << (bfv_hiding_stark::PROOF_DEGREE_BITS + bfv_hiding_stark::LOG_BLOWUP);

struct SourceFoldProgram {
    base: Vec<BaseExpr>,
    public: Vec<F>,
    periodic: Vec<Poly>,
    node_count: usize,
}
impl SourceFoldProgram {
    fn from_expected(expected: &SourceVersionExpected) -> Result<Self> {
        // Existing private owning helper assesses the actual full Source AIR,
        // StateCertificate relation and native sixteen-chunk hiding profile.
        let air = super::air(expected).map_err(|_| "Source-owning-prescreen")?;
        if (N, MAIN, PUBLIC, INPUT_HEIGHT, bfv_hiding_stark::QUERIES) != (512, 7161, 691, 8192, 192)
            || (
                air.width(),
                air.num_public_values(),
                air.preprocessed_width(),
                air.num_periodic_columns(),
            ) != (MAIN, PUBLIC, 0, N)
            || air.main_next_row_columns() != (0..MAIN).collect::<Vec<_>>()
            || !air.preprocessed_next_row_columns().is_empty()
            || !air.public_boundary_io().is_empty()
        {
            return Err("Source-owning-AIR-shape");
        }
        let u = E::from_basis_coefficients_fn(|i| F::from_bool(i == 1));
        if u.exp_u64(5) != E::from_u32(3) {
            return Err("Source-EF5-fixed-basis");
        }
        let mut builder = SymbolicAirBuilder::<F, E>::new(AirLayout::from_air(&air));
        air.eval(&mut builder);
        let base = builder.base_constraints();
        let layout = builder.constraint_layout();
        if base.is_empty()
            || !builder.extension_constraints().is_empty()
            || !layout.ext_indices.is_empty()
            || !layout.base_indices.iter().copied().eq(0..base.len())
        {
            return Err("Source-base-emission-order");
        }
        // Count THIS live source graph, not a guessed constraint/cache cap
        // copied from another AIR. Retained roots keep every Arc child alive.
        let node_count = count_nodes(&base);
        let declared = air.periodic_columns();
        if declared.len() != N
            || declared.iter().enumerate().any(|(column, values)| {
                values.len() != N
                    || values
                        .iter()
                        .enumerate()
                        .any(|(row, value)| *value != F::from_bool(row == column))
            })
        {
            return Err("Source-owning-periodic-schedule");
        }
        let matrix = air
            .periodic_columns_matrix()
            .ok_or("Source-periodic-matrix")?;
        if (matrix.height(), matrix.width()) != (N, N) {
            return Err("Source-periodic-matrix-shape");
        }
        // Periodic AIR logic is interpolated over ORIGINAL H512. Unlike PP,
        // these columns must NOT be zero-interleaved to the hiding degree1024.
        let coefficients = Radix2DitParallel::<F>::default()
            .idft_batch(matrix)
            .to_row_major_matrix();
        let periodic = (0..N)
            .map(|column| {
                ring::trim(
                    (0..N)
                        .map(|row| coefficients.values[row * N + column])
                        .collect(),
                )
            })
            .collect();
        let public = expected.statement().values();
        if public.len() != PUBLIC {
            return Err("Source-complete-public-width");
        }
        eprintln!(
            "source_public_image constraints={} source_nodes={node_count} periodic_columns={N} periodic_rows={N} PP=0 public_only=true proof=false",
            base.len()
        );
        Ok(Self {
            base,
            public,
            periodic,
            node_count,
        })
    }

    fn fold(
        &self,
        domain: &DisclosureDomain,
        input: &PublicResidues,
        alpha: E,
    ) -> Result<QuotientResidues> {
        if input.source_modulus != domain.enlarged.modulus() {
            return Err("Source-residue-domain-association");
        }
        let environment = Environment::new(self, domain, input)?;
        let ring = &domain.target;
        let mut evaluator = Evaluator {
            ring,
            environment: &environment,
            cache: HashMap::new(),
            limit: self.node_count,
        };
        let mut folded = ring.zero_tensor();
        for constraint in &self.base {
            let value = ring.lift(&evaluator.base(constraint)?);
            folded = ring.tensor_add(&ring.tensor_scale(&folded, alpha), &value);
        }
        let coordinates =
            core::array::from_fn(|i| ring.multiply(&folded[i], &environment.inverse_vanishing));
        Ok(QuotientResidues {
            expected_public: self.public.clone(),
            modulus: ring.modulus().to_vec(),
            coordinates,
            constraint_count: self.base.len(),
            cached_nodes: evaluator.cache.len(),
        })
    }
}

fn count_nodes(roots: &[BaseExpr]) -> usize {
    let mut seen = HashSet::new();
    let mut pending = roots.iter().collect::<Vec<_>>();
    while let Some(expression) = pending.pop() {
        if !seen.insert(core::ptr::from_ref(expression)) {
            continue;
        }
        match expression {
            SymbolicExpr::Leaf(_) => {}
            SymbolicExpr::Add { x, y, .. }
            | SymbolicExpr::Sub { x, y, .. }
            | SymbolicExpr::Mul { x, y, .. } => {
                pending.push(x);
                pending.push(y);
            }
            SymbolicExpr::Neg { x, .. } => pending.push(x),
        }
    }
    seen.len()
}

struct QuotientResidues {
    expected_public: Vec<F>,
    modulus: Poly,
    coordinates: Tensor,
    constraint_count: usize,
    cached_nodes: usize,
}
impl QuotientResidues {
    fn require_expected(&self, expected: &SourceVersionExpected) -> Result<()> {
        if self.expected_public != expected.statement().values() {
            return Err("Source-quotient-expected-association");
        }
        Ok(())
    }
}

struct Environment {
    main: [Vec<Poly>; 2],
    public: Vec<F>,
    periodic: Vec<Poly>,
    first: Poly,
    last: Poly,
    transition: Poly,
    inverse_vanishing: Poly,
}
impl Environment {
    fn new(
        program: &SourceFoldProgram,
        domain: &DisclosureDomain,
        input: &PublicResidues,
    ) -> Result<Self> {
        let ring = &domain.target;
        let main = core::array::from_fn(|next| {
            input
                .main
                .iter()
                .map(|p| domain.project(p, next == 1))
                .collect()
        });
        let periodic = program.periodic.iter().map(|p| ring.reduce(p)).collect();
        let vanishing = ring::sub(&ring.power(&[F::ZERO, F::ONE], N), &[F::ONE]);
        let transition = ring.reduce(&[-domain.h.inverse(), F::ONE]);
        // SDK boundary selectors are unnormalized; periodic one-hot selectors
        // instead have the row-dependent normalization h^row / 512.
        let first = ring.multiply(&vanishing, &ring.inverse(&ring.reduce(&[-F::ONE, F::ONE]))?);
        let last = ring.multiply(&vanishing, &ring.inverse(&transition)?);
        let inverse_vanishing = ring.inverse(&vanishing)?;
        Ok(Self {
            main,
            public: program.public.clone(),
            periodic,
            first,
            last,
            transition,
            inverse_vanishing,
        })
    }
}

struct Evaluator<'a> {
    ring: &'a Ring,
    environment: &'a Environment,
    // Identity only; never dereferenced. Program roots and their Arc children
    // remain live and immovable throughout counting and this complete fold.
    cache: HashMap<*const BaseExpr, Poly>,
    limit: usize,
}
impl Evaluator<'_> {
    fn base(&mut self, expression: &BaseExpr) -> Result<Poly> {
        let ring = self.ring;
        let key = core::ptr::from_ref(expression);
        if let Some(value) = self.cache.get(&key) {
            return Ok(value.clone());
        }
        let value = match expression {
            SymbolicExpr::Leaf(leaf) => match leaf {
                BaseLeaf::Constant(value) => ring::trim(vec![*value]),
                BaseLeaf::IsFirstRow => self.environment.first.clone(),
                BaseLeaf::IsLastRow => self.environment.last.clone(),
                BaseLeaf::IsTransition => self.environment.transition.clone(),
                BaseLeaf::Variable(variable) => match variable.entry {
                    BaseEntry::Main { offset } => self
                        .environment
                        .main
                        .get(offset)
                        .and_then(|row| row.get(variable.index))
                        .cloned()
                        .ok_or("Source-MAIN-reference")?,
                    BaseEntry::Public => ring::trim(vec![
                        *self
                            .environment
                            .public
                            .get(variable.index)
                            .ok_or("Source-PV-reference")?,
                    ]),
                    BaseEntry::Periodic => self
                        .environment
                        .periodic
                        .get(variable.index)
                        .cloned()
                        .ok_or("Source-periodic-reference")?,
                    BaseEntry::Preprocessed { .. } => return Err("Source-unexpected-PP-reference"),
                },
            },
            SymbolicExpr::Add { x, y, .. } => ring::add(&self.base(x)?, &self.base(y)?),
            SymbolicExpr::Sub { x, y, .. } => ring::sub(&self.base(x)?, &self.base(y)?),
            SymbolicExpr::Neg { x, .. } => ring::scale(&self.base(x)?, -F::ONE),
            SymbolicExpr::Mul { x, y, .. } => ring.multiply(&self.base(x)?, &self.base(y)?),
        };
        if self.cache.len() >= self.limit {
            return Err("Source-symbolic-DAG-source-bound");
        }
        self.cache.insert(key, value.clone());
        Ok(value)
    }
}
