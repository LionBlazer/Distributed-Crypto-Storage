//! Isolated child of owning query_formation, cfg(test) only.
//! PUBLIC image arithmetic, not a proof producer/verifier or valid-witness claim.
pub(super) mod public_disclosures;
mod ring;
#[cfg(test)]
mod tests;

use super::{Expected, hash_wire, layout, native};
use bfv_hiding_stark::{Challenge as E, Val as F};
use p3_air::BaseAir;
use p3_air::symbolic::{
    AirLayout, BaseEntry, BaseLeaf, ExtEntry, ExtLeaf, SymbolicExpr, SymbolicExpression,
    SymbolicExpressionExt,
};
use p3_batch_stark::symbolic::get_log_num_quotient_chunks_for_domain;
use p3_commit::PolynomialSpace;
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::extension::HasFrobenius;
use p3_field::{
    BasedVectorSpace, ExtensionField, Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField,
};
use p3_lookup::{
    Challenges, InteractionSymbolicBuilder, Kind, LogUpGadget, LookupProtocol, Lookups,
};
use p3_matrix::Matrix;
use ring::{Poly, Result, Ring, Tensor};
use std::collections::HashMap;

const N: usize = 2048;
const MAIN: usize = 416;
const PP: usize = 545;
const AUX_BASE: usize = 420;
const AUX_EXT: usize = 84;
const PACKED: usize = 83;
const MAX_CONSTRAINTS: usize = 16_384;
const MAX_CACHED_NODES: usize = 262_144;
type BaseExpr = SymbolicExpression<F>;
type ExtExpr = SymbolicExpressionExt<F, E>;

/// Fixed public FS coins, not independently generated or approved by this core.
pub(super) struct QueryCoins {
    pub(super) lookup_alpha: E,
    pub(super) lookup_beta: E,
    pub(super) constraint_alpha: E,
}

/// The actual target A=F[X]/M and enlarged source A_T=F[X]/M_T.
/// z/S remain public fixed inputs; no hash/FS conditioning is inferred.
pub(super) struct DisclosureDomain {
    target: Ring,
    enlarged: Ring,
    h: F,
}
impl DisclosureDomain {
    pub(super) fn target_modulus(&self) -> &[F] {
        self.target.modulus()
    }
    pub(super) fn source_modulus(&self) -> &[F] {
        self.enlarged.modulus()
    }
    pub(super) fn source_degree(&self) -> usize {
        self.enlarged.degree()
    }

    pub(super) fn checked(z: E, positions: &[F]) -> Result<Self> {
        if positions.len() > 192 || z.exp_u64(N as u64) == E::ONE {
            return Err("Query-disclosure-locations");
        }
        let h = F::two_adic_generator(11);
        let mut s = positions.to_vec();
        s.sort_unstable_by_key(|point| point.as_canonical_u64());
        s.dedup();
        if s.iter()
            .any(|point| (*point / F::GENERATOR).exp_u64(32768) != F::ONE)
        {
            return Err("Query-physical-input-domain");
        }
        let mut target_points = s.iter().copied().map(E::from).collect::<Vec<_>>();
        target_points.push(z);
        let mut all_points = target_points.clone();
        all_points.extend(s.iter().map(|&point| E::from(point * h)));
        all_points.push(z * h);
        let target = Ring::checked(minimal_product(&target_points)?)?;
        let enlarged = Ring::checked(minimal_product(&all_points)?)?;
        if target.degree() > 197 || enlarged.degree() > 394 {
            return Err("Query-disclosure-degree");
        }
        // EXACT well-definedness checks for pi_0 and pi_h INTO A. No claim that
        // rotation acts on A_T: h^2*S need not be in its disclosure set.
        if !target.reduce(enlarged.modulus()).is_empty()
            || !target
                .reduce(&ring::rotate(enlarged.modulus(), h))
                .is_empty()
        {
            return Err("Query-rotation-projection");
        }
        let z_enlarged = ring::sub(&enlarged.power(&[F::ZERO, F::ONE], N), &[F::ONE]);
        enlarged.inverse(&z_enlarged)?;
        Ok(Self {
            target,
            enlarged,
            h,
        })
    }
    fn project(&self, p: &[F], next: bool) -> Poly {
        if next {
            self.target.reduce(&ring::rotate(p, self.h))
        } else {
            self.target.reduce(p)
        }
    }
}

fn minimal_product(points: &[E]) -> Result<Poly> {
    let mut factors = Vec::<Poly>::new();
    let mut product = vec![F::ONE];
    for &point in points {
        let factor = if let Some(base) = <E as ExtensionField<F>>::as_base(&point) {
            vec![-base, F::ONE]
        } else {
            // Prime extension degree5: every non-base point has the five
            // distinct conjugates. Preserve the actual fixed coefficient basis.
            let mut p = vec![E::ONE];
            for i in 0..5 {
                let conjugate = point.repeated_frobenius(i);
                let mut next = vec![E::ZERO; p.len() + 1];
                for (j, &coefficient) in p.iter().enumerate() {
                    next[j] -= coefficient * conjugate;
                    next[j + 1] += coefficient;
                }
                p = next;
            }
            p.iter()
                .map(|value| {
                    <E as ExtensionField<F>>::as_base(value).ok_or("minimal-polynomial-not-base")
                })
                .collect::<Result<Poly>>()?
        };
        if !factors.contains(&factor) {
            product = ring::mul(&product, &factor);
            factors.push(factor);
        }
    }
    Ok(product)
}

/// Input consists ONLY of public sampler residues modulo the enlarged M_T.
/// Each AUX item is ONE of420 separate BASE-polynomial residues. No collapse
/// into84 extension values or into a single OOD evaluation is accepted.
pub(super) struct PublicResidues {
    source_modulus: Poly,
    main: Vec<Poly>,
    aux_base: Vec<Poly>,
}
impl PublicResidues {
    pub(super) fn checked(
        domain: &DisclosureDomain,
        main: Vec<Poly>,
        aux_base: Vec<Poly>,
    ) -> Result<Self> {
        if main.len() != MAIN
            || aux_base.len() != AUX_BASE
            || main
                .iter()
                .chain(&aux_base)
                .any(|p| p.len() > domain.enlarged.degree())
        {
            return Err("Query-public-residue-shape");
        }
        Ok(Self {
            source_modulus: domain.enlarged.modulus().to_vec(),
            main: main.into_iter().map(ring::trim).collect(),
            aux_base: aux_base.into_iter().map(ring::trim).collect(),
        })
    }
}

enum Emission {
    Base(usize),
    Extension(usize),
}

/// Source-derived immutable actual AIR program plus actual zero-interleaved PP.
/// No Config, private RNG, original trace or guarded Prepared is retained.
pub(super) struct QueryFoldProgram {
    binding: [u8; 64],
    base: Vec<BaseExpr>,
    extension: Vec<ExtExpr>,
    order: Vec<Emission>,
    pp_coefficients: Vec<Poly>,
    public: Vec<F>,
}
impl QueryFoldProgram {
    /// Complete PUBLIC PP polynomial coefficients after native zero interleaving.
    /// This is source association data, not a private trace/seed/config getter.
    pub(super) fn public_pp_coefficients(&self) -> &[Poly] {
        &self.pp_coefficients
    }

    pub(super) fn from_expected(expected: &Expected) -> Result<Self> {
        let (air, assessment) =
            native::prescreen(expected).map_err(|_| "Query-owning-prescreen")?;
        hash_wire::require_assessment(&assessment).map_err(|_| "Query-owning-assessment")?;
        if (
            air.width(),
            air.preprocessed_width(),
            air.num_public_values(),
            air.num_periodic_columns(),
        ) != (MAIN, PP, 32, 0)
            || !air.preprocessed_next_row_columns().is_empty()
        {
            return Err("Query-owning-AIR-shape");
        }
        let u = E::from_basis_coefficients_fn(|i| F::from_bool(i == 1));
        if u.exp_u64(5) != E::from_u32(3) {
            return Err("Query-EF5-fixed-basis");
        }
        let gadget = LogUpGadget::new();
        if gadget.num_challenges() != 2 {
            return Err("Query-lookup-challenge-width");
        }
        let original = Lookups::<F>::from_air::<E, _>(&air);
        let domain =
            TwoAdicMultiplicativeCoset::<F>::new(F::ONE, 11).ok_or("Query-original-domain")?;
        let log = get_log_num_quotient_chunks_for_domain::<F, E, _, _>(
            &air,
            AirLayout::from_air(&air),
            domain,
            &original,
            1,
            &gadget,
        );
        if log != 2 {
            return Err("Query-native-quotient-bucket");
        }
        // Same zero-override free budget as native CommonData: 2^log+1-is_zk.
        let packed = original.pack_same_bus_with_degree(1usize << log, |lookup| {
            gadget.constraint_degree_with_transition(lookup, domain.transition_degree_multiple())
        });
        if packed.len() != PACKED
            || packed.total_count_weight() != 4 * 248
            || packed
                .iter()
                .map(|lookup| lookup.elements.len())
                .sum::<usize>()
                != 248
            || packed.iter().enumerate().any(|(column, lookup)| {
                lookup.column != column
                    || lookup.kind != Kind::Global(layout::BUS.to_owned())
                    || lookup.flags.is_some()
                    || lookup.elements.is_empty()
                    || lookup.elements.len() != lookup.multiplicities.len()
                    || lookup.elements.iter().any(|tuple| tuple.len() != 2)
            })
        {
            return Err("Query-native-packed-lookups");
        }
        // This IS the actual generic SDK AirBuilder contract. A second fake AIR
        // or a ring implementing Field is unnecessary. The resulting DAG keeps
        // every original AIR AND packed LogUp constraint in native order.
        let symbolic_layout = AirLayout {
            permutation_width: AUX_EXT,
            num_permutation_challenges: PACKED * 2,
            num_permutation_values: 1,
            ..AirLayout::from_air(&air)
        };
        let mut builder = InteractionSymbolicBuilder::<F, E>::new(symbolic_layout);
        gadget.eval_air_and_lookups(&air, &mut builder, &packed);
        if !builder.indexed_reads().is_empty() || !builder.indexed_tables().is_empty() {
            return Err("Query-unhandled-indexed-declaration");
        }
        let base = builder.base_constraints();
        let extension = builder.extension_constraints();
        let layout = builder.constraint_layout();
        let count = base
            .len()
            .checked_add(extension.len())
            .ok_or("Query-constraint-count")?;
        if count == 0
            || count > MAX_CONSTRAINTS
            || layout.total_constraints() != count
            || layout.base_indices.len() != base.len()
            || layout.ext_indices.len() != extension.len()
        {
            return Err("Query-constraint-count");
        }
        let mut order = core::iter::repeat_with(|| None)
            .take(count)
            .collect::<Vec<_>>();
        for (local, &global) in layout.base_indices.iter().enumerate() {
            let slot = order.get_mut(global).ok_or("Query-base-emission-index")?;
            if slot.is_some() {
                return Err("Query-duplicate-emission-index");
            }
            *slot = Some(Emission::Base(local));
        }
        for (local, &global) in layout.ext_indices.iter().enumerate() {
            let slot = order.get_mut(global).ok_or("Query-ext-emission-index")?;
            if slot.is_some() {
                return Err("Query-duplicate-emission-index");
            }
            *slot = Some(Emission::Extension(local));
        }
        let order = order
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or("Query-missing-emission-index")?;
        let pp = air.preprocessed_trace().ok_or("Query-actual-PP")?;
        if pp.height() != N || pp.width() != PP {
            return Err("Query-actual-PP-shape");
        }
        // Native hiding_pcs::commit_preprocessing ZERO-INTERLEAVES2048->4096.
        // Interpolating the original2048-row matrix would be WRONG away from H.
        let mut padded = pp.with_zero_cols(PP);
        padded.width = PP;
        let coefficients = Radix2DitParallel::<F>::default()
            .idft_batch(padded)
            .to_row_major_matrix();
        let pp_coefficients = (0..PP)
            .map(|column| {
                ring::trim(
                    (0..2 * N)
                        .map(|row| coefficients.values[row * PP + column])
                        .collect(),
                )
            })
            .collect();
        Ok(Self {
            binding: expected.binding(),
            base,
            extension,
            order,
            pp_coefficients,
            public: expected.values().to_vec(),
        })
    }

    pub(super) fn fold(
        &self,
        domain: &DisclosureDomain,
        input: &PublicResidues,
        coins: &QueryCoins,
    ) -> Result<QuotientResidues> {
        if input.source_modulus != domain.enlarged.modulus() {
            return Err("Query-residue-domain-association");
        }
        let environment = Environment::new(self, domain, input, coins)?;
        let ring = &domain.target;
        let mut evaluate = Evaluator {
            ring,
            env: &environment,
            base: HashMap::new(),
            extension: HashMap::new(),
        };
        let mut folded = ring.zero_tensor();
        for emission in &self.order {
            let value = match *emission {
                Emission::Base(i) => ring.lift(&evaluate.base(&self.base[i])?),
                Emission::Extension(i) => evaluate.extension(&self.extension[i])?,
            };
            // Native global order is Horner: C0*alpha^(K-1)+...+C_(K-1).
            // Never concatenate the separated base/ext vectors.
            folded = ring.tensor_add(&ring.tensor_scale(&folded, coins.constraint_alpha), &value);
        }
        let coordinates = core::array::from_fn(|i| ring.multiply(&folded[i], &environment.inv_z));
        Ok(QuotientResidues {
            expected_binding: self.binding,
            modulus: ring.modulus().to_vec(),
            coordinates,
            constraint_count: self.order.len(),
        })
    }
}

/// All FIVE base-coordinate polynomials [Q_b mod M]. Arithmetic output only.
pub(super) struct QuotientResidues {
    expected_binding: [u8; 64],
    modulus: Poly,
    coordinates: Tensor,
    constraint_count: usize,
}
impl QuotientResidues {
    pub(super) fn coordinates(&self) -> &[Poly; 5] {
        &self.coordinates
    }
    pub(super) fn modulus(&self) -> &[F] {
        &self.modulus
    }
    pub(super) fn expected_binding(&self) -> &[u8; 64] {
        &self.expected_binding
    }
    pub(super) fn constraint_count(&self) -> usize {
        self.constraint_count
    }
}

struct Environment {
    main: [Vec<Poly>; 2],
    pp: [Vec<Poly>; 2],
    aux: [Vec<Tensor>; 2],
    public: Vec<F>,
    randomness: Vec<E>,
    first: Poly,
    last: Poly,
    transition: Poly,
    inv_z: Poly,
}
impl Environment {
    fn new(
        program: &QueryFoldProgram,
        domain: &DisclosureDomain,
        input: &PublicResidues,
        coins: &QueryCoins,
    ) -> Result<Self> {
        let ring = &domain.target;
        let main = core::array::from_fn(|next| {
            input
                .main
                .iter()
                .map(|p| domain.project(p, next == 1))
                .collect()
        });
        let pp = core::array::from_fn(|next| {
            program
                .pp_coefficients
                .iter()
                .map(|p| domain.project(p, next == 1))
                .collect()
        });
        let aux = core::array::from_fn(|next| {
            input
                .aux_base
                .as_chunks::<5>()
                .0
                .iter()
                .map(|columns| core::array::from_fn(|b| domain.project(&columns[b], next == 1)))
                .collect()
        });
        let z = ring::sub(&ring.power(&[F::ZERO, F::ONE], N), &[F::ONE]);
        let transition = ring.reduce(&[-domain.h.inverse(), F::ONE]);
        let first = ring.multiply(&z, &ring.inverse(&ring.reduce(&[-F::ONE, F::ONE]))?);
        let last = ring.multiply(&z, &ring.inverse(&transition)?);
        let table = Challenges::new(coins.lookup_alpha, coins.lookup_beta, 2, 1);
        let randomness = (0..PACKED)
            .flat_map(|_| [table.bus_prefix[0], coins.lookup_beta])
            .collect();
        Ok(Self {
            main,
            pp,
            aux,
            public: program.public.clone(),
            randomness,
            first,
            last,
            transition,
            inv_z: ring.inverse(&z)?,
        })
    }
}

struct Evaluator<'a> {
    ring: &'a Ring,
    env: &'a Environment,
    // Keys identify immutable live DAG nodes, never dereferenced. All owning
    // expression roots and Arc children stay alive for this complete evaluation.
    base: HashMap<*const BaseExpr, Poly>,
    extension: HashMap<*const ExtExpr, Tensor>,
}
impl Evaluator<'_> {
    fn base(&mut self, expression: &BaseExpr) -> Result<Poly> {
        let ring = self.ring;
        let key = core::ptr::from_ref(expression);
        if let Some(value) = self.base.get(&key) {
            return Ok(value.clone());
        }
        let value = match expression {
            SymbolicExpr::Leaf(leaf) => match leaf {
                BaseLeaf::Constant(value) => ring::trim(vec![*value]),
                BaseLeaf::IsFirstRow => self.env.first.clone(),
                BaseLeaf::IsLastRow => self.env.last.clone(),
                BaseLeaf::IsTransition => self.env.transition.clone(),
                BaseLeaf::Variable(variable) => match variable.entry {
                    BaseEntry::Main { offset } => self
                        .env
                        .main
                        .get(offset)
                        .and_then(|row| row.get(variable.index))
                        .cloned()
                        .ok_or("Query-MAIN-reference")?,
                    BaseEntry::Preprocessed { offset } => self
                        .env
                        .pp
                        .get(offset)
                        .and_then(|row| row.get(variable.index))
                        .cloned()
                        .ok_or("Query-PP-reference")?,
                    BaseEntry::Public => ring::trim(vec![
                        *self
                            .env
                            .public
                            .get(variable.index)
                            .ok_or("Query-PV-reference")?,
                    ]),
                    BaseEntry::Periodic => return Err("Query-unexpected-periodic-reference"),
                },
            },
            SymbolicExpr::Add { x, y, .. } => ring::add(&self.base(x)?, &self.base(y)?),
            SymbolicExpr::Sub { x, y, .. } => ring::sub(&self.base(x)?, &self.base(y)?),
            SymbolicExpr::Neg { x, .. } => ring::scale(&self.base(x)?, -F::ONE),
            SymbolicExpr::Mul { x, y, .. } => ring.multiply(&self.base(x)?, &self.base(y)?),
        };
        if self.base.len() + self.extension.len() >= MAX_CACHED_NODES {
            return Err("Query-symbolic-DAG-resource-bound");
        }
        self.base.insert(key, value.clone());
        Ok(value)
    }
    fn extension(&mut self, expression: &ExtExpr) -> Result<Tensor> {
        let ring = self.ring;
        let key = core::ptr::from_ref(expression);
        if let Some(value) = self.extension.get(&key) {
            return Ok(value.clone());
        }
        let value = match expression {
            SymbolicExpr::Leaf(leaf) => match leaf {
                ExtLeaf::Base(base) => ring.lift(&self.base(base)?),
                ExtLeaf::ExtConstant(value) => ring.constant(*value),
                ExtLeaf::ExtVariable(variable) => match variable.entry {
                    ExtEntry::Permutation { offset } => self
                        .env
                        .aux
                        .get(offset)
                        .and_then(|row| row.get(variable.index))
                        .cloned()
                        .ok_or("Query-AUX-reference")?,
                    ExtEntry::Challenge => ring.constant(
                        *self
                            .env
                            .randomness
                            .get(variable.index)
                            .ok_or("Query-lookup-challenge-reference")?,
                    ),
                    ExtEntry::PermutationValue if variable.index == 0 => ring.zero_tensor(),
                    ExtEntry::PermutationValue => return Err("Query-terminal-reference"),
                },
            },
            SymbolicExpr::Add { x, y, .. } => {
                ring.tensor_add(&self.extension(x)?, &self.extension(y)?)
            }
            SymbolicExpr::Sub { x, y, .. } => {
                ring.tensor_sub(&self.extension(x)?, &self.extension(y)?)
            }
            SymbolicExpr::Neg { x, .. } => ring.tensor_neg(&self.extension(x)?),
            SymbolicExpr::Mul { x, y, .. } => {
                ring.tensor_mul(&self.extension(x)?, &self.extension(y)?)
            }
        };
        if self.base.len() + self.extension.len() >= MAX_CACHED_NODES {
            return Err("Query-symbolic-DAG-resource-bound");
        }
        self.extension.insert(key, value.clone());
        Ok(value)
    }
}
