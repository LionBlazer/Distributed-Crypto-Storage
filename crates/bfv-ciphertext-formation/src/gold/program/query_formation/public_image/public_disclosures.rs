//! Fixed-coin PUBLIC joint trace/quotient image, owning cfg(test) only.
//! No original trace, witness, Query Prepared, Config, proof or RO is used.
use super::{DisclosureDomain, PublicResidues, QueryCoins, QueryFoldProgram, ring};
use bfv_hiding_stark::{Challenge as E, Val as F};
use p3_commit::PolynomialSpace;
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use rand_public_pp::{CryptoRng, RngExt};
use ring::{Poly, Result, Ring};
use std::collections::HashMap;

mod tests;

/// Unverified PUBLIC arithmetic values, not a native proof or accepting token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::gold::program::query_formation) struct Column {
    pub(in crate::gold::program::query_formation) rows: Vec<F>,
    pub(in crate::gold::program::query_formation) at_z: E,
    pub(in crate::gold::program::query_formation) at_hz: Option<E>,
}

/// Actual native round/matrix/point/base-column layout. S is ordered and unique;
/// a driver retains its separate raw192-index stream to reuse duplicate rows.
pub(in crate::gold::program::query_formation) struct Disclosures {
    pub(in crate::gold::program::query_formation) expected_binding: [u8; 64],
    pub(in crate::gold::program::query_formation) s: Vec<F>,
    pub(in crate::gold::program::query_formation) z: E,
    pub(in crate::gold::program::query_formation) r: Vec<Column>,
    pub(in crate::gold::program::query_formation) main: Vec<Column>,
    pub(in crate::gold::program::query_formation) quotient: Vec<Vec<Column>>,
    pub(in crate::gold::program::query_formation) pp: Vec<Column>,
    pub(in crate::gold::program::query_formation) aux: Vec<Column>,
    /// Number of sampled Gold cells, not raw RNG bytes/rejection attempts.
    pub(in crate::gold::program::query_formation) ideal_cells: usize,
}

struct Cells<'a, R: CryptoRng + ?Sized> {
    rng: &'a mut R,
    count: usize,
}
impl<R: CryptoRng + ?Sized> Cells<'_, R> {
    fn polynomial(&mut self, degree: usize) -> Poly {
        // All call counts/degrees are fixed by this sealed schema and <=394.
        self.count += degree;
        (0..degree).map(|_| self.rng.random::<F>()).collect()
    }
}

struct ChunkGeometry {
    domains: Vec<TwoAdicMultiplicativeCoset<F>>,
    ci: [F; 8],
    vanishing: [Poly; 8],
}
impl ChunkGeometry {
    fn new(ring: &Ring) -> Result<Self> {
        // Native batch prover: extended trace H4096, quotient domain7H16384,
        // split into8 ordered shifts, each original chunk height2048. Its
        // physical masked polynomial has degree<4096 on7H32768.
        let extended =
            TwoAdicMultiplicativeCoset::<F>::new(F::ONE, 12).ok_or("Query-extended-domain")?;
        let quotient = extended
            .try_create_disjoint_domain(16384)
            .ok_or("Query-quotient-domain")?;
        let domains = quotient.split_domains(8);
        if quotient.size() != 16384
            || quotient.shift() != F::GENERATOR
            || domains.len() != 8
            || domains.iter().any(|domain| domain.size() != 2048)
        {
            return Err("Query-native-chunk-geometry");
        }
        // Exactly native get_zp_cis, using NORMALIZED v_j(s_i), not monic
        // X^N-s_j^N. None of these nonzero constants depends on z or S.
        let ci = core::array::from_fn(|i| {
            domains
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, other)| other.vanishing_poly_at_point(domains[i].first_point()))
                .product::<F>()
                .inverse()
        });
        let xn = ring.power(&[F::ZERO, F::ONE], 2048);
        let vanishing = core::array::from_fn(|i| {
            ring::sub(
                &ring::scale(&xn, domains[i].shift().exp_u64(2048).inverse()),
                &[F::ONE],
            )
        });
        Ok(Self {
            domains,
            ci,
            vanishing,
        })
    }

    fn masks(&self, free: [Poly; 7]) -> [Poly; 8] {
        let last_inverse = self.ci[7].inverse();
        let mut last = Vec::new();
        for (i, mask) in free.iter().enumerate() {
            last = ring::sub(&last, &ring::scale(mask, self.ci[i] * last_inverse));
        }
        let mut free = free.into_iter();
        core::array::from_fn(|i| {
            if i == 7 {
                last.clone()
            } else {
                free.next().unwrap()
            }
        })
    }
}

fn quotient_fiber<R: CryptoRng + ?Sized>(
    ring: &Ring,
    q: &[Poly; 5],
    geometry: &ChunkGeometry,
    cells: &mut Cells<'_, R>,
) -> Vec<Vec<Poly>> {
    let mut chunks = vec![vec![Vec::new(); 10]; 8];
    for (coordinate, q) in q.iter().enumerate() {
        // Same-Q affine fiber. Seven independent uniform A cells per basis
        // coefficient; the eighth mask is correlated, NEVER independently drawn.
        let masks = geometry.masks(core::array::from_fn(|_| cells.polynomial(ring.degree())));
        for (i, mask) in masks.iter().enumerate() {
            chunks[i][coordinate] = ring::add(q, &ring.multiply(&geometry.vanishing[i], mask));
        }
    }
    // Native appended random quotient codewords have independent uniform
    // residues already, so adding their independent correlated masks preserves
    // uniform A^8. They have NO fixed original-Q recomposition constraint.
    for chunk in &mut chunks {
        for column in &mut chunk[5..] {
            *column = cells.polynomial(ring.degree());
        }
    }
    chunks
}

fn emit(polynomial: &[F], s: &[F], z: E, next: bool) -> Column {
    Column {
        rows: s
            .iter()
            .map(|&point| {
                polynomial
                    .iter()
                    .rev()
                    .fold(F::ZERO, |value, &coefficient| value * point + coefficient)
            })
            .collect(),
        at_z: ring::evaluate(polynomial, z),
        at_hz: next.then(|| ring::evaluate(polynomial, z * F::two_adic_generator(11))),
    }
}

fn physical_indices(s: &[F]) -> Result<Vec<usize>> {
    if s.len() > 192 {
        return Err("Query-disclosure-count");
    }
    let mut wanted = HashMap::new();
    for (index, &point) in s.iter().enumerate() {
        if (point / F::GENERATOR).exp_u64(32768) != F::ONE
            || wanted.insert(point.as_canonical_u64(), index).is_some()
        {
            return Err("Query-unique-physical-locations");
        }
    }
    // Derive natural DFT coordinates from the actual field points. A caller
    // cannot replace field locations by claimed raw indices or a different coset.
    let mut indices = vec![0; s.len()];
    let mut point = F::GENERATOR;
    let omega = F::two_adic_generator(15);
    for natural in 0..32768 {
        if let Some(&index) = wanted.get(&point.as_canonical_u64()) {
            indices[index] = natural;
        }
        point *= omega;
    }
    Ok(indices)
}

fn emit_pp(polynomial: &[F], s: &[F], indices: &[usize], z: E) -> Column {
    if polynomial.len() <= 64 || polynomial.len() * s.len() < 32768 {
        return emit(polynomial, s, z, false);
    }
    // Actual PUBLIC zero-interleaved coefficients; stream one native LDE only.
    let mut padded = polynomial.to_vec();
    padded.resize(32768, F::ZERO);
    let values = Radix2DitParallel::<F>::default().coset_dft(padded, F::GENERATOR);
    Column {
        rows: indices.iter().map(|&index| values[index]).collect(),
        at_z: ring::evaluate(polynomial, z),
        at_hz: None,
    }
}

/// Sample the exact fixed-location algebraic image under the ideal independent
/// Gold-cell premise in QUOTIENT-IMAGE/R-DEEP. `CryptoRng` is its concrete recipe,
/// not a claim that a chosen seed is ideal or independent of these public inputs.
/// All Expected/coins/z/S are independently fixed BEFORE these cell draws.
pub(in crate::gold::program::query_formation) fn sample<R: CryptoRng + ?Sized>(
    program: &QueryFoldProgram,
    coins: &QueryCoins,
    z: E,
    s: &[F],
    rng: &mut R,
) -> Result<Disclosures> {
    let indices = physical_indices(s)?;
    if z == E::ZERO
        || z.exp_u64(2048) == E::ONE
        || (z / E::from(F::GENERATOR)).exp_u64(32768) == E::ONE
    {
        return Err("Query-exceptional-OOD");
    }
    if program.pp_coefficients.len() != 545
        || program.pp_coefficients.iter().any(|p| p.len() > 4096)
    {
        return Err("Query-actual-public-PP-shape");
    }
    let domain = DisclosureDomain::checked(z, s)?;
    let geometry = ChunkGeometry::new(&domain.target)?;
    let mut cells = Cells { rng, count: 0 };
    let main = (0..416)
        .map(|_| cells.polynomial(domain.source_degree()))
        .collect();
    let aux = (0..420)
        .map(|_| cells.polynomial(domain.source_degree()))
        .collect();
    let input = PublicResidues::checked(&domain, main, aux)?;
    // SAME sampled enlarged MAIN/AUX and SAME lookup/folding coins. Return ALL
    // five coefficient copies, never replace them by one collapsed value Q(z).
    let folded = program.fold(&domain, &input, coins)?;
    let quotient = quotient_fiber(&domain.target, folded.coordinates(), &geometry, &mut cells)
        .iter()
        .map(|chunk| chunk.iter().map(|p| emit(p, s, z, false)).collect())
        .collect();
    let mut main: Vec<_> = input.main.iter().map(|p| emit(p, s, z, true)).collect();
    let mut aux: Vec<_> = input.aux_base.iter().map(|p| emit(p, s, z, true)).collect();
    for _ in 0..5 {
        main.push(emit(&cells.polynomial(domain.source_degree()), s, z, true));
        aux.push(emit(&cells.polynomial(domain.source_degree()), s, z, true));
    }
    let r = (0..10)
        .map(|_| emit(&cells.polynomial(domain.target.degree()), s, z, false))
        .collect();
    let pp = program
        .pp_coefficients
        .iter()
        .map(|p| emit_pp(p, s, &indices, z))
        .collect();
    Ok(Disclosures {
        expected_binding: program.binding,
        s: s.to_vec(),
        z,
        r,
        main,
        quotient,
        pp,
        aux,
        ideal_cells: cells.count,
    })
}
