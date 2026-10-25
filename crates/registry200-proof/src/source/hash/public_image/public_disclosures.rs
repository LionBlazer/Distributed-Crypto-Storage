//! Fixed-coin public Source joint image, inside the owning cfg(test) module.
//! Arbitrary residues are not a witness, native quotient baseline or proof.
use super::{
    DisclosureDomain, E, F, INPUT_HEIGHT, MAIN, N, PUBLIC, PublicResidues, SourceFoldProgram,
    SourceVersionExpected, ring,
};
use p3_commit::PolynomialSpace;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use rand_public_pp::{CryptoRng, RngExt};
use ring::{Poly, Result, Ring};
use std::collections::HashSet;

mod tests;

/// Public arithmetic cells in the native round layout; no accepting token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Column {
    pub(super) rows: Vec<F>,
    pub(super) at_z: E,
    pub(super) at_hz: Option<E>,
}

/// S is ordered and unique. A later driver owns the separate raw-index stream.
pub(super) struct Disclosures {
    pub(super) expected_public: Vec<F>,
    pub(super) s: Vec<F>,
    pub(super) z: E,
    pub(super) r: Vec<Column>,
    pub(super) main: Vec<Column>,
    pub(super) quotient: Vec<Vec<Column>>,
    /// Algebraic Gold cells, not RNG bytes, rejections or a privacy bound.
    pub(super) ideal_cells: usize,
    pub(super) constraint_count: usize,
    pub(super) cached_nodes: usize,
}
impl Disclosures {
    pub(super) fn require_expected(&self, expected: &SourceVersionExpected) -> Result<()> {
        if self.expected_public != expected.statement().values() {
            return Err("Source-joint-expected-association");
        }
        Ok(())
    }
}

struct Cells<'a, R: CryptoRng + ?Sized> {
    rng: &'a mut R,
    count: usize,
}
impl<R: CryptoRng + ?Sized> Cells<'_, R> {
    fn polynomial(&mut self, degree: usize) -> Poly {
        self.count += degree;
        (0..degree).map(|_| self.rng.random::<F>()).collect()
    }
}

struct ChunkGeometry {
    domains: Vec<TwoAdicMultiplicativeCoset<F>>,
    ci: [F; 16],
    vanishing: [Poly; 16],
}
impl ChunkGeometry {
    fn new(ring: &Ring) -> Result<Self> {
        // Genuine uni prover geometry: hidden H1024 -> quotient7H8192,
        // split into16 ordered H512 cosets. Physical masked degree is1024.
        let extended = TwoAdicMultiplicativeCoset::<F>::new(F::ONE, 10)
            .ok_or("Source-joint-extended-domain")?;
        let quotient = extended
            .try_create_disjoint_domain(INPUT_HEIGHT)
            .ok_or("Source-joint-quotient-domain")?;
        let domains = quotient.split_domains(16);
        if quotient.size() != 8192
            || quotient.shift() != F::GENERATOR
            || domains.len() != 16
            || domains.iter().any(|domain| domain.size() != N)
        {
            return Err("Source-joint-native-chunk-geometry");
        }
        // Exactly native get_zp_cis: NORMALIZED (X/s_j)^512-1.
        // The complete split happens to give all ci=-1/16; derive, do not assume.
        let ci = core::array::from_fn(|i| {
            domains
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, other)| other.vanishing_poly_at_point(domains[i].first_point()))
                .product::<F>()
                .inverse()
        });
        let xn = ring.power(&[F::ZERO, F::ONE], N);
        let vanishing = core::array::from_fn(|i| {
            ring::sub(
                &ring::scale(&xn, domains[i].shift().exp_u64(N as u64).inverse()),
                &[F::ONE],
            )
        });
        Ok(Self {
            domains,
            ci,
            vanishing,
        })
    }

    fn masks(&self, free: [Poly; 15]) -> [Poly; 16] {
        let mut last = Vec::new();
        for (i, mask) in free.iter().enumerate() {
            last = ring::sub(&last, &ring::scale(mask, self.ci[i] / self.ci[15]));
        }
        let mut free = free.into_iter();
        core::array::from_fn(|i| {
            if i == 15 {
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
    let mut chunks = vec![vec![Vec::new(); 10]; 16];
    for (coordinate, q) in q.iter().enumerate() {
        let masks = geometry.masks(core::array::from_fn(|_| cells.polynomial(ring.degree())));
        for (i, mask) in masks.iter().enumerate() {
            chunks[i][coordinate] = ring::add(q, &ring.multiply(&geometry.vanishing[i], mask));
        }
    }
    // Native masking also covers the five appended quotient codewords. Here
    // their final residues are free algebraic cells. Equivalence to conditioned
    // native wrapper baselines/masks is an UNPROVEN distribution premise.
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
        at_hz: next.then(|| ring::evaluate(polynomial, z * F::two_adic_generator(9))),
    }
}

fn preflight(
    program: &SourceFoldProgram,
    expected: &SourceVersionExpected,
    z: E,
    s: &[F],
) -> Result<(DisclosureDomain, ChunkGeometry)> {
    if program.public.len() != PUBLIC || program.public != expected.statement().values() {
        return Err("Source-joint-expected-association");
    }
    if s.len() > bfv_hiding_stark::QUERIES {
        return Err("Source-joint-disclosure-count");
    }
    let mut unique = HashSet::new();
    for &point in s {
        if (point / F::GENERATOR).exp_u64(INPUT_HEIGHT as u64) != F::ONE {
            return Err("Source-joint-physical-locations");
        }
        if !unique.insert(point.as_canonical_u64()) {
            return Err("Source-joint-duplicate-locations");
        }
    }
    // This arithmetic sampler handles only the generic regime. These explicit
    // refusals do not change native verifier acceptance or solve those cases.
    if z == E::ZERO {
        return Err("Source-joint-zero-OOD");
    }
    if z.exp_u64(N as u64) == E::ONE {
        return Err("Source-joint-H512-OOD");
    }
    if (z / E::from(F::GENERATOR)).exp_u64(INPUT_HEIGHT as u64) == E::ONE {
        return Err("Source-joint-physical-OOD");
    }
    let domain = DisclosureDomain::checked(z, s)?;
    // Individual vanishing factors are zero divisors at REAL Source rows.
    // Deliberately no all-v_i-units requirement.
    let geometry = ChunkGeometry::new(&domain.target)?;
    Ok((domain, geometry))
}

/// Fixed public inputs precede every draw. Named preflight failures consume no
/// cells/RNG state. An unexpected later fold error is not a rewind guarantee.
/// This is an ideal-cell arithmetic recipe, not a conditioned-native law.
pub(super) fn sample<R: CryptoRng + ?Sized>(
    program: &SourceFoldProgram,
    expected: &SourceVersionExpected,
    alpha: E,
    z: E,
    s: &[F],
    rng: &mut R,
) -> Result<Disclosures> {
    let (domain, geometry) = preflight(program, expected, z, s)?;
    let mut cells = Cells { rng, count: 0 };
    // Explicit stream order: original MAIN;15*5 free Q masks;16*5 Q wrapper
    // residues;5 MAIN wrapper residues;10 R residues. No PP or AUX exists.
    let main = (0..MAIN)
        .map(|_| cells.polynomial(domain.enlarged.degree()))
        .collect();
    let input = PublicResidues::checked(&domain, main)?;
    let folded = program.fold(&domain, &input, alpha)?;
    folded.require_expected(expected)?;
    let quotient = quotient_fiber(&domain.target, &folded.coordinates, &geometry, &mut cells)
        .iter()
        .map(|chunk| chunk.iter().map(|p| emit(p, s, z, false)).collect())
        .collect();
    let mut main: Vec<_> = input.main.iter().map(|p| emit(p, s, z, true)).collect();
    for _ in 0..5 {
        main.push(emit(
            &cells.polynomial(domain.enlarged.degree()),
            s,
            z,
            true,
        ));
    }
    let r = (0..10)
        .map(|_| emit(&cells.polynomial(domain.target.degree()), s, z, false))
        .collect();
    Ok(Disclosures {
        expected_public: folded.expected_public,
        s: s.to_vec(),
        z,
        r,
        main,
        quotient,
        ideal_cells: cells.count,
        constraint_count: folded.constraint_count,
        cached_nodes: folded.cached_nodes,
    })
}
