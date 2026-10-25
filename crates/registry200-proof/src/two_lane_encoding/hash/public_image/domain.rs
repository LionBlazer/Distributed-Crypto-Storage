//! Fixed Role3 disclosure geometry; public arithmetic, not sampling or proof.
use super::{E, F, INPUT_HEIGHT, MAIN, N};
use p3_field::extension::HasFrobenius;
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use proof_research_support::ring::{self, Poly, Result, Ring};

pub(super) struct DisclosureDomain {
    pub(super) target: Ring,
    pub(super) enlarged: Ring,
    pub(super) h: F,
}
impl DisclosureDomain {
    pub(super) fn checked(z: E, positions: &[F]) -> Result<Self> {
        if positions.len() > bfv_hiding_stark::QUERIES || z.exp_u64(N as u64) == E::ONE {
            return Err("Role3-disclosure-locations");
        }
        let h = F::two_adic_generator(bfv_hiding_stark::TRACE_LOG_HEIGHT);
        let mut positions = positions.to_vec();
        positions.sort_unstable_by_key(|point| point.as_canonical_u64());
        positions.dedup();
        if positions
            .iter()
            .any(|point| (*point / F::GENERATOR).exp_u64(INPUT_HEIGHT as u64) != F::ONE)
        {
            return Err("Role3-physical-input-domain");
        }
        let mut target_points = positions.iter().copied().map(E::from).collect::<Vec<_>>();
        target_points.push(z);
        let mut source_points = target_points.clone();
        source_points.extend(positions.iter().map(|&point| E::from(point * h)));
        source_points.push(z * h);
        let target = Ring::checked(minimal_product(&target_points)?)?;
        let enlarged = Ring::checked(minimal_product(&source_points)?)?;
        let max_target = bfv_hiding_stark::QUERIES + 5;
        if target.degree() > max_target || enlarged.degree() > 2 * max_target {
            return Err("Role3-disclosure-degree");
        }
        // Two well-defined maps INTO the target; rotation is not asserted to
        // act on the enlarged ring (h^2*S may not be among its points).
        if !target.reduce(enlarged.modulus()).is_empty()
            || !target
                .reduce(&ring::rotate(enlarged.modulus(), h))
                .is_empty()
        {
            return Err("Role3-rotation-projection");
        }
        let vanishing = ring::sub(&enlarged.power(&[F::ZERO, F::ONE], N), &[F::ONE]);
        enlarged.inverse(&vanishing)?;
        Ok(Self {
            target,
            enlarged,
            h,
        })
    }
    pub(super) fn project(&self, polynomial: &[F], next: bool) -> Poly {
        if next {
            self.target.reduce(&ring::rotate(polynomial, self.h))
        } else {
            self.target.reduce(polynomial)
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
            let mut polynomial = vec![E::ONE];
            for conjugate in (0..5).map(|i| point.repeated_frobenius(i)) {
                let mut next = vec![E::ZERO; polynomial.len() + 1];
                for (i, &coefficient) in polynomial.iter().enumerate() {
                    next[i] -= coefficient * conjugate;
                    next[i + 1] += coefficient;
                }
                polynomial = next;
            }
            polynomial
                .iter()
                .map(|coefficient| {
                    <E as ExtensionField<F>>::as_base(coefficient)
                        .ok_or("Role3-minimal-polynomial-not-base")
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

pub(super) struct PublicResidues {
    pub(super) source_modulus: Poly,
    pub(super) main: Vec<Poly>,
}
impl PublicResidues {
    pub(super) fn checked(domain: &DisclosureDomain, main: Vec<Poly>) -> Result<Self> {
        if main.len() != MAIN || main.iter().any(|p| p.len() > domain.enlarged.degree()) {
            return Err("Role3-public-residue-shape");
        }
        Ok(Self {
            source_modulus: domain.enlarged.modulus().to_vec(),
            main: main.into_iter().map(ring::trim).collect(),
        })
    }
}
