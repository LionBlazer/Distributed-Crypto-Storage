//! Private exact integer equations shared by both optional AIR representations.
use crate::{BASE, Basis, CARRY_OFFSET, TERMS};
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks as Val;

fn product<AB: AirBuilder<F = Val>>(out: &mut [AB::Expr; 8], x: &[AB::Expr], y: &[AB::Expr]) {
    for (i, x) in x.iter().enumerate() {
        for (j, y) in y.iter().enumerate() {
            out[i + j] += x.clone() * y.clone();
        }
    }
}

/// Existing 61-column order: input16/output12/quotient12/carry21.
pub(crate) fn enforce<AB: AirBuilder<F = Val>>(builder: &mut AB, basis: Basis, p: &[AB::Expr]) {
    let modulus: Vec<_> = crate::math::digits(basis.modulus())
        .map(|d| AB::Expr::from(Val::from_u16(d)))
        .collect();
    for (component, terms) in TERMS.iter().enumerate() {
        let mut a = core::array::from_fn(|_| AB::Expr::ZERO);
        let mut d = core::array::from_fn(|_| AB::Expr::ZERO);
        for &(x, y) in *terms {
            product::<AB>(&mut a, &p[4 * x..4 * x + 4], &p[4 * y..4 * y + 4]);
        }
        for (i, v) in p[16 + 4 * component..20 + 4 * component].iter().enumerate() {
            d[i] += v.clone();
        }
        product::<AB>(&mut d, &p[28 + 4 * component..32 + 4 * component], &modulus);
        let carry = &p[40 + 7 * component..47 + 7 * component];
        for (i, (a, d)) in a.into_iter().zip(d).enumerate() {
            let here = if i == 0 {
                AB::Expr::from(Val::from_u64(CARRY_OFFSET as u64))
            } else {
                carry[i - 1].clone()
            };
            let next = if i == 7 {
                AB::Expr::from(Val::from_u64(CARRY_OFFSET as u64))
            } else {
                carry[i].clone()
            };
            builder.assert_zero(
                a + here + Val::from_u64((CARRY_OFFSET * (BASE - 1)) as u64)
                    - d
                    - next * Val::from_u64(BASE as u64),
            );
        }
    }
}
