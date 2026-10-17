//! Shared exact eight digit residuals for both optional NTT AIR representations.
use crate::{BASE, Basis, CARRY_OFFSET};
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks as Val;

fn product<AB: AirBuilder<F = Val>>(out: &mut [AB::Expr; 8], a: &[AB::Expr], b: &[AB::Expr]) {
    for (i, x) in a.iter().enumerate() {
        for (j, y) in b.iter().enumerate() {
            if i + j < 8 {
                out[i + j] += x.clone() * y.clone();
            }
        }
    }
}
pub(crate) fn modulus_digits<AB: AirBuilder<F = Val>>(basis: Basis) -> [AB::Expr; 4] {
    core::array::from_fn(|i| AB::Expr::from(Val::from_u16((basis.modulus() >> (16 * i)) as u16)))
}
// Exact former PP32 layout: x4,y4,z4,a4,b4,U5,d7. No public kernel API.
pub(crate) fn enforce<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    modulus_digits: &[AB::Expr; 4],
    p: &[AB::Expr],
) {
    let mut a = core::array::from_fn(|_| AB::Expr::ZERO);
    let mut d = core::array::from_fn(|_| AB::Expr::ZERO);
    product::<AB>(&mut a, &p[..4], &p[12..16]);
    product::<AB>(&mut a, &p[4..8], &p[16..20]);
    for (i, v) in modulus_digits.iter().enumerate() {
        a[4 + i] += v.clone();
    }
    for (i, v) in p[8..12].iter().enumerate() {
        d[i] += v.clone();
    }
    product::<AB>(&mut d, &p[20..25], modulus_digits);
    for (i, (a, d)) in a.into_iter().zip(d).enumerate() {
        let here = if i == 0 {
            AB::Expr::from(Val::from_u64(CARRY_OFFSET as u64))
        } else {
            p[24 + i].clone()
        };
        let next = if i == 7 {
            AB::Expr::from(Val::from_u64(CARRY_OFFSET as u64))
        } else {
            p[25 + i].clone()
        };
        builder.assert_zero(
            a + here + Val::from_u64((CARRY_OFFSET * (BASE - 1)) as u64)
                - d
                - next * Val::from_u64(BASE as u64),
        );
    }
}
