//! Private exact limb equations shared by the two optional AIR representations.
use crate::{BASE, CARRY_OFFSET, Role, W_OFFSET, constants};
use ethnum::U256;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks as Val;

fn number<AB: AirBuilder<F = Val>>(out: &mut [AB::Expr], number: U256) {
    for (i, v) in out.iter_mut().enumerate() {
        *v += Val::from_u16(((number >> (16 * i)).as_u128() & 65535) as u16);
    }
}
fn product<AB: AirBuilder<F = Val>>(out: &mut [AB::Expr], a: &[AB::Expr], constant: &[u16]) {
    for (i, x) in a.iter().enumerate() {
        for (j, &y) in constant.iter().enumerate() {
            if i + j < out.len() {
                out[i + j] += x.clone() * Val::from_u16(y);
            }
        }
    }
}
fn digits(v: u128, n: usize) -> Vec<u16> {
    crate::math::unsigned_limbs(v, n)
}
fn equation<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    a: Vec<AB::Expr>,
    d: Vec<AB::Expr>,
    carry: &[AB::Expr],
) {
    for (i, (a, d)) in a.into_iter().zip(d).enumerate() {
        let here = if i == 0 {
            AB::Expr::from(Val::from_u64(CARRY_OFFSET as u64))
        } else {
            carry[i - 1].clone()
        };
        let next = if i == carry.len() {
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

/// Existing 4n+124-column order, including all 56 reconstructed 25-bit carries.
pub(crate) fn enforce<AB: AirBuilder<F = Val>>(builder: &mut AB, role: Role, p: &[AB::Expr]) {
    let c = constants(role);
    let n = role.input_moduli().len();
    let y = 4 * n;
    let v = y + 20;
    let rv = v + 4;
    let wb = rv + 8;
    let re = wb + 3;
    let u = re + 8;
    let carry = u + 25;
    let mut a = vec![AB::Expr::ZERO; 12];
    let mut d = vec![AB::Expr::ZERO; 12];
    for (i, &t) in c.t.iter().enumerate() {
        product::<AB>(&mut a, &p[4 * i..4 * i + 4], &digits(t, 8));
    }
    number::<AB>(&mut a, U256::ONE << (c.shift - 1));
    product::<AB>(&mut d, &p[v..v + 4], &digits(1u128 << c.shift, 8));
    for (i, x) in p[rv..rv + 8].iter().enumerate() {
        d[i] += x.clone();
    }
    equation(builder, a, d, &p[carry..carry + 11]);
    let mut a = vec![AB::Expr::ZERO; 11];
    let mut d = vec![AB::Expr::ZERO; 11];
    for (i, t) in c.theta.iter().enumerate() {
        product::<AB>(
            if t.negative { &mut d } else { &mut a },
            &p[4 * i..4 * i + 4],
            &digits(t.magnitude, 8),
        );
    }
    number::<AB>(&mut a, (U256::ONE << 126) + (U256::ONE << 172));
    product::<AB>(&mut d, &p[wb..wb + 3], &digits(1u128 << 127, 8));
    for (i, x) in p[re..re + 8].iter().enumerate() {
        d[i] += x.clone();
    }
    equation(builder, a, d, &p[carry + 11..carry + 21]);
    for j in 0..5 {
        let modulus = role.computed_moduli()[j];
        let mut a = vec![AB::Expr::ZERO; 8];
        let mut d = vec![AB::Expr::ZERO; 8];
        for i in 0..n {
            product::<AB>(
                &mut a,
                &p[4 * i..4 * i + 4],
                &digits(c.omega[j][i] as u128, 4),
            );
        }
        for (i, x) in p[wb..wb + 3].iter().enumerate() {
            a[i] += x.clone();
        }
        number::<AB>(&mut a, U256::from(modulus) << 64);
        product::<AB>(&mut d, &p[v..v + 4], &digits(c.gamma[j] as u128, 4));
        for (i, x) in p[y + 4 * j..y + 4 * j + 4].iter().enumerate() {
            d[i] += x.clone();
        }
        product::<AB>(
            &mut d,
            &p[u + 5 * j..u + 5 * j + 5],
            &digits(modulus as u128, 4),
        );
        number::<AB>(&mut d, U256::from(W_OFFSET));
        equation(builder, a, d, &p[carry + 21 + 7 * j..carry + 28 + 7 * j]);
    }
}
