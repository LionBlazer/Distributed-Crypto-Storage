//! Stateless coefficient equations shared by distinct, typed opening adapters.
use super::{
    air::{self, CARRY, COEFF, LANE_BITS},
    matrix,
};
use crate::backend::Val;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;

pub(in crate::opening) fn assert_bits<AB: AirBuilder<F = Val>>(b: &mut AB, row: &[AB::Var]) {
    for &bit in &row[COEFF..CARRY] {
        b.assert_bool(bit);
    }
}
pub(in crate::opening) fn evaluate<AB: AirBuilder<F = Val>>(
    b: &mut AB,
    row: &[AB::Var],
    periodic: &[AB::PeriodicVar],
) {
    for l in 0..16 {
        let sum: AB::Expr = (0..12)
            .map(|k| {
                let a: AB::Expr = periodic[l * 12 + k].into();
                a * air::original::<AB::Expr, _>(row, k)
            })
            .sum();
        let m: AB::Expr = air::lane(row, l, 0);
        let w: AB::Expr = air::lane(row, l, 1);
        let km: AB::Expr = air::lane(row, l, 2);
        let kw: AB::Expr = air::lane(row, l, 3);
        let sm: AB::Expr = air::lane(row, l, 4);
        let sw: AB::Expr = air::lane(row, l, 5);
        b.assert_eq(sum, m.clone() + km * Val::from_u64(matrix::T));
        b.assert_eq(
            m.clone() * Val::from_u64(matrix::Q_MOD_T),
            w.clone() + kw * Val::from_u64(matrix::T),
        );
        b.assert_eq(m + sm, Val::from_u64(matrix::T - 1));
        b.assert_eq(w + sw, Val::from_u64(matrix::T - 1));
    }
}
pub(in crate::opening) fn coefficients(original: [u64; 12]) -> Vec<(u64, u64)> {
    matrix::coefficients()
        .iter()
        .map(|a| {
            let dot: u64 = a.iter().zip(original).map(|(a, x)| u64::from(*a) * x).sum();
            let m = dot % matrix::T;
            (m, m * matrix::Q_MOD_T % matrix::T)
        })
        .collect()
}
pub(in crate::opening) fn write_lanes(row: &mut [Val], index: usize, original: [u64; 12]) {
    for l in 0..16 {
        let dot: u64 = matrix::coefficients()[index * 16 + l]
            .iter()
            .zip(original)
            .map(|(a, x)| u64::from(*a) * x)
            .sum();
        let m = dot % matrix::T;
        let w = m * matrix::Q_MOD_T % matrix::T;
        let fields = [
            m,
            w,
            dot / matrix::T,
            m * matrix::Q_MOD_T / matrix::T,
            matrix::T - 1 - m,
            matrix::T - 1 - w,
        ];
        for ((start, len), v) in [(0, 17), (17, 17), (34, 19), (53, 17), (70, 17), (87, 17)]
            .into_iter()
            .zip(fields)
        {
            let at = COEFF + l * LANE_BITS + start;
            for (i, x) in row[at..at + len].iter_mut().enumerate() {
                *x = Val::from_u64((v >> i) & 1);
            }
        }
    }
}
