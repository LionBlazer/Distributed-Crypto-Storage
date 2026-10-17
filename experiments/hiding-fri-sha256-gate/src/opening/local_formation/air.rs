//! Seven exact producer openings and all40960 INTEGER equations in Goldilocks.
use super::{
    DELTA, Q, STREAMS,
    statement::{PUBLIC_VALUES, Statement, root_offset},
};
use crate::backend::{TRACE_HEIGHT, Val};
use crate::opening::poseidon;
use crate::primitive::PublicStatement;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess, utils::pack_bits_le};
use p3_field::{Algebra, PrimeCharacteristicRing};
use std::{borrow::Cow, sync::OnceLock};

pub(super) const CP: usize = 21 * poseidon::WIDTH;
pub(super) const SALTS: usize = CP + 7 * 12;
pub(super) const CARRY: usize = SALTS + 7 * 4;
pub(super) const COEFFICIENTS: usize = CARRY + 7 * 8;
pub(super) const LANE_BITS: usize = 461;
pub(crate) const WIDTH: usize = COEFFICIENTS + 16 * LANE_BITS;
pub(super) const PERIODICS: usize = TRACE_HEIGHT + 5 * 16;
const _: () = assert!(WIDTH == 12752 && COEFFICIENTS == 5376);
pub(super) fn packed<E: Algebra<Val>, T: Copy + Into<E>>(
    row: &[T],
    lane: usize,
    start: usize,
    bits: usize,
) -> E {
    let a = COEFFICIENTS + lane * LANE_BITS + start;
    pack_bits_le(row[a..a + bits].iter().copied())
}
pub(super) fn value<E: Algebra<Val>, T: Copy + Into<E>>(
    row: &[T],
    lane: usize,
    stream: usize,
) -> E {
    match stream {
        0..=4 => packed(row, lane, stream * 63, 63) - Val::from_u64(1 << 62),
        5 => packed(row, lane, 427, 17),
        _ => packed(row, lane, 415, 6) - Val::from_u8(20),
    }
}
pub(crate) struct LocalAir {
    values: [Val; PUBLIC_VALUES],
    contexts: [[Val; 8]; STREAMS],
    b: [Vec<u64>; 5],
    periodics: OnceLock<Vec<Vec<Val>>>,
}
impl LocalAir {
    pub(super) fn new(s: &Statement) -> Self {
        Self {
            values: s.public_values().try_into().unwrap(),
            contexts: s.contexts(),
            b: core::array::from_fn(|i| {
                s.expected.bases[i]
                    .expected
                    .ciphertext()
                    .b_coefficients()
                    .to_vec()
            }),
            periodics: OnceLock::new(),
        }
    }
}
impl BaseAir<Val> for LocalAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        (0..WIDTH).collect()
    }
    fn num_periodic_columns(&self) -> usize {
        PERIODICS
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(5)
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        Cow::Borrowed(self.periodics.get_or_init(|| {
            let mut p: Vec<_> = (0..TRACE_HEIGHT)
                .map(|r| {
                    let mut v = vec![Val::ZERO; TRACE_HEIGHT];
                    v[r] = Val::ONE;
                    v
                })
                .collect();
            for i in 0..5 {
                for lane in 0..16 {
                    p.push(
                        (0..TRACE_HEIGHT)
                            .map(|r| Val::from_u64(self.b[i][16 * r + lane]))
                            .collect(),
                    );
                }
            }
            p
        }))
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for LocalAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let next = main.next_slice();
        let periodic = builder.periodic_values().to_vec();
        for (a, b) in builder
            .public_values()
            .to_vec()
            .into_iter()
            .zip(self.values)
        {
            builder.assert_eq(a, b);
        }
        for bit in &row[COEFFICIENTS..WIDTH] {
            builder.assert_bool(*bit);
        }
        let zero: AB::Expr = periodic[0].into();
        let one: AB::Expr = periodic[1].into();
        let later = AB::Expr::ONE - zero.clone() - one.clone();
        let third = zero.clone() + one.clone();
        for lane in 0..16 {
            let e: AB::Expr = value(row, lane, 6);
            let w: AB::Expr = value(row, lane, 5);
            let z: AB::Expr = packed(row, lane, 415, 6);
            let slack: AB::Expr = packed(row, lane, 421, 6);
            builder.assert_eq(z + slack, Val::from_u8(40));
            let slack: AB::Expr = packed(row, lane, 444, 17);
            builder.assert_eq(w.clone() + slack, Val::from_u32(114688));
            for i in 0..5 {
                let r: AB::Expr = value(row, lane, i);
                let k: AB::Expr =
                    packed::<AB::Expr, _>(row, lane, 315 + 20 * i, 20) - Val::from_u64(1 << 19);
                let b: AB::Expr = periodic[TRACE_HEIGHT + i * 16 + lane].into();
                builder.assert_zero(
                    b + r
                        - e.clone()
                        - w.clone() * Val::from_u64(DELTA[i])
                        - k * Val::from_u64(Q[i]),
                );
            }
        }
        for stream in 0..STREAMS {
            let out: [[AB::Expr; 12]; 3] = core::array::from_fn(|g| {
                poseidon::evaluate(
                    builder,
                    &row[(stream * 3 + g) * poseidon::WIDTH
                        ..(stream * 3 + g + 1) * poseidon::WIDTH],
                )
            });
            for g in 0..3 {
                for slot in 0..12 {
                    let want: AB::Expr = if slot < 8 {
                        match g {
                            0 => {
                                zero.clone() * self.contexts[stream][slot]
                                    + one.clone() * row[CARRY + stream * 8 + slot]
                                    + later.clone() * value::<AB::Expr, _>(row, slot, stream)
                            }
                            1 => {
                                let salt: AB::Expr = if slot < 4 {
                                    row[SALTS + stream * 4 + slot].into()
                                } else {
                                    AB::Expr::ZERO
                                };
                                zero.clone() * salt
                                    + one.clone() * value::<AB::Expr, _>(row, slot, stream)
                                    + later.clone() * value::<AB::Expr, _>(row, 8 + slot, stream)
                            }
                            _ => {
                                zero.clone() * value::<AB::Expr, _>(row, slot, stream)
                                    + one.clone() * value::<AB::Expr, _>(row, 8 + slot, stream)
                            }
                        }
                    } else {
                        match g {
                            0 => (AB::Expr::ONE - zero.clone()) * row[CP + stream * 12 + slot],
                            1 => out[0][slot].clone(),
                            _ => third.clone() * out[1][slot].clone(),
                        }
                    };
                    builder.assert_eq(row[(stream * 3 + g) * poseidon::WIDTH + slot], want);
                }
            }
            for slot in 0..12 {
                builder
                    .when_first_row()
                    .assert_zero(row[CP + stream * 12 + slot]);
                builder.when_transition().assert_eq(
                    next[CP + stream * 12 + slot],
                    third.clone() * out[2][slot].clone() + later.clone() * out[1][slot].clone(),
                );
            }
            for slot in 0..8 {
                builder
                    .when_first_row()
                    .assert_zero(row[CARRY + stream * 8 + slot]);
                builder.when_transition().assert_eq(
                    next[CARRY + stream * 8 + slot],
                    zero.clone() * value::<AB::Expr, _>(row, 8 + slot, stream),
                );
            }
            for i in 0..4 {
                builder
                    .when_transition()
                    .assert_eq(next[SALTS + stream * 4 + i], row[SALTS + stream * 4 + i]);
                builder
                    .when_last_row()
                    .assert_eq(out[1][i].clone(), self.values[root_offset(stream) + i]);
            }
        }
    }
}
