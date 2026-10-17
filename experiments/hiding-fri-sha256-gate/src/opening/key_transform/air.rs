//! One fixed vector bank; all column routes and twiddles are verifier-owned constants.
use super::statement::{PUBLIC_VALUES, Statement};
use super::{
    BLOCKS, FIELDS, FIRST_STAGE, GADGETS, HASH_ROWS, N, TWIST_ROW, hash_phase, psi, reverse,
};
use crate::backend::{TRACE_HEIGHT, Val};
use crate::opening::poseidon;
use crate::primitive::PublicStatement;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess, utils::pack_bits_le};
use p3_field::PrimeCharacteristicRing;
use std::{borrow::Cow, sync::OnceLock};

pub(super) const VECTOR: usize = 0;
pub(super) const P2: usize = N;
pub(super) const CHECKPOINT: usize = P2 + GADGETS * poseidon::WIDTH;
pub(super) const SALTS: usize = CHECKPOINT + 12;
pub(super) const RANGE: usize = SALTS + 8;
pub(crate) const WIDTH: usize = RANGE + 40 * 12;
const _: () = assert!(WIDTH == 9932 && FIELDS == 8208 && HASH_ROWS == 206);

pub(crate) struct TransformAir {
    values: [Val; PUBLIC_VALUES],
    contexts: [[Val; 8]; 2],
    periodic: OnceLock<Vec<Vec<Val>>>,
    twist_powers: Vec<Val>,
    stage_powers: Vec<Vec<Val>>,
}
impl TransformAir {
    pub(super) fn new(statement: &Statement) -> Self {
        let mut power = Val::ONE;
        let twist_powers = (0..N)
            .map(|_| {
                let old = power;
                power *= psi();
                old
            })
            .collect();
        let phi = psi() * psi();
        let stage_powers = (0..13)
            .map(|stage| {
                let half = 1 << stage;
                let step = phi.exp_u64((N / (2 * half)) as u64);
                let mut power = Val::ONE;
                (0..half)
                    .map(|_| {
                        let old = power;
                        power *= step;
                        old
                    })
                    .collect()
            })
            .collect();
        Self {
            twist_powers,
            stage_powers,
            values: statement.public_values().try_into().unwrap(),
            contexts: statement.contexts(),
            periodic: OnceLock::new(),
        }
    }
}
impl BaseAir<Val> for TransformAir {
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
        TRACE_HEIGHT
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(5)
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        Cow::Borrowed(self.periodic.get_or_init(|| {
            (0..TRACE_HEIGHT)
                .map(|i| {
                    let mut v = vec![Val::ZERO; TRACE_HEIGHT];
                    v[i] = Val::ONE;
                    v
                })
                .collect()
        }))
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for TransformAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let next = main.next_slice();
        let selectors = builder.periodic_values().to_vec();
        let pv = builder.public_values().to_vec();
        for (actual, expected) in pv.into_iter().zip(self.values) {
            builder.assert_eq(actual, expected);
        }
        for at in SALTS..RANGE {
            builder.when_transition().assert_eq(row[at], next[at]);
        }
        for value in &row[CHECKPOINT..CHECKPOINT + 12] {
            builder.when_first_row().assert_zero(*value);
        }
        for bit in &row[RANGE..WIDTH] {
            builder.assert_bool(*bit);
        }
        let output: [[AB::Expr; 12]; GADGETS] = core::array::from_fn(|g| {
            poseidon::evaluate(
                builder,
                &row[P2 + g * poseidon::WIDTH..P2 + (g + 1) * poseidon::WIDTH],
            )
        });
        // Each lane is one rate input. The first16 fields and inactive slots have zero range auxiliaries.
        for g in 0..GADGETS {
            let mut expected: [AB::Expr; 12] = core::array::from_fn(|_| AB::Expr::ZERO);
            for (physical, selector) in selectors.iter().copied().enumerate() {
                let Some((role, local)) = hash_phase(physical) else {
                    continue;
                };
                let block = local * GADGETS + g;
                if block >= BLOCKS {
                    continue;
                }
                let active: AB::Expr = selector.into();
                for (slot, value) in expected[..8].iter_mut().enumerate() {
                    let field = block * 8 + slot;
                    let term: AB::Expr = match field {
                        0..=7 => self.contexts[role][field].into(),
                        8..=11 => row[SALTS + role * 4 + field - 8].into(),
                        12..=15 => AB::Expr::ZERO,
                        _ => {
                            let v: AB::Expr = row[VECTOR + field - 16].into();
                            v + Val::from_u8(if role == 0 { 20 } else { 0 })
                        }
                    };
                    *value = value.clone() + active.clone() * term;
                }
                if block != 0 {
                    for (cap, value) in expected.iter_mut().enumerate().skip(8) {
                        let prev: AB::Expr = if g == 0 {
                            row[CHECKPOINT + cap].into()
                        } else {
                            output[g - 1][cap].clone()
                        };
                        *value = value.clone() + active.clone() * prev;
                    }
                }
            }
            for (i, want) in expected.into_iter().enumerate() {
                builder.assert_eq(row[P2 + g * poseidon::WIDTH + i], want);
            }
            for slot in 0..8 {
                let lane = g * 8 + slot;
                let at = RANGE + lane * 12;
                let z: AB::Expr = pack_bits_le(row[at..at + 6].iter().copied());
                let slack: AB::Expr = pack_bits_le(row[at + 6..at + 12].iter().copied());
                let mut bound = AB::Expr::ZERO;
                let mut used = AB::Expr::ZERO;
                for (physical, selector) in selectors.iter().copied().enumerate().take(HASH_ROWS) {
                    let field = (physical * GADGETS + g) * 8 + slot;
                    if (16..FIELDS).contains(&field) {
                        let selector: AB::Expr = selector.into();
                        let coefficient: AB::Expr = row[VECTOR + field - 16].into();
                        bound += selector.clone() * (coefficient + Val::from_u8(20));
                        used += selector;
                    }
                }
                builder.assert_eq(z.clone(), bound);
                builder.assert_eq(z + slack, used * Val::from_u8(40));
            }
        }
        // Checkpoint changes only to an ACTIVE gadget; a partial last row ends at gadget0.
        let mut cp: [AB::Expr; 12] = core::array::from_fn(|i| row[CHECKPOINT + i].into());
        for (physical, selector) in selectors.iter().copied().enumerate() {
            let Some((role, local)) = hash_phase(physical) else {
                continue;
            };
            let last = (BLOCKS - local * GADGETS).min(GADGETS) - 1;
            let sel: AB::Expr = selector.into();
            for (i, value) in cp.iter_mut().enumerate() {
                let old: AB::Expr = row[CHECKPOINT + i].into();
                *value = value.clone() + sel.clone() * (output[last][i].clone() - old);
            }
            if local == HASH_ROWS - 1 {
                for (i, digest) in output[last][..4].iter().enumerate() {
                    builder.assert_zero(
                        sel.clone()
                            * (digest.clone() - self.values[PUBLIC_VALUES - 8 + role * 4 + i]),
                    );
                }
            }
        }
        for (i, want) in cp.into_iter().enumerate() {
            builder
                .when_transition()
                .assert_eq(next[CHECKPOINT + i], want);
        }
        let twist: AB::Expr = selectors[TWIST_ROW].into();
        let mut hold = AB::Expr::ONE - twist.clone();
        for selector in &selectors[FIRST_STAGE..FIRST_STAGE + 13] {
            let selected: AB::Expr = (*selector).into();
            hold -= selected;
        }
        for i in 0..N {
            let current: AB::Expr = row[VECTOR + i].into();
            let reversed: AB::Expr = row[VECTOR + reverse(i)].into();
            let mut want =
                hold.clone() * current + twist.clone() * self.twist_powers[reverse(i)] * reversed;
            for stage in 0..13 {
                let half = 1 << stage;
                let within = i % (2 * half);
                let j = within % half;
                let base = i - within;
                let a: AB::Expr = row[VECTOR + base + j].into();
                let b: AB::Expr = row[VECTOR + base + j + half].into();
                let twiddle = self.stage_powers[stage][j];
                let value = if within < half {
                    a + b * twiddle
                } else {
                    a - b * twiddle
                };
                let sel: AB::Expr = selectors[FIRST_STAGE + stage].into();
                want += sel * value;
            }
            // SDK transition selector is used directly, never 1-is_last_row().
            builder.when_transition().assert_eq(next[VECTOR + i], want);
        }
    }
}
