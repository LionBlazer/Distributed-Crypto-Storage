//! One vector bank; public A, routing and inverse twiddles are verifier-derived.
use crate::statement::{INPUT_ROOT, OUTPUT_ROOT, PUBLIC_VALUES, Statement};
use crate::{
    BLOCKS, FIRST_STAGE, GADGETS, HASH_ROWS, MULTIPLY_ROW, N, OUTPUT_ROW, SCALE_ROW, hash_phase,
    psi, reverse,
};
use bfv_hiding_stark::poseidon;
use bfv_hiding_stark::{TRACE_HEIGHT, Val};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use std::{borrow::Cow, sync::OnceLock};

pub const VECTOR: usize = 0;
pub const P2: usize = N;
pub const CHECKPOINT: usize = P2 + GADGETS * poseidon::WIDTH;
pub const SALTS: usize = CHECKPOINT + 12;
pub const WIDTH: usize = SALTS + 8;
const _: () = assert!(WIDTH == 9452 && HASH_ROWS == 206 && OUTPUT_ROW + HASH_ROWS == 427);
pub struct ConvolutionAir {
    values: [Val; PUBLIC_VALUES],
    contexts: [[Val; 8]; 2],
    a_hat: Vec<Val>,
    inverse_powers: Vec<Vec<Val>>,
    normalization: Vec<Val>,
    periodic: OnceLock<Vec<Vec<Val>>>,
}
impl ConvolutionAir {
    pub fn new(statement: &Statement) -> Self {
        let phi_inverse = (psi() * psi()).inverse();
        let inverse_powers = (0..13)
            .map(|stage| {
                let half = 1 << stage;
                let step = phi_inverse.exp_u64((N / (2 * half)) as u64);
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
        let step = psi().inverse();
        let mut power = Val::from_usize(N).inverse();
        let normalization = (0..N)
            .map(|_| {
                let old = power;
                power *= step;
                old
            })
            .collect();
        Self {
            values: statement.public_values().try_into().unwrap(),
            contexts: statement.contexts(),
            a_hat: statement.expected.ciphertext().evaluations().to_vec(),
            inverse_powers,
            normalization,
            periodic: OnceLock::new(),
        }
    }
}
impl BaseAir<Val> for ConvolutionAir {
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
impl<AB: AirBuilder<F = Val>> Air<AB> for ConvolutionAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let next = main.next_slice();
        let selectors = builder.periodic_values().to_vec();
        for (actual, expected) in builder
            .public_values()
            .to_vec()
            .into_iter()
            .zip(self.values)
        {
            builder.assert_eq(actual, expected);
        }
        for at in SALTS..WIDTH {
            builder.when_transition().assert_eq(row[at], next[at]);
        }
        for value in &row[CHECKPOINT..CHECKPOINT + 12] {
            builder.when_first_row().assert_zero(*value);
        }
        // Every gadget always executes the same native P2 permutation, including idle zero inputs.
        let output: [[AB::Expr; 12]; GADGETS] = core::array::from_fn(|g| {
            poseidon::evaluate(
                builder,
                &row[P2 + g * poseidon::WIDTH..P2 + (g + 1) * poseidon::WIDTH],
            )
        });
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
                        _ => row[VECTOR + field - 16].into(),
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
        }
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
                let at = if role == 0 { INPUT_ROOT } else { OUTPUT_ROOT };
                for (i, digest) in output[last][..4].iter().enumerate() {
                    builder.assert_zero(sel.clone() * (digest.clone() - self.values[at + i]));
                }
            }
        }
        for (i, want) in cp.into_iter().enumerate() {
            builder
                .when_transition()
                .assert_eq(next[CHECKPOINT + i], want);
        }
        let multiply: AB::Expr = selectors[MULTIPLY_ROW].into();
        let scale: AB::Expr = selectors[SCALE_ROW].into();
        let mut hold = AB::Expr::ONE - multiply.clone() - scale.clone();
        for selector in &selectors[FIRST_STAGE..FIRST_STAGE + 13] {
            let selected: AB::Expr = (*selector).into();
            hold -= selected;
        }
        for i in 0..N {
            let current: AB::Expr = row[VECTOR + i].into();
            let reversed: AB::Expr = row[VECTOR + reverse(i)].into();
            let mut want = hold.clone() * current.clone()
                + multiply.clone() * self.a_hat[reverse(i)] * reversed
                + scale.clone() * self.normalization[i] * current;
            for stage in 0..13 {
                let half = 1 << stage;
                let within = i % (2 * half);
                let j = within % half;
                let base = i - within;
                let a: AB::Expr = row[VECTOR + base + j].into();
                let b: AB::Expr = row[VECTOR + base + j + half].into();
                let v = if within < half {
                    a + b * self.inverse_powers[stage][j]
                } else {
                    a - b * self.inverse_powers[stage][j]
                };
                let sel: AB::Expr = selectors[FIRST_STAGE + stage].into();
                want += sel * v;
            }
            // Real SDK transition selector: never the non-Boolean complement of is_last_row.
            builder.when_transition().assert_eq(next[VECTOR + i], want);
        }
    }
}
