//! Opens the original Ccmd and proves its hidden opcode belongs to six controls.
use super::{Expected, PUBLIC_VALUES, layout::*};
use crate::{Val, lifecycle::opening, source};
use bfv_hiding_stark::{TRACE_HEIGHT, poseidon};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Algebra, PrimeCharacteristicRing};
use std::{borrow::Cow, sync::OnceLock};

pub struct ControlKindAir {
    expected: Expected,
    values: Vec<Val>,
    context: Vec<Val>,
    periodics: OnceLock<Vec<Vec<Val>>>,
}
impl ControlKindAir {
    pub fn new(e: &Expected) -> Self {
        Self {
            expected: e.clone(),
            values: e.values(),
            context: e.lifecycle().expected.context(),
            periodics: OnceLock::new(),
        }
    }
    /// Pure original field ABI. Suffix policy is established by genuine Lifecycle.
    pub fn field<E: Algebra<Val>, T: Copy + Into<E>>(&self, row: &[T], f: usize) -> E {
        if let Some(v) = opening::command_prefix(&self.context, self.expected.roots().0, f) {
            return v;
        }
        match f {
            109 => CONTROL_OPCODES
                .iter()
                .enumerate()
                .map(|(i, op)| row[OPCODE + i].into() * E::from_u8(*op))
                .sum(),
            110..=158 => row[SUFFIX + f - 110].into(),
            _ => E::ZERO,
        }
    }
}
impl BaseAir<Val> for ControlKindAir {
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
    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        Cow::Borrowed(self.periodics.get_or_init(source::schedule::columns))
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(5)
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for ControlKindAir {
    fn eval(&self, b: &mut AB) {
        let public = b.public_values().to_vec();
        assert_eq!(public.len(), PUBLIC_VALUES);
        for (actual, expected) in public.into_iter().zip(&self.values) {
            b.assert_eq(actual, *expected);
        }
        let selectors: [AB::Expr; TRACE_HEIGHT] =
            core::array::from_fn(|i| b.periodic_values()[i].into());
        let main = b.main();
        let row = main.current_slice();
        let next = main.next_slice();
        for at in BANK..WIDTH {
            b.when_transition().assert_eq(next[at], row[at]);
        }
        for value in &row[OPCODE..SUFFIX] {
            b.assert_bool(*value);
        }
        b.assert_eq(
            row[OPCODE..SUFFIX]
                .iter()
                .copied()
                .map(Into::into)
                .sum::<AB::Expr>(),
            AB::Expr::ONE,
        );
        let active: AB::Expr = selectors[..END].iter().cloned().sum();
        for word in 0..8 {
            let expected: AB::Expr = selectors[..END]
                .iter()
                .enumerate()
                .map(|(r, s)| s.clone() * self.field::<AB::Expr, _>(row, 8 * r + word))
                .sum();
            b.assert_eq(row[word], expected);
        }
        for word in 8..12 {
            b.assert_eq(
                row[word],
                (active.clone() - selectors[0].clone()) * row[CP + word],
            );
        }
        let output = poseidon::evaluate(b, &row[..CP]);
        for (word, value) in output.iter().enumerate() {
            b.when_first_row().assert_zero(row[CP + word]);
            b.when_transition().assert_eq(
                next[CP + word],
                active.clone() * value.clone() + (AB::Expr::ONE - active.clone()) * row[CP + word],
            );
        }
        for (i, root) in self.expected.roots().1.iter().enumerate() {
            b.assert_zero(selectors[END - 1].clone() * (output[i].clone() - *root));
        }
    }
}
