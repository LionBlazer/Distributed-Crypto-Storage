//! Actual hiding AIR: one persistent private mask opens three distinct commitments.
use super::{Expected, PUBLIC_VALUES, layout::*};
use crate::{
    Val, coefficient_encoding,
    lifecycle::{
        opening,
        ranges::{code, pack},
    },
    source,
};
use bfv_hiding_stark::{TRACE_HEIGHT, poseidon};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Algebra, PrimeCharacteristicRing};
use std::{borrow::Cow, sync::OnceLock};

pub struct PredicateAcquireAir {
    expected: Expected,
    values: Vec<Val>,
    query_prefix: Vec<Val>,
    context: Vec<Val>,
    roots: [Val; 12],
    periodics: OnceLock<Vec<Vec<Val>>>,
}
impl PredicateAcquireAir {
    pub fn new(e: &Expected) -> Self {
        let q = &e.query().expected;
        let query_prefix = source::statement::words(&coefficient_encoding::COMMAND_DOMAIN)
            .chain([Val::ONE])
            .chain(source::statement::words(
                &coefficient_encoding::profile_digest(coefficient_encoding::Role::PrivateMask),
            ))
            .chain(q.base_context())
            .chain(source::statement::words(&q.sql_identity()))
            .collect();
        Self {
            expected: e.clone(),
            values: e.values(),
            query_prefix,
            context: e.lifecycle().expected.context(),
            roots: e.roots(),
            periodics: OnceLock::new(),
        }
    }
    /// Pure field assembly; this does not execute Acquire or inspect Source rows.
    pub fn field<E: Algebra<Val>, T: Copy + Into<E>>(
        &self,
        row: &[T],
        stream: Stream,
        f: usize,
    ) -> E {
        match stream {
            Stream::Mask => match f {
                0..=28 => E::from(self.query_prefix[f]),
                29..=36 => pack(row, MASK + 32 * (f - 29), 32),
                37..=40 => row[SALTS + f - 37].into(),
                _ => E::ZERO,
            },
            Stream::Command => {
                if let Some(value) =
                    opening::command_prefix(&self.context, self.roots[..4].try_into().unwrap(), f)
                {
                    return value;
                }
                match f {
                    109 => E::ONE, // Acquire, never another old operation.
                    110..=111 => pack(row, TX + 32 * (f - 110), 32),
                    112 => row[PRINCIPAL].into() + row[PRINCIPAL + 1].into() * E::from_u8(2),
                    113..=120 => pack(row, CONTROLLER + 32 * (f - 113), 32),
                    121..=122 => pack(row, REV + 32 * (f - 121), 32),
                    123..=124 => pack(row, SEQ + 32 * (f - 123), 32),
                    125..=132 => pack(row, MASK + 32 * (f - 125), 32),
                    133 => {
                        code::<E, _>(row, MODE, 4) + (0..4).map(|i| row[MODE + i].into()).sum::<E>()
                    }
                    134 => code(row, WAIT, 3),
                    135 => pack(row, OFFSET, 3),
                    136 => pack(row, LIMIT, 3),
                    137 => pack(row, PROJECTION, 2),
                    155..=158 => row[SALTS + 4 + f - 155].into(),
                    _ => E::ZERO,
                }
            }
            Stream::Result => {
                if let Some(value) = opening::result_prefix(&self.context, self.roots, f) {
                    return value;
                }
                match f {
                    117 => E::ONE,
                    118 => E::ZERO, // Acquire SUCCESS only.
                    119..=120 => pack(row, TX + 32 * (f - 119), 32),
                    121..=132 => row[FLAGS + f - 121].into(),
                    133..=136 => row[SALTS + 8 + f - 133].into(),
                    _ => E::ZERO,
                }
            }
        }
    }
}
impl BaseAir<Val> for PredicateAcquireAir {
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
impl<AB: AirBuilder<F = Val>> Air<AB> for PredicateAcquireAir {
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
        for value in &row[BANK..SALTS] {
            b.assert_bool(*value);
        }
        for (at, n) in [(PRINCIPAL, 2), (MODE, 4), (WAIT, 3)] {
            b.assert_eq(
                row[at..at + n]
                    .iter()
                    .copied()
                    .map(Into::into)
                    .sum::<AB::Expr>(),
                AB::Expr::ONE,
            );
        }
        for at in [OFFSET, LIMIT] {
            b.assert_zero(row[at + 2] * (row[at] + row[at + 1]));
        }
        b.assert_zero(
            (AB::Expr::ONE - row[PROJECTION].into()) * (AB::Expr::ONE - row[PROJECTION + 1].into()),
        );
        let active: AB::Expr = selectors[..END].iter().cloned().sum();
        let resets: AB::Expr = [0, 6, 26].into_iter().map(|r| selectors[r].clone()).sum();
        for word in 0..8 {
            let expected: AB::Expr = selectors[..END]
                .iter()
                .enumerate()
                .map(|(r, selector)| {
                    let (stream, block) = absorb(r).unwrap();
                    selector.clone() * self.field::<AB::Expr, _>(row, stream, 8 * block + word)
                })
                .sum();
            b.assert_eq(row[word], expected);
        }
        for word in 8..12 {
            b.assert_eq(
                row[word],
                (active.clone() - resets.clone()) * row[CP + word],
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
        for (last, root) in [
            (5, self.expected.query().expected.command()),
            (25, self.roots[4..8].try_into().unwrap()),
            (43, self.expected.lifecycle().result),
        ] {
            for i in 0..4 {
                b.assert_zero(selectors[last].clone() * (output[i].clone() - root[i]));
            }
        }
    }
}
