//! Actual sequential progress/carry equations; never calls a native model.
use super::{
    transition::Statement,
    transition_fields::{self as fields, Fields, selected_progress},
    transition_layout::*,
};
use crate::{
    Val,
    lifecycle::{
        control, predicate,
        ranges::{self, pack},
    },
    poseidon,
    source::schedule,
};
use bfv_hiding_stark::TRACE_HEIGHT;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use std::{borrow::Cow, sync::OnceLock};
pub(super) struct ProgressAir {
    pub fields: Fields,
    values: Vec<Val>,
    periodics: OnceLock<Vec<Vec<Val>>>,
}
impl ProgressAir {
    pub fn new(s: &Statement) -> Self {
        Self {
            fields: Fields::new(s),
            values: s.values(),
            periodics: OnceLock::new(),
        }
    }
}
impl BaseAir<Val> for ProgressAir {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }
    fn num_public_values(&self) -> usize {
        self.values.len()
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        (0..TRACE_WIDTH).collect()
    }
    fn num_periodic_columns(&self) -> usize {
        TRACE_HEIGHT
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        Cow::Borrowed(self.periodics.get_or_init(schedule::columns))
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(5)
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for ProgressAir {
    fn eval(&self, b: &mut AB) {
        for (a, v) in b.public_values().to_vec().into_iter().zip(&self.values) {
            b.assert_eq(a, *v);
        }
        let selectors: [AB::Expr; TRACE_HEIGHT] =
            core::array::from_fn(|r| b.periodic_values()[r].into());
        let main = b.main();
        let row = main.current_slice();
        let next = main.next_slice();
        for at in (TABLE..ACC).chain(SEARCH..TRACE_WIDTH) {
            b.when_transition().assert_eq(next[at], row[at]);
        }
        for at in (WORDS..TABLE)
            .chain(CONTROLLERS..SALTS)
            .chain(CLIENT..STMT_ROOT)
            .chain(RESUME..POP_INVERSES)
        {
            b.assert_bool(row[at]);
        }
        for &cell in &row[MATCHES..ACC] {
            b.assert_bool(cell);
        }
        for &cell in &row[SEARCH..WIDTH] {
            b.assert_bool(cell);
        }
        for bank in [OLD_PROGRESS, NEW_PROGRESS] {
            for t in 0..2 {
                let at = progress(bank, t);
                b.assert_bool(row[at]);
                let base = slot(if bank == OLD_PROGRESS { OLD } else { NEW }, t);
                b.assert_zero(row[at] * (AB::Expr::ONE - row[base + PRESENT].into()));
                b.assert_zero(row[at] * row[base + FAILED]);
                for w in 1..5 {
                    b.assert_zero((AB::Expr::ONE - row[at].into()) * row[at + w]);
                }
            }
        }
        let source_active: AB::Expr = selectors[..85].iter().cloned().sum();
        for bit in 0..256 {
            b.assert_zero((AB::Expr::ONE - source_active.clone()) * row[WORDS + bit]);
        }
        for (r, sel) in selectors[..85].iter().enumerate() {
            for word in 0..8 {
                if !(87..674).contains(&(8 * r + word)) {
                    for bit in 0..32 {
                        b.assert_zero(sel.clone() * row[WORDS + 32 * word + bit]);
                    }
                }
            }
        }
        for (bank, first, count) in [(TABLE, 31, 8), (IDS, 555, 32)] {
            for word in 0..count {
                let f = 87 + first + word;
                b.assert_zero(
                    selectors[f / 8].clone()
                        * (row[bank + word] - pack::<AB::Expr, _>(row, WORDS + 32 * (f % 8), 32)),
                );
            }
        }
        for r in 0..4 {
            for bit in 0..8 {
                let byte = 3 * r;
                let f = 87 + byte / 4;
                b.assert_zero(
                    selectors[f / 8].clone()
                        * (row[AGES + 8 * r + bit]
                            - row[WORDS + 32 * (f % 8) + 8 * (byte % 4) + bit]),
                );
            }
        }
        for t in 0..2 {
            let pop: AB::Expr = row[CONTROLLERS + 256 * t..CONTROLLERS + 256 * (t + 1)]
                .iter()
                .copied()
                .map(Into::into)
                .sum();
            b.assert_eq(pop * row[CTRL_INV + t], AB::Expr::ONE);
        }
        ranges::canonical(b, row);
        b.assert_eq(row[SUCCESS], AB::Expr::ONE);
        let parent = crate::source::statement::words(&self.fields.statement.expected.base.parent)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        control::eval(b, row, parent);
        let scan: AB::Expr = selectors[..256].iter().cloned().sum();
        let threshold: AB::Expr = selectors[..256]
            .iter()
            .enumerate()
            .map(|(r, s)| s.clone() * Val::from_usize(r))
            .sum();
        let mask: AB::Expr = selectors[..256]
            .iter()
            .enumerate()
            .map(|(r, s)| s.clone() * row[QUERY_MASK + r])
            .sum();
        for i in 0..4 {
            predicate::eval_row(
                b,
                row,
                next,
                &selectors,
                pack(row, AGES + 8 * i, 8),
                predicate::Columns {
                    equality: EQUALITY + 11 * i,
                    accumulator: ACC + i,
                    matched: MATCHES + i,
                },
                predicate::Scan {
                    active: scan.clone(),
                    threshold: threshold.clone(),
                    mask: mask.clone(),
                },
            );
        }
        let predicate = self.fields.statement.expected.is_predicate();
        if predicate {
            self.predicate(b, row);
        } else {
            b.assert_zero(row[OP + 1]);
            b.assert_zero(row[OP + 2]);
            for &cell in &row[CLIENT..TRACE_WIDTH] {
                b.assert_zero(cell);
            }
            for &cell in &row[SEARCH..DESIRED] {
                b.assert_zero(cell);
            }
            let parked: AB::Expr = selected_progress(row, OLD_PROGRESS, 0);
            b.assert_zero(parked.clone() * (AB::Expr::ONE - row[OP + 6].into()));
            b.assert_zero(parked * (AB::Expr::ONE - row[ABORT].into()));
        }
        // Desired held modes are shared with the original exact base transition.
        for i in 0..4 {
            for m in 0..5 {
                let own: AB::Expr = (0..2)
                    .map(|t| row[ACTOR + t] * row[held(slot(OLD, t), i, m)])
                    .sum();
                let expected = if predicate {
                    let desired: AB::Expr = (0..5)
                        .flat_map(|old| {
                            (1..5)
                                .filter(move |r| old.max(*r) == m)
                                .map(move |r| (old, r))
                        })
                        .map(|(old, r)| {
                            let own: AB::Expr = (0..2)
                                .map(|t| row[ACTOR + t] * row[held(slot(OLD, t), i, old)])
                                .sum();
                            own * row[QUERY_MODE + r - 1]
                        })
                        .sum();
                    (AB::Expr::ONE - row[STATUS + 2].into()) * desired + row[STATUS + 2] * own
                } else {
                    own
                };
                b.assert_eq(row[DESIRED + 5 * i + m], expected);
            }
        }
        for t in 0..2 {
            for part in 0..5 {
                let old = row[progress(OLD_PROGRESS, t) + part];
                let expected: AB::Expr = if predicate {
                    if part == 0 {
                        (AB::Expr::ONE - row[ACTOR + t].into()) * old + row[ACTOR + t] * row[STATUS]
                    } else {
                        (AB::Expr::ONE - row[ACTOR + t].into()) * old
                            + row[ACTOR + t] * row[progress(NEW_PROGRESS, t) + part]
                    }
                } else {
                    let ended: AB::Expr = if t == 0 {
                        (AB::Expr::ONE - row[ACTOR].into()) * row[progress(OLD_PROGRESS, 0) + part]
                            + row[ACTOR] * row[progress(OLD_PROGRESS, 1) + part]
                    } else {
                        AB::Expr::ZERO
                    };
                    let end: AB::Expr = row[OP + 6].into();
                    old + end * (ended - old)
                };
                b.assert_eq(row[progress(NEW_PROGRESS, t) + part], expected);
            }
        }
        let output = poseidon::evaluate(b, &row[..CP]);
        let active: AB::Expr = selectors[..215].iter().cloned().sum();
        for word in 0..8 {
            let expected: AB::Expr = selectors[..215]
                .iter()
                .enumerate()
                .map(|(r, s)| {
                    let (stream, block) = fields::absorb(r).unwrap();
                    s.clone()
                        * self
                            .fields
                            .field::<AB::Expr, _>(row, stream, 8 * block + word, word)
                })
                .sum();
            b.assert_eq(row[word], expected);
        }
        let resets: AB::Expr = fields::RESETS
            .into_iter()
            .map(|r| selectors[r].clone())
            .sum();
        for w in 8..12 {
            b.assert_eq(row[w], (active.clone() - resets.clone()) * row[CP + w]);
        }
        for (w, out) in output.iter().enumerate() {
            b.when_first_row().assert_zero(row[CP + w]);
            b.when_transition().assert_eq(
                next[CP + w],
                active.clone() * out.clone() + (AB::Expr::ONE - active.clone()) * row[CP + w],
            );
        }
        let e = &self.fields.statement.expected;
        for (last, root) in [
            (84, e.source().open_commitment),
            (92, e.base.enrollment),
            (118, e.old),
            (138, e.command),
            (164, self.fields.statement.next),
            (184, self.fields.statement.result),
        ] {
            for (w, out) in output.iter().take(4).enumerate() {
                b.assert_zero(selectors[last].clone() * (out.clone() - root[w]));
            }
        }
        if let Some(query) = e.query() {
            for (w, out) in output.iter().take(4).enumerate() {
                b.assert_zero(selectors[196].clone() * (out.clone() - row[STMT_ROOT + w]));
                b.assert_zero(
                    selectors[202].clone()
                        * row[RESUME]
                        * (out.clone()
                            - selected_progress::<AB::Expr, _>(row, OLD_PROGRESS, 1 + w)),
                );
                b.assert_zero(
                    selectors[208].clone()
                        * row[STATUS]
                        * (out.clone()
                            - selected_progress::<AB::Expr, _>(row, NEW_PROGRESS, 1 + w)),
                );
                b.assert_zero(selectors[214].clone() * (out.clone() - query.expected.command()[w]));
            }
        }
    }
}
impl ProgressAir {
    fn predicate<AB: AirBuilder<F = Val>>(&self, b: &mut AB, row: &[AB::Var]) {
        super::equations::predicate(
            b,
            row,
            self.fields
                .statement
                .expected
                .query()
                .unwrap()
                .expected
                .sql_identity(),
        );
    }
}
