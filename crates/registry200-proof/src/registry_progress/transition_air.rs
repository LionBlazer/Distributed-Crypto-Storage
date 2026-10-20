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
        ranges::{self, code, pack},
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
fn compare<AB: AirBuilder<F = Val>>(
    b: &mut AB,
    row: &[AB::Var],
    prefix: AB::Expr,
    bound: AB::Expr,
    at: usize,
) {
    b.assert_eq(
        prefix + Val::from_u8(8) - bound,
        pack::<AB::Expr, _>(row, at, 3) + row[at + 3] * Val::from_u8(8),
    );
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
        let error: AB::Expr = row[STATUS + 2].into();
        let resume: AB::Expr = row[RESUME].into();
        for i in [0, 3, 4, 5, 6] {
            b.assert_zero(row[OP + i]);
        }
        b.assert_eq(row[OP + 1], AB::Expr::ONE - error.clone());
        b.assert_eq(row[OP + 2], error.clone());
        b.assert_eq(
            resume.clone(),
            selected_progress::<AB::Expr, _>(row, OLD_PROGRESS, 0),
        );
        let query = self.fields.statement.expected.query().unwrap();
        for (w, v) in crate::source::statement::words(&query.expected.sql_identity()).enumerate() {
            b.assert_zero(
                (AB::Expr::ONE - resume.clone())
                    * (pack::<AB::Expr, _>(row, ORIGINAL_SQL + 32 * w, 32) - v),
            );
        }
        for (at, n) in [
            (QUERY_MODE, 4),
            (QUERY_WAIT, 3),
            (OLD_CURSOR, 5),
            (NEW_CURSOR, 5),
            (STATUS, 3),
        ] {
            b.assert_eq(
                row[at..at + n]
                    .iter()
                    .copied()
                    .map(Into::into)
                    .sum::<AB::Expr>(),
                AB::Expr::ONE,
            );
        }
        b.assert_zero(row[ABORT]);
        b.assert_zero(resume.clone() * (row[QUERY_WAIT + 1] + row[QUERY_WAIT + 2]));
        for bit in 0..256 {
            b.assert_eq(
                row[MASK + bit],
                (AB::Expr::ONE - error.clone()) * row[QUERY_MASK + bit],
            );
        }
        for i in 0..4 {
            b.assert_eq(
                row[MODE + i],
                (AB::Expr::ONE - error.clone()) * row[QUERY_MODE + i],
            );
        }
        for i in 0..3 {
            b.assert_eq(
                row[WAIT + i],
                (AB::Expr::ONE - error.clone()) * row[QUERY_WAIT + i],
            );
        }
        for i in 0..2 {
            b.assert_eq(
                row[PROJECTION + i],
                (AB::Expr::ONE - error.clone()) * row[QUERY_PROJECTION + i],
            );
        }
        b.assert_zero(
            (AB::Expr::ONE - row[QUERY_PROJECTION].into())
                * (AB::Expr::ONE - row[QUERY_PROJECTION + 1].into()),
        );
        for at in [QUERY_OFFSET, QUERY_LIMIT] {
            b.assert_zero(row[at + 2] * (row[at] + row[at + 1]));
        }
        for i in 0..3 {
            b.assert_eq(
                row[OFFSET + i],
                (AB::Expr::ONE - error.clone()) * row[QUERY_OFFSET + i],
            );
            b.assert_eq(
                row[LIMIT + i],
                (AB::Expr::ONE - error.clone()) * row[QUERY_LIMIT + i],
            );
        }
        b.assert_zero(row[OLD_CURSOR + 4]);
        b.assert_zero((AB::Expr::ONE - resume.clone()) * (AB::Expr::ONE - row[OLD_CURSOR].into()));
        for (at, n, index) in [
            (CLIENT, 256, 0),
            (CALL, 64, 1),
            (INVOCATION, 256, 2),
            (OLD_MICRO, 64, 3),
            (OLD_HOLDER, 64, 4),
        ] {
            let gate = if index < 3 {
                AB::Expr::ONE
            } else {
                resume.clone()
            };
            let pop: AB::Expr = row[at..at + n].iter().copied().map(Into::into).sum();
            b.assert_eq(pop * row[POP_INVERSES + index], gate.clone());
            if index >= 3 {
                b.assert_zero((AB::Expr::ONE - gate.clone()) * row[POP_INVERSES + index]);
                for v in &row[at..at + n] {
                    b.assert_zero((AB::Expr::ONE - gate.clone()) * *v);
                }
            }
        }
        let difference: AB::Expr = (0..64)
            .map(|i| {
                let d: AB::Expr = row[OLD_HOLDER + i] - row[ID_CMD + i];
                d.clone() * d
            })
            .sum();
        b.assert_eq(
            resume.clone() * difference * row[POP_INVERSES + 5],
            resume.clone(),
        );
        b.assert_zero((AB::Expr::ONE - resume.clone()) * row[POP_INVERSES + 5]);
        b.assert_eq(
            row[OLD_HOLDER_MODE..OLD_HOLDER_MODE + 4]
                .iter()
                .copied()
                .map(Into::into)
                .sum::<AB::Expr>(),
            resume.clone(),
        );
        let old_conflict: AB::Expr = (1..5)
            .flat_map(|a| {
                (1..5)
                    .filter(move |c| crate::lifecycle::conflicts(a as u8, *c as u8))
                    .map(move |c| (a, c))
            })
            .map(|(a, c)| row[QUERY_MODE + a - 1] * row[OLD_HOLDER_MODE + c - 1])
            .sum();
        b.assert_eq(old_conflict, resume.clone());
        b.assert_zero(row[BLOCK_REV_COMPARE]);
        for bit in 0..64 {
            b.assert_zero((AB::Expr::ONE - resume.clone()) * row[OLD_BLOCK_REV + bit]);
            let d: AB::Expr =
                row[OLD_BLOCK_REV + bit] - row[OLD + REV + bit] - row[BLOCK_REV_COMPARE + bit]
                    + row[BLOCK_REV_COMPARE + bit + 1] * Val::from_u8(2);
            b.when(resume.clone()).assert_bool(d);
        }
        b.assert_eq(row[BLOCK_REV_COMPARE + 64], resume.clone());
        for bit in 0..65 {
            b.assert_zero((AB::Expr::ONE - resume.clone()) * row[BLOCK_REV_COMPARE + bit]);
        }
        for w in 0..4 {
            b.assert_zero((AB::Expr::ONE - resume.clone()) * row[EXTRA_SALTS + 4 + w]);
        }
        ranges::increment(
            b,
            row,
            [pack(row, OLD_MICRO, 32), pack(row, OLD_MICRO + 32, 32)],
            NEW_MICRO,
            MICRO_CARRY,
            AB::Expr::ONE,
        );
        for i in 0..4 {
            let before: AB::Expr = (i + 1..5).map(|j| row[OLD_CURSOR + j].into()).sum();
            b.assert_eq(
                row[OLD_VISITED + i],
                resume.clone() * before.clone() * row[MATCHES + i],
            );
            compare(
                b,
                row,
                (0..i).map(|j| row[OLD_VISITED + j].into()).sum(),
                pack(row, QUERY_OFFSET, 3),
                OLD_OFFSET_CMP + 4 * i,
            );
            b.assert_eq(
                row[OLD_SELECTED + i],
                row[OLD_VISITED + i] * row[OLD_OFFSET_CMP + 4 * i + 3],
            );
            let bad_held: AB::Expr = (1..5)
                .flat_map(|m| (0..m).map(move |h| (m, h)))
                .map(|(m, h)| {
                    let own: AB::Expr = (0..2)
                        .map(|t| row[ACTOR + t] * row[held(slot(OLD, t), i, h)])
                        .sum();
                    row[QUERY_MODE + m - 1] * own
                })
                .sum();
            b.assert_zero(row[OLD_VISITED + i] * bad_held);
            let other: [AB::Expr; 5] = core::array::from_fn(|m| {
                (0..2)
                    .map(|t| row[ACTOR + t] * row[held(slot(OLD, 1 - t), i, m)])
                    .sum()
            });
            let conflict: AB::Expr = row[QUERY_MODE] * other[4].clone()
                + row[QUERY_MODE + 1] * (other[3].clone() + other[4].clone())
                + row[QUERY_MODE + 2] * (other[2].clone() + other[3].clone() + other[4].clone())
                + row[QUERY_MODE + 3]
                    * (other[1].clone() + other[2].clone() + other[3].clone() + other[4].clone());
            b.assert_eq(row[CONFLICT + i], conflict);
            compare(
                b,
                row,
                (0..i).map(|j| row[NEW_SELECTED + j].into()).sum(),
                pack(row, QUERY_LIMIT, 3),
                LIMIT_CMP + 4 * i,
            );
            compare(
                b,
                row,
                (0..i).map(|j| row[NEW_VISITED + j].into()).sum(),
                pack(row, QUERY_OFFSET, 3),
                OFFSET_CMP + 4 * i,
            );
            let prior_block: AB::Expr = (0..i).map(|j| row[BLOCK + j].into()).sum();
            b.assert_eq(
                row[SEARCH + i],
                (AB::Expr::ONE - before)
                    * (AB::Expr::ONE - prior_block)
                    * (AB::Expr::ONE - row[LIMIT_CMP + 4 * i + 3].into()),
            );
            b.assert_eq(row[ATTEMPT + i], row[SEARCH + i] * row[MATCHES + i]);
            b.assert_eq(
                row[BLOCK + i],
                row[ATTEMPT + i] * row[CONFLICT + i] * (AB::Expr::ONE - row[QUERY_WAIT + 2].into()),
            );
            b.assert_eq(
                row[SKIP + i],
                row[ATTEMPT + i] * row[CONFLICT + i] * row[QUERY_WAIT + 2],
            );
            b.assert_eq(
                row[VISIT + i],
                row[ATTEMPT + i] * (AB::Expr::ONE - row[CONFLICT + i].into()),
            );
            b.assert_eq(
                row[RETURN + i],
                row[VISIT + i] * row[OFFSET_CMP + 4 * i + 3],
            );
            b.assert_eq(row[NEW_VISITED + i], row[OLD_VISITED + i] + row[VISIT + i]);
            b.assert_eq(
                row[NEW_SELECTED + i],
                row[OLD_SELECTED + i] + row[RETURN + i],
            );
        }
        compare(
            b,
            row,
            row[OLD_SELECTED..OLD_SELECTED + 4]
                .iter()
                .copied()
                .map(Into::into)
                .sum(),
            pack(row, QUERY_LIMIT, 3),
            OLD_LIMIT_CMP,
        );
        b.assert_zero(resume.clone() * row[OLD_LIMIT_CMP + 3]);
        let blocked: AB::Expr = (0..4).map(|i| row[BLOCK + i].into()).sum();
        b.assert_bool(blocked.clone());
        b.assert_eq(row[STATUS], blocked.clone() * row[QUERY_WAIT]);
        b.assert_eq(row[STATUS + 1], AB::Expr::ONE - blocked.clone());
        b.assert_eq(row[STATUS + 2], blocked.clone() * row[QUERY_WAIT + 1]);
        b.assert_eq(
            code::<AB::Expr, _>(row, NEW_CURSOR, 5),
            code::<AB::Expr, _>(row, OLD_CURSOR, 5)
                + (0..4).map(|i| row[SEARCH + i].into()).sum::<AB::Expr>()
                - blocked,
        );
    }
}
