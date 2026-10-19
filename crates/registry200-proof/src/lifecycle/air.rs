//! Fixed six-stream lifecycle relation. No native state transition is called here.
use super::{
    acquire, control,
    layout::*,
    ranges::{self, code, pack},
    statement::{self, Phase, Statement},
};
use crate::{
    poseidon,
    source::{commitment, schedule, statement as source},
};
use bfv_hiding_stark::{TRACE_HEIGHT, Val};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Algebra, PrimeCharacteristicRing};
use std::{borrow::Cow, sync::OnceLock};
#[derive(Clone, Copy)]
pub enum Stream {
    Source,
    Enrollment,
    Old,
    Command,
    New,
    Result,
}
pub fn absorb(r: usize) -> Option<(Stream, usize)> {
    match r {
        0..=84 => Some((Stream::Source, r)),
        85..=92 => Some((Stream::Enrollment, r - 85)),
        93..=117 => Some((Stream::Old, r - 93)),
        118..=137 => Some((Stream::Command, r - 118)),
        138..=162 => Some((Stream::New, r - 138)),
        163..=180 => Some((Stream::Result, r - 163)),
        _ => None,
    }
}
pub fn reset(r: usize) -> bool {
    matches!(r, 0 | 85 | 93 | 118 | 138 | 163)
}
pub struct LifecycleAir {
    pub statement: Statement,
    values: [Val; statement::STEP_VALUES],
    source_prefix: Vec<Val>,
    enrollment_prefix: Vec<Val>,
    registry_prefix: Vec<Val>,
    context: Vec<Val>,
    periodics: OnceLock<Vec<Vec<Val>>>,
}
impl LifecycleAir {
    pub fn new(s: &Statement) -> Self {
        Self {
            statement: s.clone(),
            values: s.values().try_into().unwrap(),
            source_prefix: commitment::prefix(&s.expected.source, [Val::ZERO; 4]),
            enrollment_prefix: statement::stable_prefix(&s.expected, true),
            registry_prefix: statement::stable_prefix(&s.expected, false),
            context: s.expected.context(),
            periodics: OnceLock::new(),
        }
    }
    pub fn field<E: Algebra<Val>, T: Copy + Into<E>>(
        &self,
        row: &[T],
        stream: Stream,
        f: usize,
        word: usize,
    ) -> E {
        match stream {
            Stream::Source => {
                super::opening::source_field(&self.source_prefix, row, WORDS, SALTS, f, word)
            }
            Stream::Enrollment => super::opening::enrollment_field(
                &self.enrollment_prefix,
                row,
                super::opening::Banks {
                    words: WORDS,
                    table: TABLE,
                    ids: IDS,
                    controllers: CONTROLLERS,
                },
                SALTS + 4,
                f,
            ),
            Stream::Old | Stream::New => {
                let new = matches!(stream, Stream::New);
                super::opening::registry_field(
                    &self.registry_prefix,
                    self.statement.expected.enrollment,
                    row,
                    super::opening::Banks {
                        words: WORDS,
                        table: TABLE,
                        ids: IDS,
                        controllers: CONTROLLERS,
                    },
                    SALTS + if new { 16 } else { 8 },
                    if new { NEW } else { OLD },
                    f,
                )
            }
            Stream::Command => {
                if let Some(value) = super::opening::command_prefix(
                    &self.context,
                    self.values[100..104].try_into().unwrap(),
                    f,
                ) {
                    value
                } else {
                    match f {
                        109 => code(row, OP, 7),
                        110..=111 => pack(row, ID_CMD + 32 * (f - 110), 32),
                        112 => {
                            row[PRINCIPAL_CMD].into()
                                + row[PRINCIPAL_CMD + 1].into() * E::from_u8(2)
                        }
                        113..=120 => {
                            super::opening::controller(row, PRINCIPAL_CMD, f - 113, CONTROLLERS)
                        }
                        121..=122 => pack(row, OLD + REV + 32 * (f - 121), 32),
                        123..=124 => (0..2)
                            .map(|t| {
                                row[ACTOR + t].into()
                                    * pack::<E, _>(row, slot(OLD, t) + SEQ + 32 * (f - 123), 32)
                            })
                            .sum(),
                        125..=132 => pack(row, MASK + 32 * (f - 125), 32),
                        133 => {
                            code::<E, _>(row, MODE, 4)
                                + (0..4).map(|m| row[MODE + m].into()).sum::<E>()
                        }
                        134 => code(row, WAIT, 3),
                        135 => pack(row, OFFSET, 3),
                        136 => pack(row, LIMIT, 3),
                        137 => pack(row, PROJECTION, 2),
                        138..=145 => pack(row, NAME_CMD + 32 * (f - 138), 32),
                        146..=153 => {
                            row[OP].into()
                                * E::from(
                                    source::words(&self.statement.expected.parent)
                                        .nth(f - 146)
                                        .unwrap(),
                                )
                        }
                        154 => row[ABORT].into(),
                        155..=158 => row[SALTS + 12 + f - 155].into(),
                        _ => E::ZERO,
                    }
                }
            }
            Stream::Result => {
                if let Some(value) = super::opening::result_prefix(
                    &self.context,
                    self.values[100..112].try_into().unwrap(),
                    f,
                ) {
                    value
                } else {
                    match f {
                        117 => code(row, OP, 7),
                        118 => {
                            let failed: E = (0..2)
                                .map(|t| row[ACTOR + t].into() * row[slot(OLD, t) + FAILED].into())
                                .sum();
                            let abort: E = row[ABORT].into();
                            (E::ONE - row[SUCCESS].into())
                                * (row[WAIT].into() + row[WAIT + 1].into() * E::from_u8(2))
                                + row[OP + 6].into()
                                    * (abort.clone() + failed.clone() - abort * failed)
                                    * E::from_u8(3)
                        }
                        119..=120 => pack(row, ID_CMD + 32 * (f - 119), 32),
                        121..=132 => {
                            let at = match (f - 121) / 4 {
                                0 => RETURN,
                                1 => SKIP,
                                2 => VISIT,
                                _ => unreachable!(),
                            };
                            row[SUCCESS].into() * row[at + (f - 121) % 4].into()
                        }
                        133..=136 => row[SALTS + 20 + f - 133].into(),
                        _ => E::ZERO,
                    }
                }
            }
        }
    }
}
impl BaseAir<Val> for LifecycleAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        statement::STEP_VALUES
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        (0..WIDTH).collect()
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
impl<AB: AirBuilder<F = Val>> Air<AB> for LifecycleAir {
    fn eval(&self, b: &mut AB) {
        let public: [AB::PublicVar; statement::STEP_VALUES] = b.public_values().try_into().unwrap();
        for (actual, expected) in public.into_iter().zip(self.values) {
            b.assert_eq(actual, expected);
        }
        let selectors: [AB::Expr; TRACE_HEIGHT] =
            core::array::from_fn(|r| b.periodic_values()[r].into());
        let main = b.main();
        let row = main.current_slice();
        let next = main.next_slice();
        for at in (TABLE..ACC).chain(SEARCH..WIDTH) {
            b.when_transition().assert_eq(next[at], row[at]);
        }
        for at in (WORDS..TABLE).chain(CONTROLLERS..SALTS) {
            b.assert_bool(row[at]);
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
        acquire::eval(b, row, next, &selectors);
        let parent: [Val; 8] = source::words(&self.statement.expected.parent)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        control::eval(b, row, parent);
        let blocked: AB::Expr = AB::Expr::ONE - row[SUCCESS].into();
        for w in 0..4 {
            b.assert_zero(blocked.clone() * (self.values[108 + w] - self.values[100 + w]));
        }
        let output = poseidon::evaluate(b, &row[..CP]);
        let active: AB::Expr = selectors[..181].iter().cloned().sum();
        for word in 0..8 {
            let expected: AB::Expr = selectors[..181]
                .iter()
                .enumerate()
                .map(|(r, s)| {
                    let (stream, block) = absorb(r).unwrap();
                    s.clone() * self.field::<AB::Expr, _>(row, stream, 8 * block + word, word)
                })
                .sum();
            b.assert_eq(row[word], expected);
        }
        let resets: AB::Expr = [0, 85, 93, 118, 138, 163]
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
        for (last, target) in [
            (84, 76),
            (92, 96),
            (117, 100),
            (137, 104),
            (162, 108),
            (180, 112),
        ] {
            for (w, out) in output.iter().take(4).enumerate() {
                b.assert_zero(selectors[last].clone() * (out.clone() - self.values[target + w]));
            }
        }
        let Phase::Transition { .. } = self.statement.expected.phase else {
            unreachable!()
        };
    }
}
