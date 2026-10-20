//! Exact fixed opening expressions; native producers do not define the AIR.
use super::{transition::Statement, transition_layout::*};
use crate::{
    Val,
    lifecycle::{
        opening,
        ranges::{code, pack},
    },
    source::statement as source,
};
use p3_field::{Algebra, PrimeCharacteristicRing};
pub(super) fn actor<E: Algebra<Val>, T: Copy + Into<E>>(row: &[T], part: usize) -> E {
    (0..2)
        .map(|t| row[ACTOR + t].into() * row[slot(OLD, t) + part].into())
        .sum()
}
pub(super) fn actor_word<E: Algebra<Val>, T: Copy + Into<E>>(row: &[T], part: usize) -> E {
    (0..2)
        .map(|t| row[ACTOR + t].into() * pack::<E, _>(row, slot(OLD, t) + part, 32))
        .sum()
}
pub(super) fn selected_progress<E: Algebra<Val>, T: Copy + Into<E>>(
    row: &[T],
    at: usize,
    part: usize,
) -> E {
    (0..2)
        .map(|t| row[ACTOR + t].into() * row[progress(at, t) + part].into())
        .sum()
}
fn holder<E: Algebra<Val>, T: Copy + Into<E>>(row: &[T], word: usize) -> E {
    let blocked: E = (0..4).map(|i| row[BLOCK + i].into()).sum();
    blocked
        * (0..2)
            .map(|t| {
                row[ACTOR + t].into() * pack::<E, _>(row, slot(OLD, 1 - t) + ID + 32 * word, 32)
            })
            .sum::<E>()
}
fn holder_mode<E: Algebra<Val>, T: Copy + Into<E>>(row: &[T]) -> E {
    (0..4)
        .flat_map(|i| (0..2).map(move |t| (i, t)))
        .map(|(i, t)| {
            row[BLOCK + i].into()
                * row[ACTOR + t].into()
                * code::<E, _>(row, held(slot(OLD, 1 - t), i, 0), 5)
        })
        .sum()
}
fn query_mode<E: Algebra<Val>, T: Copy + Into<E>>(row: &[T]) -> E {
    code::<E, _>(row, QUERY_MODE, 4) + (0..4).map(|i| row[QUERY_MODE + i].into()).sum::<E>()
}
fn principal<E: Algebra<Val>, T: Copy + Into<E>>(row: &[T]) -> E {
    row[PRINCIPAL_CMD].into() + row[PRINCIPAL_CMD + 1].into() * E::from_u8(2)
}

pub(super) struct Fields {
    pub statement: Statement,
    pub source: Vec<Val>,
    pub enrollment: Vec<Val>,
    pub registry: Vec<Val>,
    pub context: Vec<Val>,
    scope: [Val; 16],
    query: [Val; 48],
}
impl Fields {
    pub fn new(s: &Statement) -> Self {
        let e = &s.expected;
        let query = e
            .query()
            .map(|q| {
                crate::coefficient_encoding::commitment::command_fields(
                    &q.expected,
                    [0; 32],
                    [Val::ZERO; 4],
                )
            })
            .unwrap_or([Val::ZERO; 48]);
        Self {
            statement: s.clone(),
            source: crate::source::commitment::prefix(e.source(), [Val::ZERO; 4]),
            enrollment: crate::lifecycle::statement::stable_prefix(&e.base.legacy(), true),
            registry: super::fields::registry_prefix(&e.base),
            context: e.context(),
            scope: source::words(&e.scope())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            query,
        }
    }
    fn statement_field<E: Algebra<Val>, T: Copy + Into<E>>(&self, row: &[T], f: usize) -> E {
        match f {
            0..=3 => E::from(
                source::words(&super::fields::STATEMENT_DOMAIN)
                    .nth(f)
                    .unwrap(),
            ),
            4 => E::ONE,
            5..=12 => E::from(
                source::words(&super::statement_profile_digest())
                    .nth(f - 5)
                    .unwrap(),
            ),
            13..=28 => E::from(self.scope[f - 13]),
            29..=32 => E::from(self.statement.expected.base.enrollment[f - 29]),
            33..=40 => pack(row, CLIENT + 32 * (f - 33), 32),
            41..=42 => pack(row, CALL + 32 * (f - 41), 32),
            43..=44 => pack(row, ID_CMD + 32 * (f - 43), 32),
            45 => principal(row),
            46..=53 => opening::controller(row, PRINCIPAL_CMD, f - 46, CONTROLLERS),
            54..=61 => pack(row, INVOCATION + 32 * (f - 54), 32),
            62..=69 => pack(row, ORIGINAL_SQL + 32 * (f - 62), 32),
            70..=77 => actor_word(row, SNAPSHOT + 32 * (f - 70)),
            78..=85 => pack(row, QUERY_MASK + 32 * (f - 78), 32),
            86 => query_mode(row),
            87 => code(row, QUERY_WAIT, 3),
            88 => pack(row, QUERY_OFFSET, 3),
            89 => pack(row, QUERY_LIMIT, 3),
            90 => pack(row, QUERY_PROJECTION, 2),
            91..=94 => row[EXTRA_SALTS + f - 91].into(),
            _ => E::ZERO,
        }
    }
    fn progress_field<E: Algebra<Val>, T: Copy + Into<E>>(
        &self,
        row: &[T],
        new: bool,
        f: usize,
    ) -> E {
        match f {
            0..=3 => E::from(
                source::words(&super::fields::PROGRESS_DOMAIN)
                    .nth(f)
                    .unwrap(),
            ),
            4 => E::ONE,
            5..=12 => E::from(
                source::words(&super::progress_profile_digest())
                    .nth(f - 5)
                    .unwrap(),
            ),
            13..=16 => row[STMT_ROOT + f - 13].into(),
            17..=18 => pack(row, ID_CMD + 32 * (f - 17), 32),
            19 => principal(row),
            20..=21 => pack(row, CALL + 32 * (f - 20), 32),
            22..=23 => pack(
                row,
                if new { NEW_MICRO } else { OLD_MICRO } + 32 * (f - 22),
                32,
            ),
            24 | 34 => code(row, if new { NEW_CURSOR } else { OLD_CURSOR }, 5),
            25..=28 => row[if new { NEW_VISITED } else { OLD_VISITED } + f - 25].into(),
            29..=32 => row[if new { NEW_SELECTED } else { OLD_SELECTED } + f - 29].into(),
            33 => E::ONE,
            35..=36 => {
                if new {
                    holder(row, f - 35)
                } else {
                    pack(row, OLD_HOLDER + 32 * (f - 35), 32)
                }
            }
            37 => {
                if new {
                    holder_mode(row)
                } else {
                    code::<E, _>(row, OLD_HOLDER_MODE, 4)
                        + (0..4).map(|i| row[OLD_HOLDER_MODE + i].into()).sum::<E>()
                }
            }
            38..=39 => pack(
                row,
                if new { OLD + REV } else { OLD_BLOCK_REV } + 32 * (f - 38),
                32,
            ),
            40..=43 => row[EXTRA_SALTS + if new { 8 } else { 4 } + f - 40].into(),
            _ => E::ZERO,
        }
    }
    pub fn field<E: Algebra<Val>, T: Copy + Into<E>>(
        &self,
        row: &[T],
        stream: Stream,
        f: usize,
        word: usize,
    ) -> E {
        let e = &self.statement.expected;
        match stream {
            Stream::Source => opening::source_field(&self.source, row, WORDS, SALTS, f, word),
            Stream::Enrollment => opening::enrollment_field(
                &self.enrollment,
                row,
                opening::Banks {
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
                if f < 194 {
                    opening::registry_field(
                        &self.registry,
                        e.base.enrollment,
                        row,
                        opening::Banks {
                            words: WORDS,
                            table: TABLE,
                            ids: IDS,
                            controllers: CONTROLLERS,
                        },
                        SALTS + if new { 16 } else { 8 },
                        if new { NEW } else { OLD },
                        f,
                    )
                } else if f < 204 {
                    row[progress(if new { NEW_PROGRESS } else { OLD_PROGRESS }, (f - 194) / 5)
                        + (f - 194) % 5]
                        .into()
                } else {
                    E::ZERO
                }
            }
            Stream::Command => {
                if let Some(v) = opening::command_prefix(&self.context, e.old, f) {
                    return v;
                }
                match f {
                    109 => {
                        if e.is_predicate() {
                            E::ONE
                        } else {
                            code(row, OP, 7)
                        }
                    }
                    110..=111 => pack(row, ID_CMD + 32 * (f - 110), 32),
                    112 => principal(row),
                    113..=120 => opening::controller(row, PRINCIPAL_CMD, f - 113, CONTROLLERS),
                    121..=122 => pack(row, OLD + REV + 32 * (f - 121), 32),
                    123..=124 => actor_word(row, SEQ + 32 * (f - 123)),
                    125..=132 => pack(
                        row,
                        if e.is_predicate() { QUERY_MASK } else { MASK } + 32 * (f - 125),
                        32,
                    ),
                    133 => {
                        if e.is_predicate() {
                            query_mode(row)
                        } else {
                            E::ZERO
                        }
                    }
                    134 => {
                        if e.is_predicate() {
                            code(row, QUERY_WAIT, 3)
                        } else {
                            E::ZERO
                        }
                    }
                    135 => pack(
                        row,
                        if e.is_predicate() {
                            QUERY_OFFSET
                        } else {
                            OFFSET
                        },
                        3,
                    ),
                    136 => pack(row, if e.is_predicate() { QUERY_LIMIT } else { LIMIT }, 3),
                    137 => pack(
                        row,
                        if e.is_predicate() {
                            QUERY_PROJECTION
                        } else {
                            PROJECTION
                        },
                        2,
                    ),
                    138..=145 => pack(row, NAME_CMD + 32 * (f - 138), 32),
                    146..=153 => {
                        row[OP].into()
                            * E::from(source::words(&e.base.parent).nth(f - 146).unwrap())
                    }
                    154 => row[ABORT].into(),
                    155..=158 => row[SALTS + 12 + f - 155].into(),
                    _ => E::ZERO,
                }
            }
            Stream::Statement => self.statement_field(row, f),
            Stream::OldProgress => self.progress_field(row, false, f),
            Stream::NewProgress => self.progress_field(row, true, f),
            Stream::Query => match f {
                29..=36 => pack(row, QUERY_MASK + 32 * (f - 29), 32),
                37..=40 => row[EXTRA_SALTS + 12 + f - 37].into(),
                _ => E::from(self.query[f]),
            },
            Stream::Result => {
                let p = e.is_predicate();
                match f {
                    0..=3 => E::from(source::words(&super::fields::RESULT_DOMAIN).nth(f).unwrap()),
                    4 => E::ONE,
                    5..=104 => E::from(self.context[f - 5]),
                    105..=108 => E::from(e.old[f - 105]),
                    109..=112 => E::from(self.statement.next[f - 109]),
                    113..=116 => row[STMT_ROOT + f - 113].into(),
                    117 => {
                        if p {
                            row[RESUME].into()
                        } else {
                            code::<E, _>(row, OP, 7) + E::from_u8(2)
                        }
                    }
                    118 => {
                        if p {
                            row[STATUS + 1].into() + row[STATUS + 2].into() * E::from_u8(2)
                        } else {
                            let failed: E = actor(row, FAILED);
                            let abort: E = row[ABORT].into();
                            E::ONE
                                + row[OP + 6].into()
                                    * (abort.clone() + failed.clone() - abort * failed)
                                    * E::from_u8(2)
                        }
                    }
                    119..=120 => pack(row, ID_CMD + 32 * (f - 119), 32),
                    121 => code(row, OLD_CURSOR, 5),
                    122 => code(row, NEW_CURSOR, 5),
                    123..=126 => row[NEW_VISITED + f - 123].into(),
                    127..=130 => row[NEW_SELECTED + f - 127].into(),
                    131..=134 => row[BLOCK + f - 131].into(),
                    135..=138 => selected_progress(row, OLD_PROGRESS, 1 + f - 135),
                    139..=142 => {
                        let v: E = selected_progress(row, NEW_PROGRESS, 1 + f - 139);
                        if p {
                            v
                        } else {
                            (E::ONE - row[OP + 6].into()) * v
                        }
                    }
                    143..=144 => holder(row, f - 143),
                    145 => holder_mode(row),
                    146..=147 => pack(row, CALL + 32 * (f - 146), 32),
                    148..=149 => pack(row, NEW_MICRO + 32 * (f - 148), 32),
                    150..=153 => row[SALTS + 20 + f - 150].into(),
                    _ => E::ZERO,
                }
            }
        }
    }
}
#[derive(Clone, Copy)]
pub(super) enum Stream {
    Source,
    Enrollment,
    Old,
    Command,
    New,
    Result,
    Statement,
    OldProgress,
    NewProgress,
    Query,
}
pub(super) fn absorb(r: usize) -> Option<(Stream, usize)> {
    match r {
        0..=84 => Some((Stream::Source, r)),
        85..=92 => Some((Stream::Enrollment, r - 85)),
        93..=118 => Some((Stream::Old, r - 93)),
        119..=138 => Some((Stream::Command, r - 119)),
        139..=164 => Some((Stream::New, r - 139)),
        165..=184 => Some((Stream::Result, r - 165)),
        185..=196 => Some((Stream::Statement, r - 185)),
        197..=202 => Some((Stream::OldProgress, r - 197)),
        203..=208 => Some((Stream::NewProgress, r - 203)),
        209..=214 => Some((Stream::Query, r - 209)),
        _ => None,
    }
}
pub(super) const RESETS: [usize; 10] = [0, 85, 93, 119, 139, 165, 185, 197, 203, 209];
