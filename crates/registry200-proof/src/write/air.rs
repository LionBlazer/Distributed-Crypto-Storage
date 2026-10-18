//! One complete Source opening, current Registry and all four logical rows.
use super::{
    layout::*,
    statement::{self, Statement},
};
use crate::{
    lifecycle::{
        self, layout as state, opening, predicate,
        ranges::{self, pack},
        registry,
    },
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
    Registry,
    Command,
    Image,
}
pub fn absorb(r: usize) -> Option<(Stream, usize)> {
    match r {
        0..=84 => Some((Stream::Source, r)),
        85..=92 => Some((Stream::Enrollment, r - 85)),
        93..=117 => Some((Stream::Registry, r - 93)),
        118..=137 => Some((Stream::Command, r - 118)),
        138..=161 => Some((Stream::Image, r - 138)),
        _ => None,
    }
}
pub fn reset(r: usize) -> bool {
    matches!(r, 0 | 85 | 93 | 118 | 138)
}
pub struct WriteAir {
    values: [Val; statement::PUBLIC_VALUES],
    source_prefix: Vec<Val>,
    enrollment_prefix: Vec<Val>,
    registry_prefix: Vec<Val>,
    context: Vec<Val>,
    command_domain: [Val; 4],
    image_domain: [Val; 4],
    periodics: OnceLock<Vec<Vec<Val>>>,
}
impl WriteAir {
    pub fn new(s: &Statement) -> Self {
        let anchor = s
            .expected
            .lifecycle_anchor()
            .expect("Checked canonical mathematical Expected");
        Self {
            values: s.values().try_into().unwrap(),
            source_prefix: commitment::prefix(s.expected.source(), [Val::ZERO; 4]),
            enrollment_prefix: lifecycle::statement::stable_prefix(&anchor, true),
            registry_prefix: lifecycle::statement::stable_prefix(&anchor, false),
            context: s.expected.context(),
            command_domain: source::words(&statement::COMMAND_DOMAIN)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            image_domain: source::words(&statement::IMAGE_DOMAIN)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
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
                opening::source_field(&self.source_prefix, row, WORDS, SALTS, f, word)
            }
            Stream::Enrollment => {
                opening::enrollment_field(&self.enrollment_prefix, row, banks(), SALTS + 4, f)
            }
            Stream::Registry => opening::registry_field(
                &self.registry_prefix,
                self.values[96..100].try_into().unwrap(),
                row,
                banks(),
                SALTS + 8,
                STATE,
                f,
            ),
            Stream::Command => match f {
                0..=3 => E::from(self.command_domain[f]),
                4 => E::ONE,
                5..=120 => E::from(self.context[f - 5]),
                121..=124 => E::from(self.values[116 + f - 121]),
                125 => E::ONE,
                126..=127 => pack(row, TXID + 32 * (f - 126), 32),
                128 => row[PRINCIPAL].into() + row[PRINCIPAL + 1].into() * E::from_u8(2),
                129..=136 => opening::controller(row, PRINCIPAL, f - 129, CONTROLLERS),
                137..=138 => pack(row, REV + 32 * (f - 137), 32),
                139..=140 => pack(row, SEQ + 32 * (f - 139), 32),
                141..=148 => pack(row, MASK + 32 * (f - 141), 32),
                149 => pack(row, DELTA, 16),
                150..=153 => row[SALTS + 12 + f - 150].into(),
                _ => E::ZERO,
            },
            Stream::Image => match f {
                0..=3 => E::from(self.image_domain[f]),
                4 => E::ONE,
                5..=120 => E::from(self.context[f - 5]),
                121..=128 => E::from(self.values[116 + f - 121]),
                129 => E::from_u8(4),
                130..=137 => row[TABLE + f - 130].into(),
                138..=181 => {
                    let i = (f - 138) / 11;
                    match (f - 138) % 11 {
                        0 => E::from_usize(i),
                        j @ 1..=8 => row[IDS + 8 * i + j - 1].into(),
                        9 => pack(row, DATA + 24 * i, 8),
                        10 => pack(row, NEW_AMOUNTS + 16 * i, 16),
                        _ => unreachable!(),
                    }
                }
                182..=185 => row[SALTS + 16 + f - 182].into(),
                _ => E::ZERO,
            },
        }
    }
}
impl BaseAir<Val> for WriteAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        statement::PUBLIC_VALUES
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
impl<AB: AirBuilder<F = Val>> Air<AB> for WriteAir {
    fn eval(&self, b: &mut AB) {
        let public: [AB::PublicVar; statement::PUBLIC_VALUES] =
            b.public_values().try_into().unwrap();
        for (a, v) in public.into_iter().zip(self.values) {
            b.assert_eq(a, v);
        }
        let selectors: [AB::Expr; TRACE_HEIGHT] =
            core::array::from_fn(|r| b.periodic_values()[r].into());
        let main = b.main();
        let row = main.current_slice();
        let next = main.next_slice();
        // Includes actor, predicates, output rows and all salts through row511, after the row256 scan.
        for c in (DATA..ACC).chain(NEXT_REV..WIDTH) {
            b.when_transition().assert_eq(next[c], row[c]);
        }
        for c in (WORDS..TABLE)
            .chain(CONTROLLERS..SALTS)
            .chain(ACTOR..ACC)
            .chain(NEXT_REV..CARRY)
        {
            b.assert_bool(row[c]);
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
        for byte in 0..12 {
            let f = 87 + byte / 4;
            for bit in 0..8 {
                b.assert_zero(
                    selectors[f / 8].clone()
                        * (row[DATA + 8 * byte + bit]
                            - row[WORDS + 32 * (f % 8) + 8 * (byte % 4) + bit]),
                );
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
        for t in 0..2 {
            let pop: AB::Expr = row[CONTROLLERS + 256 * t..CONTROLLERS + 256 * (t + 1)]
                .iter()
                .copied()
                .map(Into::into)
                .sum();
            b.assert_eq(pop * row[CTRL_INV + t], AB::Expr::ONE);
        }
        registry::boolean(b, row, registry_columns());
        registry::canonical(b, row, registry_columns());
        b.assert_eq(row[ACTOR] + row[ACTOR + 1], AB::Expr::ONE);
        b.assert_eq(row[PRINCIPAL] + row[PRINCIPAL + 1], AB::Expr::ONE);
        for t in 0..2 {
            let at = state::slot(STATE, t);
            b.assert_zero(row[ACTOR + t] * (AB::Expr::ONE - row[at + state::PRESENT].into()));
            b.assert_zero(row[ACTOR + t] * row[at + state::FAILED]);
        }
        for principal in 0..2 {
            let expected: AB::Expr = (0..2)
                .map(|t| row[ACTOR + t] * row[state::slot(STATE, t) + state::PRINCIPAL + principal])
                .sum();
            b.assert_eq(row[PRINCIPAL + principal], expected);
        }
        for limb in 0..2 {
            let actor_field = |offset| -> AB::Expr {
                (0..2)
                    .map(|t| {
                        row[ACTOR + t]
                            * pack::<AB::Expr, _>(
                                row,
                                state::slot(STATE, t) + offset + 32 * limb,
                                32,
                            )
                    })
                    .sum()
            };
            b.assert_eq(
                pack::<AB::Expr, _>(row, TXID + 32 * limb, 32),
                actor_field(state::ID),
            );
            b.assert_eq(
                pack::<AB::Expr, _>(row, SEQ + 32 * limb, 32),
                actor_field(state::SEQ),
            );
            b.assert_eq(
                pack::<AB::Expr, _>(row, REV + 32 * limb, 32),
                pack::<AB::Expr, _>(row, STATE + state::REV + 32 * limb, 32),
            );
        }
        // Successor bits are explicitly Boolean above; increment alone only checks the carry.
        ranges::increment(
            b,
            row,
            [pack(row, REV, 32), pack(row, REV + 32, 32)],
            NEXT_REV,
            CARRY,
            AB::Expr::ONE,
        );
        ranges::increment(
            b,
            row,
            [pack(row, SEQ, 32), pack(row, SEQ + 32, 32)],
            NEXT_SEQ,
            CARRY + 1,
            AB::Expr::ONE,
        );
        let scan: AB::Expr = selectors[..256].iter().cloned().sum();
        let threshold: AB::Expr = selectors[..256]
            .iter()
            .enumerate()
            .map(|(r, s)| s.clone() * Val::from_usize(r))
            .sum();
        let mask: AB::Expr = selectors[..256]
            .iter()
            .enumerate()
            .map(|(r, s)| s.clone() * row[MASK + r])
            .sum();
        for i in 0..4 {
            predicate::eval_row(
                b,
                row,
                next,
                &selectors,
                pack(row, DATA + 24 * i, 8),
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
            let allowed: AB::Expr = (0..2)
                .map(|t| {
                    row[ACTOR + t]
                        * (row[state::held(state::slot(STATE, t), i, 3)]
                            + row[state::held(state::slot(STATE, t), i, 4)])
                })
                .sum();
            b.assert_zero(row[MATCHES + i] * (AB::Expr::ONE - allowed));
            // Both sides are integers below 2^17, so a selected u16 overflow cannot wrap in Gold.
            b.assert_eq(
                pack::<AB::Expr, _>(row, DATA + 24 * i + 8, 16)
                    + row[MATCHES + i] * pack::<AB::Expr, _>(row, DELTA, 16),
                pack::<AB::Expr, _>(row, NEW_AMOUNTS + 16 * i, 16),
            );
        }
        let output = poseidon::evaluate(b, &row[..CP]);
        let active: AB::Expr = selectors[..162].iter().cloned().sum();
        for word in 0..8 {
            let expected: AB::Expr = selectors[..162]
                .iter()
                .enumerate()
                .map(|(r, s)| {
                    let (stream, block) = absorb(r).unwrap();
                    s.clone() * self.field::<AB::Expr, _>(row, stream, block * 8 + word, word)
                })
                .sum();
            b.assert_eq(row[word], expected);
        }
        let resets: AB::Expr = [0, 85, 93, 118, 138]
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
        for (last, target) in [(84, 76), (92, 96), (117, 116), (137, 120), (161, 124)] {
            for (w, out) in output.iter().take(4).enumerate() {
                b.assert_zero(selectors[last].clone() * (out.clone() - self.values[target + w]));
            }
        }
    }
}
