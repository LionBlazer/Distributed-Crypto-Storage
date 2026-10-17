//! Full closed-registry conflict, prefix selection and atomic control relation.
use super::statement::{self, Statement};
use crate::backend::{TRACE_HEIGHT, Val};
use crate::opening::{commitment, poseidon, schedule, statement as source};
use crate::primitive::PublicStatement;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess, utils::pack_bits_le};
use p3_field::{Algebra, PrimeCharacteristicRing};
use std::{borrow::Cow, sync::OnceLock};
pub(super) const CHECKPOINT: usize = 248;
pub(super) const WORDS: usize = 260;
pub(super) const MASK: usize = 516;
pub(super) const AGES: usize = 772;
pub(super) const AMOUNTS: usize = 804;
pub(super) const TABLE: usize = 808;
pub(super) const IDS: usize = 816;
pub(super) const MATCHES: usize = 848;
pub(super) const ACCUMULATOR: usize = 852;
pub(super) const EQUALITY: usize = 856;
pub(super) const TX_IDS: usize = 900;
pub(super) const CONTROLLERS: usize = 964;
pub(super) const FAILED: usize = 1476;
pub(super) const SEQUENCES: usize = 1478;
pub(super) const CANDIDATE_SEQUENCES: usize = 1542;
pub(super) const REVISION: usize = 1606;
pub(super) const CANDIDATE_REVISION: usize = 1638;
pub(super) const HELD: usize = 1670;
pub(super) const NEXT_HELD: usize = 1710;
pub(super) const ACTOR: usize = 1750;
pub(super) const MODE: usize = 1751;
pub(super) const WAIT: usize = 1755;
pub(super) const OFFSET: usize = 1758;
pub(super) const LIMIT: usize = 1761;
pub(super) const PROJECTION: usize = 1764;
pub(super) const INVERSES: usize = 1766;
pub(super) const SEARCH: usize = 1773;
pub(super) const ATTEMPT: usize = 1777;
pub(super) const CONFLICT: usize = 1781;
pub(super) const VISIT: usize = 1785;
pub(super) const SKIP: usize = 1789;
pub(super) const RETURN: usize = 1793;
pub(super) const BLOCK: usize = 1797;
pub(super) const LIMIT_CMP: usize = 1801;
pub(super) const OFFSET_CMP: usize = 1817;
pub(super) const OWN_MODES: usize = 1833;
pub(super) const DESIRED: usize = 1853;
pub(super) const TARGETS: usize = 1873;
pub(super) const OUTCOME: usize = 1881;
pub(super) const COMPACT_RETURN: usize = 1884;
pub(super) const COMPACT_OWNED: usize = 1900;
pub(super) const PRESENT_RETURN: usize = 1916;
pub(super) const PRESENT_OWNED: usize = 1920;
pub(super) const SALTS: usize = 1924;
pub(crate) const WIDTH: usize = 1948;
const _: () = assert!(WIDTH == SALTS + 24 && CHECKPOINT == poseidon::WIDTH);
#[derive(Clone, Copy)]
pub(super) enum Stream {
    Source,
    Old,
    Plan,
    New,
    Owned,
    Returned,
}
pub(super) fn absorb(r: usize) -> Option<(Stream, usize)> {
    match r {
        0..=84 => Some((Stream::Source, r)),
        85..=98 => Some((Stream::Old, r - 85)),
        99..=116 => Some((Stream::Plan, r - 99)),
        117..=130 => Some((Stream::New, r - 117)),
        257..=277 => Some((Stream::Owned, r - 257)),
        278..=298 => Some((Stream::Returned, r - 278)),
        _ => None,
    }
}
pub(super) fn reset(r: usize) -> bool {
    matches!(r, 0 | 85 | 99 | 117 | 257 | 278)
}
fn packed<E: Algebra<Val>, T: Copy + Into<E>>(row: &[T], start: usize, n: usize) -> E {
    pack_bits_le(row[start..start + n].iter().copied())
}
fn actor<E: Algebra<Val>, T: Copy + Into<E>>(row: &[T], t: usize) -> E {
    let a: E = row[ACTOR].into();
    if t == 0 { E::ONE - a } else { a }
}
fn held<E: Algebra<Val>, T: Copy + Into<E>>(
    row: &[T],
    new: bool,
    t: usize,
    i: usize,
    m: usize,
) -> E {
    row[if new { NEXT_HELD } else { HELD } + (t * 4 + i) * 5 + m].into()
}
fn mode_code<E: Algebra<Val>, T: Copy + Into<E>>(
    row: &[T],
    start: usize,
    n: usize,
    first: usize,
) -> E {
    (0..n)
        .map(|m| row[start + m].into() * E::from_usize(m + first))
        .sum()
}

pub(crate) struct LockingAir {
    pub(super) statement: Statement,
    values: [Val; statement::PUBLIC_VALUES],
    source_prefix: Vec<Val>,
    context: Vec<Val>,
    periodics: OnceLock<Vec<Vec<Val>>>,
}
impl LockingAir {
    pub(super) fn new(s: &Statement) -> Self {
        Self {
            statement: s.clone(),
            values: s.public_values().try_into().unwrap(),
            source_prefix: commitment::prefix(&s.expected.source, [Val::ZERO; 4]),
            context: s.context(),
            periodics: OnceLock::new(),
        }
    }
    pub(super) fn field<E: Algebra<Val>, T: Copy + Into<E>>(
        &self,
        row: &[T],
        stream: Stream,
        f: usize,
        slot: usize,
    ) -> E {
        let tx_field = |t: usize, part: usize, new: bool| -> E {
            match part {
                0 => packed(row, TX_IDS + 32 * t, 32),
                1..=8 => packed(row, CONTROLLERS + t * 256 + (part - 1) * 32, 32),
                9 => {
                    let seq: E = packed(row, SEQUENCES + 32 * t, 32);
                    if new {
                        let success: E = row[OUTCOME].into();
                        seq + success * actor::<E, _>(row, t)
                    } else {
                        seq
                    }
                }
                10 => row[FAILED + t].into(),
                11..=14 => {
                    let i = part - 11;
                    (0..5)
                        .map(|m| held(row, new, t, i, m) * E::from_usize(m))
                        .sum()
                }
                _ => unreachable!(),
            }
        };
        let actor_part = |part: usize| -> E {
            (0..2)
                .map(|t| actor::<E, _>(row, t) * tx_field(t, part, false))
                .sum()
        };
        match stream {
            Stream::Source => match f {
                0..=82 => E::from(self.source_prefix[f]),
                83..=86 => row[SALTS + f - 83].into(),
                87..=673 => packed(row, WORDS + slot * 32, 32),
                _ => E::ZERO,
            },
            Stream::Old | Stream::New => {
                let new = matches!(stream, Stream::New);
                match f {
                    0..=3 => E::from(source::words(&statement::REGISTRY_DOMAIN).nth(f).unwrap()),
                    4 => E::ONE,
                    5..=12 => E::from(
                        source::words(&statement::registry_profile())
                            .nth(f - 5)
                            .unwrap(),
                    ),
                    13..=20 => E::from(
                        source::words(&self.statement.expected.genesis)
                            .nth(f - 13)
                            .unwrap(),
                    ),
                    21..=28 => E::from(
                        source::words(&self.statement.expected.source.heads[0][8..40])
                            .nth(f - 21)
                            .unwrap(),
                    ),
                    29..=32 => E::from(self.statement.expected.source.key_commitment[f - 29]),
                    33..=40 => row[TABLE + f - 33].into(),
                    41..=72 => row[IDS + f - 41].into(),
                    73 => E::from_u8(2),
                    74 => E::from_u8(4),
                    75 => {
                        let revision: E = packed(row, REVISION, 32);
                        if new {
                            let success: E = row[OUTCOME].into();
                            revision + success
                        } else {
                            revision
                        }
                    }
                    76..=105 => tx_field((f - 76) / 15, (f - 76) % 15, new),
                    106..=109 => row[SALTS + if new { 12 } else { 4 } + f - 106].into(),
                    _ => E::ZERO,
                }
            }
            Stream::Plan => match f {
                0..=3 => E::from(source::words(&statement::PLAN_DOMAIN).nth(f).unwrap()),
                4 => E::ONE,
                5..=100 => E::from(self.context[f - 5]),
                101..=104 => E::from(self.statement.expected.old[f - 101]),
                105..=112 => row[TABLE + f - 105].into(),
                113..=120 => packed(row, MASK + (f - 113) * 32, 32),
                121 => actor_part(0),
                122..=129 => actor_part(f - 121),
                130 => actor_part(9),
                131 => packed(row, REVISION, 32),
                132 => mode_code(row, MODE, 4, 1),
                133 => mode_code(row, WAIT, 3, 0),
                134 => packed(row, OFFSET, 3),
                135 => packed(row, LIMIT, 3),
                136 => packed(row, PROJECTION, 2),
                137..=140 => row[SALTS + 8 + f - 137].into(),
                _ => E::ZERO,
            },
            Stream::Owned | Stream::Returned => {
                let owned = matches!(stream, Stream::Owned);
                match f {
                    0..=3 => E::from(
                        source::words(if owned {
                            &statement::OWNED_DOMAIN
                        } else {
                            &statement::RETURN_DOMAIN
                        })
                        .nth(f)
                        .unwrap(),
                    ),
                    4 => E::ONE,
                    5..=100 => E::from(self.context[f - 5]),
                    101..=104 => E::from(self.statement.expected.old[f - 101]),
                    105..=108 => E::from(self.statement.expected.plan[f - 105]),
                    109..=112 => E::from(self.statement.next[f - 109]),
                    113 => E::from_u8(4),
                    114 => row[OUTCOME + 1].into() + row[OUTCOME + 2].into() * E::from_u8(2),
                    115..=118 => row[SALTS + if owned { 16 } else { 20 } + f - 115].into(),
                    119..=166 => {
                        let out_slot = (f - 119) / 12;
                        let part = (f - 119) % 12;
                        let compact = if owned { COMPACT_OWNED } else { COMPACT_RETURN };
                        (0..4)
                            .map(|i| {
                                let select: E = row[compact + out_slot * 4 + i].into();
                                let value = if owned {
                                    match part {
                                        0 => E::ONE,
                                        1 => E::from_usize(i),
                                        2..=9 => row[IDS + i * 8 + part - 2].into(),
                                        10 => mode_code(row, OWN_MODES + i * 5, 5, 0),
                                        11 => (0..2)
                                            .map(|t| {
                                                actor::<E, _>(row, t)
                                                    * mode_code::<E, _>(
                                                        row,
                                                        NEXT_HELD + (t * 4 + i) * 5,
                                                        5,
                                                        0,
                                                    )
                                            })
                                            .sum(),
                                        _ => unreachable!(),
                                    }
                                } else {
                                    match part {
                                        0 => E::ONE,
                                        1 => E::from_usize(i),
                                        2 => packed(row, AGES + i * 8, 8),
                                        3 => row[AMOUNTS + i].into(),
                                        _ => row[IDS + i * 8 + part - 4].into(),
                                    }
                                };
                                select * value
                            })
                            .sum()
                    }
                    _ => E::ZERO,
                }
            }
        }
    }
}
impl BaseAir<Val> for LockingAir {
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
        512
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        Cow::Borrowed(self.periodics.get_or_init(schedule::columns))
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(5)
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for LockingAir {
    fn eval(&self, b: &mut AB) {
        let public: [AB::PublicVar; statement::PUBLIC_VALUES] =
            b.public_values().try_into().unwrap();
        for (v, w) in public.into_iter().zip(self.values) {
            b.assert_eq(v, w);
        }
        let selectors: [AB::Expr; TRACE_HEIGHT] =
            core::array::from_fn(|r| b.periodic_values()[r].into());
        let main = b.main();
        let row = main.current_slice();
        let next = main.next_slice();
        for c in (MASK..ACCUMULATOR).chain(TX_IDS..WIDTH) {
            b.when_transition().assert_eq(next[c], row[c]);
        }
        for c in (WORDS..AMOUNTS)
            .chain(MATCHES..ACCUMULATOR)
            .chain(TX_IDS..INVERSES)
            .chain(SEARCH..SALTS)
        {
            b.assert_bool(row[c]);
        }
        // Source scratch is exact-u32 stream data, with a separate row300 ordering proof.
        let source_active: AB::Expr = selectors[..85].iter().cloned().sum();
        for bit in 0..256 {
            let order = if bit < 32 {
                selectors[300].clone()
            } else {
                AB::Expr::ZERO
            };
            b.assert_zero((AB::Expr::ONE - source_active.clone() - order) * row[WORDS + bit]);
        }
        for (physical, sel) in selectors.iter().take(85).enumerate() {
            for slot in 0..8 {
                if !(87..674).contains(&(physical * 8 + slot)) {
                    for bit in 0..32 {
                        b.assert_zero(sel.clone() * row[WORDS + slot * 32 + bit]);
                    }
                }
            }
        }
        let ages: [AB::Expr; 4] = core::array::from_fn(|i| packed(row, AGES + i * 8, 8));
        for i in 0..4 {
            for bit in 0..8 {
                let byte = 3 * i;
                let f = 87 + byte / 4;
                b.assert_zero(
                    selectors[f / 8].clone()
                        * (row[AGES + i * 8 + bit]
                            - row[WORDS + (f % 8) * 32 + (byte % 4) * 8 + bit]),
                );
            }
            let amount: AB::Expr = (0..16)
                .map(|bit| {
                    let byte = 3 * i + 1 + bit / 8;
                    let f = 87 + byte / 4;
                    row[WORDS + (f % 8) * 32 + (byte % 4) * 8 + bit % 8] * Val::from_u64(1 << bit)
                })
                .sum();
            b.assert_zero(
                selectors[(87 + (3 * i + 1) / 4) / 8].clone() * (row[AMOUNTS + i] - amount),
            );
        }
        for (bank, first, count) in [(TABLE, 31, 8), (IDS, 555, 32)] {
            for word in 0..count {
                let f = 87 + first + word;
                b.assert_zero(
                    selectors[f / 8].clone()
                        * (row[bank + word] - packed::<AB::Expr, _>(row, WORDS + (f % 8) * 32, 32)),
                );
            }
        }
        let scan: AB::Expr = selectors[..256].iter().cloned().sum();
        let threshold: AB::Expr = (0..256)
            .map(|r| selectors[r].clone() * Val::from_usize(r))
            .sum();
        let mask: AB::Expr = (0..256).map(|r| selectors[r].clone() * row[MASK + r]).sum();
        for (i, age) in ages.iter().enumerate() {
            let at = EQUALITY + 11 * i;
            for v in &row[at..at + 10] {
                b.assert_bool(*v);
            }
            for v in &row[at..at + 11] {
                b.assert_zero((AB::Expr::ONE - scan.clone()) * *v);
            }
            let d: AB::Expr = packed(row, at, 8);
            let c: AB::Expr = row[at + 8].into();
            let z: AB::Expr = row[at + 9].into();
            let inv: AB::Expr = row[at + 10].into();
            b.assert_zero(
                scan.clone()
                    * (age.clone() + Val::from_u16(256)
                        - threshold.clone()
                        - d.clone()
                        - c * Val::from_u16(256)),
            );
            b.assert_zero(scan.clone() * d.clone() * z.clone());
            b.assert_zero(scan.clone() * (d * inv.clone() - (AB::Expr::ONE - z.clone())));
            b.assert_zero(scan.clone() * z.clone() * inv);
            b.when_first_row().assert_zero(row[ACCUMULATOR + i]);
            b.when_transition().assert_eq(
                next[ACCUMULATOR + i],
                row[ACCUMULATOR + i] + mask.clone() * z,
            );
            b.assert_zero(selectors[256].clone() * (row[MATCHES + i] - row[ACCUMULATOR + i]));
        }
        let a: AB::Expr = row[ACTOR].into();
        let success: AB::Expr = row[OUTCOME].into();
        let blocked: AB::Expr = (0..4).map(|i| row[BLOCK + i].into()).sum();
        b.assert_bool(blocked.clone());
        b.assert_eq(row[OUTCOME], AB::Expr::ONE - blocked.clone());
        b.assert_eq(row[OUTCOME + 1], blocked.clone() * row[WAIT]);
        b.assert_eq(row[OUTCOME + 2], blocked.clone() * row[WAIT + 1]);
        for (start, count) in [(MODE, 4), (WAIT, 3), (OUTCOME, 3)] {
            let sum: AB::Expr = row[start..start + count].iter().map(|v| (*v).into()).sum();
            b.assert_eq(sum, AB::Expr::ONE);
        }
        for start in [OFFSET, LIMIT] {
            b.assert_zero(row[start + 2] * (row[start] + row[start + 1]));
        }
        let revision: AB::Expr = packed(row, REVISION, 32);
        b.assert_eq(
            packed::<AB::Expr, _>(row, CANDIDATE_REVISION, 32),
            revision + AB::Expr::ONE,
        );
        for t in 0..2 {
            let id: AB::Expr = packed(row, TX_IDS + 32 * t, 32);
            let seq: AB::Expr = packed(row, SEQUENCES + 32 * t, 32);
            b.assert_eq(id * row[INVERSES + t], AB::Expr::ONE);
            b.assert_eq(seq.clone() * row[INVERSES + 3 + t], AB::Expr::ONE);
            let popcount: AB::Expr = row[CONTROLLERS + 256 * t..CONTROLLERS + 256 * (t + 1)]
                .iter()
                .map(|v| (*v).into())
                .sum();
            b.assert_eq(popcount * row[INVERSES + 5 + t], AB::Expr::ONE);
            b.assert_eq(
                packed::<AB::Expr, _>(row, CANDIDATE_SEQUENCES + 32 * t, 32),
                seq + actor::<AB::Expr, _>(row, t),
            );
        }
        let iddiff: AB::Expr =
            packed::<AB::Expr, _>(row, TX_IDS + 32, 32) - packed::<AB::Expr, _>(row, TX_IDS, 32);
        b.assert_eq(iddiff.clone() * row[INVERSES + 2], AB::Expr::ONE);
        b.assert_zero(
            selectors[300].clone()
                * (iddiff - AB::Expr::ONE - packed::<AB::Expr, _>(row, WORDS, 32)),
        );
        b.assert_zero((AB::Expr::ONE - a.clone()) * row[FAILED] + a.clone() * row[FAILED + 1]);
        let requested: [AB::Expr; 4] = core::array::from_fn(|m| row[MODE + m].into());
        for i in 0..4 {
            for start in [
                HELD + i * 5,
                HELD + 20 + i * 5,
                NEXT_HELD + i * 5,
                NEXT_HELD + 20 + i * 5,
                OWN_MODES + i * 5,
                DESIRED + i * 5,
            ] {
                let sum: AB::Expr = row[start..start + 5].iter().map(|v| (*v).into()).sum();
                b.assert_eq(sum, AB::Expr::ONE);
            }
            for new in [false, true] {
                for left in 1..5 {
                    for right in 1..5 {
                        if super::trace::conflicts(left as u8, right as u8) {
                            b.assert_zero(
                                held::<AB::Expr, _>(row, new, 0, i, left)
                                    * held::<AB::Expr, _>(row, new, 1, i, right),
                            );
                        }
                    }
                }
            }
            for m in 0..5 {
                let own = (AB::Expr::ONE - a.clone()) * held::<AB::Expr, _>(row, false, 0, i, m)
                    + a.clone() * held::<AB::Expr, _>(row, false, 1, i, m);
                b.assert_eq(row[OWN_MODES + i * 5 + m], own);
                let desired: AB::Expr = (0..5)
                    .flat_map(|old| {
                        (1..5)
                            .filter(move |r| old.max(*r) == m)
                            .map(move |r| (old, r))
                    })
                    .map(|(old, r)| row[OWN_MODES + i * 5 + old] * row[MODE + r - 1])
                    .sum();
                b.assert_eq(row[DESIRED + i * 5 + m], desired);
                for t in 0..2 {
                    b.assert_eq(
                        held::<AB::Expr, _>(row, true, t, i, m),
                        held::<AB::Expr, _>(row, false, t, i, m)
                            + row[TARGETS + t * 4 + i]
                                * (row[DESIRED + i * 5 + m]
                                    - held::<AB::Expr, _>(row, false, t, i, m)),
                    );
                }
            }
            let other: [AB::Expr; 5] = core::array::from_fn(|m| {
                a.clone() * held::<AB::Expr, _>(row, false, 0, i, m)
                    + (AB::Expr::ONE - a.clone()) * held::<AB::Expr, _>(row, false, 1, i, m)
            });
            let conflict = requested[0].clone() * other[4].clone()
                + requested[1].clone() * (other[3].clone() + other[4].clone())
                + requested[2].clone() * (other[2].clone() + other[3].clone() + other[4].clone())
                + requested[3].clone() * (AB::Expr::ONE - other[0].clone());
            b.assert_eq(row[CONFLICT + i], conflict);
            for (start, prefix, bound) in [
                (
                    LIMIT_CMP,
                    (0..i).map(|j| row[RETURN + j].into()).sum::<AB::Expr>(),
                    packed::<AB::Expr, _>(row, LIMIT, 3),
                ),
                (
                    OFFSET_CMP,
                    (0..i).map(|j| row[VISIT + j].into()).sum::<AB::Expr>(),
                    packed::<AB::Expr, _>(row, OFFSET, 3),
                ),
            ] {
                let at = start + 4 * i;
                b.assert_eq(
                    prefix + Val::from_u8(8) - bound,
                    packed::<AB::Expr, _>(row, at, 3) + row[at + 3] * Val::from_u8(8),
                );
            }
            let previous_blocked: AB::Expr = (0..i).map(|j| row[BLOCK + j].into()).sum();
            b.assert_eq(
                row[SEARCH + i],
                (AB::Expr::ONE - previous_blocked)
                    * (AB::Expr::ONE - row[LIMIT_CMP + 4 * i + 3].into()),
            );
            b.assert_eq(row[ATTEMPT + i], row[SEARCH + i] * row[MATCHES + i]);
            b.assert_eq(
                row[BLOCK + i],
                row[ATTEMPT + i] * row[CONFLICT + i] * (row[WAIT] + row[WAIT + 1]),
            );
            b.assert_eq(
                row[SKIP + i],
                row[ATTEMPT + i] * row[CONFLICT + i] * row[WAIT + 2],
            );
            b.assert_eq(
                row[VISIT + i],
                row[ATTEMPT + i] * (AB::Expr::ONE - row[CONFLICT + i].into()),
            );
            b.assert_eq(
                row[RETURN + i],
                row[VISIT + i] * row[OFFSET_CMP + 4 * i + 3],
            );
            for t in 0..2 {
                b.assert_eq(
                    row[TARGETS + t * 4 + i],
                    success.clone() * row[VISIT + i] * actor::<AB::Expr, _>(row, t),
                );
            }
            for (matrix, flags) in [(COMPACT_RETURN, RETURN), (COMPACT_OWNED, VISIT)] {
                let sum: AB::Expr = (0..4).map(|slot| row[matrix + slot * 4 + i].into()).sum();
                b.assert_eq(sum, row[flags + i] * success.clone());
                let rank: AB::Expr = (0..i).map(|j| row[flags + j] * success.clone()).sum();
                for slot in 0..4 {
                    b.assert_zero(
                        row[matrix + slot * 4 + i] * (rank.clone() - Val::from_usize(slot)),
                    );
                }
            }
        }
        for (matrix, presence) in [
            (COMPACT_RETURN, PRESENT_RETURN),
            (COMPACT_OWNED, PRESENT_OWNED),
        ] {
            for slot in 0..4 {
                let count: AB::Expr = (0..4).map(|j| row[matrix + slot * 4 + j].into()).sum();
                b.assert_eq(row[presence + slot], count);
                if slot < 3 {
                    b.assert_zero(
                        row[presence + slot + 1] * (AB::Expr::ONE - row[presence + slot].into()),
                    );
                }
            }
        }
        // Blocked/no-wait: exact root/salt and no changed state, not reblinding.
        for w in 0..4 {
            b.assert_zero(blocked.clone() * (row[SALTS + 12 + w] - row[SALTS + 4 + w]));
            b.assert_zero(
                blocked.clone()
                    * (self.values[statement::NEW + w] - self.values[statement::OLD + w]),
            );
        }
        let output = poseidon::evaluate(b, &row[..CHECKPOINT]);
        let active: AB::Expr = (0..512)
            .filter(|r| absorb(*r).is_some())
            .map(|r| selectors[r].clone())
            .sum();
        for slot in 0..8 {
            let expected: AB::Expr = (0..512)
                .filter_map(|r| {
                    absorb(r).map(|(stream, block)| {
                        selectors[r].clone()
                            * self.field::<AB::Expr, _>(row, stream, block * 8 + slot, slot)
                    })
                })
                .sum();
            b.assert_eq(row[slot], expected);
        }
        let resets: AB::Expr = [0, 85, 99, 117, 257, 278]
            .into_iter()
            .map(|r| selectors[r].clone())
            .sum();
        for w in 8..12 {
            b.assert_eq(
                row[w],
                (active.clone() - resets.clone()) * row[CHECKPOINT + w],
            );
        }
        for w in 0..12 {
            b.when_first_row().assert_zero(row[CHECKPOINT + w]);
            b.when_transition().assert_eq(
                next[CHECKPOINT + w],
                active.clone() * output[w].clone()
                    + (AB::Expr::ONE - active.clone()) * row[CHECKPOINT + w],
            );
        }
        for (w, out) in output.iter().take(4).enumerate() {
            for (last, target) in [
                (84, 76),
                (98, statement::OLD),
                (116, statement::PLAN),
                (130, statement::NEW),
                (277, statement::OWNED),
                (298, statement::RETURNED),
            ] {
                b.assert_zero(selectors[last].clone() * (out.clone() - self.values[target + w]));
            }
        }
    }
}
