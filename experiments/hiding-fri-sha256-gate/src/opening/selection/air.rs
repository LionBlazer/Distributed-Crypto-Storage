//! One source-opening sponge plus complete private membership and stable compaction.
use super::{
    PLAN_DOMAIN, SELECT_DOMAIN, VERSION,
    statement::{self, Statement},
};
use crate::backend::{TRACE_HEIGHT, Val};
use crate::opening::{commitment, poseidon, schedule, statement as source};
use crate::primitive::PublicStatement;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess, utils::pack_bits_le};
use p3_field::{Algebra, PrimeCharacteristicRing};
use std::borrow::Cow;

pub(super) const CHECKPOINT: usize = poseidon::WIDTH;
pub(super) const WORDS: usize = CHECKPOINT + 12;
pub(super) const MASK: usize = WORDS + 256;
pub(super) const AGES: usize = MASK + 256;
pub(super) const AMOUNTS: usize = AGES + 32;
pub(super) const TABLE: usize = AMOUNTS + 4;
pub(super) const IDS: usize = TABLE + 8;
pub(super) const MATCHES: usize = IDS + 32;
pub(super) const ACCUMULATOR: usize = MATCHES + 4;
pub(super) const RETAIN: usize = ACCUMULATOR + 4;
pub(super) const LIMIT: usize = RETAIN + 4;
pub(super) const PROJECTION: usize = LIMIT + 3;
pub(super) const COMPARE: usize = PROJECTION + 2;
pub(super) const COMPACT: usize = COMPARE + 16;
pub(super) const PRESENCE: usize = COMPACT + 16;
pub(super) const SALTS: usize = PRESENCE + 4;
pub(super) const EQUALITY: usize = SALTS + 12;
pub(crate) const WIDTH: usize = EQUALITY + 44;
const _: () = assert!(WIDTH == 957);

#[derive(Clone, Copy)]
pub(super) enum Stream {
    Source,
    Plan,
    Selected,
}
pub(super) fn absorb(row: usize) -> Option<(Stream, usize)> {
    match row {
        0..=84 => Some((Stream::Source, row)),
        85..=98 => Some((Stream::Plan, row - 85)),
        257..=267 => Some((Stream::Selected, row - 257)),
        _ => None,
    }
}
pub(super) fn reset(row: usize) -> bool {
    matches!(row, 0 | 85 | 257)
}

pub(crate) struct SelectionAir {
    pub(super) statement: Statement,
    values: [Val; statement::PUBLIC_VALUES],
    source_prefix: Vec<Val>,
    context: Vec<Val>,
}
impl SelectionAir {
    pub(super) fn new(statement: &Statement) -> Self {
        Self {
            statement: statement.clone(),
            values: statement.public_values().try_into().unwrap(),
            source_prefix: commitment::prefix(&statement.source, [Val::ZERO; 4]),
            context: statement.context(),
        }
    }
    pub(super) fn field<E: Algebra<Val>, T: Copy + Into<E>>(
        &self,
        row: &[T],
        stream: Stream,
        field: usize,
        slot: usize,
    ) -> E {
        match stream {
            Stream::Source => match field {
                0..=82 => E::from(self.source_prefix[field]),
                83..=86 => row[SALTS + field - 83].into(),
                87..=673 => pack_bits_le(
                    row[WORDS + slot * 32..WORDS + (slot + 1) * 32]
                        .iter()
                        .copied(),
                ),
                _ => E::ZERO,
            },
            Stream::Plan => match field {
                0..=3 => E::from(source::words(&PLAN_DOMAIN).nth(field).unwrap()),
                4 => E::from_u32(VERSION),
                5..=84 => E::from(self.context[field - 5]),
                85..=92 => row[TABLE + field - 85].into(),
                93..=100 => pack_bits_le(
                    row[MASK + (field - 93) * 32..MASK + (field - 92) * 32]
                        .iter()
                        .copied(),
                ),
                101 => pack_bits_le(row[LIMIT..PROJECTION].iter().copied()),
                102 => pack_bits_le(row[PROJECTION..COMPARE].iter().copied()),
                103..=106 => row[SALTS + 4 + field - 103].into(),
                _ => E::ZERO,
            },
            Stream::Selected => match field {
                0..=3 => E::from(source::words(&SELECT_DOMAIN).nth(field).unwrap()),
                4 => E::from_u32(VERSION),
                5..=12 => E::from(self.values[field - 5]),
                13..=20 => E::from(self.values[8 + field - 13]),
                21..=24 => E::from(self.statement.source.open_commitment[field - 21]),
                25..=28 => E::from(self.statement.plan[field - 25]),
                29 => E::from_u8(4),
                30..=33 => row[SALTS + 8 + field - 30].into(),
                34..=81 => {
                    let slot = (field - 34) / 12;
                    let part = (field - 34) % 12;
                    (0..4)
                        .map(|i| {
                            let selector: E = row[COMPACT + slot * 4 + i].into();
                            let value = match part {
                                0 => E::ONE,
                                1 => E::from_usize(i),
                                2 => pack_bits_le(
                                    row[AGES + i * 8..AGES + (i + 1) * 8].iter().copied(),
                                ),
                                3 => row[AMOUNTS + i].into(),
                                _ => row[IDS + i * 8 + part - 4].into(),
                            };
                            selector * value
                        })
                        .sum()
                }
                _ => E::ZERO,
            },
        }
    }
}
impl BaseAir<Val> for SelectionAir {
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
        Cow::Owned(schedule::columns())
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(5)
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for SelectionAir {
    fn eval(&self, b: &mut AB) {
        let public: [AB::PublicVar; statement::PUBLIC_VALUES] =
            b.public_values().try_into().unwrap();
        for (actual, expected) in public.into_iter().zip(self.values) {
            b.assert_eq(actual, expected);
        }
        let selectors: [AB::Expr; TRACE_HEIGHT] =
            core::array::from_fn(|r| b.periodic_values()[r].into());
        let main = b.main();
        let row = main.current_slice();
        let next = main.next_slice();
        // Secret banks are immutable from row0, even before their stream captures.
        for column in (MASK..ACCUMULATOR).chain(RETAIN..EQUALITY) {
            b.when_transition().assert_eq(next[column], row[column]);
        }
        for column in (MASK..AMOUNTS)
            .chain(MATCHES..ACCUMULATOR)
            .chain(RETAIN..SALTS)
            .chain(WORDS..MASK)
        {
            b.assert_bool(row[column]);
        }
        let ages: [AB::Expr; 4] = core::array::from_fn(|i| {
            pack_bits_le(row[AGES + i * 8..AGES + (i + 1) * 8].iter().copied())
        });
        let limit: AB::Expr = pack_bits_le(row[LIMIT..PROJECTION].iter().copied());
        b.assert_zero(row[LIMIT + 2] * (row[LIMIT] + row[LIMIT + 1]));
        for (physical, selector) in selectors.iter().take(85).enumerate() {
            for slot in 0..8 {
                let field = physical * 8 + slot;
                if !(87..674).contains(&field) {
                    for bit in 0..32 {
                        b.assert_zero(selector.clone() * row[WORDS + slot * 32 + bit]);
                    }
                }
            }
        }
        let not_source: AB::Expr =
            AB::Expr::ONE - selectors[..85].iter().cloned().sum::<AB::Expr>();
        for cell in &row[WORDS..MASK] {
            b.assert_zero(not_source.clone() * *cell);
        }
        // Every capture uses the exact bit register already entering the C_open sponge.
        for i in 0..4 {
            for bit in 0..8 {
                let byte = 3 * i;
                let field = 87 + byte / 4;
                b.assert_zero(
                    selectors[field / 8].clone()
                        * (row[AGES + i * 8 + bit]
                            - row[WORDS + (field % 8) * 32 + (byte % 4) * 8 + bit]),
                );
            }
            let amount: AB::Expr = (0..16)
                .map(|bit| {
                    let byte = 3 * i + 1 + bit / 8;
                    let field = 87 + byte / 4;
                    row[WORDS + (field % 8) * 32 + (byte % 4) * 8 + bit % 8]
                        * Val::from_u64(1 << bit)
                })
                .sum();
            let capture = (87 + (3 * i + 1) / 4) / 8;
            b.assert_zero(selectors[capture].clone() * (row[AMOUNTS + i] - amount));
        }
        for (bank, first, count) in [(TABLE, 31, 8), (IDS, 555, 32)] {
            for word in 0..count {
                let field = 87 + first + word;
                let packed: AB::Expr = pack_bits_le(
                    row[WORDS + (field % 8) * 32..WORDS + (field % 8 + 1) * 32]
                        .iter()
                        .copied(),
                );
                b.assert_zero(selectors[field / 8].clone() * (row[bank + word] - packed));
            }
        }
        let scan: AB::Expr = selectors[..256].iter().cloned().sum();
        let threshold: AB::Expr = (0..256)
            .map(|r| selectors[r].clone() * Val::from_usize(r))
            .sum();
        let mask: AB::Expr = (0..256).map(|r| selectors[r].clone() * row[MASK + r]).sum();
        for (i, age) in ages.iter().enumerate() {
            let start = EQUALITY + i * 11;
            for cell in &row[start..start + 10] {
                b.assert_bool(*cell);
            }
            for cell in &row[start..start + 11] {
                b.assert_zero((AB::Expr::ONE - scan.clone()) * *cell);
            }
            let difference: AB::Expr = pack_bits_le(row[start..start + 8].iter().copied());
            let carry: AB::Expr = row[start + 8].into();
            let zero: AB::Expr = row[start + 9].into();
            let inverse: AB::Expr = row[start + 10].into();
            b.assert_zero(
                scan.clone()
                    * (age.clone() + Val::from_u16(256)
                        - threshold.clone()
                        - difference.clone()
                        - carry * Val::from_u16(256)),
            );
            b.assert_zero(scan.clone() * difference.clone() * zero.clone());
            b.assert_zero(
                scan.clone() * (difference * inverse.clone() - (AB::Expr::ONE - zero.clone())),
            );
            b.assert_zero(scan.clone() * zero.clone() * inverse);
            b.when_first_row().assert_zero(row[ACCUMULATOR + i]);
            b.when_transition().assert_eq(
                next[ACCUMULATOR + i],
                row[ACCUMULATOR + i] + mask.clone() * zero,
            );
            b.assert_zero(selectors[256].clone() * (row[MATCHES + i] - row[ACCUMULATOR + i]));
            // Prefix rank is bounded0..3. Its relation to L cannot wrap the field.
            let prefix: AB::Expr = (0..i).map(|j| row[MATCHES + j].into()).sum();
            let cmp = COMPARE + 4 * i;
            let d: AB::Expr = pack_bits_le(row[cmp..cmp + 3].iter().copied());
            let c: AB::Expr = row[cmp + 3].into();
            b.assert_eq(
                prefix + Val::from_u8(8) - limit.clone(),
                d + c.clone() * Val::from_u8(8),
            );
            b.assert_eq(row[RETAIN + i], row[MATCHES + i] * (AB::Expr::ONE - c));
            let column: AB::Expr = (0..4).map(|s| row[COMPACT + s * 4 + i].into()).sum();
            b.assert_eq(column, row[RETAIN + i]);
            let rank: AB::Expr = (0..i).map(|j| row[RETAIN + j].into()).sum();
            for slot in 0..4 {
                b.assert_zero(row[COMPACT + slot * 4 + i] * (rank.clone() - Val::from_usize(slot)));
            }
        }
        for slot in 0..4 {
            let sum: AB::Expr = (0..4).map(|i| row[COMPACT + slot * 4 + i].into()).sum();
            b.assert_eq(sum, row[PRESENCE + slot]);
            if slot < 3 {
                b.assert_zero(row[PRESENCE + slot + 1] * (AB::Expr::ONE - row[PRESENCE + slot]));
            }
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
        let resets = selectors[0].clone() + selectors[85].clone() + selectors[257].clone();
        for word in 8..12 {
            b.assert_eq(
                row[word],
                (active.clone() - resets.clone()) * row[CHECKPOINT + word],
            );
        }
        for word in 0..12 {
            b.when_first_row().assert_zero(row[CHECKPOINT + word]);
            b.when_transition().assert_eq(
                next[CHECKPOINT + word],
                active.clone() * output[word].clone()
                    + (AB::Expr::ONE - active.clone()) * row[CHECKPOINT + word],
            );
        }
        for (word, out) in output.iter().take(4).enumerate() {
            for (last, commitment) in [
                (84, statement::OPEN),
                (98, statement::PLAN),
                (267, statement::SELECTED),
            ] {
                b.assert_zero(
                    selectors[last].clone() * (out.clone() - self.values[commitment + word]),
                );
            }
        }
    }
}
