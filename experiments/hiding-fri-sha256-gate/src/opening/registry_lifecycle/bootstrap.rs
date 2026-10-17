//! Three complete fixed streams, one genuine Poseidon gadget on every row.
use super::statement::{self, Statement};
use crate::backend::{TRACE_HEIGHT, Val};
use crate::opening::{commitment, poseidon, schedule};
use crate::primitive::PublicStatement;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess, utils::pack_bits_le};
use p3_field::{Algebra, PrimeCharacteristicRing};
use std::{borrow::Cow, sync::OnceLock};

pub(super) const CHECKPOINT: usize = poseidon::WIDTH;
pub(super) const WORDS: usize = CHECKPOINT + 12;
pub(super) const TABLE: usize = WORDS + 256;
pub(super) const IDS: usize = TABLE + 8;
pub(super) const CONTROLLERS: usize = IDS + 32;
pub(super) const SALTS: usize = CONTROLLERS + 512;
pub(super) const INVERSES: usize = SALTS + 12;
pub(crate) const WIDTH: usize = INVERSES + 2;
const _: () = assert!(WIDTH == 1082);
#[derive(Clone, Copy)]
pub(super) enum Stream {
    Source,
    Enrollment,
    Registry,
}
pub(super) fn absorb(row: usize) -> Option<(Stream, usize)> {
    match row {
        0..=84 => Some((Stream::Source, row)),
        85..=92 => Some((Stream::Enrollment, row - 85)),
        93..=117 => Some((Stream::Registry, row - 93)),
        _ => None,
    }
}
pub(super) fn reset(row: usize) -> bool {
    matches!(row, 0 | 85 | 93)
}
fn packed<E: Algebra<Val>, T: Copy + Into<E>>(row: &[T], start: usize) -> E {
    pack_bits_le(row[start..start + 32].iter().copied())
}
pub(crate) struct BootstrapAir {
    values: [Val; statement::BOOTSTRAP_VALUES],
    source_prefix: Vec<Val>,
    enrollment_prefix: Vec<Val>,
    registry_prefix: Vec<Val>,
    periodics: OnceLock<Vec<Vec<Val>>>,
}
impl BootstrapAir {
    pub(super) fn new(s: &Statement) -> Self {
        Self {
            values: s.public_values().try_into().unwrap(),
            source_prefix: commitment::prefix(&s.expected.source, [Val::ZERO; 4]),
            enrollment_prefix: statement::stable_prefix(&s.expected, true),
            registry_prefix: statement::stable_prefix(&s.expected, false),
            periodics: OnceLock::new(),
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
                87..=673 => packed(row, WORDS + 32 * slot),
                _ => E::ZERO,
            },
            Stream::Enrollment => match field {
                0..=32 => E::from(self.enrollment_prefix[field]),
                33..=40 => row[TABLE + field - 33].into(),
                41 => E::from_u8(2),
                42 | 51 => E::from_usize(if field == 42 { 1 } else { 2 }),
                43..=50 => packed(row, CONTROLLERS + 32 * (field - 43)),
                52..=59 => packed(row, CONTROLLERS + 256 + 32 * (field - 52)),
                60..=63 => row[SALTS + 4 + field - 60].into(),
                _ => unreachable!(),
            },
            Stream::Registry => match field {
                0..=32 => E::from(self.registry_prefix[field]),
                33..=36 => E::from(self.values[96 + field - 33]),
                37..=44 => row[TABLE + field - 37].into(),
                45..=76 => row[IDS + field - 45].into(),
                77 | 79 => E::from_u8(2),
                78 => E::from_u8(4),
                190..=193 => row[SALTS + 8 + field - 190].into(),
                _ => E::ZERO,
            },
        }
    }
}
impl BaseAir<Val> for BootstrapAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        statement::BOOTSTRAP_VALUES
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
impl<AB: AirBuilder<F = Val>> Air<AB> for BootstrapAir {
    fn eval(&self, b: &mut AB) {
        let public: [AB::PublicVar; statement::BOOTSTRAP_VALUES] =
            b.public_values().try_into().unwrap();
        for (a, v) in public.into_iter().zip(self.values) {
            b.assert_eq(a, v);
        }
        let selectors: [AB::Expr; TRACE_HEIGHT] =
            core::array::from_fn(|r| b.periodic_values()[r].into());
        let main = b.main();
        let row = main.current_slice();
        let next = main.next_slice();
        // Every private immutable field, including salts/inverses, survives padding.
        for c in TABLE..WIDTH {
            b.when_transition().assert_eq(next[c], row[c]);
        }
        for c in (WORDS..TABLE).chain(CONTROLLERS..SALTS) {
            b.assert_bool(row[c]);
        }
        let source_active: AB::Expr = selectors[..85].iter().cloned().sum();
        for bit in 0..256 {
            b.assert_zero((AB::Expr::ONE - source_active.clone()) * row[WORDS + bit]);
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
        // Capture exactly all eight TableId and all32 ordinal RowId words from C_open.
        for (bank, first, count) in [(TABLE, 31, 8), (IDS, 555, 32)] {
            for word in 0..count {
                let f = 87 + first + word;
                b.assert_zero(
                    selectors[f / 8].clone()
                        * (row[bank + word] - packed::<AB::Expr, _>(row, WORDS + (f % 8) * 32)),
                );
            }
        }
        for t in 0..2 {
            let population: AB::Expr = row[CONTROLLERS + 256 * t..CONTROLLERS + 256 * (t + 1)]
                .iter()
                .copied()
                .map(Into::into)
                .sum();
            b.assert_eq(population * row[INVERSES + t], AB::Expr::ONE);
        }
        let output = poseidon::evaluate(b, &row[..CHECKPOINT]);
        let active: AB::Expr = selectors[..118].iter().cloned().sum();
        for slot in 0..8 {
            let expected: AB::Expr = selectors
                .iter()
                .take(118)
                .enumerate()
                .map(|(r, sel)| {
                    let (stream, block) = absorb(r).unwrap();
                    sel.clone() * self.field::<AB::Expr, _>(row, stream, block * 8 + slot, slot)
                })
                .sum();
            b.assert_eq(row[slot], expected);
        }
        let resets: AB::Expr = [0, 85, 93].into_iter().map(|r| selectors[r].clone()).sum();
        for w in 8..12 {
            b.assert_eq(
                row[w],
                (active.clone() - resets.clone()) * row[CHECKPOINT + w],
            );
        }
        for (w, out) in output.iter().enumerate() {
            b.when_first_row().assert_zero(row[CHECKPOINT + w]);
            b.when_transition().assert_eq(
                next[CHECKPOINT + w],
                active.clone() * out.clone()
                    + (AB::Expr::ONE - active.clone()) * row[CHECKPOINT + w],
            );
        }
        for (w, out) in output.iter().take(4).enumerate() {
            for (last, target) in [(84, 76), (92, 96), (117, 100)] {
                b.assert_zero(selectors[last].clone() * (out.clone() - self.values[target + w]));
            }
        }
    }
}
