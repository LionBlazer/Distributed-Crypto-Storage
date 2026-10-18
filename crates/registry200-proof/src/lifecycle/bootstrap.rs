//! Three complete fixed streams, one genuine Poseidon gadget on every row.
use super::statement::{self, Statement};
use crate::{
    poseidon,
    source::{commitment, schedule},
};
use bfv_hiding_stark::{TRACE_HEIGHT, Val};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Algebra, PrimeCharacteristicRing};
use std::{borrow::Cow, sync::OnceLock};

pub const CHECKPOINT: usize = poseidon::WIDTH;
pub const WORDS: usize = CHECKPOINT + 12;
pub const TABLE: usize = WORDS + 256;
pub const IDS: usize = TABLE + 8;
pub const CONTROLLERS: usize = IDS + 32;
pub const SALTS: usize = CONTROLLERS + 512;
pub const INVERSES: usize = SALTS + 12;
pub const WIDTH: usize = INVERSES + 2;
const _: () = assert!(WIDTH == 1082);
#[derive(Clone, Copy)]
pub enum Stream {
    Source,
    Enrollment,
    Registry,
}
pub fn absorb(row: usize) -> Option<(Stream, usize)> {
    match row {
        0..=84 => Some((Stream::Source, row)),
        85..=92 => Some((Stream::Enrollment, row - 85)),
        93..=117 => Some((Stream::Registry, row - 93)),
        _ => None,
    }
}
pub fn reset(row: usize) -> bool {
    matches!(row, 0 | 85 | 93)
}
pub struct BootstrapAir {
    values: [Val; statement::BOOTSTRAP_VALUES],
    source_prefix: Vec<Val>,
    enrollment_prefix: Vec<Val>,
    registry_prefix: Vec<Val>,
    periodics: OnceLock<Vec<Vec<Val>>>,
}
impl BootstrapAir {
    pub fn new(s: &Statement) -> Self {
        Self {
            values: s.values().try_into().unwrap(),
            source_prefix: commitment::prefix(&s.expected.source, [Val::ZERO; 4]),
            enrollment_prefix: statement::stable_prefix(&s.expected, true),
            registry_prefix: statement::stable_prefix(&s.expected, false),
            periodics: OnceLock::new(),
        }
    }
    pub fn field<E: Algebra<Val>, T: Copy + Into<E>>(
        &self,
        row: &[T],
        stream: Stream,
        field: usize,
        slot: usize,
    ) -> E {
        match stream {
            Stream::Source => {
                super::opening::source_field(&self.source_prefix, row, WORDS, SALTS, field, slot)
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
                field,
            ),
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
                        * (row[bank + word]
                            - super::ranges::pack::<AB::Expr, _>(row, WORDS + (f % 8) * 32, 32)),
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
