//! New EMPTY Registry208 bootstrap. No legacy AIR/profile is modified.
use super::{BOOTSTRAP_VALUES, BootstrapStatement};
use crate::{
    Val,
    lifecycle::{opening, ranges},
    poseidon,
    source::{commitment, schedule},
};
use bfv_hiding_stark::TRACE_HEIGHT;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Algebra, PrimeCharacteristicRing};
use std::{borrow::Cow, sync::OnceLock};

pub(super) const CHECKPOINT: usize = poseidon::WIDTH;
pub(super) const WORDS: usize = CHECKPOINT + 12;
pub(super) const TABLE: usize = WORDS + 256;
pub(super) const IDS: usize = TABLE + 8;
pub(super) const CONTROLLERS: usize = IDS + 32;
pub(super) const SALTS: usize = CONTROLLERS + 512;
pub(super) const INVERSES: usize = SALTS + 12;
pub const WIDTH: usize = INVERSES + 2;
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
        93..=118 => Some((Stream::Registry, row - 93)),
        _ => None,
    }
}
pub(super) fn reset(row: usize) -> bool {
    matches!(row, 0 | 85 | 93)
}

pub(super) struct BootstrapAir {
    values: [Val; BOOTSTRAP_VALUES],
    source_prefix: Vec<Val>,
    enrollment_prefix: Vec<Val>,
    registry_prefix: Vec<Val>,
    enrollment: [Val; 4],
    opening: [Val; 4],
    next: [Val; 4],
    periodics: OnceLock<Vec<Vec<Val>>>,
}
impl BootstrapAir {
    pub(super) fn new(s: &BootstrapStatement) -> Self {
        Self {
            values: s.values().try_into().unwrap(),
            source_prefix: commitment::prefix(s.expected.source(), [Val::ZERO; 4]),
            enrollment_prefix: crate::lifecycle::statement::stable_prefix(
                &s.expected.legacy(),
                true,
            ),
            registry_prefix: super::fields::registry_prefix(&s.expected),
            enrollment: s.expected.enrollment,
            opening: s.expected.source().open_commitment,
            next: s.next,
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
            Stream::Source => {
                opening::source_field(&self.source_prefix, row, WORDS, SALTS, field, slot)
            }
            Stream::Enrollment => opening::enrollment_field(
                &self.enrollment_prefix,
                row,
                opening::Banks {
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
                33..=36 => E::from(self.enrollment[field - 33]),
                37..=44 => row[TABLE + field - 37].into(),
                45..=76 => row[IDS + field - 45].into(),
                77 | 79 => E::from_u8(2),
                78 => E::from_u8(4),
                190..=193 => row[SALTS + 8 + field - 190].into(),
                // Default old bank, both progress presences/roots and all padding.
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
        BOOTSTRAP_VALUES
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
        let public: [AB::PublicVar; BOOTSTRAP_VALUES] = b.public_values().try_into().unwrap();
        for (a, v) in public.into_iter().zip(self.values) {
            b.assert_eq(a, v);
        }
        let selectors: [AB::Expr; TRACE_HEIGHT] =
            core::array::from_fn(|r| b.periodic_values()[r].into());
        let main = b.main();
        let row = main.current_slice();
        let next = main.next_slice();
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
        // Exact ordinal IDs/TableId, captured from the full authenticated opening.
        for (bank, first, count) in [(TABLE, 31, 8), (IDS, 555, 32)] {
            for word in 0..count {
                let f = 87 + first + word;
                b.assert_zero(
                    selectors[f / 8].clone()
                        * (row[bank + word]
                            - ranges::pack::<AB::Expr, _>(row, WORDS + (f % 8) * 32, 32)),
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
        let active: AB::Expr = selectors[..119].iter().cloned().sum();
        for slot in 0..8 {
            let expected: AB::Expr = selectors
                .iter()
                .take(119)
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
            for (last, target) in [(84, self.opening), (92, self.enrollment), (118, self.next)] {
                b.assert_zero(selectors[last].clone() * (out.clone() - target[w]));
            }
        }
    }
}
