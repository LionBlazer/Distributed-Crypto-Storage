use std::borrow::Cow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess, utils::pack_bits_le};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use super::statement::{PUBLIC_VALUES, Statement};
use super::{BITS, CONSTANTS, HCHACHA_OUTPUT, QUARTER_ROUNDS, SCHEDULE, WORDS};
use crate::backend::{TRACE_HEIGHT, Val};
use crate::primitive::Kind;
use crate::statement::ID_WORDS;

pub(crate) const ADD: usize = WORDS * BITS;
pub(crate) const XOR: usize = ADD + 4 * BITS;
pub(crate) const CARRY: usize = XOR + 4 * BITS;
pub(crate) const FEEDFORWARD_CARRY: usize = CARRY + 4;
pub(crate) const WIDTH: usize = FEEDFORWARD_CARRY + WORDS;
pub(crate) const PERIODIC_COLUMNS: usize = SCHEDULE.len();

const _: () = {
    assert!(WIDTH == 788);
    assert!(QUARTER_ROUNDS == 10 * SCHEDULE.len());
    assert!(QUARTER_ROUNDS < TRACE_HEIGHT - 1);
};

pub(crate) struct ChaChaAir {
    kind: Kind,
    identity: [Val; ID_WORDS],
}

impl ChaChaAir {
    pub(crate) fn new(statement: &Statement) -> Self {
        assert!(matches!(statement.kind, Kind::HChaCha20 | Kind::ChaCha20));
        Self {
            kind: statement.kind,
            identity: statement.identity_values(),
        }
    }

    /// The claimed output is deliberately ignored by the genuine generator.
    pub(crate) fn trace(statement: &Statement) -> RowMajorMatrix<Val> {
        let mut values = Val::zero_vec(TRACE_HEIGHT * WIDTH);
        let mut state = statement.input;
        for (row_index, row) in values.as_chunks_mut::<WIDTH>().0.iter_mut().enumerate() {
            for (word, bits) in state.iter().zip(row[..ADD].as_chunks_mut::<BITS>().0) {
                write_bits(bits, *word);
            }
            if row_index < QUARTER_ROUNDS {
                let indices = SCHEDULE[row_index % SCHEDULE.len()];
                super::arithmetic::write_round(row, &mut state, indices);
            }
            if row_index == TRACE_HEIGHT - 1 && statement.kind == Kind::ChaCha20 {
                for word in 0..WORDS {
                    row[FEEDFORWARD_CARRY + word] =
                        Val::from_bool(state[word].overflowing_add(statement.input[word]).1);
                }
            }
        }
        RowMajorMatrix::new(values, WIDTH)
    }
}

pub(crate) fn write_bits(destination: &mut [Val], word: u32) {
    for (bit, value) in destination.iter_mut().enumerate() {
        *value = Val::from_u32((word >> bit) & 1);
    }
}

/// Fixed public schedule only: one column is 1 in each of the first 80 rows;
/// all are 0 afterwards. These values contain no fixture/key/witness bytes.
pub(crate) fn schedule_columns() -> Vec<Vec<Val>> {
    (0..PERIODIC_COLUMNS)
        .map(|step| {
            (0..TRACE_HEIGHT)
                .map(|row| Val::from_bool(row < QUARTER_ROUNDS && row % SCHEDULE.len() == step))
                .collect()
        })
        .collect()
}

impl BaseAir<Val> for ChaChaAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        (0..ADD).collect()
    }
    fn num_periodic_columns(&self) -> usize {
        PERIODIC_COLUMNS
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        Cow::Owned(schedule_columns())
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for ChaChaAir {
    fn eval(&self, builder: &mut AB) {
        let public: [AB::PublicVar; PUBLIC_VALUES] = builder.public_values().try_into().unwrap();
        let selectors: [AB::Expr; PERIODIC_COLUMNS] =
            core::array::from_fn(|step| builder.periodic_values()[step].into());
        let main = builder.main();
        let row = main.current_slice();
        let next = main.next_slice();
        for cell in row {
            builder.assert_bool(*cell);
        }
        for (actual, expected) in public[..ID_WORDS].iter().zip(self.identity) {
            builder.assert_eq(*actual, expected);
        }
        for word in 0..WORDS {
            let bits = row[word * BITS..(word + 1) * BITS].iter().copied();
            builder.when_first_row().assert_eq(
                pack_bits_le::<AB::Expr, _, _>(bits),
                public[ID_WORDS + word],
            );
        }
        for (word, constant) in CONSTANTS.into_iter().enumerate() {
            builder.assert_eq(public[ID_WORDS + word], Val::from_u32(constant));
        }

        let updated = super::arithmetic::updated_bits(builder, row, &selectors);
        for (actual, expected) in next[..ADD].iter().zip(updated) {
            builder.when_transition().assert_eq(*actual, expected);
        }
        match self.kind {
            Kind::HChaCha20 => {
                for (output, word) in HCHACHA_OUTPUT.into_iter().enumerate() {
                    builder.when_last_row().assert_eq(
                        pack_bits_le::<AB::Expr, _, _>(
                            row[word * BITS..(word + 1) * BITS].iter().copied(),
                        ),
                        public[ID_WORDS + WORDS + output],
                    );
                }
                for output in 8..WORDS {
                    builder.assert_zero(public[ID_WORDS + WORDS + output]);
                }
                for carry in &row[FEEDFORWARD_CARRY..] {
                    builder.assert_zero(*carry);
                }
            }
            Kind::ChaCha20 => {
                for word in 0..WORDS {
                    let input: AB::Expr = public[ID_WORDS + word].into();
                    let output: AB::Expr = public[ID_WORDS + WORDS + word].into();
                    builder
                        .when_transition()
                        .assert_zero(row[FEEDFORWARD_CARRY + word]);
                    builder.when_last_row().assert_eq(
                        pack_bits_le::<AB::Expr, _, _>(
                            row[word * BITS..(word + 1) * BITS].iter().copied(),
                        ) + input,
                        output + row[FEEDFORWARD_CARRY + word] * Val::from_u64(1 << 32),
                    );
                }
            }
            Kind::Sha256
            | Kind::Poly1305Raw
            | Kind::Poly1305Padded
            | Kind::PairOpening
            | Kind::CanonicalIndexOpening
            | Kind::SelectionOpening
            | Kind::PackedCanonicalIndexOpening
            | Kind::FactorizedPackedCanonicalIndexOpening
            | Kind::StateCertificate
            | Kind::VersionSelection
            | Kind::SelectedEncoding
            | Kind::LockingSelection => {
                unreachable!("separate typed SHA AIR")
            }
        }
    }
}
