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
                let [a, b, c, d] = indices.map(|index| state[index]);
                let mut sum = [0; 4];
                let mut xor = [0; 4];
                let mut carry = [false; 4];
                (sum[0], carry[0]) = a.overflowing_add(b);
                xor[0] = d ^ sum[0];
                (sum[1], carry[1]) = c.overflowing_add(xor[0].rotate_left(16));
                xor[1] = b ^ sum[1];
                (sum[2], carry[2]) = sum[0].overflowing_add(xor[1].rotate_left(12));
                xor[2] = xor[0].rotate_left(16) ^ sum[2];
                (sum[3], carry[3]) = sum[1].overflowing_add(xor[2].rotate_left(8));
                xor[3] = xor[1].rotate_left(12) ^ sum[3];
                for operation in 0..4 {
                    write_bits(
                        &mut row[ADD + operation * BITS..ADD + (operation + 1) * BITS],
                        sum[operation],
                    );
                    write_bits(
                        &mut row[XOR + operation * BITS..XOR + (operation + 1) * BITS],
                        xor[operation],
                    );
                    row[CARRY + operation] = Val::from_bool(carry[operation]);
                }
                for (index, word) in indices.into_iter().zip([
                    sum[2],
                    xor[3].rotate_left(7),
                    sum[3],
                    xor[2].rotate_left(8),
                ]) {
                    state[index] = word;
                }
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

fn write_bits(destination: &mut [Val], word: u32) {
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

        let selected: [[AB::Expr; BITS]; 4] = core::array::from_fn(|register| {
            core::array::from_fn(|bit| {
                SCHEDULE
                    .iter()
                    .enumerate()
                    .fold(AB::Expr::ZERO, |sum, (step, indices)| {
                        sum + selectors[step].clone() * row[indices[register] * BITS + bit]
                    })
            })
        });
        let add: [[AB::Expr; BITS]; 4] = core::array::from_fn(|operation| {
            core::array::from_fn(|bit| row[ADD + operation * BITS + bit].into())
        });
        let xor: [[AB::Expr; BITS]; 4] = core::array::from_fn(|operation| {
            core::array::from_fn(|bit| row[XOR + operation * BITS + bit].into())
        });
        let rotate = |word: &[AB::Expr; BITS], amount: usize| -> [AB::Expr; BITS] {
            core::array::from_fn(|bit| word[(bit + BITS - amount) % BITS].clone())
        };
        let d16 = rotate(&xor[0], 16);
        let b12 = rotate(&xor[1], 12);
        let d8 = rotate(&xor[2], 8);
        let b7 = rotate(&xor[3], 7);
        let left = [&selected[0], &selected[2], &add[0], &add[1]];
        let right = [&selected[1], &d16, &b12, &d8];
        let xor_left = [&selected[3], &selected[1], &d16, &b12];
        for operation in 0..4 {
            // All operands are 32-bit and carry is boolean: both integer sides
            // are <2^33, strictly below Goldilocks. No modular-wrap shortcut.
            builder.assert_eq(
                pack_bits_le::<AB::Expr, _, _>(left[operation].iter().cloned())
                    + pack_bits_le::<AB::Expr, _, _>(right[operation].iter().cloned()),
                pack_bits_le::<AB::Expr, _, _>(add[operation].iter().cloned())
                    + row[CARRY + operation] * Val::from_u64(1 << 32),
            );
            for bit in 0..BITS {
                let left = xor_left[operation][bit].clone();
                let right = add[operation][bit].clone();
                builder.assert_eq(
                    xor[operation][bit].clone(),
                    left.clone() + right.clone() - left * right * Val::TWO,
                );
            }
        }
        let outputs = [&add[2], &b7, &add[3], &d8];
        for word in 0..WORDS {
            for bit in 0..BITS {
                let current: AB::Expr = row[word * BITS + bit].into();
                let mut updated = current.clone();
                for (step, indices) in SCHEDULE.iter().enumerate() {
                    if let Some(register) = indices.iter().position(|index| *index == word) {
                        updated += selectors[step].clone()
                            * (outputs[register][bit].clone() - current.clone());
                    }
                }
                builder
                    .when_transition()
                    .assert_eq(next[word * BITS + bit], updated);
            }
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
            Kind::Sha256 | Kind::Poly1305Raw | Kind::Poly1305Padded => {
                unreachable!("separate typed SHA AIR")
            }
        }
    }
}
