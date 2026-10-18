//! One fixed quarter-round constraint/row ABI; no key or prover ownership.
use bfv_hiding_stark::Val;
use p3_air::{AirBuilder, utils::pack_bits_le};
use p3_field::PrimeCharacteristicRing;
pub const WORDS: usize = 16;
pub const BITS: usize = 32;
pub const QUARTER_ROUNDS: usize = 80;
pub const SCHEDULE: [[usize; 4]; 8] = [
    [0, 4, 8, 12],
    [1, 5, 9, 13],
    [2, 6, 10, 14],
    [3, 7, 11, 15],
    [0, 5, 10, 15],
    [1, 6, 11, 12],
    [2, 7, 8, 13],
    [3, 4, 9, 14],
];
pub const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
pub const HCHACHA_OUTPUT: [usize; 8] = [0, 1, 2, 3, 12, 13, 14, 15];
pub const ADD: usize = WORDS * BITS;
pub const XOR: usize = ADD + 4 * BITS;
pub const CARRY: usize = XOR + 4 * BITS;
pub const FEEDFORWARD_CARRY: usize = CARRY + 4;
pub const WIDTH: usize = FEEDFORWARD_CARRY + WORDS;
pub const PERIODIC_COLUMNS: usize = SCHEDULE.len();

pub fn updated_bits<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    row: &[AB::Var],
    selectors: &[AB::Expr; 8],
) -> Vec<AB::Expr> {
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
    let mut result = vec![AB::Expr::ZERO; ADD];
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
            result[word * BITS + bit] = updated;
        }
    }
    result
}

pub fn write_round(row: &mut [Val], state: &mut [u32; 16], indices: [usize; 4]) {
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
    for (index, word) in
        indices
            .into_iter()
            .zip([sum[2], xor[3].rotate_left(7), sum[3], xor[2].rotate_left(8)])
    {
        state[index] = word;
    }
}

pub fn write_bits(destination: &mut [Val], word: u32) {
    for (bit, value) in destination.iter_mut().enumerate() {
        *value = Val::from_u32((word >> bit) & 1);
    }
}
