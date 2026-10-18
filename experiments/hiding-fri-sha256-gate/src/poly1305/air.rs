use std::borrow::Cow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess, utils::pack_bits_le};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use super::statement::{
    KEY_PUBLIC, Layout, META_PUBLIC, PAYLOAD_PUBLIC, PUBLIC_VALUES, Statement, TAG_PUBLIC,
};
use super::{CLAMP, LIMB_BITS, LIMBS, MASK, MAX_BLOCKS, MAX_BYTES, RADIX};
use crate::backend::{TRACE_HEIGHT, Val};
use crate::statement::ID_WORDS;

pub(crate) const STATE: usize = LIMBS * LIMB_BITS;
pub(crate) const KEY: usize = STATE;
pub(crate) const MESSAGE: usize = KEY + 256;
pub(crate) const PRODUCT_CARRY: usize = MESSAGE + 128;
pub(crate) const CANONICAL: usize = PRODUCT_CARRY + LIMBS * 32;
pub(crate) const CANONICAL_CARRY: usize = CANONICAL + STATE;
pub(crate) const TAG_CARRY: usize = CANONICAL_CARRY + LIMBS;
pub(crate) const WIDTH: usize = TAG_CARRY + 4;
const _: () = {
    assert!(WIDTH == 813);
    assert!(MAX_BLOCKS < TRACE_HEIGHT - 1);
};

pub(crate) struct Poly1305Air {
    identity: [Val; ID_WORDS],
    layout: Layout,
}
impl Poly1305Air {
    pub(crate) fn new(statement: &Statement) -> Self {
        Self {
            identity: statement.identity_values(),
            layout: statement.layout().clone(),
        }
    }

    /// Genuine radix computation; claimed tag is never read. No 130-bit state
    /// or folded product is accumulated in u128 or in a single field element.
    pub(crate) fn trace(statement: &Statement) -> RowMajorMatrix<Val> {
        let mut values = Val::zero_vec(TRACE_HEIGHT * WIDTH);
        let mut state = [0; LIMBS];
        let r = clamped_r(statement.key);
        for (index, row) in values.as_chunks_mut::<WIDTH>().0.iter_mut().enumerate() {
            write_state(row, state);
            for (byte, value) in statement.key.into_iter().enumerate() {
                write_bits(
                    &mut row[KEY + byte * 8..KEY + (byte + 1) * 8],
                    u64::from(value),
                );
            }
            if index < statement.layout().active {
                let block = statement.layout().blocks[index];
                let mut message = [0; 16];
                for (byte, source) in block.payload.into_iter().enumerate() {
                    if let Some(source) = source {
                        message[byte] = statement.payload()[source];
                    }
                    write_bits(
                        &mut row[MESSAGE + byte * 8..MESSAGE + (byte + 1) * 8],
                        u64::from(message[byte]),
                    );
                }
                let n = message_limbs(message, block.appended_bit);
                let product = folded_product(state, n, r);
                let (updated, carry) = reduce(product);
                for (limb, value) in carry.into_iter().enumerate() {
                    write_bits(
                        &mut row[PRODUCT_CARRY + limb * 32..PRODUCT_CARRY + (limb + 1) * 32],
                        value,
                    );
                }
                state = updated;
            }
            if index == TRACE_HEIGHT - 1 {
                write_tag_carries(row, state, statement.key);
            }
        }
        RowMajorMatrix::new(values, WIDTH)
    }
}

/// The H+5 comparator is populated on EVERY row, including inactive padding.
pub(crate) fn write_state(row: &mut [Val], state: [u64; LIMBS]) {
    let (state_cells, rest) = row.split_at_mut(STATE);
    let canonical = &mut rest[CANONICAL - STATE..];
    let (values, carries) = canonical.split_at_mut(STATE);
    super::arithmetic::write_canonical(state_cells, values, &mut carries[..LIMBS], state);
}

pub(crate) fn clamped_r(key: [u8; 32]) -> [u64; LIMBS] {
    let bytes: [u8; 16] = core::array::from_fn(|byte| key[byte] & CLAMP[byte]);
    message_limbs(bytes, 130) // No appended bit for the key.
}

pub(crate) fn folded_product(h: [u64; LIMBS], n: [u64; LIMBS], r: [u64; LIMBS]) -> [u64; LIMBS] {
    let mut result = [0; LIMBS];
    for (i, (h, n)) in h.into_iter().zip(n).enumerate() {
        for (j, r) in r.into_iter().enumerate() {
            let degree = i + j;
            result[degree % LIMBS] += (h + n) * r * if degree >= LIMBS { 5 } else { 1 };
        }
    }
    result
}

/// Normalize only five bounded u64 coefficients, folding B^5 to 5. The first
/// pass leaves at most 215B in limb0, the second can fold at most one, and a
/// third finishes. One extra bounded pass asserts stabilization independently.
pub(crate) fn reduce(product: [u64; LIMBS]) -> ([u64; LIMBS], [u64; LIMBS]) {
    let mut h = product;
    let mut quotient = 0;
    for _ in 0..4 {
        for limb in 0..LIMBS - 1 {
            let carry = h[limb] >> LIMB_BITS;
            h[limb] &= MASK;
            h[limb + 1] += carry;
        }
        let carry = h[LIMBS - 1] >> LIMB_BITS;
        h[LIMBS - 1] &= MASK;
        h[0] += 5 * carry;
        quotient += carry;
    }
    assert!(h.into_iter().all(|value| value < RADIX));
    let mut plus_five = h;
    let mut carry = 5;
    for value in &mut plus_five {
        let sum = *value + carry;
        *value = sum & MASK;
        carry = sum >> LIMB_BITS;
    }
    if carry != 0 {
        h = plus_five;
        quotient += 1;
    }
    (h, cyclic_carries(product, h, quotient))
}

pub(crate) fn cyclic_carries(
    product: [u64; LIMBS],
    h: [u64; LIMBS],
    quotient: u64,
) -> [u64; LIMBS] {
    let mut carry = [0; LIMBS];
    let mut previous = 5 * quotient;
    for limb in 0..LIMBS {
        let numerator = product[limb] + previous - h[limb];
        assert_eq!(numerator % RADIX, 0);
        carry[limb] = numerator / RADIX;
        assert!(carry[limb] < 1 << 32);
        previous = carry[limb];
    }
    assert_eq!(carry[LIMBS - 1], quotient);
    carry
}

pub(crate) fn tag_words(h: [u64; LIMBS], key: [u8; 32]) -> ([u32; 4], [bool; 4]) {
    let mut low = [0_u32; 4];
    for bit in 0..128 {
        low[bit / 32] |= (((h[bit / LIMB_BITS] >> (bit % LIMB_BITS)) & 1) as u32) << (bit % 32);
    }
    let mut carry = false;
    let mut carries = [false; 4];
    for (word, value) in low.iter_mut().enumerate() {
        let s = u32::from_le_bytes(key[16 + word * 4..20 + word * 4].try_into().unwrap());
        let sum = u64::from(*value) + u64::from(s) + u64::from(carry);
        *value = sum as u32;
        carry = sum >> 32 != 0;
        carries[word] = carry;
    }
    (low, carries)
}
pub(crate) fn write_tag_carries(row: &mut [Val], h: [u64; LIMBS], key: [u8; 32]) {
    for (word, carry) in tag_words(h, key).1.into_iter().enumerate() {
        row[TAG_CARRY + word] = Val::from_bool(carry);
    }
}

pub(crate) fn schedule_columns() -> Vec<Vec<Val>> {
    (0..MAX_BLOCKS)
        .map(|block| {
            (0..TRACE_HEIGHT)
                .map(|row| Val::from_bool(row == block))
                .collect()
        })
        .collect()
}
impl BaseAir<Val> for Poly1305Air {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        (0..STATE).collect()
    }
    fn num_periodic_columns(&self) -> usize {
        MAX_BLOCKS
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        Cow::Owned(schedule_columns())
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for Poly1305Air {
    fn eval(&self, builder: &mut AB) {
        let public: [AB::PublicVar; PUBLIC_VALUES] = builder.public_values().try_into().unwrap();
        let selectors: [AB::Expr; MAX_BLOCKS] =
            core::array::from_fn(|index| builder.periodic_values()[index].into());
        let active = selectors[..self.layout.active]
            .iter()
            .cloned()
            .sum::<AB::Expr>();
        let main = builder.main();
        let row = main.current_slice();
        let next = main.next_slice();
        for cell in row {
            builder.assert_bool(*cell);
        }
        for (actual, expected) in public[..ID_WORDS].iter().zip(self.identity) {
            builder.assert_eq(*actual, expected);
        }
        for byte in 0..32 {
            // Bind the SAME raw key on every row; clamped-away bits are valid
            // public input bits, but cannot contribute to effective R.
            builder.assert_eq(
                pack_bits_le::<AB::Expr, _, _>(
                    row[KEY + byte * 8..KEY + (byte + 1) * 8].iter().copied(),
                ),
                public[KEY_PUBLIC + byte],
            );
        }
        for (segment, length) in self.layout.lengths.into_iter().enumerate() {
            builder.assert_eq(public[META_PUBLIC + segment], Val::from_usize(length));
        }
        builder.assert_eq(
            public[META_PUBLIC + 3],
            Val::from_usize(self.layout.segments),
        );
        builder.assert_eq(
            public[META_PUBLIC + 4],
            Val::from_u8(self.layout.mode.code()),
        );
        // Keep the assertion count/degree geometry fixed for empty, partial and
        // full inputs, so the shared backend's per-kind analysis stays exact.
        for byte in 0..MAX_BYTES {
            let payload: AB::Expr = public[PAYLOAD_PUBLIC + byte].into();
            builder.assert_zero(payload * Val::from_bool(byte >= self.layout.bytes));
        }
        for byte in 0..16 {
            let expected = self.layout.blocks[..self.layout.active]
                .iter()
                .enumerate()
                .fold(AB::Expr::ZERO, |sum, (block, mapping)| {
                    match mapping.payload[byte] {
                        Some(source) => {
                            let payload: AB::Expr = public[PAYLOAD_PUBLIC + source].into();
                            sum + selectors[block].clone() * payload
                        }
                        None => sum,
                    }
                });
            builder.assert_eq(
                pack_bits_le::<AB::Expr, _, _>(
                    row[MESSAGE + byte * 8..MESSAGE + (byte + 1) * 8]
                        .iter()
                        .copied(),
                ),
                expected,
            );
        }
        let n: [AB::Expr; LIMBS] = core::array::from_fn(|limb| {
            let mut value = AB::Expr::ZERO;
            for bit in 0..LIMB_BITS {
                let position = limb * LIMB_BITS + bit;
                if position < 128 {
                    value += row[MESSAGE + position] * Val::from_u64(1 << bit);
                }
                for (block, mapping) in self.layout.blocks[..self.layout.active].iter().enumerate()
                {
                    if mapping.appended_bit == position {
                        value += selectors[block].clone() * Val::from_u64(1 << bit);
                    }
                }
            }
            value
        });
        let cells = super::arithmetic::Cells {
            state: &row[..STATE],
            carry: &row[PRODUCT_CARRY..CANONICAL],
            canonical: &row[CANONICAL..CANONICAL_CARRY],
            canonical_carry: &row[CANONICAL_CARRY..TAG_CARRY],
            tag: &row[TAG_CARRY..],
        };
        let step = super::arithmetic::Step {
            updated: super::arithmetic::limbs(&next[..STATE]),
            key: core::array::from_fn(|bit| row[KEY + bit].into()),
            message: n,
            active: active.clone(),
            finalize: builder.is_last_row(),
            inactive_tag: builder.is_transition(),
            tag: core::array::from_fn(|word| public[TAG_PUBLIC + word].into()),
        };
        super::arithmetic::evaluate(builder, cells, step);
        for bit in 0..STATE {
            builder.when_first_row().assert_zero(row[bit]);
            builder
                .when_transition()
                .assert_zero((AB::Expr::ONE - active.clone()) * (next[bit] - row[bit]));
        }
    }
}
pub(crate) use registry200_proof::source::poly1305::{message_limbs, write_bits};
