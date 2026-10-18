//! One fixed radix26 constraint/row ABI; no private witness ownership.
use bfv_hiding_stark::Val;
use p3_air::{AirBuilder, utils::pack_bits_le};
use p3_field::PrimeCharacteristicRing;
pub const LIMBS: usize = 5;
pub const LIMB_BITS: usize = 26;
pub const RADIX: u64 = 1 << LIMB_BITS;
pub const MASK: u64 = RADIX - 1;
pub const CLAMP: [u8; 16] = [
    255, 255, 255, 15, 252, 255, 255, 15, 252, 255, 255, 15, 252, 255, 255, 15,
];
pub const STATE: usize = 130;
pub const CARRY: usize = STATE;
pub const CANONICAL: usize = CARRY + 160;
pub const CANONICAL_CARRY: usize = CANONICAL + STATE;
pub const TAG: usize = CANONICAL_CARRY + LIMBS;
pub const WIDTH: usize = TAG + 4;

pub struct Cells<'a, T> {
    pub state: &'a [T],
    pub carry: &'a [T],
    pub canonical: &'a [T],
    pub canonical_carry: &'a [T],
    pub tag: &'a [T],
}
impl<'a, T> Cells<'a, T> {
    pub fn packed(row: &'a [T]) -> Self {
        assert_eq!(row.len(), WIDTH);
        Self {
            state: &row[..STATE],
            carry: &row[CARRY..CANONICAL],
            canonical: &row[CANONICAL..CANONICAL_CARRY],
            canonical_carry: &row[CANONICAL_CARRY..TAG],
            tag: &row[TAG..],
        }
    }
}
pub struct Step<E> {
    pub updated: [E; LIMBS],
    pub key: [E; 256],
    pub message: [E; LIMBS],
    pub active: E,
    pub finalize: E,
    // Boundary selectors need not be Boolean; do not infer this from finalize.
    pub inactive_tag: E,
    pub tag: [E; 4],
}
pub fn limbs<E: PrimeCharacteristicRing, T: Into<E> + Copy>(bits: &[T]) -> [E; LIMBS] {
    core::array::from_fn(|limb| {
        pack_bits_le(
            bits[limb * LIMB_BITS..(limb + 1) * LIMB_BITS]
                .iter()
                .copied(),
        )
    })
}
pub fn evaluate<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    cells: Cells<'_, AB::Var>,
    step: Step<AB::Expr>,
) {
    let h: [AB::Expr; LIMBS] = limbs(cells.state);
    let r: [AB::Expr; LIMBS] = core::array::from_fn(|limb| {
        pack_bits_le((0..LIMB_BITS).map(|bit| {
            let position = limb * LIMB_BITS + bit;
            if position < 128 && (CLAMP[position / 8] >> (position % 8)) & 1 != 0 {
                step.key[position].clone()
            } else {
                AB::Expr::ZERO
            }
        }))
    });
    let carry: [AB::Expr; LIMBS] = core::array::from_fn(|limb| {
        pack_bits_le(cells.carry[limb * 32..(limb + 1) * 32].iter().copied())
    });
    for limb in 0..LIMBS {
        let mut product = AB::Expr::ZERO;
        for (i, (h, n)) in h.iter().zip(&step.message).enumerate() {
            for (j, r) in r.iter().enumerate() {
                if (i + j) % LIMBS == limb {
                    product += (h.clone() + n.clone())
                        * r.clone()
                        * Val::from_u8(if i + j >= LIMBS { 5 } else { 1 });
                }
            }
        }
        let incoming = if limb == 0 {
            carry[LIMBS - 1].clone() * Val::from_u8(5)
        } else {
            carry[limb - 1].clone()
        };
        // Every local integer side is <2^58; canonicality prevents the p alias.
        builder.assert_zero(
            step.active.clone()
                * (product + incoming
                    - step.updated[limb].clone()
                    - carry[limb].clone() * Val::from_u64(RADIX)),
        );
        for bit in &cells.carry[limb * 32..(limb + 1) * 32] {
            builder.assert_zero((AB::Expr::ONE - step.active.clone()) * *bit);
        }
        let z: AB::Expr = pack_bits_le(
            cells.canonical[limb * LIMB_BITS..(limb + 1) * LIMB_BITS]
                .iter()
                .copied(),
        );
        let incoming: AB::Expr = if limb == 0 {
            Val::from_u8(5).into()
        } else {
            cells.canonical_carry[limb - 1].into()
        };
        builder.assert_eq(
            h[limb].clone() + incoming,
            z + cells.canonical_carry[limb] * Val::from_u64(RADIX),
        );
    }
    builder.assert_zero(cells.canonical_carry[LIMBS - 1]);
    for word in 0..4 {
        let low: AB::Expr = pack_bits_le(cells.state[word * 32..(word + 1) * 32].iter().copied());
        let s: AB::Expr = pack_bits_le(
            step.key[128 + word * 32..128 + (word + 1) * 32]
                .iter()
                .cloned(),
        );
        let incoming: AB::Expr = if word == 0 {
            AB::Expr::ZERO
        } else {
            cells.tag[word - 1].into()
        };
        builder.assert_zero(step.inactive_tag.clone() * cells.tag[word]);
        builder.assert_zero(
            step.finalize.clone()
                * (low + s + incoming
                    - step.tag[word].clone()
                    - cells.tag[word] * Val::from_u64(1 << 32)),
        );
    }
}

pub fn write_canonical(
    state: &mut [Val],
    canonical: &mut [Val],
    carries: &mut [Val],
    h: [u64; LIMBS],
) {
    let mut carry = 5;
    for (limb, value) in h.into_iter().enumerate() {
        write_bits(&mut state[limb * LIMB_BITS..(limb + 1) * LIMB_BITS], value);
        let sum = value + carry;
        write_bits(
            &mut canonical[limb * LIMB_BITS..(limb + 1) * LIMB_BITS],
            sum & MASK,
        );
        carry = sum >> LIMB_BITS;
        carries[limb] = Val::from_u64(carry);
    }
}

pub fn message_limbs(message: [u8; 16], appended_bit: usize) -> [u64; LIMBS] {
    let mut result = [0; LIMBS];
    for bit in 0..128 {
        result[bit / LIMB_BITS] |=
            u64::from((message[bit / 8] >> (bit % 8)) & 1) << (bit % LIMB_BITS);
    }
    if appended_bit < STATE {
        result[appended_bit / LIMB_BITS] += 1 << (appended_bit % LIMB_BITS);
    }
    result
}
pub fn write_bits(destination: &mut [Val], value: u64) {
    assert!(destination.len() <= 32 && value < (1_u64 << destination.len()));
    for (bit, cell) in destination.iter_mut().enumerate() {
        *cell = Val::from_u64((value >> bit) & 1);
    }
}

// Shared owner-side radix row construction; these functions do not verify proofs.
pub fn clamped_r(key: [u8; 32]) -> [u64; LIMBS] {
    let bytes: [u8; 16] = core::array::from_fn(|byte| key[byte] & CLAMP[byte]);
    message_limbs(bytes, 130) // No appended bit for the key.
}

pub fn folded_product(h: [u64; LIMBS], n: [u64; LIMBS], r: [u64; LIMBS]) -> [u64; LIMBS] {
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
pub fn reduce(product: [u64; LIMBS]) -> ([u64; LIMBS], [u64; LIMBS]) {
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

pub fn cyclic_carries(product: [u64; LIMBS], h: [u64; LIMBS], quotient: u64) -> [u64; LIMBS] {
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

pub fn tag_words(h: [u64; LIMBS], key: [u8; 32]) -> ([u32; 4], [bool; 4]) {
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
