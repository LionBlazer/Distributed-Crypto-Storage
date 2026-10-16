//! Shared canonical radix26 state, cyclic reduction and tag arithmetic.
use super::{CLAMP, LIMB_BITS, LIMBS, RADIX};
use crate::backend::Val;
use p3_air::{AirBuilder, utils::pack_bits_le};
use p3_field::PrimeCharacteristicRing;

pub(crate) const STATE: usize = 130;
pub(crate) const CARRY: usize = STATE;
pub(crate) const CANONICAL: usize = CARRY + 160;
pub(crate) const CANONICAL_CARRY: usize = CANONICAL + STATE;
pub(crate) const TAG: usize = CANONICAL_CARRY + LIMBS;
pub(crate) const WIDTH: usize = TAG + 4;

pub(crate) struct Cells<'a, T> {
    pub(crate) state: &'a [T],
    pub(crate) carry: &'a [T],
    pub(crate) canonical: &'a [T],
    pub(crate) canonical_carry: &'a [T],
    pub(crate) tag: &'a [T],
}
impl<'a, T> Cells<'a, T> {
    pub(crate) fn packed(row: &'a [T]) -> Self {
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
pub(crate) struct Step<E> {
    pub(crate) updated: [E; LIMBS],
    pub(crate) key: [E; 256],
    pub(crate) message: [E; LIMBS],
    pub(crate) active: E,
    pub(crate) finalize: E,
    // Boundary selectors need not be Boolean; do not infer this from finalize.
    pub(crate) inactive_tag: E,
    pub(crate) tag: [E; 4],
}
pub(crate) fn limbs<E: PrimeCharacteristicRing, T: Into<E> + Copy>(bits: &[T]) -> [E; LIMBS] {
    core::array::from_fn(|limb| {
        pack_bits_le(
            bits[limb * LIMB_BITS..(limb + 1) * LIMB_BITS]
                .iter()
                .copied(),
        )
    })
}
pub(crate) fn evaluate<AB: AirBuilder<F = Val>>(
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

pub(crate) fn write_canonical(
    state: &mut [Val],
    canonical: &mut [Val],
    carries: &mut [Val],
    h: [u64; LIMBS],
) {
    let mut carry = 5;
    for (limb, value) in h.into_iter().enumerate() {
        super::air::write_bits(&mut state[limb * LIMB_BITS..(limb + 1) * LIMB_BITS], value);
        let sum = value + carry;
        super::air::write_bits(
            &mut canonical[limb * LIMB_BITS..(limb + 1) * LIMB_BITS],
            sum & super::MASK,
        );
        carry = sum >> LIMB_BITS;
        carries[limb] = Val::from_u64(carry);
    }
}
