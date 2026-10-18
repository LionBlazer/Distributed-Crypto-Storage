//! Exact 8208-field vector schedule shared by these two roles; no SIMD arithmetic.
use super::{COMMAND_FIELDS, Role, layout::*, statement::Expected};
use bfv_hiding_stark::{Val, poseidon};
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::default_goldilocks_poseidon2_12;
use p3_symmetric::Permutation;
/// New Cmd48 only. Original commitment domains and accepted stream lengths stay untouched.
pub fn command_digest(fields: &[Val; COMMAND_FIELDS]) -> [Val; 4] {
    let mut s = [Val::ZERO; 12];
    let p = default_goldilocks_poseidon2_12();
    for block in fields.as_chunks::<8>().0 {
        s[..8].copy_from_slice(block);
        p.permute_mut(&mut s);
    }
    s[..4].try_into().unwrap()
}
pub fn command_fields(e: &Expected, mask: [u8; 32], salt: [Val; 4]) -> [Val; COMMAND_FIELDS] {
    assert_eq!(e.role(), Role::PrivateMask);
    crate::source::statement::words(&super::COMMAND_DOMAIN)
        .chain([Val::ONE])
        .chain(crate::source::statement::words(&super::profile_digest(
            Role::PrivateMask,
        )))
        .chain(e.base_context())
        .chain(crate::source::statement::words(&e.sql_identity()))
        .chain(crate::source::statement::words(&mask))
        .chain(salt)
        .chain([Val::ZERO; 7])
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}
/// Public vector context/root and the role's private salt column offset.
pub struct VectorBinding {
    pub context: [Val; 8],
    pub salt: usize,
    pub root: [Val; 4],
}
/// Constraints for context8,salt4,zero4,W8192; capacity always carries in overwrite mode.
pub fn evaluate<AB: AirBuilder<F = Val>>(
    b: &mut AB,
    row: &[AB::Var],
    next: &[AB::Var],
    first: AB::Expr,
    last: AB::Expr,
    w: &[AB::Expr; 16],
    binding: VectorBinding,
) {
    let VectorBinding {
        context,
        salt,
        root,
    } = binding;
    let a = poseidon::evaluate(b, &row[..P2]);
    let d = poseidon::evaluate(b, &row[P2..2 * P2]);
    let end = first.clone() + last.clone();
    let c = poseidon::evaluate(&mut b.when(end.clone()), &row[2 * P2..3 * P2]);
    for v in &row[2 * P2..3 * P2] {
        b.assert_zero((AB::Expr::ONE - end.clone()) * *v);
    }
    for i in 0..8 {
        b.assert_eq(
            row[i],
            first.clone() * context[i] + (AB::Expr::ONE - first.clone()) * row[CARRY + i],
        );
        let prefix: AB::Expr = if i < 4 {
            row[salt + i].into()
        } else {
            AB::Expr::ZERO
        };
        b.assert_eq(
            row[P2 + i],
            first.clone() * prefix + (AB::Expr::ONE - first.clone()) * w[i].clone(),
        );
        b.assert_eq(
            row[2 * P2 + i],
            first.clone() * w[i].clone() + last.clone() * w[8 + i].clone(),
        );
        b.when_first_row().assert_zero(row[CARRY + i]);
        b.when_transition()
            .assert_eq(next[CARRY + i], w[8 + i].clone());
    }
    for i in 8..12 {
        b.assert_eq(row[i], row[VECTOR_CP + i]);
        b.assert_eq(row[P2 + i], a[i].clone());
        b.assert_eq(row[2 * P2 + i], end.clone() * d[i].clone());
    }
    for i in 0..12 {
        b.when_first_row().assert_zero(row[VECTOR_CP + i]);
        b.when_transition().assert_eq(
            next[VECTOR_CP + i],
            first.clone() * c[i].clone() + (AB::Expr::ONE - first.clone()) * d[i].clone(),
        );
    }
    for (i, v) in c.iter().take(4).enumerate() {
        b.assert_zero(last.clone() * (v.clone() - root[i]));
    }
}
/// Native trace-side writer only. The AIR above independently enforces every cell.
pub fn write_vector(
    row: &mut [Val],
    index: usize,
    context: [Val; 8],
    salt: [Val; 4],
    w: [Val; 16],
    checkpoint: [Val; 12],
    carry: [Val; 8],
) -> ([Val; 12], [Val; 4]) {
    row[VECTOR_CP..VECTOR_CP + 12].copy_from_slice(&checkpoint);
    row[CARRY..CARRY + 8].copy_from_slice(&carry);
    let mut a = [Val::ZERO; 12];
    a[..8].copy_from_slice(if index == 0 { &context } else { &carry });
    a[8..].copy_from_slice(&checkpoint[8..]);
    let a = poseidon::write(&mut row[..P2], a);
    let mut d = [Val::ZERO; 12];
    if index == 0 {
        d[..4].copy_from_slice(&salt);
    } else {
        d[..8].copy_from_slice(&w[..8]);
    }
    d[8..].copy_from_slice(&a[8..]);
    let d = poseidon::write(&mut row[P2..2 * P2], d);
    row[2 * P2..3 * P2].fill(Val::ZERO);
    let mut c = [Val::ZERO; 12];
    if index == 0 || index == 511 {
        c[..8].copy_from_slice(if index == 0 { &w[..8] } else { &w[8..] });
        c[8..].copy_from_slice(&d[8..]);
        c = poseidon::write(&mut row[2 * P2..3 * P2], c);
    }
    (if index == 0 { c } else { d }, c[..4].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all8192_vector_schedule_matches_the_existing_formation_digest_including_last_word() {
        let context = core::array::from_fn(|i| Val::from_usize(17 + i));
        let salt = [Val::from_u8(29); 4];
        let words: Vec<_> = (0..8192)
            .map(|i| Val::from_usize((i * 7919 + 8191) % 114689))
            .collect();
        let expected = bfv_key_transform::circuit::digest(context, salt, &words);
        let mut cp = [Val::ZERO; 12];
        let mut carry = [Val::ZERO; 8];
        let mut root = [Val::ZERO; 4];
        let mut row = vec![Val::ZERO; SOURCE_WIDTH];
        for r in 0..512 {
            let w = core::array::from_fn(|l| words[16 * r + l]);
            let (next, digest) = write_vector(&mut row, r, context, salt, w, cp, carry);
            cp = next;
            carry = w[8..].try_into().unwrap();
            if r == 511 {
                root = digest;
            }
        }
        assert_eq!(root, expected);
        let mut changed = words;
        changed[8191] += Val::ONE;
        assert_ne!(
            root,
            bfv_key_transform::circuit::digest(context, salt, &changed)
        );
    }
}
