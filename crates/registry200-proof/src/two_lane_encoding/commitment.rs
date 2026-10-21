//! New4112-field salted vector and distinct private Cmd48; no old root is relabeled.
use super::{COMMAND_FIELDS, N, Role, T, layout::*, statement::Expected};
use bfv_hiding_stark::{Error, Val, poseidon};
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::default_goldilocks_poseidon2_12;
use p3_symmetric::Permutation;
pub fn command_digest(fields: &[Val; COMMAND_FIELDS]) -> [Val; 4] {
    let mut state = [Val::ZERO; 12];
    let p = default_goldilocks_poseidon2_12();
    for block in fields.as_chunks::<8>().0 {
        state[..8].copy_from_slice(block);
        p.permute_mut(&mut state);
    }
    state[..4].try_into().unwrap()
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
/// Caller-owned mathematical vector hash, not an accepted commitment opening.
pub fn vector_digest(context: [Val; 8], salt: [Val; 4], words: &[Val]) -> Result<[Val; 4], Error> {
    use p3_field::PrimeField64;
    if words.len() != N || words.iter().any(|x| x.as_canonical_u64() >= T) {
        return Err(Error::Shape);
    }
    let fields = context
        .into_iter()
        .chain(salt)
        .chain([Val::ZERO; 4])
        .chain(words.iter().copied())
        .collect::<Vec<_>>();
    let mut state = [Val::ZERO; 12];
    let p = default_goldilocks_poseidon2_12();
    for block in fields.as_chunks::<8>().0 {
        state[..8].copy_from_slice(block);
        p.permute_mut(&mut state);
    }
    Ok(state[..4].try_into().unwrap())
}
pub struct VectorBinding {
    pub context: [Val; 8],
    pub salt: usize,
    pub root: [Val; 4],
}
/// One delayed8-word block per row. Row0 absorbs context+salt; row511 flushes lastW.
pub fn evaluate<AB: AirBuilder<F = Val>>(
    b: &mut AB,
    row: &[AB::Var],
    next: &[AB::Var],
    first: AB::Expr,
    last: AB::Expr,
    w: &[AB::Expr; 8],
    binding: VectorBinding,
) {
    let VectorBinding {
        context,
        salt,
        root,
    } = binding;
    let main = poseidon::evaluate(b, &row[..P2]);
    let end = first.clone() + last.clone();
    let extra = poseidon::evaluate(&mut b.when(end.clone()), &row[P2..2 * P2]);
    for v in &row[P2..2 * P2] {
        b.assert_zero((AB::Expr::ONE - end.clone()) * *v);
    }
    for i in 0..8 {
        b.assert_eq(
            row[i],
            first.clone() * context[i] + (AB::Expr::ONE - first.clone()) * row[CARRY + i],
        );
        let prefix = if i < 4 {
            row[salt + i].into()
        } else {
            AB::Expr::ZERO
        };
        b.assert_eq(
            row[P2 + i],
            first.clone() * prefix + last.clone() * w[i].clone(),
        );
        b.when_first_row().assert_zero(row[CARRY + i]);
        b.when_transition().assert_eq(next[CARRY + i], w[i].clone());
    }
    for i in 8..12 {
        b.assert_eq(row[i], row[VECTOR_CP + i]);
        b.assert_eq(row[P2 + i], end.clone() * main[i].clone());
    }
    for i in 0..12 {
        b.when_first_row().assert_zero(row[VECTOR_CP + i]);
        b.when_transition().assert_eq(
            next[VECTOR_CP + i],
            first.clone() * extra[i].clone() + (AB::Expr::ONE - first.clone()) * main[i].clone(),
        );
    }
    for (i, value) in extra.iter().take(4).enumerate() {
        b.assert_zero(last.clone() * (value.clone() - root[i]));
    }
}
/// Private trace writer. Every gadget/checkpoint/word is constrained by evaluate.
pub fn write_vector(
    row: &mut [Val],
    index: usize,
    context: [Val; 8],
    salt: [Val; 4],
    w: [Val; 8],
    checkpoint: [Val; 12],
    carry: [Val; 8],
) -> ([Val; 12], [Val; 4]) {
    row[VECTOR_CP..VECTOR_CP + 12].copy_from_slice(&checkpoint);
    row[CARRY..CARRY + 8].copy_from_slice(&carry);
    let mut input = [Val::ZERO; 12];
    input[..8].copy_from_slice(if index == 0 { &context } else { &carry });
    input[8..].copy_from_slice(&checkpoint[8..]);
    let main = poseidon::write(&mut row[..P2], input);
    row[P2..2 * P2].fill(Val::ZERO);
    let mut extra = [Val::ZERO; 12];
    if index == 0 || index == 511 {
        if index == 0 {
            extra[..4].copy_from_slice(&salt);
        } else {
            extra[..8].copy_from_slice(&w);
        }
        extra[8..].copy_from_slice(&main[8..]);
        extra = poseidon::write(&mut row[P2..2 * P2], extra);
    }
    (
        if index == 0 { extra } else { main },
        extra[..4].try_into().unwrap(),
    )
}
