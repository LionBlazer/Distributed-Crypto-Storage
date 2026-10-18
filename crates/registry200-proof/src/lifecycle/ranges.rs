//! Canonical fixed images and unsigned comparisons, without 64-bit Gold recomposition.
use super::{layout::*, registry};
use bfv_hiding_stark::Val;
use p3_air::{AirBuilder, utils::pack_bits_le};
use p3_field::{Algebra, PrimeCharacteristicRing};
pub fn pack<E: Algebra<Val>, T: Copy + Into<E>>(row: &[T], at: usize, n: usize) -> E {
    pack_bits_le(row[at..at + n].iter().copied())
}
pub fn code<E: Algebra<Val>, T: Copy + Into<E>>(row: &[T], at: usize, n: usize) -> E {
    (0..n).map(|m| row[at + m].into() * E::from_usize(m)).sum()
}
pub fn increment<AB: AirBuilder<F = Val>>(
    b: &mut AB,
    row: &[AB::Var],
    old: [AB::Expr; 2],
    next: usize,
    carry: usize,
    gate: AB::Expr,
) {
    b.assert_bool(row[carry]);
    b.assert_zero(
        gate.clone()
            * (old[0].clone() + AB::Expr::ONE
                - pack::<AB::Expr, _>(row, next, 32)
                - row[carry] * Val::from_u64(1 << 32)),
    );
    b.assert_zero(
        gate.clone() * (old[1].clone() + row[carry] - pack::<AB::Expr, _>(row, next + 32, 32)),
    );
    b.assert_zero((AB::Expr::ONE - gate.clone()) * row[carry]);
    for bit in 0..64 {
        b.assert_zero((AB::Expr::ONE - gate.clone()) * row[next + bit]);
    }
}
/// Preserve the original two-bank constraint order: both Boolean banks, then each canonical bank.
pub fn canonical<AB: AirBuilder<F = Val>>(b: &mut AB, row: &[AB::Var]) {
    let banks = core::array::from_fn::<_, 2, _>(|i| registry::Columns {
        state: [OLD, NEW][i],
        comparisons: COMPARE + i * 4 * 65,
        inverses: NONZERO + i * 4,
    });
    for bank in banks {
        registry::boolean(b, row, bank);
    }
    for bank in banks {
        registry::canonical(b, row, bank);
    }
}
