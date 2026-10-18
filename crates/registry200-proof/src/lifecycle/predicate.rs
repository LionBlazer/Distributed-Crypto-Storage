//! One complete 256-age equality scan, shared by Acquire and AddAmount.
use super::ranges::pack;
use bfv_hiding_stark::{TRACE_HEIGHT, Val};
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
#[derive(Clone, Copy)]
pub struct Columns {
    pub equality: usize,
    pub accumulator: usize,
    pub matched: usize,
}
pub struct Scan<E> {
    pub active: E,
    pub threshold: E,
    pub mask: E,
}
pub fn eval_row<AB: AirBuilder<F = Val>>(
    b: &mut AB,
    row: &[AB::Var],
    next: &[AB::Var],
    selectors: &[AB::Expr; TRACE_HEIGHT],
    age: AB::Expr,
    columns: Columns,
    scan: Scan<AB::Expr>,
) {
    let Columns {
        equality: at,
        accumulator,
        matched,
    } = columns;
    let Scan {
        active: scan,
        threshold,
        mask,
    } = scan;
    for v in &row[at..at + 10] {
        b.assert_bool(*v);
    }
    for v in &row[at..at + 11] {
        b.assert_zero((AB::Expr::ONE - scan.clone()) * *v);
    }
    let difference: AB::Expr = pack(row, at, 8);
    let zero: AB::Expr = row[at + 9].into();
    b.assert_zero(
        scan.clone()
            * (age + Val::from_u16(256)
                - threshold.clone()
                - difference.clone()
                - row[at + 8] * Val::from_u16(256)),
    );
    b.assert_zero(scan.clone() * difference.clone() * zero.clone());
    b.assert_zero(scan.clone() * (difference * row[at + 10] - (AB::Expr::ONE - zero.clone())));
    b.assert_zero(scan.clone() * zero.clone() * row[at + 10]);
    b.when_first_row().assert_zero(row[accumulator]);
    b.when_transition()
        .assert_eq(next[accumulator], row[accumulator] + mask.clone() * zero);
    b.assert_zero(selectors[256].clone() * (row[matched] - row[accumulator]));
}
