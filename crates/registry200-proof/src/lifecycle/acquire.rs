//! Full four-row conflict/prefix walker. No owner-computed answer is an AIR substitute.
use super::{layout::*, ranges::pack};
use bfv_hiding_stark::{TRACE_HEIGHT, Val};
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
pub fn eval<AB: AirBuilder<F = Val>>(
    b: &mut AB,
    row: &[AB::Var],
    next: &[AB::Var],
    selectors: &[AB::Expr; TRACE_HEIGHT],
) {
    let acquire: AB::Expr = row[OP + 1].into();
    for value in &row[MATCHES..ACC] {
        b.assert_bool(*value);
    }
    for value in &row[SEARCH..SUCCESS] {
        b.assert_bool(*value);
    }
    b.assert_bool(row[SUCCESS]);
    b.assert_eq(
        row[MODE..MODE + 4]
            .iter()
            .copied()
            .map(Into::into)
            .sum::<AB::Expr>(),
        acquire.clone(),
    );
    b.assert_eq(
        row[WAIT..WAIT + 3]
            .iter()
            .copied()
            .map(Into::into)
            .sum::<AB::Expr>(),
        acquire.clone(),
    );
    for at in [OFFSET, LIMIT] {
        b.assert_zero(row[at + 2] * (row[at] + row[at + 1]));
    }
    let scan: AB::Expr = selectors[..256].iter().cloned().sum();
    let threshold: AB::Expr = selectors[..256]
        .iter()
        .enumerate()
        .map(|(r, s)| s.clone() * Val::from_usize(r))
        .sum();
    let mask: AB::Expr = selectors[..256]
        .iter()
        .enumerate()
        .map(|(r, s)| s.clone() * row[MASK + r])
        .sum();
    for i in 0..4 {
        let at = EQUALITY + 11 * i;
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
                * (pack::<AB::Expr, _>(row, AGES + 8 * i, 8) + Val::from_u16(256)
                    - threshold.clone()
                    - difference.clone()
                    - row[at + 8] * Val::from_u16(256)),
        );
        b.assert_zero(scan.clone() * difference.clone() * zero.clone());
        b.assert_zero(scan.clone() * (difference * row[at + 10] - (AB::Expr::ONE - zero.clone())));
        b.assert_zero(scan.clone() * zero.clone() * row[at + 10]);
        b.when_first_row().assert_zero(row[ACC + i]);
        b.when_transition()
            .assert_eq(next[ACC + i], row[ACC + i] + mask.clone() * zero);
        b.assert_zero(selectors[256].clone() * (row[MATCHES + i] - row[ACC + i]));
        let own: [AB::Expr; 5] = core::array::from_fn(|m| {
            (0..2)
                .map(|t| row[ACTOR + t] * row[held(slot(OLD, t), i, m)])
                .sum()
        });
        for m in 0..5 {
            let desired: AB::Expr = (0..5)
                .flat_map(|old| {
                    (1..5)
                        .filter(move |r| old.max(*r) == m)
                        .map(move |r| (old, r))
                })
                .map(|(old, r)| own[old].clone() * row[MODE + r - 1])
                .sum();
            b.assert_eq(
                row[DESIRED + 5 * i + m],
                desired + (AB::Expr::ONE - acquire.clone()) * own[m].clone(),
            );
        }
        let other: [AB::Expr; 5] = core::array::from_fn(|m| {
            (0..2)
                .map(|t| row[ACTOR + t] * row[held(slot(OLD, 1 - t), i, m)])
                .sum()
        });
        let conflict: AB::Expr = row[MODE] * other[4].clone()
            + row[MODE + 1] * (other[3].clone() + other[4].clone())
            + row[MODE + 2] * (other[2].clone() + other[3].clone() + other[4].clone())
            + row[MODE + 3]
                * (other[1].clone() + other[2].clone() + other[3].clone() + other[4].clone());
        b.assert_eq(row[CONFLICT + i], conflict);
        for (start, prefix, bound) in [
            (
                LIMIT_CMP,
                (0..i).map(|j| row[RETURN + j].into()).sum::<AB::Expr>(),
                pack::<AB::Expr, _>(row, LIMIT, 3),
            ),
            (
                OFFSET_CMP,
                (0..i).map(|j| row[VISIT + j].into()).sum::<AB::Expr>(),
                pack::<AB::Expr, _>(row, OFFSET, 3),
            ),
        ] {
            let at = start + 4 * i;
            b.assert_eq(
                prefix + Val::from_u8(8) - bound,
                pack::<AB::Expr, _>(row, at, 3) + row[at + 3] * Val::from_u8(8),
            );
        }
        let previous: AB::Expr = (0..i).map(|j| row[BLOCK + j].into()).sum();
        b.assert_eq(
            row[SEARCH + i],
            acquire.clone()
                * (AB::Expr::ONE - previous)
                * (AB::Expr::ONE - row[LIMIT_CMP + 4 * i + 3].into()),
        );
        b.assert_eq(row[ATTEMPT + i], row[SEARCH + i] * row[MATCHES + i]);
        b.assert_eq(
            row[BLOCK + i],
            row[ATTEMPT + i] * row[CONFLICT + i] * (row[WAIT] + row[WAIT + 1]),
        );
        b.assert_eq(
            row[SKIP + i],
            row[ATTEMPT + i] * row[CONFLICT + i] * row[WAIT + 2],
        );
        b.assert_eq(
            row[VISIT + i],
            row[ATTEMPT + i] * (AB::Expr::ONE - row[CONFLICT + i].into()),
        );
        b.assert_eq(
            row[RETURN + i],
            row[VISIT + i] * row[OFFSET_CMP + 4 * i + 3],
        );
    }
    let blocked: AB::Expr = (0..4).map(|i| row[BLOCK + i].into()).sum();
    b.assert_bool(blocked.clone());
    b.assert_eq(row[SUCCESS], AB::Expr::ONE - blocked.clone());
    for w in 0..4 {
        b.assert_zero(blocked.clone() * (row[SALTS + 16 + w] - row[SALTS + 8 + w]));
    }
}
