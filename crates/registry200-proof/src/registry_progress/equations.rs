//! Private pure sequential equations shared by the unchanged legacy wrapper.
//! No proof constructor, Source policy, verifier callback or admission capability.
use super::{transition_fields::selected_progress, transition_layout::*};
use crate::{
    Val,
    lifecycle::ranges::{self, code, pack},
};
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
fn compare<AB: AirBuilder<F = Val>>(
    b: &mut AB,
    row: &[AB::Var],
    prefix: AB::Expr,
    bound: AB::Expr,
    at: usize,
) {
    b.assert_eq(
        prefix + Val::from_u8(8) - bound,
        pack::<AB::Expr, _>(row, at, 3) + row[at + 3] * Val::from_u8(8),
    );
}
pub(super) fn predicate<AB: AirBuilder<F = Val>>(
    b: &mut AB,
    row: &[AB::Var],
    sql_identity: [u8; 32],
) {
    let error: AB::Expr = row[STATUS + 2].into();
    let resume: AB::Expr = row[RESUME].into();
    for i in [0, 3, 4, 5, 6] {
        b.assert_zero(row[OP + i]);
    }
    b.assert_eq(row[OP + 1], AB::Expr::ONE - error.clone());
    b.assert_eq(row[OP + 2], error.clone());
    b.assert_eq(
        resume.clone(),
        selected_progress::<AB::Expr, _>(row, OLD_PROGRESS, 0),
    );
    for (w, v) in crate::source::statement::words(&sql_identity).enumerate() {
        b.assert_zero(
            (AB::Expr::ONE - resume.clone())
                * (pack::<AB::Expr, _>(row, ORIGINAL_SQL + 32 * w, 32) - v),
        );
    }
    for (at, n) in [
        (QUERY_MODE, 4),
        (QUERY_WAIT, 3),
        (OLD_CURSOR, 5),
        (NEW_CURSOR, 5),
        (STATUS, 3),
    ] {
        b.assert_eq(
            row[at..at + n]
                .iter()
                .copied()
                .map(Into::into)
                .sum::<AB::Expr>(),
            AB::Expr::ONE,
        );
    }
    b.assert_zero(row[ABORT]);
    b.assert_zero(resume.clone() * (row[QUERY_WAIT + 1] + row[QUERY_WAIT + 2]));
    for bit in 0..256 {
        b.assert_eq(
            row[MASK + bit],
            (AB::Expr::ONE - error.clone()) * row[QUERY_MASK + bit],
        );
    }
    for i in 0..4 {
        b.assert_eq(
            row[MODE + i],
            (AB::Expr::ONE - error.clone()) * row[QUERY_MODE + i],
        );
    }
    for i in 0..3 {
        b.assert_eq(
            row[WAIT + i],
            (AB::Expr::ONE - error.clone()) * row[QUERY_WAIT + i],
        );
    }
    for i in 0..2 {
        b.assert_eq(
            row[PROJECTION + i],
            (AB::Expr::ONE - error.clone()) * row[QUERY_PROJECTION + i],
        );
    }
    b.assert_zero(
        (AB::Expr::ONE - row[QUERY_PROJECTION].into())
            * (AB::Expr::ONE - row[QUERY_PROJECTION + 1].into()),
    );
    for at in [QUERY_OFFSET, QUERY_LIMIT] {
        b.assert_zero(row[at + 2] * (row[at] + row[at + 1]));
    }
    for i in 0..3 {
        b.assert_eq(
            row[OFFSET + i],
            (AB::Expr::ONE - error.clone()) * row[QUERY_OFFSET + i],
        );
        b.assert_eq(
            row[LIMIT + i],
            (AB::Expr::ONE - error.clone()) * row[QUERY_LIMIT + i],
        );
    }
    b.assert_zero(row[OLD_CURSOR + 4]);
    b.assert_zero((AB::Expr::ONE - resume.clone()) * (AB::Expr::ONE - row[OLD_CURSOR].into()));
    for (at, n, index) in [
        (CLIENT, 256, 0),
        (CALL, 64, 1),
        (INVOCATION, 256, 2),
        (OLD_MICRO, 64, 3),
        (OLD_HOLDER, 64, 4),
    ] {
        let gate = if index < 3 {
            AB::Expr::ONE
        } else {
            resume.clone()
        };
        let pop: AB::Expr = row[at..at + n].iter().copied().map(Into::into).sum();
        b.assert_eq(pop * row[POP_INVERSES + index], gate.clone());
        if index >= 3 {
            b.assert_zero((AB::Expr::ONE - gate.clone()) * row[POP_INVERSES + index]);
            for v in &row[at..at + n] {
                b.assert_zero((AB::Expr::ONE - gate.clone()) * *v);
            }
        }
    }
    let difference: AB::Expr = (0..64)
        .map(|i| {
            let d: AB::Expr = row[OLD_HOLDER + i] - row[ID_CMD + i];
            d.clone() * d
        })
        .sum();
    b.assert_eq(
        resume.clone() * difference * row[POP_INVERSES + 5],
        resume.clone(),
    );
    b.assert_zero((AB::Expr::ONE - resume.clone()) * row[POP_INVERSES + 5]);
    b.assert_eq(
        row[OLD_HOLDER_MODE..OLD_HOLDER_MODE + 4]
            .iter()
            .copied()
            .map(Into::into)
            .sum::<AB::Expr>(),
        resume.clone(),
    );
    let old_conflict: AB::Expr = (1..5)
        .flat_map(|a| {
            (1..5)
                .filter(move |c| crate::lifecycle::conflicts(a as u8, *c as u8))
                .map(move |c| (a, c))
        })
        .map(|(a, c)| row[QUERY_MODE + a - 1] * row[OLD_HOLDER_MODE + c - 1])
        .sum();
    b.assert_eq(old_conflict, resume.clone());
    b.assert_zero(row[BLOCK_REV_COMPARE]);
    for bit in 0..64 {
        b.assert_zero((AB::Expr::ONE - resume.clone()) * row[OLD_BLOCK_REV + bit]);
        let d: AB::Expr =
            row[OLD_BLOCK_REV + bit] - row[OLD + REV + bit] - row[BLOCK_REV_COMPARE + bit]
                + row[BLOCK_REV_COMPARE + bit + 1] * Val::from_u8(2);
        b.when(resume.clone()).assert_bool(d);
    }
    b.assert_eq(row[BLOCK_REV_COMPARE + 64], resume.clone());
    for bit in 0..65 {
        b.assert_zero((AB::Expr::ONE - resume.clone()) * row[BLOCK_REV_COMPARE + bit]);
    }
    for w in 0..4 {
        b.assert_zero((AB::Expr::ONE - resume.clone()) * row[EXTRA_SALTS + 4 + w]);
    }
    ranges::increment(
        b,
        row,
        [pack(row, OLD_MICRO, 32), pack(row, OLD_MICRO + 32, 32)],
        NEW_MICRO,
        MICRO_CARRY,
        AB::Expr::ONE,
    );
    for i in 0..4 {
        let before: AB::Expr = (i + 1..5).map(|j| row[OLD_CURSOR + j].into()).sum();
        b.assert_eq(
            row[OLD_VISITED + i],
            resume.clone() * before.clone() * row[MATCHES + i],
        );
        compare(
            b,
            row,
            (0..i).map(|j| row[OLD_VISITED + j].into()).sum(),
            pack(row, QUERY_OFFSET, 3),
            OLD_OFFSET_CMP + 4 * i,
        );
        b.assert_eq(
            row[OLD_SELECTED + i],
            row[OLD_VISITED + i] * row[OLD_OFFSET_CMP + 4 * i + 3],
        );
        let bad_held: AB::Expr = (1..5)
            .flat_map(|m| (0..m).map(move |h| (m, h)))
            .map(|(m, h)| {
                let own: AB::Expr = (0..2)
                    .map(|t| row[ACTOR + t] * row[held(slot(OLD, t), i, h)])
                    .sum();
                row[QUERY_MODE + m - 1] * own
            })
            .sum();
        b.assert_zero(row[OLD_VISITED + i] * bad_held);
        let other: [AB::Expr; 5] = core::array::from_fn(|m| {
            (0..2)
                .map(|t| row[ACTOR + t] * row[held(slot(OLD, 1 - t), i, m)])
                .sum()
        });
        let conflict: AB::Expr = row[QUERY_MODE] * other[4].clone()
            + row[QUERY_MODE + 1] * (other[3].clone() + other[4].clone())
            + row[QUERY_MODE + 2] * (other[2].clone() + other[3].clone() + other[4].clone())
            + row[QUERY_MODE + 3]
                * (other[1].clone() + other[2].clone() + other[3].clone() + other[4].clone());
        b.assert_eq(row[CONFLICT + i], conflict);
        compare(
            b,
            row,
            (0..i).map(|j| row[NEW_SELECTED + j].into()).sum(),
            pack(row, QUERY_LIMIT, 3),
            LIMIT_CMP + 4 * i,
        );
        compare(
            b,
            row,
            (0..i).map(|j| row[NEW_VISITED + j].into()).sum(),
            pack(row, QUERY_OFFSET, 3),
            OFFSET_CMP + 4 * i,
        );
        let prior_block: AB::Expr = (0..i).map(|j| row[BLOCK + j].into()).sum();
        b.assert_eq(
            row[SEARCH + i],
            (AB::Expr::ONE - before)
                * (AB::Expr::ONE - prior_block)
                * (AB::Expr::ONE - row[LIMIT_CMP + 4 * i + 3].into()),
        );
        b.assert_eq(row[ATTEMPT + i], row[SEARCH + i] * row[MATCHES + i]);
        b.assert_eq(
            row[BLOCK + i],
            row[ATTEMPT + i] * row[CONFLICT + i] * (AB::Expr::ONE - row[QUERY_WAIT + 2].into()),
        );
        b.assert_eq(
            row[SKIP + i],
            row[ATTEMPT + i] * row[CONFLICT + i] * row[QUERY_WAIT + 2],
        );
        b.assert_eq(
            row[VISIT + i],
            row[ATTEMPT + i] * (AB::Expr::ONE - row[CONFLICT + i].into()),
        );
        b.assert_eq(
            row[RETURN + i],
            row[VISIT + i] * row[OFFSET_CMP + 4 * i + 3],
        );
        b.assert_eq(row[NEW_VISITED + i], row[OLD_VISITED + i] + row[VISIT + i]);
        b.assert_eq(
            row[NEW_SELECTED + i],
            row[OLD_SELECTED + i] + row[RETURN + i],
        );
    }
    compare(
        b,
        row,
        row[OLD_SELECTED..OLD_SELECTED + 4]
            .iter()
            .copied()
            .map(Into::into)
            .sum(),
        pack(row, QUERY_LIMIT, 3),
        OLD_LIMIT_CMP,
    );
    b.assert_zero(resume.clone() * row[OLD_LIMIT_CMP + 3]);
    let blocked: AB::Expr = (0..4).map(|i| row[BLOCK + i].into()).sum();
    b.assert_bool(blocked.clone());
    b.assert_eq(row[STATUS], blocked.clone() * row[QUERY_WAIT]);
    b.assert_eq(row[STATUS + 1], AB::Expr::ONE - blocked.clone());
    b.assert_eq(row[STATUS + 2], blocked.clone() * row[QUERY_WAIT + 1]);
    b.assert_eq(
        code::<AB::Expr, _>(row, NEW_CURSOR, 5),
        code::<AB::Expr, _>(row, OLD_CURSOR, 5)
            + (0..4).map(|i| row[SEARCH + i].into()).sum::<AB::Expr>()
            - blocked,
    );
}
