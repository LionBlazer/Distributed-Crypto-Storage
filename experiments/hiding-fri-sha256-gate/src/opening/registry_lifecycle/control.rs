//! Seven authorized command equations, exact target matching and whole-slot compaction.
use super::{
    layout::*,
    ranges::{increment, pack},
};
use crate::backend::Val;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
fn selected<AB: AirBuilder<F = Val>>(row: &[AB::Var], part: usize) -> AB::Expr {
    (0..2)
        .map(|t| row[ACTOR + t] * row[slot(OLD, t) + part])
        .sum()
}
fn selected_word<AB: AirBuilder<F = Val>>(row: &[AB::Var], part: usize) -> AB::Expr {
    (0..2)
        .map(|t| row[ACTOR + t] * pack::<AB::Expr, _>(row, slot(OLD, t) + part, 32))
        .sum()
}
pub(super) fn eval<AB: AirBuilder<F = Val>>(b: &mut AB, row: &[AB::Var], parent: [Val; 8]) {
    for v in &row[OP..COMPARE] {
        b.assert_bool(*v);
    }
    let begin: AB::Expr = row[OP].into();
    let acquire: AB::Expr = row[OP + 1].into();
    let fail: AB::Expr = row[OP + 2].into();
    let save: AB::Expr = row[OP + 3].into();
    let rollback: AB::Expr = row[OP + 4].into();
    let release: AB::Expr = row[OP + 5].into();
    let end: AB::Expr = row[OP + 6].into();
    b.assert_eq(
        row[OP..OP + 7]
            .iter()
            .copied()
            .map(Into::into)
            .sum::<AB::Expr>(),
        AB::Expr::ONE,
    );
    b.assert_eq(row[ACTOR] + row[ACTOR + 1], AB::Expr::ONE - begin.clone());
    b.assert_eq(row[PRINCIPAL_CMD] + row[PRINCIPAL_CMD + 1], AB::Expr::ONE);
    for t in 0..2 {
        let base = slot(OLD, t);
        b.assert_zero(row[ACTOR + t] * (AB::Expr::ONE - row[base + PRESENT].into()));
        for bit in 0..64 {
            b.assert_zero(row[ACTOR + t] * (row[ID_CMD + bit] - row[base + ID + bit]));
        }
        for i in 0..2 {
            b.assert_zero(row[ACTOR + t] * (row[PRINCIPAL_CMD + i] - row[base + PRINCIPAL + i]));
        }
        b.assert_zero(
            row[ACTOR + t] * row[base + FAILED] * (AB::Expr::ONE - rollback.clone() - end.clone()),
        );
    }
    for bit in 0..64 {
        b.assert_zero(begin.clone() * (row[ID_CMD + bit] - row[CAND_ALLOC + bit]));
    }
    b.assert_zero(begin.clone() * row[slot(OLD, 1) + PRESENT]);
    for bit in 0..256 {
        b.assert_zero((AB::Expr::ONE - acquire.clone()) * row[MASK + bit]);
        b.assert_zero(
            (AB::Expr::ONE - save.clone() - rollback.clone() - release.clone())
                * row[NAME_CMD + bit],
        );
    }
    for value in &row[MODE..ABORT] {
        b.assert_zero((AB::Expr::ONE - acquire.clone()) * *value);
    }
    b.assert_zero((AB::Expr::ONE - end.clone()) * row[ABORT]);
    increment(
        b,
        row,
        [pack(row, OLD + REV, 32), pack(row, OLD + REV + 32, 32)],
        CAND_REV,
        CARRY,
        AB::Expr::ONE,
    );
    increment(
        b,
        row,
        [pack(row, OLD + ALLOC, 32), pack(row, OLD + ALLOC + 32, 32)],
        CAND_ALLOC,
        CARRY + 1,
        begin.clone(),
    );
    let sequence = [
        selected_word::<AB>(row, SEQ),
        selected_word::<AB>(row, SEQ + 32),
    ];
    increment(
        b,
        row,
        sequence,
        CAND_SEQ,
        CARRY + 2,
        AB::Expr::ONE - begin.clone() - end.clone(),
    );
    for f in 0..2 {
        let at = EQ_NAME + 25 * f;
        for i in 0..8 {
            let delta = selected_word::<AB>(row, SP + FRAME * f + NAME + 32 * i)
                - pack::<AB::Expr, _>(row, NAME_CMD + 32 * i, 32);
            let zero: AB::Expr = row[at + 2 * i].into();
            b.assert_bool(zero.clone());
            b.assert_zero(delta.clone() * zero.clone());
            b.assert_eq(delta * row[at + 2 * i + 1], AB::Expr::ONE - zero.clone());
            b.assert_zero(zero * row[at + 2 * i + 1]);
        }
        b.assert_eq(row[at + 16], AB::Expr::ONE);
        for i in 0..8 {
            b.assert_bool(row[at + 17 + i]);
            b.assert_eq(row[at + 17 + i], row[at + 16 + i] * row[at + 2 * i]);
        }
    }
    for v in &row[TARGET..TARGET + 2] {
        b.assert_bool(*v);
    }
    b.assert_eq(
        row[TARGET + 1],
        selected::<AB>(row, SP + FRAME) * row[EQ_NAME + 25 + 24],
    );
    b.assert_eq(
        row[TARGET],
        selected::<AB>(row, SP) * row[EQ_NAME + 24] * (AB::Expr::ONE - row[TARGET + 1].into()),
    );
    b.assert_zero(
        (rollback.clone() + release.clone()) * (row[TARGET] + row[TARGET + 1] - AB::Expr::ONE),
    );
    b.assert_zero(save.clone() * selected::<AB>(row, SP + FRAME));
    let success: AB::Expr = row[SUCCESS].into();
    for bit in 0..64 {
        b.assert_eq(
            row[NEW + REV + bit],
            row[OLD + REV + bit] + success.clone() * (row[CAND_REV + bit] - row[OLD + REV + bit]),
        );
        b.assert_eq(
            row[NEW + ALLOC + bit],
            row[OLD + ALLOC + bit]
                + begin.clone() * (row[CAND_ALLOC + bit] - row[OLD + ALLOC + bit]),
        );
    }
    for t in 0..2 {
        let old = slot(OLD, t);
        let new = slot(NEW, t);
        let append = if t == 0 {
            begin.clone() * (AB::Expr::ONE - row[old + PRESENT].into())
        } else {
            begin.clone() * row[slot(OLD, 0) + PRESENT]
        };
        for part in 0..SLOT {
            let mut changed: AB::Expr = row[old + part].into();
            match part {
                SEQ..=130 => {
                    changed += (AB::Expr::ONE - begin.clone() - end.clone())
                        * (row[CAND_SEQ + part - SEQ] - row[old + part]);
                }
                FAILED => {
                    changed += fail.clone() * (AB::Expr::ONE - row[old + FAILED].into())
                        - rollback.clone() * row[old + FAILED];
                }
                HELD..=407 => {
                    let r = (part - HELD) / 5;
                    let m = (part - HELD) % 5;
                    let f0 = frame(old, 0);
                    let f1 = frame(old, 1);
                    let latest: AB::Expr = row[f1] * row[f1 + SAVED + 5 * r + m]
                        + (row[f0] - row[f1]) * row[f0 + SAVED + 5 * r + m]
                        + (AB::Expr::ONE - row[f0].into()) * Val::from_bool(m == 0);
                    let target: AB::Expr = row[TARGET] * row[f0 + SAVED + 5 * r + m]
                        + row[TARGET + 1] * row[f1 + SAVED + 5 * r + m];
                    changed += acquire.clone()
                        * row[VISIT + r]
                        * (row[DESIRED + 5 * r + m] - row[old + part])
                        + fail.clone() * (latest - row[old + part])
                        + rollback.clone() * (target - row[old + part]);
                }
                SP..=961 => {
                    let f = (part - SP) / FRAME;
                    let component = (part - SP) % FRAME;
                    let current = frame(old, f);
                    let push = if f == 0 {
                        AB::Expr::ONE - row[frame(old, 0)].into()
                    } else {
                        row[frame(old, 0)].into()
                    };
                    let inserted = match component {
                        0 => AB::Expr::ONE,
                        NAME..=256 => row[NAME_CMD + component - NAME].into(),
                        SAVED..=276 => row[old + HELD + component - SAVED].into(),
                        _ => unreachable!(),
                    };
                    let canonical_zero = if component >= SAVED {
                        Val::from_bool((component - SAVED).is_multiple_of(5))
                    } else {
                        Val::ZERO
                    };
                    let remove = if f == 0 {
                        release.clone() * row[TARGET]
                    } else {
                        release.clone() + rollback.clone() * row[TARGET]
                    };
                    changed += save.clone() * push * (inserted - row[current + component])
                        + remove * (AB::Expr::from(canonical_zero) - row[current + component]);
                }
                _ => {}
            }
            let mut expected: AB::Expr =
                row[old + part] + row[ACTOR + t] * success.clone() * (changed - row[old + part]);
            let fresh = match part {
                PRESENT => AB::Expr::ONE,
                ID..=64 => row[ID_CMD + part - ID].into(),
                PRINCIPAL..=66 => row[PRINCIPAL_CMD + part - PRINCIPAL].into(),
                SEQ => AB::Expr::ONE,
                SNAPSHOT..=387 => {
                    let index = part - SNAPSHOT;
                    let word = index / 32;
                    let bit = index % 32;
                    AB::Expr::from(Val::from_bool(
                        (p3_field::PrimeField64::as_canonical_u64(&parent[word]) >> bit) & 1 != 0,
                    ))
                }
                HELD..=407 => AB::Expr::from(Val::from_bool((part - HELD).is_multiple_of(5))),
                SP..=961 => {
                    let component = (part - SP) % FRAME;
                    AB::Expr::from(Val::from_bool(
                        component >= SAVED && (component - SAVED).is_multiple_of(5),
                    ))
                }
                _ => AB::Expr::ZERO,
            };
            // An absent slot already contains canonical zero-mode bits, not an allzero internal bank.
            let empty = if (HELD..SP).contains(&part) {
                (part - HELD).is_multiple_of(5)
            } else if part >= SP {
                let component = (part - SP) % FRAME;
                component >= SAVED && (component - SAVED).is_multiple_of(5)
            } else {
                false
            };
            expected += append.clone() * (fresh - Val::from_bool(empty));
            let ended: AB::Expr = if t == 0 {
                (AB::Expr::ONE - row[ACTOR].into()) * row[slot(OLD, 0) + part]
                    + row[ACTOR] * row[slot(OLD, 1) + part]
            } else {
                Val::from_bool(empty).into()
            };
            expected += end.clone() * (ended - row[old + part]);
            b.assert_eq(row[new + part], expected);
        }
    }
}
