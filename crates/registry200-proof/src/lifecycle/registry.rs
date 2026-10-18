//! The one canonical Registry200 bank, independent of a transition or operation.
use super::layout::*;
use bfv_hiding_stark::Val;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
/// Caller-owned circuit offsets; this is not a checked state or admission token.
#[derive(Clone, Copy)]
pub struct Columns {
    pub state: usize,
    pub comparisons: usize,
    pub inverses: usize,
}
pub fn boolean<AB: AirBuilder<F = Val>>(b: &mut AB, row: &[AB::Var], columns: Columns) {
    for value in &row[columns.state..columns.state + STATE] {
        b.assert_bool(*value);
    }
}
fn comparison<AB: AirBuilder<F = Val>>(
    b: &mut AB,
    row: &[AB::Var],
    left: usize,
    right: usize,
    at: usize,
) {
    // left-right subtraction in base2; all difference digits are derived Booleans.
    b.assert_zero(row[at]);
    for bit in 0..64 {
        b.assert_bool(row[at + bit + 1]);
        let difference: AB::Expr = row[left + bit] - row[right + bit] - row[at + bit]
            + row[at + bit + 1] * Val::from_u8(2);
        b.assert_bool(difference);
    }
}
pub fn canonical<AB: AirBuilder<F = Val>>(b: &mut AB, row: &[AB::Var], columns: Columns) {
    let state = columns.state;
    let bases = [slot(state, 0), slot(state, 1)];
    let pairs = [
        (state + REV, state + ALLOC),
        (state + ALLOC, bases[0] + ID),
        (state + ALLOC, bases[1] + ID),
        (bases[0] + ID, bases[1] + ID),
    ];
    for (i, (left, right)) in pairs.into_iter().enumerate() {
        let at = columns.comparisons + i * 65;
        comparison(b, row, left, right, at);
        if i < 3 {
            b.assert_zero(row[at + 64]);
        } else {
            b.assert_zero(row[bases[1] + PRESENT] * (AB::Expr::ONE - row[at + 64].into()));
        }
    }
    b.assert_zero(row[bases[1] + PRESENT] * (AB::Expr::ONE - row[bases[0] + PRESENT].into()));
    for (t, base) in bases.into_iter().enumerate() {
        let present: AB::Expr = row[base + PRESENT].into();
        for at in [base + ID, base + SEQ] {
            let index = columns.inverses + t * 2 + usize::from(at == base + SEQ);
            let population: AB::Expr = row[at..at + 64].iter().copied().map(Into::into).sum();
            b.assert_eq(population * row[index], present.clone());
            b.assert_zero((AB::Expr::ONE - present.clone()) * row[index]);
        }
        b.assert_eq(
            row[base + PRINCIPAL] + row[base + PRINCIPAL + 1],
            present.clone(),
        );
        // All serialized absent fields are zero; internal zero-mode one-hots remain canonical.
        for at in (base + ID..base + HELD).chain(base + SP..base + SLOT) {
            // Frame one-hot mode banks are handled separately below.
            let in_frame_mode =
                (0..2).any(|f| (frame(base, f) + SAVED..frame(base, f) + FRAME).contains(&at));
            if !in_frame_mode {
                b.assert_zero((AB::Expr::ONE - present.clone()) * row[at]);
            }
        }
        let frames = [frame(base, 0), frame(base, 1)];
        b.assert_zero(row[frames[1]] * (AB::Expr::ONE - row[frames[0]].into()));
        for f in frames {
            b.assert_zero(row[f] * (AB::Expr::ONE - present.clone()));
            for at in f + NAME..f + SAVED {
                b.assert_zero((AB::Expr::ONE - row[f].into()) * row[at]);
            }
        }
        for r in 0..4 {
            let modes = [
                base + HELD + 5 * r,
                frames[0] + SAVED + 5 * r,
                frames[1] + SAVED + 5 * r,
            ];
            for (i, at) in modes.into_iter().enumerate() {
                let sum: AB::Expr = row[at..at + 5].iter().copied().map(Into::into).sum();
                b.assert_eq(sum, AB::Expr::ONE);
                let p = if i == 0 {
                    present.clone()
                } else {
                    row[frames[i - 1]].into()
                };
                for m in 1..5 {
                    b.assert_zero((AB::Expr::ONE - p.clone()) * row[at + m]);
                }
            }
            for a in 0..5 {
                for c in 0..a {
                    b.assert_zero(
                        row[frames[0] + SAVED + 5 * r + a] * row[base + HELD + 5 * r + c],
                    );
                    b.assert_zero(
                        row[frames[1] + SAVED + 5 * r + a] * row[base + HELD + 5 * r + c],
                    );
                    b.assert_zero(
                        row[frames[1]]
                            * row[frames[0] + SAVED + 5 * r + a]
                            * row[frames[1] + SAVED + 5 * r + c],
                    );
                }
            }
            for m in 0..5 {
                let latest: AB::Expr = row[frames[1]] * row[frames[1] + SAVED + 5 * r + m]
                    + (row[frames[0]] - row[frames[1]]) * row[frames[0] + SAVED + 5 * r + m]
                    + (AB::Expr::ONE - row[frames[0]].into()) * Val::from_bool(m == 0);
                b.assert_zero(row[base + FAILED] * (row[base + HELD + 5 * r + m] - latest));
            }
        }
    }
    for r in 0..4 {
        for a in 1..5 {
            for c in 1..5 {
                if super::conflicts(a as u8, c as u8) {
                    b.assert_zero(row[held(bases[0], r, a)] * row[held(bases[1], r, c)]);
                }
            }
        }
    }
}
