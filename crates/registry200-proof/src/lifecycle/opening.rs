//! Pure fixed commitment field expressions. No witness, producer or policy authority.
use super::{
    layout::*,
    ranges::{code, pack},
};
use bfv_hiding_stark::Val;
use p3_field::Algebra;

/// Shared PUBLIC prefix only; private command banks have their own owning AIR.
pub fn command_prefix<E: Algebra<Val>>(context: &[Val], old: [Val; 4], f: usize) -> Option<E> {
    match f {
        0..=3 => Some(E::from(
            crate::source::statement::words(&super::statement::COMMAND_DOMAIN)
                .nth(f)
                .unwrap(),
        )),
        4 => Some(E::from_u8(2)),
        5..=104 => Some(E::from(context[f - 5])),
        105..=108 => Some(E::from(old[f - 105])),
        _ => None,
    }
}

/// The original Result144 prefix, with unchanged domains, field order and values.
pub fn result_prefix<E: Algebra<Val>>(context: &[Val], roots: [Val; 12], f: usize) -> Option<E> {
    match f {
        0..=3 => Some(E::from(
            crate::source::statement::words(&super::statement::RESULT_DOMAIN)
                .nth(f)
                .unwrap(),
        )),
        4 => Some(E::from_u8(2)),
        5..=104 => Some(E::from(context[f - 5])),
        105..=116 => Some(E::from(roots[f - 105])),
        _ => None,
    }
}
#[derive(Clone, Copy)]
pub struct Banks {
    pub words: usize,
    pub table: usize,
    pub ids: usize,
    pub controllers: usize,
}
pub fn controller<E: Algebra<Val>, T: Copy + Into<E>>(
    row: &[T],
    principal: usize,
    word: usize,
    controllers: usize,
) -> E {
    (0..2)
        .map(|p| {
            row[principal + p].into() * pack::<E, _>(row, controllers + 256 * p + 32 * word, 32)
        })
        .sum()
}
pub fn slot_field<E: Algebra<Val>, T: Copy + Into<E>>(
    row: &[T],
    base: usize,
    part: usize,
    controllers: usize,
) -> E {
    match part {
        0 => row[base + PRESENT].into(),
        1..=2 => pack(row, base + ID + 32 * (part - 1), 32),
        3 => row[base + PRINCIPAL].into() + row[base + PRINCIPAL + 1].into() * E::from_u8(2),
        4..=11 => controller(row, base + PRINCIPAL, part - 4, controllers),
        12..=13 => pack(row, base + SEQ + 32 * (part - 12), 32),
        14 => row[base + FAILED].into(),
        15..=22 => pack(row, base + SNAPSHOT + 32 * (part - 15), 32),
        23..=26 => code(row, base + HELD + 5 * (part - 23), 5),
        27..=52 => {
            let f = (part - 27) / 13;
            let at = (part - 27) % 13;
            let base = frame(base, f);
            match at {
                0 => row[base].into(),
                1..=8 => pack(row, base + NAME + 32 * (at - 1), 32),
                9..=12 => code(row, base + SAVED + 5 * (at - 9), 5),
                _ => unreachable!(),
            }
        }
        _ => unreachable!(),
    }
}

pub fn source_field<E: Algebra<Val>, T: Copy + Into<E>>(
    prefix: &[Val],
    row: &[T],
    words: usize,
    salt: usize,
    f: usize,
    word: usize,
) -> E {
    match f {
        0..=82 => E::from(prefix[f]),
        83..=86 => row[salt + f - 83].into(),
        87..=673 => pack(row, words + 32 * word, 32),
        _ => E::ZERO,
    }
}
pub fn enrollment_field<E: Algebra<Val>, T: Copy + Into<E>>(
    prefix: &[Val],
    row: &[T],
    banks: Banks,
    salt: usize,
    f: usize,
) -> E {
    match f {
        0..=32 => E::from(prefix[f]),
        33..=40 => row[banks.table + f - 33].into(),
        41 => E::from_u8(2),
        42 => E::ONE,
        51 => E::from_u8(2),
        43..=50 => pack(row, banks.controllers + 32 * (f - 43), 32),
        52..=59 => pack(row, banks.controllers + 256 + 32 * (f - 52), 32),
        60..=63 => row[salt + f - 60].into(),
        _ => unreachable!(),
    }
}
pub fn registry_field<E: Algebra<Val>, T: Copy + Into<E>>(
    prefix: &[Val],
    enrollment: [Val; 4],
    row: &[T],
    banks: Banks,
    salt: usize,
    state: usize,
    f: usize,
) -> E {
    match f {
        0..=32 => E::from(prefix[f]),
        33..=36 => E::from(enrollment[f - 33]),
        37..=44 => row[banks.table + f - 37].into(),
        45..=76 => row[banks.ids + f - 45].into(),
        77 | 79 => E::from_u8(2),
        78 => E::from_u8(4),
        80..=81 => pack(row, state + REV + 32 * (f - 80), 32),
        82..=83 => pack(row, state + ALLOC + 32 * (f - 82), 32),
        84..=189 => slot_field(
            row,
            slot(state, (f - 84) / 53),
            (f - 84) % 53,
            banks.controllers,
        ),
        190..=193 => row[salt + f - 190].into(),
        _ => E::ZERO,
    }
}
