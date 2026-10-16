//! Fixed public schedule. All tables use the full power-of-two height512.
use crate::backend::{TRACE_HEIGHT, Val};
use p3_field::PrimeCharacteristicRing;
pub(crate) const JOB_ROWS: usize = 81;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Job {
    H(usize),
    Cha { page: usize, counter: u32 },
}
pub(crate) fn job(index: usize) -> Job {
    match index {
        0 => Job::H(0),
        1 => Job::H(1),
        2 => Job::Cha {
            page: 0,
            counter: 0,
        },
        3 => Job::Cha {
            page: 1,
            counter: 0,
        },
        4 => Job::Cha {
            page: 0,
            counter: 1,
        },
        _ => Job::Cha {
            page: 1,
            counter: (index - 4) as u32,
        },
    }
}
pub(crate) fn boundary(group: usize) -> usize {
    group * JOB_ROWS + 80
}
pub(crate) fn absorb(row: usize) -> Option<(bool, usize)> {
    match row {
        0..=3 => Some((true, row)),
        4..=13 => Some((false, row - 4)),
        81..=85 => Some((false, 10 + row - 81)),
        162..=175 => Some((false, 15 + row - 162)),
        243..=256 => Some((false, 29 + row - 243)),
        324..=337 => Some((false, 43 + row - 324)),
        405..=418 => Some((false, 57 + row - 405)),
        486..=499 => Some((false, 71 + row - 486)),
        _ => None,
    }
}
pub(crate) const CAPTURES: [usize; 5] = [86, 176, 257, 338, 419];
pub(crate) fn capture(row: usize) -> Option<usize> {
    CAPTURES.iter().position(|r| *r == row)
}
pub(crate) fn plain_location(word: usize) -> (usize, usize, usize) {
    if word < 3 {
        (0, 4, word)
    } else {
        let w = word - 3;
        let index = 5 + w / 16;
        (index / 7, index % 7, w % 16)
    }
}
#[derive(Clone, Copy)]
pub(crate) enum Mac {
    Block { page: usize, block: usize },
    Final(usize),
    Idle,
}
pub(crate) fn mac(row: usize) -> Mac {
    match row {
        0..=8 => Mac::Block {
            page: 0,
            block: row,
        },
        9 => Mac::Final(0),
        10..=163 => Mac::Block {
            page: 1,
            block: row - 10,
        },
        164 => Mac::Final(1),
        _ => Mac::Idle,
    }
}
/// One selector per physical row avoids non-power-of-two periods or secret schedules.
/// Source-derived inputs are selected by the same verifier-owned public statement.
pub(crate) fn columns() -> Vec<Vec<Val>> {
    (0..TRACE_HEIGHT)
        .map(|selected| {
            (0..TRACE_HEIGHT)
                .map(|row| Val::from_bool(row == selected))
                .collect()
        })
        .collect()
}
