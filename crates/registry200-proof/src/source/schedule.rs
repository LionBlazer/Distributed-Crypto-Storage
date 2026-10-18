//! Fixed public schedule. All tables use the full power-of-two height512.
use bfv_hiding_stark::{TRACE_HEIGHT, Val};
use p3_field::PrimeCharacteristicRing;
pub const JOB_ROWS: usize = 81;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Job {
    H(usize),
    Cha { page: usize, counter: u32 },
}
pub fn job(index: usize) -> Job {
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
pub const fn boundary(group: usize) -> usize {
    group * JOB_ROWS + 80
}
pub fn absorb(row: usize) -> Option<(bool, usize)> {
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
pub const CAPTURES: [usize; 5] = [86, 176, 257, 338, 419];
pub fn capture(row: usize) -> Option<usize> {
    CAPTURES.iter().position(|r| *r == row)
}
pub fn plain_location(word: usize) -> (usize, usize, usize) {
    if word < 3 {
        (0, 4, word)
    } else {
        let w = word - 3;
        let index = 5 + w / 16;
        (index / 7, index % 7, w % 16)
    }
}
#[derive(Clone, Copy)]
pub enum Mac {
    Block { page: usize, block: usize },
    Final(usize),
    Idle,
}
pub fn mac(row: usize) -> Mac {
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
pub fn columns() -> Vec<Vec<Val>> {
    (0..TRACE_HEIGHT)
        .map(|selected| {
            (0..TRACE_HEIGHT)
                .map(|row| Val::from_bool(row == selected))
                .collect()
        })
        .collect()
}

/// The original retained-bit profile remains 81 rows per group. The packed
/// profile uses one additional bit-state row to range-bind feedforward output.
#[derive(Clone, Copy)]
pub struct Schedule {
    packed: bool,
}
impl Schedule {
    pub const fn new(packed: bool) -> Self {
        Self { packed }
    }
    pub const fn job_rows(self) -> usize {
        if self.packed { 82 } else { JOB_ROWS }
    }
    pub const fn boundary(self, group: usize) -> usize {
        if self.packed {
            group * self.job_rows() + self.job_rows() - 1
        } else {
            boundary(group)
        }
    }
    pub const fn final_absorb(self) -> usize {
        499 + if self.packed { 6 } else { 0 }
    }
    pub fn captures(self) -> [usize; 5] {
        core::array::from_fn(|i| CAPTURES[i] + if self.packed { i + 1 } else { 0 })
    }
    pub fn capture(self, row: usize) -> Option<usize> {
        if self.packed {
            self.captures().iter().position(|r| *r == row)
        } else {
            capture(row)
        }
    }
    pub fn absorb(self, row: usize) -> Option<(bool, usize)> {
        if !self.packed {
            return absorb(row);
        }
        match row {
            0..=3 => Some((true, row)),
            4..=13 => Some((false, row - 4)),
            _ => {
                let group = row / self.job_rows();
                let step = row % self.job_rows();
                match group {
                    1 if step < 5 => Some((false, 10 + step)),
                    2..=6 if step < 14 => Some((false, 15 + (group - 2) * 14 + step)),
                    _ => None,
                }
            }
        }
    }
}
