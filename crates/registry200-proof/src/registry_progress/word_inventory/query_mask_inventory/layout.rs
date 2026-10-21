//! Closed structural schedule; no caller-selected routes, roots or private values.
use crate::Val;
use bfv_hiding_stark::poseidon;
use p3_field::PrimeCharacteristicRing;

pub(super) const HEIGHT: usize = 1024;
pub(super) const LOG_HEIGHT: usize = 10;
pub(super) const STATEMENT_FIELDS: usize = 96;
pub(super) const VECTOR_FIELDS: usize = 4112;
pub(super) const ABSORBS: usize = 526;
pub(super) const SCALE: u64 = 16389;
pub(super) const T: u64 = 65537;
pub(super) const P2: usize = poseidon::WIDTH;
pub(super) const CHECKPOINT: usize = P2;
pub(super) const STATEMENT: usize = CHECKPOINT + 12;
pub(super) const MASK: usize = STATEMENT + STATEMENT_FIELDS;
pub(super) const VECTOR_SALT: usize = MASK + 256;
pub(super) const PUBLIC: usize = VECTOR_SALT + 4;
pub(super) const WIDTH: usize = PUBLIC + super::PUBLIC_COUNT;
pub(super) const ACTIVE: usize = 0;
pub(super) const STATEMENT_LAST: usize = 1;
pub(super) const VECTOR_LAST: usize = 2;
pub(super) const STATEMENT_BLOCK: usize = 3;
pub(super) const VECTOR_CONTEXT: usize = STATEMENT_BLOCK + 12;
pub(super) const VECTOR_PREFIX_SALT: usize = VECTOR_CONTEXT + 1;
pub(super) const MASK_BLOCK: usize = VECTOR_PREFIX_SALT + 1;
pub(super) const PP_WIDTH: usize = MASK_BLOCK + 32;
const _: () = assert!(P2 == 248 && WIDTH == 649 && PP_WIDTH == 49);
const _: () = assert!(SCALE < T && STATEMENT_FIELDS + VECTOR_FIELDS == 4208);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Stream {
    Statement,
    Vector,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Field {
    Statement(usize),
    Context(usize),
    VectorSalt(usize),
    ScaledMask { coefficient: usize, bit: usize },
    Zero,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Absorb {
    pub stream: Stream,
    pub block: usize,
}
impl Absorb {
    pub(super) fn field(self, lane: usize) -> Field {
        assert!(lane < 8);
        let index = 8 * self.block + lane;
        match self.stream {
            Stream::Statement => Field::Statement(index),
            Stream::Vector => match index {
                0..=7 => Field::Context(index),
                8..=11 => Field::VectorSalt(index - 8),
                16..=271 => Field::ScaledMask {
                    coefficient: index - 16,
                    bit: 271 - index,
                },
                _ => Field::Zero,
            },
        }
    }
}
#[derive(Clone)]
pub(super) struct Plan {
    pub rows: Vec<Absorb>,
}
impl Plan {
    pub(super) fn closed() -> Result<Self, String> {
        let rows = (0..12)
            .map(|block| Absorb {
                stream: Stream::Statement,
                block,
            })
            .chain((0..514).map(|block| Absorb {
                stream: Stream::Vector,
                block,
            }))
            .collect();
        let plan = Self { rows };
        plan.inventory()?;
        Ok(plan)
    }
    pub(super) fn inventory(&self) -> Result<(), String> {
        if self.rows.len() != ABSORBS || HEIGHT != 1024 || WIDTH != 649 || PP_WIDTH != 49 {
            return Err("query-mask:closed-shape".into());
        }
        let mut statements = [0usize; 96];
        let mut context = [0usize; 8];
        let mut salt = [0usize; 4];
        let mut bits = [0usize; 256];
        let mut vector_fields = 0;
        let mut high_zero = 0;
        let mut prefix_zero = 0;
        for (row_index, row) in self.rows.iter().copied().enumerate() {
            let (stream, block) = if row_index < 12 {
                (Stream::Statement, row_index)
            } else {
                (Stream::Vector, row_index - 12)
            };
            if row != (Absorb { stream, block }) {
                return Err(format!("query-mask:foreign-route:{row_index}"));
            }
            for lane in 0..8 {
                let index = 8 * row.block + lane;
                match (row.stream, row.field(lane)) {
                    (Stream::Statement, Field::Statement(i)) if i == index && i < 96 => {
                        statements[i] += 1
                    }
                    (Stream::Vector, field) => {
                        vector_fields += 1;
                        match (index, field) {
                            (0..=7, Field::Context(i)) if i == index => context[i] += 1,
                            (8..=11, Field::VectorSalt(i)) if i + 8 == index => salt[i] += 1,
                            (12..=15, Field::Zero) => prefix_zero += 1,
                            (16..=271, Field::ScaledMask { coefficient, bit })
                                if coefficient + 16 == index && bit + coefficient == 255 =>
                            {
                                bits[bit] += 1
                            }
                            (272..=4111, Field::Zero) => high_zero += 1,
                            _ => return Err(format!("query-mask:vector-field:{index}")),
                        }
                    }
                    _ => return Err(format!("query-mask:statement-field:{index}")),
                }
            }
            let pp = self.pp_row(row_index);
            let selectors = pp[STATEMENT_BLOCK..VECTOR_CONTEXT]
                .iter()
                .chain(pp[MASK_BLOCK..].iter())
                .filter(|v| **v == Val::ONE)
                .count();
            let expected_selectors = usize::from(row_index < 12 || (14..46).contains(&row_index));
            if pp[ACTIVE] != Val::ONE
                || selectors != expected_selectors
                || pp[STATEMENT_LAST] != Val::from_bool(row_index == 11)
                || pp[VECTOR_LAST] != Val::from_bool(row_index == 525)
                || pp[VECTOR_CONTEXT] != Val::from_bool(row_index == 12)
                || pp[VECTOR_PREFIX_SALT] != Val::from_bool(row_index == 13)
            {
                return Err("query-mask:pp-route".into());
            }
        }
        if statements != [1; 96]
            || context != [1; 8]
            || salt != [1; 4]
            || bits != [1; 256]
            || vector_fields != VECTOR_FIELDS
            || high_zero != 3840
            || prefix_zero != 4
            || (ABSORBS..HEIGHT).any(|r| self.pp_row(r) != [Val::ZERO; PP_WIDTH])
        {
            return Err("query-mask:incomplete-fields".into());
        }
        Ok(())
    }
    pub(super) fn pp_row(&self, index: usize) -> [Val; PP_WIDTH] {
        let mut row = [Val::ZERO; PP_WIDTH];
        let Some(absorb) = self.rows.get(index) else {
            return row;
        };
        row[ACTIVE] = Val::ONE;
        match absorb.stream {
            Stream::Statement => {
                row[STATEMENT_BLOCK + absorb.block] = Val::ONE;
                row[STATEMENT_LAST] = Val::from_bool(absorb.block == 11);
            }
            Stream::Vector => {
                row[VECTOR_LAST] = Val::from_bool(absorb.block == 513);
                match absorb.block {
                    0 => row[VECTOR_CONTEXT] = Val::ONE,
                    1 => row[VECTOR_PREFIX_SALT] = Val::ONE,
                    2..=33 => row[MASK_BLOCK + absorb.block - 2] = Val::ONE,
                    _ => {}
                }
            }
        }
        row
    }
}
