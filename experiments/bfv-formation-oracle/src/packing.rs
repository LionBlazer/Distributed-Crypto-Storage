//! The original-input layouts, copied as contracts from their owning core APIs.
use crate::{DEGREE, Result};
use zeroize::Zeroizing;

pub(crate) const ROW_CAPACITY: usize = 256;
pub(crate) const AGGREGATE_CAPACITY: usize = 2560;
pub(crate) const PRESENCE: usize = 2 * ROW_CAPACITY;

#[derive(Clone, Copy)]
pub(crate) struct Row {
    pub(crate) age: u8,
    pub(crate) amount: u16,
}

/// Explicitly PUBLIC NONSECRET source records, not a simulated query answer.
pub(crate) const PUBLIC_ROWS: [Row; 4] = [
    Row {
        age: 255,
        amount: 0,
    },
    Row {
        age: 0,
        amount: 65535,
    },
    Row {
        age: 255,
        amount: 256,
    },
    Row {
        age: 128,
        amount: 255,
    },
];

#[derive(Clone, Copy)]
pub(crate) enum Layout {
    ExactSelect,
    UpdateAmounts,
    PolynomialAggregate,
}
impl Layout {
    pub(crate) const ALL: [Self; 3] = [
        Self::ExactSelect,
        Self::UpdateAmounts,
        Self::PolynomialAggregate,
    ];
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::ExactSelect => "exact-select-original",
            Self::UpdateAmounts => "indexed-update-original-amounts",
            Self::PolynomialAggregate => "Q2-polynomial-aggregate-original",
        }
    }
    pub(crate) fn simd(self) -> bool {
        !matches!(self, Self::PolynomialAggregate)
    }
}

pub(crate) struct Packed {
    pub(crate) layout: Layout,
    pub(crate) values: Zeroizing<Vec<u64>>,
}

pub(crate) fn pack(layout: Layout, rows: &[Row]) -> Result<Packed> {
    let cap = if matches!(layout, Layout::PolynomialAggregate) {
        AGGREGATE_CAPACITY
    } else {
        ROW_CAPACITY
    };
    if rows.len() > cap {
        return Err("original source exceeds this core operation's capacity".into());
    }
    let mut values = Zeroizing::new(vec![0; DEGREE]);
    for (slot, row) in rows.iter().enumerate() {
        match layout {
            // indexed_select::prepare_exact_select_for_experiment:
            // ORIGINAL age/amount and private presence, before public projection.
            Layout::ExactSelect => {
                values[slot] = u64::from(row.age);
                values[DEGREE / 2 + slot] = u64::from(row.amount);
                values[PRESENCE + slot] = 1;
            }
            // indexed_update::prepare_indexed_update_for_experiment:
            // Original amount byte limbs. This input has NO presence lane.
            Layout::UpdateAmounts => {
                values[slot] = u64::from(row.amount & 255);
                values[DEGREE / 2 + slot] = u64::from(row.amount >> 8);
            }
            // polynomial_aggregate Q2: coefficient packing, NOT SIMD.
            Layout::PolynomialAggregate => {
                values[slot] = u64::from(row.amount & 255);
                values[AGGREGATE_CAPACITY + slot] = u64::from(row.amount >> 8);
                values[2 * AGGREGATE_CAPACITY + slot] = 1;
            }
        }
    }
    Ok(Packed { layout, values })
}
