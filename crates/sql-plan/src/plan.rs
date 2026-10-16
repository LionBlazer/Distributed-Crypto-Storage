/// Public statement values supplied by the authorized client, never peer data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RowValues {
    pub age: u8,
    pub amount: u16,
}

pub const MAX_SQL_BYTES: usize = 4_096;

/// Compiled WHERE truth over the fixed nonnullable age domain; no stored rows are read.
/// The canonical mask stays owner-side: bit `age % 8` of byte `age / 8` is SQL TRUE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Predicate(pub(crate) [u8; 32]);
impl Predicate {
    /// Exact final TRUE set after three-valued compilation, never a peer query field.
    pub fn age_mask(self) -> [u8; 32] {
        self.0
    }
}
impl Default for Predicate {
    fn default() -> Self {
        Self([u8::MAX; 32])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Column {
    Age,
    Amount,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Projection {
    Age,
    Amount,
    AgeAmount,
    AmountAge,
}
impl Projection {
    pub fn columns(self) -> Vec<Column> {
        match self {
            Self::Age => vec![Column::Age],
            Self::Amount => vec![Column::Amount],
            Self::AgeAmount => vec![Column::Age, Column::Amount],
            Self::AmountAge => vec![Column::Amount, Column::Age],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueryPlan {
    Aggregate {
        predicate: Predicate,
    },
    Count {
        predicate: Predicate,
    },
    Sum {
        predicate: Predicate,
    },
    Select {
        predicate: Predicate,
        projection: Projection,
        /// Output bound only; the complete exact selection is still authenticated.
        limit: Option<usize>,
    },
    AddAmount {
        predicate: Predicate,
        delta: u16,
    },
    Insert {
        /// All literal tuples from one statement, in their original order.
        rows: Vec<RowValues>,
    },
}
