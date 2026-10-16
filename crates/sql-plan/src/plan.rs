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

/// Owner-side output window over the complete matching rows in ordinal order.
/// This plan value is not a serialized peer request or a computation proof.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RowWindow {
    pub offset: usize,
    pub limit: Option<usize>,
}
impl RowWindow {
    /// The prefix each shard must prove before the global offset can be applied.
    /// An empty window still requires complete source validation and a real proof.
    pub fn prefix_limit(self) -> Result<Option<usize>, crate::Error> {
        match self.limit {
            None => Ok(None),
            Some(0) => Ok(Some(0)),
            Some(limit) => self.offset.checked_add(limit).map(Some).ok_or_else(|| {
                crate::Error::InvalidInput("OFFSET plus LIMIT exceeds the row-window range".into())
            }),
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
        window: RowWindow,
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
