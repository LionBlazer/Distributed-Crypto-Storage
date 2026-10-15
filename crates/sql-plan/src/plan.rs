/// Public statement values supplied by the authorized client, never peer data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RowValues {
    pub age: u8,
    pub amount: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgeRange {
    pub lower: u8,
    pub upper: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Comparison {
    Equal,
    AtLeast,
    LessThan,
    AtMost,
    GreaterThan,
    Between { upper: u8 },
}

pub const MAX_SQL_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Predicate {
    pub comparison: Comparison,
    /// Comparison bound, or the inclusive lower bound of BETWEEN.
    pub threshold: u8,
}

impl Predicate {
    /// Normalize the public SQL condition without inspecting any stored rows.
    /// None denotes a constant-false condition in the unsigned age domain.
    pub fn age_range(self) -> Option<AgeRange> {
        let (lower, upper) = match self.comparison {
            Comparison::Equal => (self.threshold, self.threshold),
            Comparison::AtLeast => (self.threshold, u8::MAX),
            Comparison::LessThan => (0, self.threshold.checked_sub(1)?),
            Comparison::AtMost => (0, self.threshold),
            Comparison::GreaterThan => (self.threshold.checked_add(1)?, u8::MAX),
            Comparison::Between { upper } => (self.threshold, upper),
        };
        (lower <= upper).then_some(AgeRange { lower, upper })
    }
}

impl Default for Predicate {
    fn default() -> Self {
        Self {
            comparison: Comparison::AtLeast,
            threshold: 0,
        }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
        row: RowValues,
    },
}
