use tfhe::{FheUint8, FheUint16};

/// Bounds both table allocation and the u32 aggregate's maximum possible value.
pub const MAX_ROWS: usize = 1_024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlainRow {
    pub age: u8,
    pub amount: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Comparison {
    Equal,
    AtLeast,
}

pub struct AgePredicate {
    pub(crate) domain: KeyDomain,
    pub(crate) comparison: Comparison,
    pub(crate) threshold: FheUint8,
}

pub struct AmountDelta {
    pub(crate) domain: KeyDomain,
    pub(crate) value: FheUint16,
}

/// Owned ciphertexts; row count is public, age and amount are encrypted.
pub struct EncryptedTable {
    pub(crate) domain: KeyDomain,
    pub(crate) rows: Vec<EncryptedRow>,
}

impl EncryptedTable {
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

pub(crate) struct EncryptedRow {
    pub age: FheUint8,
    pub amount: FheUint16,
}

/// An accidental key-mixing check, not an authentication mechanism.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeyDomain(pub [u8; 16]);
