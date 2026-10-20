use crate::QueryPlan;

/// Owner-side statement syntax, without a transaction, proof or execution grant.
/// BEGIN/START TRANSACTION, COMMIT/END and ROLLBACK/ABORT normalize aliases.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatementPlan {
    Query(QueryPlan),
    /// Modes retain their original order, including repeated or conflicting items.
    /// An empty list leaves defaults unspecified; a consumer must validate support
    /// and semantics instead of dropping options or inferring an isolation level.
    Begin {
        modes: Vec<TransactionMode>,
    },
    Commit {
        chain: TransactionChain,
    },
    Rollback {
        chain: TransactionChain,
    },
    Savepoint {
        name: SavepointName,
    },
    Release {
        name: SavepointName,
    },
    RollbackTo {
        name: SavepointName,
    },
}

/// A PG18 UTF8 identifier normalized for named transaction syntax only.
/// Unquoted ASCII letters fold to lowercase; quoted spelling is preserved.
/// Both forms clip to 63 UTF8 bytes at a character boundary. No database lookup,
/// savepoint existence, transaction state, hash identity or authority is implied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SavepointName(String);

impl SavepointName {
    /// PostgreSQL's standard NAMEDATALEN - 1, not the whole-input SQL budget.
    pub const MAX_BYTES: usize = 63;

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn from_identifier(value: &str, quoted: bool) -> Self {
        let mut end = value.len().min(Self::MAX_BYTES);
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        let value = &value[..end];
        Self(if quoted {
            value.to_owned()
        } else {
            value.to_ascii_lowercase()
        })
    }
}

/// A requested isolation level, never a guarantee that a backend implements it.
/// READ UNCOMMITTED remains distinct from READ COMMITTED at this syntax boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IsolationLevel {
    Serializable,
    RepeatableRead,
    ReadCommitted,
    ReadUncommitted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionAccess {
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deferrability {
    Deferrable,
    NotDeferrable,
}

/// One explicitly supplied PostgreSQL transaction characteristic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionMode {
    Isolation(IsolationLevel),
    Access(TransactionAccess),
    Deferrability(Deferrability),
}

/// Retains both the presence and meaning of AND [NO] CHAIN.
/// The parser never starts the next transaction or supplies inherited modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionChain {
    Unspecified,
    Chain,
    NoChain,
}
