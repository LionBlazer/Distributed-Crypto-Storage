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
