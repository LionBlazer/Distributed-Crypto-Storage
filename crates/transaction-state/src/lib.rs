//! Deterministic, bounded transaction and row-lock control state.
//!
//! Authenticated metadata witnesses prove public control transitions only. They
//! neither execute SQL nor establish candidate completeness, data proofs, row
//! existence, isolation or consensus finality. Runtime waiting and publication
//! belong to the caller; accepted SQL still requires its genuine FHE proof.
#![forbid(unsafe_code)]

mod journal;
mod state;
mod wire;

pub use journal::{MetadataVerifier, PreparedTransition, SignedIntent, VerifiedControl};
pub use state::State;

pub type Digest = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TransactionId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ControllerId(pub [u8; 32]);

/// Stable opaque identities, independent of physical ordinal, shard and key edits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RowKey {
    pub table: [u8; 32],
    pub row: [u8; 32],
}

/// The caller maps normalized SQL identifiers into these opaque equalities.
pub type SavepointName = [u8; 32];

/// Admission parameters pinned by the application's independent trust anchor.
/// There is deliberately no production default or local-clock expiry policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    pub max_transactions: u32,
    pub max_locks: u32,
    pub max_lock_events: u32,
    pub max_candidates: u32,
    pub max_savepoints_per_transaction: u32,
    pub max_state_bytes: u32,
    pub max_command_bytes: u32,
}
impl Profile {
    pub fn validate(self) -> Result<()> {
        if self.max_transactions == 0
            || self.max_transactions > 4096
            || self.max_locks == 0
            || self.max_locks > 262_144
            || self.max_lock_events < self.max_locks
            || self.max_lock_events > 262_144
            || self.max_candidates == 0
            || self.max_candidates > 65_536
            || self.max_savepoints_per_transaction == 0
            || self.max_savepoints_per_transaction > 1024
            || !(512..=16 * 1024 * 1024).contains(&self.max_state_bytes)
            || !(512..=16 * 1024 * 1024).contains(&self.max_command_bytes)
        {
            return Err(Error::InvalidProfile);
        }
        Ok(())
    }
    pub fn commitment(self) -> Digest {
        wire::profile_commitment(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context {
    network: Digest,
    database: [u8; 16],
    profile: Profile,
}
impl Context {
    pub fn new(network: Digest, database: [u8; 16], profile: Profile) -> Result<Self> {
        profile.validate()?;
        Ok(Self {
            network,
            database,
            profile,
        })
    }
    pub fn network(self) -> Digest {
        self.network
    }
    pub fn database(self) -> [u8; 16] {
        self.database
    }
    pub fn profile(self) -> Profile {
        self.profile
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LockMode {
    KeyShare,
    Share,
    NoKeyUpdate,
    Update,
}
impl LockMode {
    /// Conflict between different owners. A transaction never conflicts with itself.
    pub fn conflicts(self, held: Self) -> bool {
        match self {
            Self::KeyShare => held == Self::Update,
            Self::Share => held >= Self::NoKeyUpdate,
            Self::NoKeyUpdate => held >= Self::Share,
            Self::Update => true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitPolicy {
    Wait,
    NoWait,
    SkipLocked,
}

/// Whether the current transaction/subtransaction frame can accept work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionStatus {
    Active,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completion {
    Commit,
    Abort,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Begin {
        snapshot: Digest,
    },
    Acquire {
        /// Ordered row references supplied by the SQL/completeness layer. Repeated
        /// references are allowed; they do not create duplicate held locks.
        candidates: Vec<RowKey>,
        mode: LockMode,
        wait: WaitPolicy,
        /// Offset references still acquire locks; only subsequent ones are returned.
        offset: u32,
        limit: Option<u32>,
    },
    /// Authenticated voluntary failure of the current frame. This is control
    /// intent, not evidence that a SQL statement failed or encrypted data rolled back.
    FailCurrent,
    Savepoint {
        name: SavepointName,
    },
    RollbackTo {
        name: SavepointName,
    },
    Release {
        name: SavepointName,
    },
    /// Ends control ownership. Encrypted data commit/rollback needs the separate
    /// composite SQL transition, not this metadata-only operation. A failed frame
    /// always produces `Outcome::Ended(Completion::Abort)`, even for Commit intent.
    End {
        completion: Completion,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command {
    pub expected_revision: u64,
    pub transaction: TransactionId,
    pub sequence: u64,
    pub action: Action,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intent {
    pub genesis: Digest,
    pub parent: Digest,
    pub controller: ControllerId,
    /// Opaque original statement identity; not a proof of its SQL meaning.
    pub statement: Digest,
    pub command: Command,
}
impl Intent {
    pub fn signing_message(&self, context: Context) -> Result<Digest> {
        wire::intent_message(self, context)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conflict {
    pub candidate: u32,
    pub row: RowKey,
    pub holders: Vec<TransactionId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selection {
    pub selected: Vec<u32>,
    /// Positions with an actual conflicting owner in the exact prior state.
    /// Holder sets are not repeated per candidate: that could multiply a small
    /// state and repeated row references into gigabytes of receipt allocation.
    pub skipped: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Began(TransactionId),
    Acquired(Selection),
    Failed,
    Savepoint,
    RolledBackTo,
    Released,
    Ended(Completion),
}

pub struct Transition {
    pub state: State,
    pub outcome: Outcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionInfo {
    pub controller: ControllerId,
    pub next_sequence: u64,
    pub snapshot: Digest,
    pub status: TransactionStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitment {
    pub revision: u64,
    pub transactions: Digest,
    pub locks: Digest,
    pub transaction_count: u32,
    pub holder_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidProfile,
    InvalidEncoding,
    ResourceLimit,
    WrongDomain,
    StaleRevision,
    WrongSequence,
    UnknownTransaction,
    WrongController,
    CounterExhausted,
    UnknownSavepoint,
    TransactionFailed,
    InvalidCommand,
    InvalidState,
    InvalidSignature,
    InvalidTransition,
    Blocked(Conflict),
    LockUnavailable(Conflict),
}
impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Transaction control rejected {self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
