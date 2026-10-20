//! Bounded cumulative-work ordering of encrypted database commitments.
//!
//! Work orders only independently authorized and computation-proved transitions.
//! This crate does not implement SQL proofs or an unconditional latest-state oracle.
#![forbid(unsafe_code)]

mod chain;
mod durable;
#[cfg(test)]
mod floor_tests;
mod wire;

pub use chain::{Freshness, HeadRef, ImportOutcome, Journal, Reorganization};
pub use durable::DurableJournal;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];
pub type Result<T> = std::result::Result<T, Error>;
pub const HEAD_BYTES: usize = 112;
pub const HEADER_BYTES: usize = 192;
pub const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_JOURNAL_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidProfile,
    InvalidEncoding,
    ResourceLimit,
    InvalidOwnerKey,
    WrongDomain,
    UnknownParent,
    UnknownHead,
    InvalidHeight,
    InvalidTarget,
    InvalidWork,
    InvalidTimestamp,
    InvalidBody,
    BodyUnavailable,
    InvalidAncestor,
    Unauthorized,
    InvalidTransition,
    MissingComputationProof,
    RejectedComputationProof,
    Unconfirmed,
    StaleHead,
    Reorganized,
    MiningExhausted,
    ExistingPath,
    JournalLocked,
    CorruptJournal,
    Io(std::io::ErrorKind),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.kind())
    }
}

/// Full, unsigned, big-endian 256-bit target. No compact target rounding exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Target(pub [u8; 32]);
impl Target {
    pub fn valid(self) -> bool {
        self.0 != [0; 32]
    }
    pub fn permits(self, hash: Hash) -> bool {
        self.valid() && hash <= self.0
    }
    /// Exact floor(2^256 / (target+1)), not claimed hashpower or peer count.
    pub fn work(self) -> Result<BigUint> {
        if !self.valid() {
            return Err(Error::InvalidTarget);
        }
        Ok((BigUint::from(1u8) << 256usize)
            / (BigUint::from_bytes_be(&self.0) + BigUint::from(1u8)))
    }
    pub(crate) fn retarget(self, elapsed: u64, expected: u64, limit: Self) -> Self {
        let elapsed = elapsed.clamp(expected.div_ceil(4), expected.saturating_mul(4));
        let value =
            BigUint::from_bytes_be(&self.0) * BigUint::from(elapsed) / BigUint::from(expected);
        let value = value
            .max(BigUint::from(1u8))
            .min(BigUint::from_bytes_be(&limit.0));
        let bytes = value.to_bytes_be();
        let mut target = [0; 32];
        target[32 - bytes.len()..].copy_from_slice(&bytes);
        Self(target)
    }
}

/// Immutable consensus and admission bounds pinned by the genesis hash.
/// There is deliberately no production default or claimed safe numerical profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolProfile {
    pub initial_target: Target,
    pub pow_limit: Target,
    pub block_spacing_secs: u64,
    /// Heights 1..=interval use the initial target; interval+1 retargets using
    /// timestamps at heights interval and 0. Each later interval uses its branch.
    pub retarget_interval: u32,
    pub max_future_secs: u64,
    /// Number of descendant blocks required; zero is explicitly unconfirmed work.
    pub confirmation_depth: u32,
    pub max_headers: u32,
    pub max_shards: u32,
    pub max_updates: u32,
    pub max_body_bytes: u32,
    pub max_request_bytes: u32,
    pub max_proof_bytes: u32,
    pub max_journal_bytes: u64,
}
impl ProtocolProfile {
    pub fn validate(&self) -> Result<()> {
        let expected = self
            .block_spacing_secs
            .checked_mul(u64::from(self.retarget_interval))
            .ok_or(Error::InvalidProfile)?;
        if !self.initial_target.valid()
            || !self.pow_limit.valid()
            || self.initial_target > self.pow_limit
            || self.block_spacing_secs == 0
            || self.retarget_interval < 2
            || expected > u64::MAX / 4
            || self.max_future_secs == 0
            || self.confirmation_depth == 0
            || self.max_headers < 2
            || self.max_headers > 65_536
            || self.confirmation_depth >= self.max_headers
            || self.max_shards == 0
            || self.max_shards > 4096
            || self.max_updates == 0
            || self.max_updates > self.max_shards
            || self.max_body_bytes < 1024
            || self.max_body_bytes as usize > MAX_BODY_BYTES
            || self.max_request_bytes == 0
            || self.max_proof_bytes == 0
            || self.max_request_bytes > self.max_body_bytes
            || self.max_proof_bytes > self.max_body_bytes
            || self.max_journal_bytes == 0
            || self.max_journal_bytes > MAX_JOURNAL_BYTES
        {
            return Err(Error::InvalidProfile);
        }
        Ok(())
    }
}

/// Opaque, exact canonical storage manifests. Their computation relation is the
/// proof verifier's responsibility; hashing a pair is not a SQL proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadPair {
    pub data: [u8; HEAD_BYTES],
    pub index: [u8; HEAD_BYTES],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardState {
    pub id: u64,
    pub heads: HeadPair,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardUpdate {
    pub id: u64,
    pub old: HeadPair,
    pub new: HeadPair,
}

/// A trust anchor supplied independently of the responding peer. Owner keys
/// authorize database writes and confer no mining weight or infrastructure veto.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Genesis {
    pub network_id: Hash,
    pub database: [u8; 16],
    pub owner: [u8; 32],
    /// Pins application proof parameters and schema/profile semantics. This crate
    /// treats the commitment as opaque; the verifier must check its own setup.
    pub application_commitment: Hash,
    pub timestamp: u64,
    pub profile: ProtocolProfile,
    /// Fixed, sorted initial shard membership. Dynamic shard creation is unsupported.
    pub initial_shards: Vec<ShardState>,
}
impl Genesis {
    pub fn validate(&self) -> Result<()> {
        self.profile.validate()?;
        let key = VerifyingKey::from_bytes(&self.owner).map_err(|_| Error::InvalidOwnerKey)?;
        if key.is_weak() {
            return Err(Error::InvalidOwnerKey);
        }
        if self.initial_shards.is_empty()
            || self.initial_shards.len() > self.profile.max_shards as usize
            || self.initial_shards.windows(2).any(|w| w[0].id >= w[1].id)
        {
            return Err(Error::InvalidTransition);
        }
        Ok(())
    }
    pub fn id(&self) -> Result<Hash> {
        self.validate()?;
        Ok(hash(&self.encode()?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub genesis: Hash,
    pub parent: Hash,
    pub height: u64,
    pub timestamp: u64,
    pub target: Target,
    pub body_hash: Hash,
    pub state_root: Hash,
    pub nonce: u64,
}
impl Header {
    /// Domain-separated SHA256d over the complete canonical header.
    pub fn id(&self) -> Hash {
        double_hash(&self.encode())
    }
    /// Bounded, cancellable-by-chunk mining helper; the caller owns scheduling.
    /// A test using an easy target demonstrates validation, not economic security.
    pub fn mine(&mut self, attempts: u64) -> Result<Hash> {
        for _ in 0..attempts {
            let id = self.id();
            if self.target.permits(id) {
                return Ok(id);
            }
            self.nonce = self.nonce.checked_add(1).ok_or(Error::MiningExhausted)?;
        }
        Err(Error::MiningExhausted)
    }
}

/// One atomic authorization of the exact request, parent and shard changes.
/// Signatures authenticate permission, never computation correctness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedTransition {
    pub parent: Hash,
    pub request: Vec<u8>,
    pub updates: Vec<ShardUpdate>,
    pub proof: Vec<u8>,
    pub owner_signature: [u8; 64],
}
impl AuthorizedTransition {
    pub fn signing_message(&self, genesis: Hash) -> Hash {
        let mut h = Sha256::new();
        h.update(b"dcs/version-journal/authorization/v1");
        h.update(genesis);
        h.update(self.parent);
        h.update(hash(&self.request));
        h.update((self.updates.len() as u64).to_le_bytes());
        for update in &self.updates {
            h.update(update.id.to_le_bytes());
            h.update(update.old.data);
            h.update(update.old.index);
            h.update(update.new.data);
            h.update(update.new.index);
        }
        h.update(hash(&self.proof));
        h.finalize().into()
    }
    pub fn sign(&mut self, genesis: Hash, owner: &SigningKey) {
        self.owner_signature = owner.sign(&self.signing_message(genesis)).to_bytes();
    }
    /// Owner permission for these exact canonical fields only; no computation,
    /// completeness, agreement, current-head or SQL authority is established.
    pub fn check_authorization(&self, owner: &[u8; 32], genesis: Hash) -> Result<()> {
        let key = VerifyingKey::from_bytes(owner).map_err(|_| Error::InvalidOwnerKey)?;
        key.verify_strict(
            &self.signing_message(genesis),
            &Signature::from_bytes(&self.owner_signature),
        )
        .map_err(|_| Error::Unauthorized)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    /// Advances work/confirmation without changing database contents.
    Empty,
    Transition(AuthorizedTransition),
}

/// Exact statement handed to the application-owned cryptographic proof backend.
/// Public validators verify the proof components available to them. In an
/// owner-finalized compact-store model, the owner separately verifies complete
/// authenticated selection and finalization before authorizing the root update;
/// public STARK arithmetic verification does not prove that private AEAD linkage.
pub struct TransitionStatement<'a> {
    pub genesis: Hash,
    pub database: [u8; 16],
    pub application_commitment: Hash,
    pub parent: HeadRef,
    pub previous_shards: &'a [ShardState],
    pub next_shards: &'a [ShardState],
    pub request: &'a [u8],
    pub updates: &'a [ShardUpdate],
    pub proof: &'a [u8],
    pub next_state_root: Hash,
}
pub trait TransitionVerifier {
    /// Must verify the pinned application's genuine cryptographic execution proofs
    /// and exact request/job/state bindings. Returning Ok merely for an owner
    /// signature, hash, decryption or replayed result is invalid. Applications must
    /// separately enforce any owner-side completeness/finalization checks; journal
    /// validation by itself does not establish those SQL acceptance guarantees.
    fn verify(&self, statement: TransitionStatement<'_>) -> Result<()>;
}

/// Fail-closed adapter for deployments where the SQL proof backend is absent.
pub struct RejectUnprovedTransitions;
impl TransitionVerifier for RejectUnprovedTransitions {
    fn verify(&self, _statement: TransitionStatement<'_>) -> Result<()> {
        Err(Error::MissingComputationProof)
    }
}

pub fn state_root(shards: &[ShardState]) -> Hash {
    let mut h = Sha256::new();
    h.update(b"dcs/version-journal/state/v1");
    h.update((shards.len() as u64).to_le_bytes());
    for shard in shards {
        h.update(shard.id.to_le_bytes());
        h.update(shard.heads.data);
        h.update(shard.heads.index);
    }
    h.finalize().into()
}
pub fn hash(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
}
fn double_hash(bytes: &[u8]) -> Hash {
    hash(&hash(bytes))
}
