//! Closed owner of one new Progress installation. Cryptographic proof and QC
//! acceptance, private result opening and a synced record all precede SQL output.
mod completion;
mod host;
mod inventory;
mod prepare;
mod state;
#[cfg(test)]
mod tests;
mod wal;

use crate::private_predicate::{
    EncryptedSourceState, FetchedSource, SourceOwner, SourceStateAuthority, SourceStateIdentity,
};
use bfv_query_core::{
    BfvKeyAnchor, EncryptedOwnerState, Owner as BfvOwner, OwnerStateAuthority, OwnerStateIdentity,
    PublicSetup,
};
pub use host::{
    Bootstrap, Call, Computed, ControlOutcome, Cursor, Outcome, Owner, Preparation, Reply, Row,
    Submission, Work,
};
use registry200_finality::progress::{Binding, Checkpoint};
use registry200_joint::progress::{Application, Descriptor};
use sha2::{Digest, Sha256};
use std::io;
use zeroize::Zeroizing;

pub type Result<T> = core::result::Result<T, Error>;
#[derive(Debug)]
pub enum Error {
    Encoding,
    Pins,
    Shape,
    Phase,
    Cas,
    ResourceLimit,
    Busy,
    Poisoned,
    RecoveryRequired,
    Cryptography,
    Io(io::Error),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Progress owner rejected: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
fn crypto(_: impl core::fmt::Display) -> Error {
    Error::Cryptography
}
fn storage(e: protocol_storage::Error) -> Error {
    match e {
        protocol_storage::Error::Io(e) => Error::Io(e),
        _ => Error::ResourceLimit,
    }
}
fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in parts {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part);
    }
    h.finalize().into()
}
fn app(binding: &Binding) -> Result<Application> {
    Application::new(
        binding.application_descriptor().clone(),
        binding.journal_genesis(),
    )
    .map_err(crypto)
}
fn again<'a>(source: &FetchedSource<'a>) -> FetchedSource<'a> {
    FetchedSource {
        object: source.object,
        bundle: source.bundle,
        heads: source.heads,
    }
}

pub const MAX_RECORD_BYTES: usize = 1024 * 1024;
pub const MAX_RECORDS: usize = 128;
pub const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_BODY_BYTES: usize = 64 * 1024;
pub const MAX_REPLAY_BYTES: usize = 16 * 1024 * 1024;
pub fn profile_digest() -> [u8; 32] {
    hash(&[
        b"DCS/Progress-owner/v1/closed-no-legacy-migration",
        &registry200_joint::progress::contract_digest(),
        &registry200_finality::progress::durable_profile_digest(),
        &protocol_storage::participant_profile_digest(),
        b"POWAL001/header104/record72-XChaCha20Poly1305-nonce24-tag16/ciphertext-chain-AAD/Init-Prepare-Submit-Commit-ACK-Empty/Attempt6839-cap8192/State1092/Bank1228/Book512/Call56/Parked128/Result160/one-flight-two-parked;exactBody-QC-typedStep-root-open-atomicAEAD-fsync-before-flight-free;Done-only-currentBFVdecrypt;Error-no-rows;ACK-terminal-only;strict-replay-no-success-token;Ready-external-fullALL33-originalStatement/freshattemptq;no-parkedRollbackTo-cancel-deadlock-EPQ",
        &(MAX_RECORD_BYTES as u64).to_le_bytes(), &(MAX_RECORDS as u64).to_le_bytes(),
        &MAX_FILE_BYTES.to_le_bytes(), &(MAX_BODY_BYTES as u64).to_le_bytes(),
        &(MAX_REPLAY_BYTES as u64).to_le_bytes(),
    ])
}

/// Independently authenticated logical client route, not a database permission.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ClientBinding {
    id: [u8; 32],
    principal: u8,
}
impl ClientBinding {
    pub fn new(id: [u8; 32], principal: u8) -> Result<Self> {
        if id == [0; 32] || !(1..=2).contains(&principal) {
            return Err(Error::Pins);
        }
        Ok(Self { id, principal })
    }
    pub fn client_id(&self) -> [u8; 32] {
        self.id
    }
}
/// Private local wrapping authority, kept externally by the embedding owner.
pub struct Authority(Zeroizing<[u8; 32]>);
impl Authority {
    pub fn new(key: Zeroizing<[u8; 32]>) -> Self {
        Self(key)
    }
}
/// Immutable independently selected installation, owner and logical-client pins.
/// A peer cannot supply replacement setup, Key33, Rules, clients or controllers.
pub struct Pins {
    binding: Binding,
    clients: [ClientBinding; 2],
    controllers: Zeroizing<[[u8; 32]; 2]>,
    id: [u8; 32],
}
impl Pins {
    pub fn new(
        binding: Binding,
        identity: [u8; 32],
        clients: [ClientBinding; 2],
        controllers: Zeroizing<[[u8; 32]; 2]>,
    ) -> Result<Self> {
        if identity == [0; 32]
            || clients[0].id == clients[1].id
            || controllers.contains(&[0; 32])
            || binding.rules().application_id()
                != registry200_finality::progress::durable_profile_digest()
        {
            return Err(Error::Pins);
        }
        app(&binding)?;
        let id = hash(&[
            b"DCS/Progress-owner/pins/v1",
            &profile_digest(),
            &binding.id(),
            &identity,
            &clients[0].id,
            &[clients[0].principal],
            &clients[1].id,
            &[clients[1].principal],
            &controllers[0],
            &controllers[1],
        ]);
        Ok(Self {
            binding,
            clients,
            controllers,
            id,
        })
    }
    pub fn binding_id(&self) -> [u8; 32] {
        self.binding.id()
    }
}
/// Genuine public Bootstrap/Empty lineage, still unverified until owner replay.
/// All referenced originals must already exist in this owner's SAME scoped depot.
pub struct Replay<'a> {
    pub checkpoint: &'a Checkpoint,
    pub block: &'a registry200_finality::CandidateBlock,
}

/// Original external encrypted custody. No wrapping key or Ready frame is
/// serialized into the owner WAL; fresh attempts restore exactly the same ALL33.
pub struct Material<'a> {
    pub setup: &'a PublicSetup,
    pub anchor: &'a BfvKeyAnchor,
    pub key: &'a bfv_key_transform::Statement,
    pub owner_identity: &'a OwnerStateIdentity,
    pub owner_authority: &'a OwnerStateAuthority,
    pub owner_record: &'a EncryptedOwnerState,
    pub anchor_record: &'a EncryptedOwnerState,
    pub ready_record: &'a EncryptedOwnerState,
    pub source_identity: &'a SourceStateIdentity,
    pub source_authority: &'a SourceStateAuthority,
    pub source_record: &'a EncryptedSourceState,
}
impl Material<'_> {
    fn require(&self, pins: &Pins) -> Result<()> {
        let expected = pins.binding.application_descriptor();
        let descriptor = Descriptor::checked(
            registry200_journal::ApplicationDescriptor::from_application(
                &expected.source_spec().map_err(crypto)?,
            )
            .map_err(crypto)?,
            expected.source_object(),
            self.setup,
            self.anchor,
            self.key,
        )
        .map_err(crypto)?;
        if descriptor.encode() != expected.encode()
            || self.owner_identity.scope != *self.anchor.scope()
        {
            return Err(Error::Pins);
        }
        Ok(())
    }
    fn fingerprint(&self, pins: &Pins) -> Result<[u8; 32]> {
        self.require(pins)?;
        Ok(hash(&[
            b"DCS/Progress-owner/original-custody/v1",
            &pins.id,
            &self.owner_identity.record_id,
            self.owner_record.as_bytes(),
            self.anchor_record.as_bytes(),
            self.ready_record.as_bytes(),
            self.source_record.as_bytes(),
        ]))
    }
    fn source(&self, pins: &Pins, fetched: FetchedSource<'_>) -> Result<SourceOwner> {
        self.require(pins)?;
        if fetched.object != pins.binding.application_descriptor().source_object() {
            return Err(Error::Pins);
        }
        SourceOwner::restore_private_state(
            self.source_identity,
            fetched,
            self.source_authority,
            self.source_record,
        )
        .map_err(crypto)
    }
    fn owner(&self, pins: &Pins) -> Result<BfvOwner> {
        self.require(pins)?;
        BfvOwner::restore_private_state(
            self.setup,
            self.owner_identity,
            self.owner_authority,
            self.owner_record,
        )
        .map_err(crypto)
    }
}
