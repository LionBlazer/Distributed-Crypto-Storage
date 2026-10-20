//! Historical owner Control WAL; validation is recorded in the module contract.
use super::super::{
    control::{
        self,
        state::{self, CONTROL_BYTES, IDLE_BYTES},
    },
    *,
};
use super::durable_wal::{Snapshot, Wal};
use crate::private_predicate::{FetchedSource, SourceOwner};
use protocol_storage::{ControlFile, ParticipantQuota, Reservation};
use registry200_finality::{
    CandidateBlock,
    joint::{JointCheckpoint, JointHistory},
};
use registry200_joint::{JointDepot, JointEvidenceIngress, Manifest};
use sha2::{Digest, Sha256};

pub const OWNER_VAULT_MAX_BODY_BYTES: usize = 64 * 1024;
pub const OWNER_VAULT_MAX_RECORD_BYTES: usize = 1024 * 1024;
pub const OWNER_VAULT_MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
pub(super) const MAX_RECORDS: usize = 128;
pub(super) const BLOCK_CAP: usize =
    8 + version_journal::HEADER_BYTES + 4 + OWNER_VAULT_MAX_BODY_BYTES;
const MAX_REPLAY_BYTES: usize = 16 * 1024 * 1024;
pub type VaultResult<T> = core::result::Result<T, OwnerVaultError>;

/// This distinct local format does not change participant, Journal, proof or
/// consensus profiles. It is not a power-loss or anti-rollback theorem.
pub fn owner_vault_profile_digest() -> [u8; 32] {
    hash(&[b"DCS/owner-Control-Vault/v1", b"DCSOVL01/DCSOVP01/XChaCha20Poly1305/phase-chain/strict-no-repair", b"Idle->BodyPrepared->SubmittedUnknown-on-reopen->Completed->Idle;CAS-generation-pendingID-digest;actual-Source-Life-Kind-QC-replay;historical-only", &protocol_storage::participant_profile_digest(), &(OWNER_VAULT_MAX_BODY_BYTES as u64).to_le_bytes(), &(OWNER_VAULT_MAX_RECORD_BYTES as u64).to_le_bytes(), &OWNER_VAULT_MAX_FILE_BYTES.to_le_bytes(), &(MAX_RECORDS as u64).to_le_bytes(), &(MAX_REPLAY_BYTES as u64).to_le_bytes(), &(IDLE_BYTES as u64).to_le_bytes(), &(CONTROL_BYTES as u64).to_le_bytes()])
}
pub(super) fn hash(fields: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for bytes in fields {
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    hash.finalize().into()
}

#[derive(Debug)]
pub enum OwnerVaultError {
    Encoding,
    Authentication,
    Pins,
    Cas,
    Phase,
    ResourceLimit,
    RecoveryRequired,
    Poisoned,
    Io(std::io::Error),
    Storage(protocol_storage::Error),
    Owner(crate::Error),
    Joint(registry200_finality::joint::Error),
    Finality(registry200_finality::Error),
}
impl From<std::io::Error> for OwnerVaultError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<protocol_storage::Error> for OwnerVaultError {
    fn from(e: protocol_storage::Error) -> Self {
        Self::Storage(e)
    }
}
impl From<crate::Error> for OwnerVaultError {
    fn from(e: crate::Error) -> Self {
        Self::Owner(e)
    }
}
impl From<registry200_finality::joint::Error> for OwnerVaultError {
    fn from(e: registry200_finality::joint::Error) -> Self {
        Self::Joint(e)
    }
}
impl core::fmt::Display for OwnerVaultError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Owner Control Vault rejected: {self:?}")
    }
}
impl std::error::Error for OwnerVaultError {}

/// External high-entropy wrapping authority. No database authority, public key
/// getter, filesystem key file, password KDF or operating-system backend.
pub struct OwnerVaultAuthority(pub(super) Zeroizing<[u8; 32]>);
impl OwnerVaultAuthority {
    pub fn new(key: Zeroizing<[u8; 32]>) -> Self {
        Self(key)
    }
}
#[derive(Clone)]
pub struct OwnerVaultIdentity(pub(super) [u8; 32]);
impl OwnerVaultIdentity {
    pub fn new(id: [u8; 32]) -> VaultResult<Self> {
        if id == [0; 32] {
            Err(OwnerVaultError::Pins)
        } else {
            Ok(Self(id))
        }
    }
}
#[derive(Clone)]
pub struct OwnerVaultPins {
    pub(super) binding: JointBinding,
    pub(super) identity: OwnerVaultIdentity,
}
impl OwnerVaultPins {
    pub fn new(binding: JointBinding, identity: OwnerVaultIdentity) -> Self {
        Self { binding, identity }
    }
    fn file_id(&self) -> [u8; 32] {
        hash(&[
            b"DCS/owner-Control-Vault/file/v1",
            &owner_vault_profile_digest(),
            &self.binding.id(),
            &self.identity.0,
        ])
    }
}
/// Untrusted bounded replay inputs. Every entry is actually verified by the
/// internally owned closed History; callers cannot supply a verified flag.
pub struct OwnerVaultReplay<'a> {
    pub checkpoint: &'a JointCheckpoint,
    pub block: &'a CandidateBlock,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerVaultPhase {
    Idle,
    BodyPrepared,
    SubmittedUnknown,
    Completed,
}
/// A local optimistic concurrency observation, not an authorization/lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerVaultCursor {
    generation: u64,
    pending: [u8; 32],
    digest: [u8; 32],
}
impl OwnerVaultCursor {
    pub fn generation(self) -> u64 {
        self.generation
    }
    pub fn pending_id(self) -> [u8; 32] {
        self.pending
    }
    pub fn digest(self) -> [u8; 32] {
        self.digest
    }
}
/// Public proof references for signing one exact Body. No submission bytes are
/// returned by the Vault until the complete signed candidate has synced.
pub struct OwnerVaultDraft {
    pending: [u8; 32],
    request: Vec<u8>,
    manifest: Vec<u8>,
    parent: VerifiedJointParent,
}
impl OwnerVaultDraft {
    pub fn pending_id(&self) -> [u8; 32] {
        self.pending
    }
    pub fn request(&self) -> VaultResult<JointRequest> {
        JointRequest::decode(&self.request).map_err(|e| OwnerVaultError::Owner(cryptography(e)))
    }
    pub fn manifest(&self) -> VaultResult<Manifest> {
        Manifest::decode(&self.manifest).map_err(|e| OwnerVaultError::Owner(cryptography(e)))
    }
    pub fn parent(&self) -> &VerifiedJointParent {
        &self.parent
    }
}
pub struct OwnerVaultSubmission<'a> {
    cursor: OwnerVaultCursor,
    block: &'a CandidateBlock,
}
impl OwnerVaultSubmission<'_> {
    pub fn cursor(&self) -> OwnerVaultCursor {
        self.cursor
    }
    pub fn header(&self) -> &version_journal::Header {
        self.block.header()
    }
    pub fn body(&self) -> &[u8] {
        self.block.body()
    }
}
pub struct OwnerVaultCompletion {
    cursor: OwnerVaultCursor,
    outcome: control::JointControlOutcome,
}
impl OwnerVaultCompletion {
    pub fn cursor(&self) -> OwnerVaultCursor {
        self.cursor
    }
    pub fn outcome(&self) -> control::JointControlOutcome {
        self.outcome
    }
}
struct Draft {
    public: OwnerVaultDraft,
    candidate: control::JointControlCandidate,
}

/// Exclusive owner-private historical Control state. No SQL admission, current
/// lock, private Source/BFV key backup, or anti-rollback guarantee is supplied.
/// ```compile_fail
/// fn copy<T:Clone>(){} fn forbidden(){copy::<storage_client::private_predicate::OwnerVault>();}
/// ```
/// ```compile_fail
/// fn debug<T:core::fmt::Debug>(){} fn forbidden(){debug::<storage_client::private_predicate::OwnerVaultAuthority>();}
/// ```
pub struct OwnerVault {
    pins: OwnerVaultPins,
    wal: Wal,
    history: JointHistory,
    ingress: JointEvidenceIngress,
    saved: Snapshot,
    pending_parent: Option<control::JointControlParent>,
    terminal: Option<Reservation>,
    draft: Option<Draft>,
    recovery_required: bool,
}
impl OwnerVault {
    /// New file ONLY. The supplied quota is the one actual ledger used to open
    /// both this WAL and its private History/depot. Descendants retain its lock.
    pub fn create_new(
        quota: &ParticipantQuota,
        pins: OwnerVaultPins,
        authority: OwnerVaultAuthority,
        source: &SourceOwner,
        fetched: FetchedSource<'_>,
        replay: &[OwnerVaultReplay<'_>],
        opening: control::JointRegistryOpening,
    ) -> VaultResult<Self> {
        validate_replay(replay)?;
        let depot = JointDepot::open(quota.depot_budget())
            .map_err(|e| OwnerVaultError::Owner(cryptography(e)))?;
        let ingress = depot.ingress();
        let mut history = JointHistory::new(pins.binding.clone(), depot)?;
        for entry in replay {
            history.apply(entry.checkpoint, entry.block)?;
        }
        let parent = parent(&history, &pins.binding)?;
        state::require_idle_parent(&opening, &parent)?;
        let idle = state::encode_idle(&opening)?;
        drop(opening);
        // Authenticated caller data is still not a commitment-opening check.
        drop(state::restore_idle(
            idle.as_ref(),
            source,
            fetched,
            &parent,
        )?);
        let saved = Snapshot {
            phase: OwnerVaultPhase::Idle,
            generation: 0,
            pending: [0; 32],
            stamp: current_stamp(&history, &pins.binding)?,
            idle,
            candidate: None,
            block: None,
            checkpoint: None,
            outcome: None,
        };
        let budget = quota.control_budget();
        let mut wal = Wal::create_new(
            &quota.control_file(pins.file_id(), ControlFile::Wal),
            budget,
            &pins,
            authority,
        )?;
        let lease = wal.budget.reserve(Wal::record_bytes(&saved)?)?;
        drop(wal.append(&saved, lease)?);
        Ok(Self {
            pins,
            wal,
            history,
            ingress,
            saved,
            pending_parent: None,
            terminal: None,
            draft: None,
            recovery_required: false,
        })
    }
    /// Existing file ONLY, strict complete replay with actual Source and all
    /// Source/Life/Kind proofs and QCs. No torn-tail repair or stale-bank fallback.
    pub fn open_existing(
        quota: &ParticipantQuota,
        pins: OwnerVaultPins,
        authority: OwnerVaultAuthority,
        source: &SourceOwner,
        fetched: FetchedSource<'_>,
        replay: &[OwnerVaultReplay<'_>],
    ) -> VaultResult<Self> {
        validate_replay(replay)?;
        // Lock the actual WAL before opening the shared depot or allocating a
        // second phase owner, even if both opens use the same ParticipantQuota.
        let (wal, records) = Wal::open_existing(
            &quota.control_file(pins.file_id(), ControlFile::Wal),
            quota.control_budget(),
            &pins,
            authority,
        )?;
        let depot = JointDepot::open(quota.depot_budget())
            .map_err(|e| OwnerVaultError::Owner(cryptography(e)))?;
        let ingress = depot.ingress();
        let mut history = JointHistory::new(pins.binding.clone(), depot)?;
        let mut records = records.into_iter();
        let initial = records.next().ok_or(OwnerVaultError::Encoding)?;
        if initial.phase != OwnerVaultPhase::Idle || initial.generation != 0 {
            return Err(OwnerVaultError::Encoding);
        }
        let mut at = 0;
        let initial_parent = loop {
            let entry = replay.get(at).ok_or(OwnerVaultError::RecoveryRequired)?;
            history.apply(entry.checkpoint, entry.block)?;
            at += 1;
            if let Ok(candidate) = parent(&history, &pins.binding)
                && current_stamp(&history, &pins.binding)? == initial.stamp
            {
                break candidate;
            }
        };
        drop(state::restore_idle(
            initial.idle.as_ref(),
            source,
            again(&fetched),
            &initial_parent,
        )?);
        let mut vault = Self {
            pins,
            wal,
            history,
            ingress,
            saved: initial,
            pending_parent: None,
            terminal: None,
            draft: None,
            recovery_required: false,
        };
        for record in records {
            vault.replay_record(record, source, again(&fetched), replay, &mut at)?;
        }
        if vault.is_pending() {
            // Reservations are not durable. Recreate the COMPLETE terminal
            // allowance from the current shared ledger BEFORE any API escapes.
            vault.wal.require_terminal_capacity(0)?;
            vault.terminal = Some(
                vault
                    .wal
                    .budget
                    .reserve(OWNER_VAULT_MAX_RECORD_BYTES as u64)?,
            );
        }
        while let Some(entry) = replay.get(at) {
            let exact_target = vault.is_pending()
                && vault
                    .saved
                    .block
                    .as_ref()
                    .is_some_and(|saved| same_block(saved, entry.block));
            if exact_target {
                let before = vault
                    .pending_parent
                    .as_ref()
                    .ok_or(OwnerVaultError::Encoding)?;
                let (candidate, expected) = restore_candidate(
                    &vault.saved,
                    before,
                    &vault.pins.binding,
                    source,
                    again(&fetched),
                )?;
                let operation =
                    vault
                        .history
                        .apply_control(entry.checkpoint, entry.block, &expected)?;
                // Actual private Cmd160/Result144/Cnext reopening, not an AEAD
                // receipt. Keep the original saved pending until completion sync.
                drop(candidate.complete(operation)?);
            } else {
                // A genuinely verified newer/different state cannot authorize
                // use of a private bank that was not saved for that successor.
                vault.history.apply(entry.checkpoint, entry.block)?;
                return Err(OwnerVaultError::RecoveryRequired);
            }
            at += 1;
        }
        Ok(vault)
    }
    /// Same real public-byte store; clones do not add quota or proof authority.
    /// Drop every clone before an independent exclusive namespace reopen.
    pub fn evidence_ingress(&self) -> VaultResult<JointEvidenceIngress> {
        self.live()?;
        Ok(self.ingress.clone())
    }
    pub fn cursor(&self) -> VaultResult<OwnerVaultCursor> {
        self.live()?;
        Ok(OwnerVaultCursor {
            generation: self.saved.generation,
            pending: self.saved.pending,
            digest: self.wal.digest,
        })
    }
    pub fn phase(&self) -> VaultResult<OwnerVaultPhase> {
        self.live()?;
        Ok(self.saved.phase)
    }
    /// Historical metadata only, never proof that the network has no newer head.
    pub fn historical_parent(&self) -> VaultResult<&VerifiedJointParent> {
        self.live()?;
        self.history
            .checked_parent()?
            .ok_or(OwnerVaultError::RecoveryRequired)
    }
    /// Once the caller knows a different sealed head/context, this instance may
    /// no longer expose an older bank as ready work. No raw HeadRef is accepted.
    pub fn require_known_parent(
        &mut self,
        known: &VerifiedJointParent,
        current: &work_finality::consensus::Context,
    ) -> VaultResult<()> {
        self.live()?;
        let _ = control::JointControlParent::from_verified(known, &self.pins.binding, current)?;
        if current_stamp(&self.history, &self.pins.binding)?
            != stamp(&self.pins.binding, known, current)?
        {
            self.recovery_required = true;
            return Err(OwnerVaultError::RecoveryRequired);
        }
        Ok(())
    }
    /// Produce real Source/Life/Kind from the guarded saved bank. A lost draft
    /// has not exposed Vault submission bytes and does not change the phase log.
    /// The caller holds its existing native ProofGate across this operation.
    pub fn prepare_control(
        &mut self,
        cas: OwnerVaultCursor,
        source: &SourceOwner,
        fetched: FetchedSource<'_>,
        intent: control::JointControlIntent,
    ) -> VaultResult<OwnerVaultDraft> {
        self.require_cas(cas)?;
        if self.saved.phase != OwnerVaultPhase::Idle || self.draft.is_some() {
            return Err(OwnerVaultError::Phase);
        }
        let before = parent(&self.history, &self.pins.binding)?;
        if current_stamp(&self.history, &self.pins.binding)? != self.saved.stamp {
            return Err(OwnerVaultError::RecoveryRequired);
        }
        let opening =
            state::restore_idle(self.saved.idle.as_ref(), source, again(&fetched), &before)?;
        let prepared = source.prepare_joint_control(fetched, &before, opening, intent)?;
        let (request, life, kind, candidate) = prepared.into_parts();
        let pair = self
            .ingress
            .retain_public_blob(life.as_bytes())
            .map_err(|e| OwnerVaultError::Owner(cryptography(e)))?;
        let kind_id = self
            .ingress
            .retain_public_blob(kind.as_bytes())
            .map_err(|e| OwnerVaultError::Owner(cryptography(e)))?;
        let manifest = Manifest::control(
            registry200_proof::source::statement::encode_digest(life.statement().next),
            registry200_proof::source::statement::encode_digest(life.statement().result),
            pair,
            kind_id,
        )
        .map_err(|e| OwnerVaultError::Owner(cryptography(e)))?;
        let mut pending = [0; 32];
        getrandom::getrandom(&mut pending).map_err(|e| OwnerVaultError::Owner(cryptography(e)))?;
        if pending == [0; 32] {
            return Err(OwnerVaultError::Pins);
        }
        let public = OwnerVaultDraft {
            pending,
            request: request
                .encode()
                .map_err(|e| OwnerVaultError::Owner(cryptography(e)))?,
            manifest: manifest.encode(),
            parent: self
                .history
                .checked_parent()?
                .ok_or(OwnerVaultError::RecoveryRequired)?
                .clone(),
        };
        let returned = OwnerVaultDraft {
            pending: public.pending,
            request: public.request.clone(),
            manifest: public.manifest.clone(),
            parent: public.parent.clone(),
        };
        self.draft = Some(Draft { public, candidate });
        Ok(returned)
    }
    pub fn seal_body(
        &mut self,
        cas: OwnerVaultCursor,
        block: CandidateBlock,
    ) -> VaultResult<OwnerVaultCursor> {
        self.require_cas(cas)?;
        if self.saved.phase != OwnerVaultPhase::Idle {
            return Err(OwnerVaultError::Phase);
        }
        if block.body().len() > OWNER_VAULT_MAX_BODY_BYTES {
            return Err(OwnerVaultError::ResourceLimit);
        }
        let draft = self.draft.as_ref().ok_or(OwnerVaultError::Phase)?;
        let manifest = draft.public.manifest()?;
        let expected = draft.candidate.expectation(manifest)?;
        self.history.check_control_candidate(&block, &expected)?;
        let before = parent(&self.history, &self.pins.binding)?;
        let saved = Snapshot {
            phase: OwnerVaultPhase::BodyPrepared,
            generation: self.saved.generation,
            pending: draft.public.pending,
            stamp: self.saved.stamp,
            idle: Zeroizing::new(*self.saved.idle),
            candidate: Some(state::encode_control(&draft.candidate)?),
            block: Some(block),
            checkpoint: None,
            outcome: None,
        };
        let record_bytes = Wal::record_bytes(&saved)?;
        self.wal.require_terminal_capacity(record_bytes)?;
        let bytes = record_bytes
            .checked_add(OWNER_VAULT_MAX_RECORD_BYTES as u64)
            .ok_or(OwnerVaultError::ResourceLimit)?;
        let lease = self.wal.budget.reserve(bytes)?;
        let remaining = self.wal.append(&saved, lease)?;
        self.terminal = Some(remaining);
        self.pending_parent = Some(before);
        self.saved = saved;
        self.draft = None;
        self.cursor()
    }
    /// Return the ORIGINAL synced signed candidate. Reopening BodyPrepared is
    /// always SubmittedUnknown, irrespective of whether any bytes reached peers.
    pub fn submission(&mut self, cas: OwnerVaultCursor) -> VaultResult<OwnerVaultSubmission<'_>> {
        self.require_cas(cas)?;
        if !self.is_pending() {
            return Err(OwnerVaultError::Phase);
        }
        self.saved.phase = OwnerVaultPhase::SubmittedUnknown;
        Ok(OwnerVaultSubmission {
            cursor: self.cursor()?,
            block: self.saved.block.as_ref().ok_or(OwnerVaultError::Encoding)?,
        })
    }
    /// Actual QC/application replay and original private completion, followed by
    /// successor/outcome fsync BEFORE success. No data COMMIT or lease is implied.
    pub fn complete_control(
        &mut self,
        cas: OwnerVaultCursor,
        source: &SourceOwner,
        fetched: FetchedSource<'_>,
        checkpoint: &JointCheckpoint,
    ) -> VaultResult<OwnerVaultCompletion> {
        self.require_cas(cas)?;
        if !self.is_pending() {
            return Err(OwnerVaultError::Phase);
        }
        let before = self
            .pending_parent
            .as_ref()
            .ok_or(OwnerVaultError::Encoding)?;
        let (candidate, expected) =
            restore_candidate(&self.saved, before, &self.pins.binding, source, fetched)?;
        let block = self.saved.block.as_ref().ok_or(OwnerVaultError::Encoding)?;
        let old_context = self.history.context()?.id();
        let operation = match self.history.apply_control(checkpoint, block, &expected) {
            Ok(operation) => operation,
            Err(error) => {
                if match self.history.context() {
                    Ok(context) => context.id() != old_context,
                    Err(_) => true,
                } {
                    self.poison_after_advance();
                }
                return Err(error.into());
            }
        };
        let finished = (|| -> VaultResult<(Snapshot, control::JointControlOutcome)> {
            let completed = candidate.complete(operation)?;
            let outcome = completed.outcome();
            let opening = completed.into_opening();
            let after = parent(&self.history, &self.pins.binding)?;
            state::require_idle_parent(&opening, &after)?;
            let idle = state::encode_idle(&opening)?;
            let snapshot = Snapshot {
                phase: OwnerVaultPhase::Completed,
                generation: self
                    .saved
                    .generation
                    .checked_add(1)
                    .ok_or(OwnerVaultError::ResourceLimit)?,
                pending: self.saved.pending,
                stamp: current_stamp(&self.history, &self.pins.binding)?,
                idle,
                candidate: None,
                block: Some(
                    CandidateBlock::new(block.header().clone(), block.body().to_vec())
                        .map_err(OwnerVaultError::Finality)?,
                ),
                checkpoint: Some(JointCheckpoint::decode(&checkpoint.encode())?),
                outcome: Some(outcome),
            };
            Ok((snapshot, outcome))
        })();
        let (saved, outcome) = match finished {
            Ok(result) => result,
            Err(error) => {
                self.poison_after_advance();
                return Err(error);
            }
        };
        let lease = match self.terminal.take() {
            Some(lease) => lease,
            None => {
                self.poison_after_advance();
                return Err(OwnerVaultError::Poisoned);
            }
        };
        match self.wal.append(&saved, lease) {
            Ok(remaining) => drop(remaining),
            Err(error) => {
                self.poison_after_advance();
                return Err(error);
            }
        }
        self.saved = saved;
        self.pending_parent = None;
        Ok(OwnerVaultCompletion {
            cursor: self.cursor()?,
            outcome,
        })
    }
    pub fn recovered_completion(&self) -> VaultResult<Option<OwnerVaultCompletion>> {
        self.live()?;
        let cursor = self.cursor()?;
        Ok(self
            .saved
            .outcome
            .map(|outcome| OwnerVaultCompletion { cursor, outcome }))
    }
    /// Acknowledge the saved result locally, retaining the same exact bank.
    /// The preceding Completed record is never removed or overwritten.
    pub fn acknowledge(&mut self, cas: OwnerVaultCursor) -> VaultResult<OwnerVaultCursor> {
        self.require_cas(cas)?;
        if self.saved.phase != OwnerVaultPhase::Completed {
            return Err(OwnerVaultError::Phase);
        }
        let saved = Snapshot {
            phase: OwnerVaultPhase::Idle,
            generation: self.saved.generation,
            pending: [0; 32],
            stamp: self.saved.stamp,
            idle: Zeroizing::new(*self.saved.idle),
            candidate: None,
            block: None,
            checkpoint: None,
            outcome: None,
        };
        let lease = self.wal.budget.reserve(Wal::record_bytes(&saved)?)?;
        drop(self.wal.append(&saved, lease)?);
        self.saved = saved;
        self.cursor()
    }
    fn replay_record(
        &mut self,
        next: Snapshot,
        source: &SourceOwner,
        fetched: FetchedSource<'_>,
        external: &[OwnerVaultReplay<'_>],
        at: &mut usize,
    ) -> VaultResult<()> {
        match self.saved.phase {
            OwnerVaultPhase::Idle => {
                if next.phase != OwnerVaultPhase::SubmittedUnknown
                    || next.generation != self.saved.generation
                    || next.stamp != self.saved.stamp
                    || next.idle.as_ref() != self.saved.idle.as_ref()
                {
                    return Err(OwnerVaultError::Encoding);
                }
                let before = parent(&self.history, &self.pins.binding)?;
                if current_stamp(&self.history, &self.pins.binding)? != next.stamp {
                    return Err(OwnerVaultError::Pins);
                }
                let (_candidate, expected) =
                    restore_candidate(&next, &before, &self.pins.binding, source, fetched)?;
                self.history.check_control_candidate(
                    next.block.as_ref().ok_or(OwnerVaultError::Encoding)?,
                    &expected,
                )?;
                self.pending_parent = Some(before);
            }
            OwnerVaultPhase::BodyPrepared | OwnerVaultPhase::SubmittedUnknown => {
                if next.phase != OwnerVaultPhase::Completed
                    || next.generation
                        != self
                            .saved
                            .generation
                            .checked_add(1)
                            .ok_or(OwnerVaultError::ResourceLimit)?
                    || next.pending != self.saved.pending
                {
                    return Err(OwnerVaultError::Encoding);
                }
                let before = self
                    .pending_parent
                    .as_ref()
                    .ok_or(OwnerVaultError::Encoding)?;
                let (candidate, expected) = restore_candidate(
                    &self.saved,
                    before,
                    &self.pins.binding,
                    source,
                    again(&fetched),
                )?;
                let block = next.block.as_ref().ok_or(OwnerVaultError::Encoding)?;
                if !same_block(
                    block,
                    self.saved.block.as_ref().ok_or(OwnerVaultError::Encoding)?,
                ) {
                    return Err(OwnerVaultError::Pins);
                }
                let operation = self.history.apply_control(
                    next.checkpoint.as_ref().ok_or(OwnerVaultError::Encoding)?,
                    block,
                    &expected,
                )?;
                let completed = candidate.complete(operation)?;
                if Some(completed.outcome()) != next.outcome {
                    return Err(OwnerVaultError::Pins);
                }
                let opening = completed.into_opening();
                let after = parent(&self.history, &self.pins.binding)?;
                state::require_idle_parent(&opening, &after)?;
                if state::encode_idle(&opening)?.as_ref() != next.idle.as_ref()
                    || current_stamp(&self.history, &self.pins.binding)? != next.stamp
                {
                    return Err(OwnerVaultError::Pins);
                }
                drop(state::restore_idle(
                    next.idle.as_ref(),
                    source,
                    fetched,
                    &after,
                )?);
                self.pending_parent = None;
                if let Some(entry) = external.get(*at)
                    && same_block(block, entry.block)
                {
                    self.history.apply(entry.checkpoint, entry.block)?;
                    *at += 1;
                }
            }
            OwnerVaultPhase::Completed => {
                if next.phase != OwnerVaultPhase::Idle
                    || next.generation != self.saved.generation
                    || next.stamp != self.saved.stamp
                    || next.idle.as_ref() != self.saved.idle.as_ref()
                {
                    return Err(OwnerVaultError::Encoding);
                }
            }
        }
        self.saved = next;
        Ok(())
    }
    fn require_cas(&self, cas: OwnerVaultCursor) -> VaultResult<()> {
        if self.cursor()? == cas {
            Ok(())
        } else {
            Err(OwnerVaultError::Cas)
        }
    }
    fn is_pending(&self) -> bool {
        matches!(
            self.saved.phase,
            OwnerVaultPhase::BodyPrepared | OwnerVaultPhase::SubmittedUnknown
        )
    }
    fn live(&self) -> VaultResult<()> {
        if self.recovery_required {
            return Err(OwnerVaultError::RecoveryRequired);
        }
        self.wal.live()
    }
    fn poison_after_advance(&mut self) {
        self.wal.poison();
        if let Some(lease) = self.terminal.take() {
            lease.retain_conservatively();
        }
    }
}
fn restore_candidate(
    saved: &Snapshot,
    before: &control::JointControlParent,
    binding: &JointBinding,
    source: &SourceOwner,
    fetched: FetchedSource<'_>,
) -> VaultResult<(
    control::JointControlCandidate,
    registry200_finality::joint::ControlExpectation,
)> {
    let block = saved.block.as_ref().ok_or(OwnerVaultError::Encoding)?;
    let version_journal::Body::Transition(body) =
        version_journal::Body::decode(block.body(), &binding.journal_genesis().profile)
            .map_err(|e| OwnerVaultError::Owner(cryptography(e)))?
    else {
        return Err(OwnerVaultError::Encoding);
    };
    let request =
        JointRequest::decode(&body.request).map_err(|e| OwnerVaultError::Owner(cryptography(e)))?;
    let manifest =
        Manifest::decode(&body.proof).map_err(|e| OwnerVaultError::Owner(cryptography(e)))?;
    let candidate = state::restore_control(
        saved
            .candidate
            .as_ref()
            .ok_or(OwnerVaultError::Encoding)?
            .as_ref(),
        saved.idle.as_ref(),
        source,
        fetched,
        before,
        &request,
        &manifest,
    )?;
    let expected = candidate.expectation(manifest)?;
    Ok((candidate, expected))
}
fn parent(
    history: &JointHistory,
    binding: &JointBinding,
) -> VaultResult<control::JointControlParent> {
    Ok(control::JointControlParent::from_verified(
        history
            .checked_parent()?
            .ok_or(OwnerVaultError::RecoveryRequired)?,
        binding,
        history.context()?,
    )?)
}
fn stamp(
    binding: &JointBinding,
    parent: &VerifiedJointParent,
    context: &work_finality::consensus::Context,
) -> VaultResult<[u8; 32]> {
    let head = parent.head();
    let spec = binding
        .application_descriptor()
        .source_spec()
        .map_err(|e| OwnerVaultError::Owner(cryptography(e)))?;
    let heads = parent.control().heads(&spec);
    Ok(hash(&[
        b"DCS/owner-Control-Vault/full-parent/v1",
        &binding.id(),
        &binding.application_descriptor().encode(),
        &head.genesis,
        &head.database,
        &head.block,
        &head.state_root,
        &head.height.to_le_bytes(),
        &parent.slot().to_le_bytes(),
        &parent.decision_id(),
        &heads.data,
        &heads.index,
        &context.id(),
    ]))
}
fn current_stamp(history: &JointHistory, binding: &JointBinding) -> VaultResult<[u8; 32]> {
    stamp(
        binding,
        history
            .checked_parent()?
            .ok_or(OwnerVaultError::RecoveryRequired)?,
        history.context()?,
    )
}
fn same_block(a: &CandidateBlock, b: &CandidateBlock) -> bool {
    a.header() == b.header() && a.body() == b.body()
}
fn again<'a>(fetched: &FetchedSource<'a>) -> FetchedSource<'a> {
    FetchedSource {
        object: fetched.object,
        bundle: fetched.bundle,
        heads: fetched.heads,
    }
}
fn validate_replay(replay: &[OwnerVaultReplay<'_>]) -> VaultResult<()> {
    if replay.is_empty() || replay.len() > MAX_RECORDS {
        return Err(OwnerVaultError::ResourceLimit);
    }
    let mut total = 0usize;
    for entry in replay {
        if entry.block.body().is_empty()
            || entry.block.body().len() > OWNER_VAULT_MAX_BODY_BYTES
            || entry.checkpoint.certificate().len() > work_finality::MAX_CERTIFICATE_BYTES
        {
            return Err(OwnerVaultError::ResourceLimit);
        }
        total = total
            .checked_add(entry.block.body().len())
            .and_then(|n| n.checked_add(entry.checkpoint.certificate().len()))
            .and_then(|n| {
                n.checked_add(
                    version_journal::HEADER_BYTES
                        + registry200_finality::joint::CANDIDATE_BYTES
                        + 20,
                )
            })
            .filter(|n| *n <= MAX_REPLAY_BYTES)
            .ok_or(OwnerVaultError::ResourceLimit)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "durable_tests.rs"]
mod tests;
