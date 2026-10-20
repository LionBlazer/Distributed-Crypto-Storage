//! Bounded owner orchestration. Public calls are retry identities, not rights or leases.
use super::state as bank_state;
use super::*;
use sql_plan::{LockStrength, LockWait, Projection, QueryPlan, StatementPlan, TransactionChain};
use zeroize::Zeroize;
pub(in crate::private_predicate::source::locking::joint::vault) mod state;
pub use state::JointSqlClientBinding;
use state::{Bindings, Call, Managed, Verb};
mod network;
pub use network::{
    JointSqlNetworkConfig, JointSqlNetworkError, JointSqlNetworkHost, JointSqlNetworkInput,
    JointSqlNetworkOutcome, JointSqlNetworkPending,
};

pub fn joint_sql_host_profile_digest() -> [u8; 32] {
    hash(&[b"DCS/Joint-SQL-Host/v3/DCSOVL03-DCSOVP03", &owner_vault_profile_digest(),
        b"Clients200-Pending56-two-logical-bindings-full-Registry-bijection-stableID;no-v2-migration;3Control-5Acquire-prepaidACK;lastCompleted-record-replay-only;no-intake-no-WAIT-no-CHAIN-no-currentlease",
        &(state::CLIENTS_BYTES as u64).to_le_bytes(), &(state::CALL_BYTES as u64).to_le_bytes()])
}

/// Fixed independently configured bindings. Principals may coincide; ids must
/// be nonzero, distinct and sorted. This is not client authentication.
pub struct JointSqlHostPins {
    inner: OwnerVaultPins,
}
impl JointSqlHostPins {
    pub fn new(
        binding: JointBinding,
        identity: OwnerVaultIdentity,
        clients: [JointSqlClientBinding; 2],
    ) -> VaultResult<Self> {
        let mut inner = OwnerVaultPins::new(binding, identity);
        inner.managed = Some(Bindings::new(clients)?);
        Ok(Self { inner })
    }
}
/// Opaque routing identity from this Host installation. Possession supplies no
/// database permission. The embedding owner must authenticate its clients.
pub struct JointSqlClient {
    host: [u8; 32],
    slot: usize,
}
/// Exact owner-private intent. No SQL text or digest getter/Debug/serde exists.
pub struct JointSqlCall {
    host: [u8; 32],
    slot: usize,
    sequence: u64,
    verb: Verb,
    digest: [u8; 32],
}
impl Drop for JointSqlCall {
    fn drop(&mut self) {
        self.digest.zeroize();
    }
}
pub enum JointSqlPreparation {
    /// Unsigned owner-signing metadata only. Network submission remains unavailable
    /// until seal_body actually checks and fsyncs the signed candidate.
    ControlDraft(Box<OwnerVaultDraft>),
    AcquireWork(Box<OwnerVaultAcquireWork>),
    ExistingPending(OwnerVaultCursor),
    /// An old result exists. Use take_recovered_reply after a fresh full reopen;
    /// this reference itself proves no computation or current lock.
    HistoricalLast {
        record_sequence: u64,
    },
}
enum ReplyValue {
    Control(control::JointControlOutcome),
    Acquire(OwnerVaultAcquireCompletion),
}
/// A historical original response produced by actual completion or full replay.
/// No current-head/lease, global once-only or SQL-data-COMMIT authority is supplied.
pub struct JointSqlReply {
    call: Call,
    client: [u8; 32],
    record: u64,
    invocation: [u8; 32],
    value: ReplyValue,
}
impl JointSqlReply {
    pub fn client_id(&self) -> [u8; 32] {
        self.client
    }
    pub fn call_sequence(&self) -> u64 {
        self.call.sequence
    }
    pub fn invocation_id(&self) -> [u8; 32] {
        self.invocation
    }
    pub fn completed_record_sequence(&self) -> u64 {
        self.record
    }
    pub fn control_outcome(&self) -> Option<control::JointControlOutcome> {
        match &self.value {
            ReplyValue::Control(v) => Some(*v),
            ReplyValue::Acquire(_) => None,
        }
    }
    pub fn rows(&self) -> Option<&[CompletedJointRow]> {
        match &self.value {
            ReplyValue::Acquire(v) => Some(v.rows()),
            _ => None,
        }
    }
}
impl Drop for JointSqlReply {
    fn drop(&mut self) {
        self.call.digest.zeroize();
        self.call.transaction.zeroize();
    }
}

pub(super) struct DraftCall {
    pub(super) call: Call,
    pub(super) invocation: [u8; 32],
}
impl Drop for DraftCall {
    fn drop(&mut self) {
        self.call.digest.zeroize();
        self.call.transaction.zeroize();
        self.invocation.zeroize();
    }
}

/// One exclusive concrete Vault/WAL/History/depot owner with a distinct v3 file.
/// Generic Session/Database SQL guards remain closed. No mutable Vault is exposed.
pub struct JointSqlHost {
    vault: OwnerVault,
}
impl JointSqlHost {
    pub fn create_new(
        quota: &ParticipantQuota,
        pins: JointSqlHostPins,
        authority: OwnerVaultAuthority,
        source: &SourceOwner,
        fetched: FetchedSource<'_>,
        replay: &[OwnerVaultReplay<'_>],
        opening: control::JointRegistryOpening,
    ) -> VaultResult<Self> {
        Ok(Self {
            vault: OwnerVault::create_new(
                quota, pins.inner, authority, source, fetched, replay, opening,
            )?,
        })
    }
    pub fn open_existing(
        quota: &ParticipantQuota,
        pins: JointSqlHostPins,
        authority: OwnerVaultAuthority,
        source: &SourceOwner,
        fetched: FetchedSource<'_>,
        replay: &[OwnerVaultReplay<'_>],
    ) -> VaultResult<Self> {
        Ok(Self {
            vault: OwnerVault::open_existing(
                quota, pins.inner, authority, source, fetched, replay,
            )?,
        })
    }
    pub fn open_existing_acquire(
        quota: &ParticipantQuota,
        pins: JointSqlHostPins,
        authority: OwnerVaultAuthority,
        source: &SourceOwner,
        fetched: FetchedSource<'_>,
        replay: &[OwnerVaultReplay<'_>],
        material: &OwnerVaultAcquireMaterial<'_>,
    ) -> VaultResult<Self> {
        Ok(Self {
            vault: OwnerVault::open_existing_acquire(
                quota, pins.inner, authority, source, fetched, replay, material,
            )?,
        })
    }
    pub fn client(&self, id: [u8; 32]) -> VaultResult<JointSqlClient> {
        self.vault.live()?;
        let slot = self
            .managed()?
            .clients
            .iter()
            .position(|c| c.binding.id == id)
            .ok_or(OwnerVaultError::Pins)?;
        Ok(JointSqlClient {
            host: self.vault.pins.file_id(),
            slot,
        })
    }
    /// Parse and bind exact bytes before I/O. Modes, either explicit CHAIN form,
    /// ordinary reads and WAIT/NOWAIT are unsupported in this first owner slice.
    pub fn call(
        &self,
        client: &JointSqlClient,
        sequence: u64,
        sql: &str,
    ) -> VaultResult<JointSqlCall> {
        self.vault.live()?;
        if client.host != self.vault.pins.file_id() || client.slot >= 2 || sequence == 0 {
            return Err(OwnerVaultError::Pins);
        }
        let verb = parse(sql)?;
        let c = self.managed()?.clients[client.slot];
        let digest = hash(&[
            b"DCS/Joint-SQL-Host/private-exact-intent/v3",
            &client.host,
            &c.binding.id,
            &[c.binding.principal],
            &[verb_tag(verb)],
            sql.as_bytes(),
        ]);
        Ok(JointSqlCall {
            host: client.host,
            slot: client.slot,
            sequence,
            verb,
            digest,
        })
    }
    pub fn cursor(&self) -> VaultResult<OwnerVaultCursor> {
        self.vault.cursor()
    }
    pub fn phase(&self) -> VaultResult<OwnerVaultPhase> {
        self.vault.phase()
    }
    pub fn historical_parent(&self) -> VaultResult<&VerifiedJointParent> {
        self.vault.historical_parent()
    }
    pub fn evidence_ingress(&self) -> VaultResult<JointEvidenceIngress> {
        self.vault.evidence_ingress()
    }
    #[cfg(test)]
    pub(in crate::private_predicate::source::locking::joint::vault) fn candidate_header_for_test(
        &self,
        parent: &VerifiedJointParent,
        body: &version_journal::Body,
        now: u64,
    ) -> VaultResult<version_journal::Header> {
        self.vault.live()?;
        Ok(self
            .vault
            .history
            .candidate_header(parent, body, now, now)?)
    }
    pub fn require_known_parent(
        &mut self,
        parent: &VerifiedJointParent,
        context: &work_finality::consensus::Context,
    ) -> VaultResult<()> {
        self.vault.require_known_parent(parent, context)
    }

    pub fn prepare_control(
        &mut self,
        call: &JointSqlCall,
        source: &SourceOwner,
        fetched: FetchedSource<'_>,
    ) -> VaultResult<JointSqlPreparation> {
        if call.verb == Verb::Acquire {
            return Err(OwnerVaultError::Phase);
        }
        if let Some(existing) = self.existing(call)? {
            return Ok(existing);
        }
        self.start(call, source, again(&fetched))?;
        let result = (|| -> VaultResult<OwnerVaultDraft> {
            let draft = self
                .vault
                .managed_draft
                .as_ref()
                .ok_or(OwnerVaultError::Phase)?;
            let tx = draft.call.transaction;
            let principal = self.managed()?.clients[call.slot].binding.principal;
            let nonce = fresh()?;
            let intent = match call.verb {
                Verb::Begin => control::JointControlIntent::begin(tx, principal, nonce),
                Verb::EndClose => control::JointControlIntent::end(
                    tx,
                    principal,
                    control::JointEndDisposition::Close,
                    nonce,
                ),
                Verb::EndAbort => control::JointControlIntent::end(
                    tx,
                    principal,
                    control::JointEndDisposition::Abort,
                    nonce,
                ),
                Verb::Acquire => unreachable!(),
            }?;
            self.vault
                .prepare_control(self.vault.cursor()?, source, fetched, intent)
        })();
        match result {
            Ok(draft) => Ok(JointSqlPreparation::ControlDraft(Box::new(draft))),
            Err(e) => {
                self.abandon_unpublished();
                Err(e)
            }
        }
    }
    pub fn prepare_acquire(
        &mut self,
        call: &JointSqlCall,
        sql: &str,
        source: &SourceOwner,
        fetched: FetchedSource<'_>,
        material: &OwnerVaultAcquireMaterial<'_>,
    ) -> VaultResult<JointSqlPreparation> {
        let client = JointSqlClient {
            host: call.host,
            slot: call.slot,
        };
        let exact = self.call(&client, call.sequence, sql)?;
        if exact.digest != call.digest || call.verb != Verb::Acquire {
            return Err(OwnerVaultError::Pins);
        }
        if let Some(existing) = self.existing(call)? {
            return Ok(existing);
        }
        self.start(call, source, again(&fetched))?;
        let tx = self
            .vault
            .managed_draft
            .as_ref()
            .ok_or(OwnerVaultError::Phase)?
            .call
            .transaction;
        let principal = self.managed()?.clients[call.slot].binding.principal;
        let result =
            self.vault
                .prepare_acquire(self.vault.cursor()?, fetched, material, sql, tx, principal);
        match result {
            Ok(OwnerVaultAcquirePreparation::Prepared(work)) => {
                Ok(JointSqlPreparation::AcquireWork(work))
            }
            Ok(OwnerVaultAcquirePreparation::NonAdmitted(_)) => {
                self.abandon_unpublished();
                Err(OwnerVaultError::Phase)
            }
            Err(e) => {
                self.abandon_unpublished();
                Err(e)
            }
        }
    }
    pub fn save_acquire_catalog(
        &mut self,
        call: &JointSqlCall,
        cas: OwnerVaultCursor,
        catalog: bfv_product_evidence::CatalogId,
        fetched: FetchedSource<'_>,
        material: &OwnerVaultAcquireMaterial<'_>,
    ) -> VaultResult<OwnerVaultDraft> {
        self.require_pending(call)?;
        self.vault
            .save_acquire_catalog(cas, catalog, fetched, material)
    }
    pub fn acquire_work(
        &self,
        call: &JointSqlCall,
        cas: OwnerVaultCursor,
        fetched: FetchedSource<'_>,
        material: &OwnerVaultAcquireMaterial<'_>,
    ) -> VaultResult<OwnerVaultAcquireWork> {
        self.require_pending(call)?;
        self.vault.acquire_work(cas, fetched, material)
    }
    /// Recover ORIGINAL signing metadata after catalog fsync, including a
    /// catalog-only reopen. This checks the same pending call and exact cursor;
    /// it neither reruns FHE nor verifies/adopts a candidate or result.
    pub fn acquire_draft(
        &self,
        call: &JointSqlCall,
        cas: OwnerVaultCursor,
    ) -> VaultResult<OwnerVaultDraft> {
        self.require_pending(call)?;
        self.vault.acquire_draft(cas)
    }
    pub fn seal_body(
        &mut self,
        call: &JointSqlCall,
        cas: OwnerVaultCursor,
        block: CandidateBlock,
    ) -> VaultResult<OwnerVaultCursor> {
        self.require_draft(call)?;
        self.vault.seal_body(cas, block)
    }
    pub fn seal_acquire_body(
        &mut self,
        call: &JointSqlCall,
        cas: OwnerVaultCursor,
        block: CandidateBlock,
        fetched: FetchedSource<'_>,
        material: &OwnerVaultAcquireMaterial<'_>,
    ) -> VaultResult<OwnerVaultCursor> {
        self.require_pending(call)?;
        self.vault.seal_acquire_body(cas, block, fetched, material)
    }
    pub fn submission(
        &mut self,
        call: &JointSqlCall,
        cas: OwnerVaultCursor,
    ) -> VaultResult<OwnerVaultSubmission<'_>> {
        self.require_pending(call)?;
        self.vault.submission(cas)
    }
    pub fn complete_control(
        &mut self,
        call: &JointSqlCall,
        cas: OwnerVaultCursor,
        source: &SourceOwner,
        fetched: FetchedSource<'_>,
        qc: &JointCheckpoint,
    ) -> VaultResult<JointSqlReply> {
        self.require_pending(call)?;
        let result = self.vault.complete_control(cas, source, fetched, qc)?;
        self.reply(ReplyValue::Control(result.outcome()))
    }
    pub fn complete_acquire(
        &mut self,
        call: &JointSqlCall,
        cas: OwnerVaultCursor,
        fetched: FetchedSource<'_>,
        material: &OwnerVaultAcquireMaterial<'_>,
        qc: &JointCheckpoint,
    ) -> VaultResult<JointSqlReply> {
        self.require_pending(call)?;
        let result = self.vault.complete_acquire(cas, fetched, material, qc)?;
        self.reply(ReplyValue::Acquire(result))
    }
    pub fn acknowledge(
        &mut self,
        call: &JointSqlCall,
        cas: OwnerVaultCursor,
    ) -> VaultResult<OwnerVaultCursor> {
        self.require_pending(call)?;
        self.vault.acknowledge(cas)
    }
    /// Only a reply freshly reconstructed during this open's complete forward
    /// replay. Consuming it twice requires another explicit exclusive reopen.
    pub fn take_recovered_reply(&mut self, call: &JointSqlCall) -> VaultResult<JointSqlReply> {
        self.require_call(call)?;
        let client = self.managed()?.clients[call.slot];
        if client.last != call.sequence || client.digest != call.digest {
            return Err(OwnerVaultError::Cas);
        }
        let reply = self.vault.replayed_clients[call.slot]
            .take()
            .ok_or(OwnerVaultError::RecoveryRequired)?;
        if !Self::matches_call(call, reply.call) || reply.record != client.record {
            return Err(OwnerVaultError::Pins);
        }
        Ok(reply)
    }
    fn managed(&self) -> VaultResult<&Managed> {
        self.vault
            .saved
            .managed
            .as_ref()
            .ok_or(OwnerVaultError::Pins)
    }
    fn require_call(&self, call: &JointSqlCall) -> VaultResult<()> {
        self.vault.live()?;
        if call.host != self.vault.pins.file_id() || call.slot >= 2 {
            return Err(OwnerVaultError::Pins);
        }
        Ok(())
    }
    fn matches_call(call: &JointSqlCall, saved: Call) -> bool {
        call.slot == saved.slot
            && call.sequence == saved.sequence
            && call.digest == saved.digest
            && call.verb == saved.verb
    }
    fn require_pending(&self, call: &JointSqlCall) -> VaultResult<()> {
        self.require_call(call)?;
        if !self
            .managed()?
            .call
            .is_some_and(|c| Self::matches_call(call, c))
        {
            return Err(OwnerVaultError::Cas);
        }
        Ok(())
    }
    fn require_draft(&self, call: &JointSqlCall) -> VaultResult<()> {
        self.require_call(call)?;
        if !self
            .vault
            .managed_draft
            .as_ref()
            .is_some_and(|c| Self::matches_call(call, c.call))
        {
            return Err(OwnerVaultError::Cas);
        }
        Ok(())
    }
    fn existing(&self, call: &JointSqlCall) -> VaultResult<Option<JointSqlPreparation>> {
        self.require_call(call)?;
        let saved = self.managed()?;
        if let Some(pending) = saved.call {
            if Self::matches_call(call, pending) {
                return Ok(Some(
                    if self.vault.saved.phase == OwnerVaultPhase::Completed {
                        JointSqlPreparation::HistoricalLast {
                            record_sequence: saved.clients[call.slot].record,
                        }
                    } else {
                        JointSqlPreparation::ExistingPending(self.vault.cursor()?)
                    },
                ));
            }
            return Err(OwnerVaultError::Cas);
        }
        let c = saved.clients[call.slot];
        if call.sequence == c.last && call.digest == c.digest {
            return Ok(Some(JointSqlPreparation::HistoricalLast {
                record_sequence: c.record,
            }));
        }
        if call.sequence
            != c.last
                .checked_add(1)
                .ok_or(OwnerVaultError::ResourceLimit)?
        {
            return Err(OwnerVaultError::Cas);
        }
        if self.vault.managed_draft.is_some() {
            return Err(OwnerVaultError::Phase);
        }
        Ok(None)
    }
    fn start(
        &mut self,
        call: &JointSqlCall,
        source: &SourceOwner,
        fetched: FetchedSource<'_>,
    ) -> VaultResult<()> {
        self.require_call(call)?;
        if self.vault.saved.phase != OwnerVaultPhase::Idle {
            return Err(OwnerVaultError::Phase);
        }
        self.vault
            .saved
            .generation
            .checked_add(1)
            .ok_or(OwnerVaultError::ResourceLimit)?;
        let records = if call.verb == Verb::Acquire { 5 } else { 3 };
        self.vault
            .wal
            .require_capacity(records, records * OWNER_VAULT_MAX_RECORD_BYTES as u64)?;
        let lease = self
            .vault
            .wal
            .budget
            .reserve(records * OWNER_VAULT_MAX_RECORD_BYTES as u64)?;
        let before = parent(&self.vault.history, &self.vault.pins.binding)?;
        let bank =
            bank_state::restore_idle(self.vault.saved.idle.as_ref(), source, fetched, &before)?;
        bank_state::require_host_bank(&bank, self.managed()?.rows())?;
        let client = self.managed()?.clients[call.slot];
        let transaction = if call.verb == Verb::Begin {
            bank_state::host_begin_id(&bank, self.managed()?.rows())?
        } else {
            client.active
        };
        let saved = Call {
            slot: call.slot,
            verb: call.verb,
            sequence: call.sequence,
            digest: call.digest,
            transaction,
        };
        self.managed()?.start(saved)?;
        let invocation = fresh()?;
        self.vault.managed_draft = Some(DraftCall {
            call: saved,
            invocation,
        });
        self.vault.terminal = Some(lease);
        Ok(())
    }
    fn abandon_unpublished(&mut self) {
        if self.vault.saved.phase == OwnerVaultPhase::Idle {
            if self.vault.wal.live().is_ok() {
                self.vault.managed_draft = None;
                self.vault.draft = None;
                self.vault.terminal = None;
            } else {
                self.vault.poison_after_advance();
            }
        }
    }
    fn reply(&self, value: ReplyValue) -> VaultResult<JointSqlReply> {
        let managed = self.managed()?;
        let call = managed.call.ok_or(OwnerVaultError::Encoding)?;
        Ok(JointSqlReply {
            call,
            client: managed.clients[call.slot].binding.id,
            record: managed.clients[call.slot].record,
            invocation: self.vault.saved.pending,
            value,
        })
    }
}

// Private owning-test fault/capacity fuses, never an executable proof policy.
#[cfg(test)]
impl JointSqlHost {
    pub(in crate::private_predicate::source::locking::joint::vault) fn inject_fault(
        &mut self,
        fault: super::super::durable_wal::Fault,
    ) {
        self.vault.wal.fault = Some(fault);
    }
    pub(in crate::private_predicate::source::locking::joint::vault) fn fill_physical_record_limit(
        &mut self,
    ) -> VaultResult<()> {
        // Canonical authenticated packet framing only; the deliberately repeated
        // Idle packets are NOT a valid phase history and are never reopened.
        while self.vault.wal.next_sequence().is_ok() {
            let lease = self
                .vault
                .wal
                .budget
                .reserve(Wal::record_bytes(&self.vault.saved)?)?;
            drop(self.vault.wal.append(&self.vault.saved, lease)?);
        }
        Ok(())
    }
}

fn verb_tag(verb: Verb) -> u8 {
    match verb {
        Verb::Begin => 1,
        Verb::EndClose => 2,
        Verb::EndAbort => 3,
        Verb::Acquire => 4,
    }
}
fn parse(sql: &str) -> VaultResult<Verb> {
    let plan = sql_plan::parse_statement(sql).map_err(|_| OwnerVaultError::Encoding)?;
    match plan {
        StatementPlan::Begin { modes } if modes.is_empty() => Ok(Verb::Begin),
        StatementPlan::Commit {
            chain: TransactionChain::Unspecified,
        } => Ok(Verb::EndClose),
        StatementPlan::Rollback {
            chain: TransactionChain::Unspecified,
        } => Ok(Verb::EndAbort),
        StatementPlan::Query(QueryPlan::LockingSelect {
            locking,
            projection,
            window,
            ..
        }) if locking.wait == LockWait::SkipLocked
            && locking.strength == LockStrength::Update
            && projection != Projection::AmountAge
            && window.offset <= 4
            && window.limit.is_none_or(|n| n <= 4) =>
        {
            Ok(Verb::Acquire)
        }
        _ => Err(OwnerVaultError::Phase),
    }
}
fn fresh() -> VaultResult<[u8; 32]> {
    let mut value = [0; 32];
    getrandom::getrandom(&mut value).map_err(|e| OwnerVaultError::Owner(cryptography(e)))?;
    if value == [0; 32] {
        return Err(OwnerVaultError::Pins);
    }
    Ok(value)
}

impl OwnerVault {
    pub(super) fn managed_next(
        &self,
        phase: OwnerVaultPhase,
        outcome: Option<control::JointControlOutcome>,
    ) -> VaultResult<Option<Managed>> {
        let Some(current) = &self.saved.managed else {
            return Ok(None);
        };
        Ok(Some(match phase {
            OwnerVaultPhase::Idle => current.acknowledged(),
            OwnerVaultPhase::Completed => current.completed(self.wal.next_sequence()?, outcome)?,
            _ if self.saved.phase == OwnerVaultPhase::Idle => current.start(
                self.managed_draft
                    .as_ref()
                    .ok_or(OwnerVaultError::Phase)?
                    .call,
            )?,
            _ => current.clone(),
        }))
    }
    pub(super) fn append_managed(&mut self, next: &Snapshot) -> VaultResult<()> {
        let result = match self.terminal.as_mut() {
            Some(lease) => self.wal.append_reserved(next, lease),
            None => Err(OwnerVaultError::Poisoned),
        };
        if let Err(error) = result {
            self.poison_after_advance();
            return Err(error);
        }
        Ok(())
    }
    pub(super) fn require_managed_bank(
        &self,
        snapshot: &Snapshot,
        source: &SourceOwner,
        fetched: FetchedSource<'_>,
        before: &control::JointControlParent,
    ) -> VaultResult<()> {
        if let Some(m) = &snapshot.managed {
            let bank = bank_state::restore_idle(snapshot.idle.as_ref(), source, fetched, before)?;
            bank_state::require_host_bank(&bank, m.rows())?;
        }
        Ok(())
    }
    pub(super) fn require_managed_control(
        &self,
        snapshot: &Snapshot,
        candidate: &control::JointControlCandidate,
    ) -> VaultResult<()> {
        if let Some(m) = &snapshot.managed {
            let call = m.call.ok_or(OwnerVaultError::Encoding)?;
            bank_state::require_host_control(
                candidate,
                call.transaction,
                m.clients[call.slot].binding.principal,
                verb_tag(call.verb),
            )?;
        }
        Ok(())
    }
    pub(super) fn require_managed_acquire(
        &self,
        snapshot: &Snapshot,
        candidates: &super::super::super::JointLockingCandidates,
    ) -> VaultResult<()> {
        if let Some(m) = &snapshot.managed {
            let call = m.call.ok_or(OwnerVaultError::Encoding)?;
            let actor = &candidates._staged.actor;
            if call.verb != Verb::Acquire
                || call.transaction != actor.transaction
                || m.clients[call.slot].binding.principal != actor.principal
            {
                return Err(OwnerVaultError::Pins);
            }
        }
        Ok(())
    }
    pub(super) fn check_managed_initial(
        &self,
        source: &SourceOwner,
        fetched: FetchedSource<'_>,
        before: &control::JointControlParent,
    ) -> VaultResult<()> {
        if let Some(bindings) = &self.pins.managed {
            if self.saved.managed.as_ref() != Some(&Managed::empty(bindings)) {
                return Err(OwnerVaultError::Pins);
            }
            let bank = bank_state::restore_idle(self.saved.idle.as_ref(), source, fetched, before)?;
            bank_state::require_host_initial(&bank)?;
            bank_state::require_host_bank(
                &bank,
                self.saved
                    .managed
                    .as_ref()
                    .ok_or(OwnerVaultError::Encoding)?
                    .rows(),
            )?;
        }
        Ok(())
    }
    // Called only AFTER the existing full math/QC/private-completion replay and
    // before adoption of that record. No reference can replace those checks.
    pub(super) fn check_managed_record(
        &mut self,
        next: &Snapshot,
        source: &SourceOwner,
        fetched: FetchedSource<'_>,
    ) -> VaultResult<()> {
        let sequence = self
            .replay_sequence
            .checked_add(1)
            .filter(|n| *n <= MAX_RECORDS as u64)
            .ok_or(OwnerVaultError::ResourceLimit)?;
        match (&self.saved.managed, &next.managed) {
            (None, None) => {}
            (Some(old), Some(actual)) => {
                let expected = if self.saved.phase == OwnerVaultPhase::Completed {
                    old.acknowledged()
                } else if next.phase == OwnerVaultPhase::Completed {
                    old.completed(sequence, next.outcome)?
                } else if self.saved.phase == OwnerVaultPhase::Idle {
                    let call = actual.call.ok_or(OwnerVaultError::Encoding)?;
                    if call.verb == Verb::Begin {
                        let before = parent(&self.history, &self.pins.binding)?;
                        let bank = bank_state::restore_idle(
                            self.saved.idle.as_ref(),
                            source,
                            again(&fetched),
                            &before,
                        )?;
                        if bank_state::host_begin_id(&bank, old.rows())? != call.transaction {
                            return Err(OwnerVaultError::Pins);
                        }
                    }
                    old.start(call)?
                } else {
                    old.clone()
                };
                if &expected != actual {
                    return Err(OwnerVaultError::Pins);
                }
                let before = parent(&self.history, &self.pins.binding)?;
                self.require_managed_bank(next, source, fetched, &before)?;
                if next.phase == OwnerVaultPhase::Completed {
                    let call = actual.call.ok_or(OwnerVaultError::Encoding)?;
                    let value = if let Some(outcome) = next.outcome {
                        ReplyValue::Control(outcome)
                    } else {
                        ReplyValue::Acquire(
                            self.acquire_result
                                .take()
                                .ok_or(OwnerVaultError::RecoveryRequired)?,
                        )
                    };
                    self.replayed_clients[call.slot] = Some(JointSqlReply {
                        call,
                        client: actual.clients[call.slot].binding.id,
                        record: sequence,
                        invocation: next.pending,
                        value,
                    });
                }
            }
            _ => return Err(OwnerVaultError::Pins),
        }
        self.replay_sequence = sequence;
        Ok(())
    }
}
