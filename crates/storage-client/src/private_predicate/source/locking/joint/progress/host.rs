//! Concrete custody -> actual worker -> exact signed proposal -> weighted QC
//! -> typed result/root -> fsynced private bank. No legacy host is activated.
use super::*;
use super::{
    completion::Completion,
    inventory::PublicInputs,
    prepare::{ATTEMPT_CAP, Attempt, Build},
    state::{Bank, Book, Kind, RawCall},
    wal::{self, Reader, Wal},
};
use bfv_product_evidence::CatalogId;
use ed25519_dalek::SigningKey;
use peer_runtime::{ProofGate, RecordedPrivateProduct, RemotePeer};
use protocol_storage::{ControlFile, ParticipantQuota, Reservation};
use registry200_finality::{
    CandidateBlock,
    progress::{History, MAX_CHECKPOINT_BYTES, OperationExpectation},
};
use registry200_joint::progress::{Lane, Manifest, ProgressDepot, ProgressEvidenceIngress};
use registry200_proof::registry_progress::circuit::State;
use version_journal::{AuthorizedTransition, Body, HeadRef, ShardUpdate};
use zeroize::Zeroize;

/// One exact logical call. Its SQL stays owner-private and is never serialized.
/// Explicit named-control constructors do not claim parser support for that SQL.
pub struct Call {
    client: [u8; 32],
    sequence: u64,
    kind: Kind,
    name: [u8; 32],
    sql: Option<Zeroizing<String>>,
    digest: [u8; 32],
}
impl Call {
    pub fn sql(client: [u8; 32], sequence: u64, sql: &str) -> Result<Self> {
        use sql_plan::{StatementPlan as S, TransactionChain};
        let kind = match sql_plan::parse_statement(sql).map_err(crypto)? {
            S::Begin { modes } if modes.is_empty() => Kind::Begin,
            S::Commit {
                chain: TransactionChain::Unspecified,
            } => Kind::EndClose,
            S::Rollback {
                chain: TransactionChain::Unspecified,
            } => Kind::EndAbort,
            S::Query(sql_plan::QueryPlan::LockingSelect { .. }) => Kind::Acquire,
            _ => return Err(Error::Shape),
        };
        if client == [0; 32] || sequence == 0 {
            return Err(Error::Shape);
        }
        Ok(Self {
            client,
            sequence,
            kind,
            name: [0; 32],
            sql: Some(Zeroizing::new(sql.to_owned())),
            digest: hash(&[b"DCS/Progress-owner/exact-private-call/v1", sql.as_bytes()]),
        })
    }
    pub fn savepoint(client: [u8; 32], sequence: u64, name: [u8; 32]) -> Result<Self> {
        Self::named(client, sequence, name, Kind::Savepoint)
    }
    pub fn rollback_to(client: [u8; 32], sequence: u64, name: [u8; 32]) -> Result<Self> {
        Self::named(client, sequence, name, Kind::RollbackTo)
    }
    pub fn release(client: [u8; 32], sequence: u64, name: [u8; 32]) -> Result<Self> {
        Self::named(client, sequence, name, Kind::Release)
    }
    fn named(client: [u8; 32], sequence: u64, name: [u8; 32], kind: Kind) -> Result<Self> {
        if client == [0; 32] || sequence == 0 || name == [0; 32] {
            return Err(Error::Shape);
        }
        Ok(Self {
            client,
            sequence,
            kind,
            name,
            sql: None,
            digest: hash(&[
                b"DCS/Progress-owner/named-private-call/v1",
                &[kind.tag()],
                &name,
            ]),
        })
    }
}
impl Drop for Call {
    fn drop(&mut self) {
        self.client.zeroize();
        self.sequence.zeroize();
        self.name.zeroize();
        self.digest.zeroize();
    }
}
/// Compare-and-swap cursor for this live WAL prefix, never a freshness receipt.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    sequence: u64,
    digest: [u8; 32],
}
pub enum Preparation {
    Ready(Cursor),
    Waiting(Cursor),
}
/// Independently supplied Bootstrap lineage and the empty private root salts.
/// This is unverified input. Construction genuinely replays every QC/proof.
pub struct Bootstrap<'a> {
    pub replay: &'a [Replay<'a>],
    pub salts: Zeroizing<[[u64; 4]; 2]>,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Row {
    pub ordinal: u8,
    pub row_id: [u8; 32],
    pub age: Option<u8>,
    pub amount: Option<u16>,
}
impl Drop for Row {
    fn drop(&mut self) {
        self.ordinal.zeroize();
        self.row_id.zeroize();
        self.age.zeroize();
        self.amount.zeroize();
    }
}
pub struct Reply {
    pub(super) rows: Vec<Row>,
    pub(super) head: HeadRef,
    pub(super) decision: [u8; 32],
}
impl Reply {
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }
    pub fn head(&self) -> HeadRef {
        self.head
    }
    pub fn decision_id(&self) -> [u8; 32] {
        self.decision
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlOutcome {
    Begun,
    SavepointCreated,
    RolledBackToSavepoint,
    SavepointReleased,
    Closed,
    Aborted,
}
pub enum Outcome {
    Waiting,
    Done(Reply),
    NoWaitError,
    Control(ControlOutcome),
}
/// An actual prepared input job, not a result or a SQL/finality permission.
/// The same ingress and process-owned gate travel with it; neither is swappable.
pub struct Work {
    stamp: [u8; 32],
    object: [u8; 32],
    inputs: PublicInputs,
    ingress: ProgressEvidenceIngress,
    gate: ProofGate,
}
pub struct Computed {
    stamp: [u8; 32],
    record: RecordedPrivateProduct,
}
impl Work {
    pub fn compute(self, peer: &RemotePeer) -> Result<Computed> {
        let _permit = self.gate.try_acquire().map_err(|_| Error::Busy)?;
        let PublicInputs {
            provenance,
            request,
            frames,
        } = self.inputs;
        let evidence =
            bfv_mul_relin_proof::InputEvidence::from_frames(frames.each_ref().map(Vec::as_slice))
                .map_err(crypto)?;
        let record = peer.prove_private_product_recorded_shared(
            self.object,
            provenance,
            &request,
            &evidence,
            self.ingress.recording_store(),
        )?;
        Ok(Computed {
            stamp: self.stamp,
            record,
        })
    }
}
/// Exact already-synced candidate. Submission/import ACK is not SQL success.
pub struct Submission {
    cursor: Cursor,
    block: CandidateBlock,
}
impl Submission {
    pub fn cursor(&self) -> Cursor {
        self.cursor
    }
    pub fn block(&self) -> &CandidateBlock {
        &self.block
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    Prepared,
    Submitted,
    Terminal,
}
const BLOCK_CAP: usize = 8 + version_journal::HEADER_BYTES + 4 + MAX_BODY_BYTES;
const PREP_RESERVE: u64 = (wal::OVERHEAD + 12 + ATTEMPT_CAP) as u64;
const SUB_RESERVE: u64 = (wal::OVERHEAD + 8 + 40 + 4 + BLOCK_CAP) as u64;
const COMMIT_RESERVE: u64 =
    (wal::OVERHEAD + 8 + 4 + MAX_CHECKPOINT_BYTES + state::BANK_BYTES + state::BOOK_BYTES) as u64;
const ACK_RESERVE: u64 = (wal::OVERHEAD + 8 + state::CALL_BYTES + state::BOOK_BYTES) as u64;
const CALL_RESERVE: u64 = PREP_RESERVE + SUB_RESERVE + COMMIT_RESERVE + ACK_RESERVE;

/// One installation owner. All state, custody, codec and private bookkeeping are
/// closed. No constructor accepts a verified flag, serialized success or status.
/// One externally created ProofGate must also be shared with process services.
pub struct Owner {
    pins: Pins,
    history: History,
    ingress: ProgressEvidenceIngress,
    gate: ProofGate,
    wal: Wal,
    bank: Bank,
    book: Book,
    phase: Phase,
    attempt: Option<Attempt>,
    block: Option<CandidateBlock>,
    delivery: Option<Outcome>,
    lease: Option<Reservation>,
}
impl Owner {
    pub fn create_new(
        pins: Pins,
        authority: Authority,
        quota: &ParticipantQuota,
        gate: ProofGate,
        material: &Material<'_>,
        fetched: FetchedSource<'_>,
        bootstrap: Bootstrap<'_>,
    ) -> Result<Self> {
        let _permit = gate.try_acquire().map_err(|_| Error::Busy)?;
        material.require(&pins)?;
        let depot =
            ProgressDepot::open(quota.depot_budget(), pins.binding.application_descriptor())
                .map_err(crypto)?;
        if depot.retain_setup(material.setup).map_err(crypto)?.encode()
            != pins.binding.setup_claim().encode()
        {
            return Err(Error::Pins);
        }
        let ingress = depot.ingress();
        let mut history = History::new(pins.binding.clone(), depot).map_err(crypto)?;
        let mut initial = Zeroizing::new(Vec::new());
        initial.extend_from_slice(b"POINIT01");
        let bank = Bank {
            state: Zeroizing::new(State::default()),
            controllers: pins.controllers.clone(),
            enroll_salt: Zeroizing::new(bootstrap.salts[0]),
            registry_salt: Zeroizing::new(bootstrap.salts[1]),
        };
        initial.extend_from_slice(bank.encode()?.as_ref());
        initial.extend_from_slice(&(bootstrap.replay.len() as u32).to_le_bytes());
        if bootstrap.replay.is_empty() || bootstrap.replay.len() > MAX_RECORDS {
            return Err(Error::ResourceLimit);
        }
        for r in bootstrap.replay {
            history.apply(r.checkpoint, r.block).map_err(crypto)?;
            wal::blob(&mut initial, &r.block.encode())?;
            wal::blob(&mut initial, &r.checkpoint.encode())?;
            if initial.len() > MAX_RECORD_BYTES - wal::OVERHEAD {
                return Err(Error::ResourceLimit);
            }
        }
        let source = material.source(&pins, again(&fetched))?;
        let loaded = source.load(fetched).map_err(crypto)?;
        bank.require_parent(
            &pins,
            history
                .checked_parent()
                .map_err(crypto)?
                .ok_or(Error::Phase)?,
            &loaded.draft,
            &loaded
                .plain
                .as_slice()
                .try_into()
                .map_err(|_| Error::Shape)?,
        )?;
        let book = Book::empty(&pins);
        book.audit(&bank, &pins)?;
        let path = quota.control_file(pins.id, ControlFile::Wal);
        let mut wal = Wal::create(&path, quota.control_budget(), &pins, authority)?;
        let mut lease = wal.reserve(1, (initial.len() + wal::OVERHEAD) as u64)?;
        wal.append(&initial, &mut lease)?;
        Ok(Self {
            pins,
            history,
            ingress,
            gate: gate.clone(),
            wal,
            bank,
            book,
            phase: Phase::Idle,
            attempt: None,
            block: None,
            delivery: None,
            lease: None,
        })
    }
    pub fn open_existing(
        pins: Pins,
        authority: Authority,
        quota: &ParticipantQuota,
        gate: ProofGate,
        material: &Material<'_>,
        fetched: FetchedSource<'_>,
    ) -> Result<Self> {
        let _permit = gate.try_acquire().map_err(|_| Error::Busy)?;
        material.require(&pins)?;
        let path = quota.control_file(pins.id, ControlFile::Wal);
        let (wal, records) = Wal::open(&path, quota.control_budget(), &pins, authority)?;
        let depot =
            ProgressDepot::open(quota.depot_budget(), pins.binding.application_descriptor())
                .map_err(crypto)?;
        let ingress = depot.ingress();
        let mut history = History::new(pins.binding.clone(), depot).map_err(crypto)?;
        let first = records.first().ok_or(Error::Encoding)?;
        let mut r = Reader::new(first);
        if r.array::<8>()? != *b"POINIT01" {
            return Err(Error::Encoding);
        }
        let bank = Bank::decode(r.take(state::BANK_BYTES)?)?;
        if *bank.state != State::default() || *bank.controllers != *pins.controllers {
            return Err(Error::Pins);
        }
        let n = u32::from_le_bytes(r.array()?) as usize;
        if n == 0 || n > MAX_RECORDS {
            return Err(Error::ResourceLimit);
        }
        for _ in 0..n {
            let block = CandidateBlock::decode(r.blob(BLOCK_CAP)?).map_err(crypto)?;
            let qc = Checkpoint::decode(r.blob(MAX_CHECKPOINT_BYTES)?).map_err(crypto)?;
            history.apply(&qc, &block).map_err(crypto)?;
        }
        r.end()?;
        let source = material.source(&pins, again(&fetched))?;
        let loaded = source.load(again(&fetched)).map_err(crypto)?;
        bank.require_parent(
            &pins,
            history
                .checked_parent()
                .map_err(crypto)?
                .ok_or(Error::Phase)?,
            &loaded.draft,
            &loaded
                .plain
                .as_slice()
                .try_into()
                .map_err(|_| Error::Shape)?,
        )?;
        let book = Book::empty(&pins);
        book.audit(&bank, &pins)?;
        let mut owner = Self {
            pins,
            history,
            ingress,
            gate: gate.clone(),
            wal,
            bank,
            book,
            phase: Phase::Idle,
            attempt: None,
            block: None,
            delivery: None,
            lease: None,
        };
        for (i, bytes) in records.iter().enumerate().skip(1) {
            owner.replay(bytes, (i + 1) as u64, material, again(&fetched))?;
        }
        owner.restore_lease()?;
        Ok(owner)
    }
    pub fn cursor(&self) -> Result<Cursor> {
        self.wal.live()?;
        Ok(Cursor {
            sequence: self.wal.sequence,
            digest: self.wal.digest,
        })
    }
    pub fn outcome(&self, cursor: Cursor) -> Result<Option<&Outcome>> {
        self.require(cursor)?;
        Ok(self.delivery.as_ref())
    }
    fn require(&self, c: Cursor) -> Result<()> {
        if self.cursor()? != c {
            return Err(Error::Cas);
        }
        Ok(())
    }
    fn stamp(&self) -> Result<[u8; 32]> {
        let parent = self
            .history
            .checked_parent()
            .map_err(crypto)?
            .ok_or(Error::Phase)?;
        Ok(hash(&[
            b"DCS/Progress-owner/private-before/v1",
            &self.pins.id,
            self.bank.encode()?.as_ref(),
            self.book.encode().as_ref(),
            &parent.head().block,
            &self.history.context().map_err(crypto)?.id(),
        ]))
    }
    fn raw(&self, call: &Call) -> Result<RawCall> {
        let slot = self
            .pins
            .clients
            .iter()
            .position(|c| c.id == call.client)
            .ok_or(Error::Pins)?;
        let transaction = if call.kind == Kind::Begin {
            self.bank
                .state
                .registry
                .allocator
                .checked_add(1)
                .ok_or(Error::ResourceLimit)?
        } else {
            self.book.clients[slot].active
        };
        Ok(RawCall {
            slot,
            kind: call.kind,
            sequence: call.sequence,
            digest: hash(&[
                b"DCS/Progress-owner/bound-private-call/v1",
                &self.pins.id,
                &call.digest,
                &call.client,
                &call.sequence.to_le_bytes(),
            ]),
            transaction,
        })
    }
    pub fn prepare(
        &mut self,
        cursor: Cursor,
        call: &Call,
        material: &Material<'_>,
        fetched: FetchedSource<'_>,
    ) -> Result<Preparation> {
        self.require(cursor)?;
        if self.phase != Phase::Idle {
            return Err(Error::Busy);
        }
        let raw = self.raw(call)?;
        if let Some(p) = self.book.parked[raw.slot] {
            if p.call == raw {
                return Ok(Preparation::Waiting(cursor));
            }
            return Err(Error::Phase);
        }
        self.prepare_raw(
            raw,
            call.sql.as_deref().map(String::as_str),
            call.name,
            false,
            material,
            fetched,
        )
    }
    /// Continue the SAME original private statement after another genuine owner
    /// operation changed the bank. This accepts no replacement WHERE or window.
    pub fn resume(
        &mut self,
        cursor: Cursor,
        client: [u8; 32],
        material: &Material<'_>,
        fetched: FetchedSource<'_>,
    ) -> Result<Preparation> {
        self.require(cursor)?;
        if self.phase != Phase::Idle {
            return Err(Error::Busy);
        }
        let slot = self
            .pins
            .clients
            .iter()
            .position(|c| c.id == client)
            .ok_or(Error::Pins)?;
        let parked = self.book.parked[slot].ok_or(Error::Phase)?;
        let p = self
            .bank
            .state
            .progress
            .iter()
            .flatten()
            .find(|p| p.statement.transaction == parked.call.transaction)
            .ok_or(Error::Pins)?;
        if self.bank.state.registry.revision
            <= p.blocked_revision
                .checked_add(1)
                .ok_or(Error::ResourceLimit)?
        {
            return Ok(Preparation::Waiting(cursor));
        }
        self.prepare_raw(parked.call, None, [0; 32], true, material, fetched)
    }
    fn prepare_raw(
        &mut self,
        call: RawCall,
        sql: Option<&str>,
        name: [u8; 32],
        resume: bool,
        material: &Material<'_>,
        fetched: FetchedSource<'_>,
    ) -> Result<Preparation> {
        let next_book = self.book.start(call, resume)?;
        self.book.audit(&self.bank, &self.pins)?;
        // Prepromise the full terminal+ACK byte and slot allowance BEFORE any
        // expensive proof, external work, signed proposal or visible new flight.
        let mut lease = self.wal.reserve(4, CALL_RESERVE)?;
        let _permit = self.gate.try_acquire().map_err(|_| Error::Busy)?;
        let attempt = Build {
            pins: &self.pins,
            bank: &self.bank,
            parent: self
                .history
                .checked_parent()
                .map_err(crypto)?
                .ok_or(Error::Phase)?,
            ingress: &self.ingress,
            material,
            fetched,
            call,
            before: self.stamp()?,
            sql,
            resume,
            name,
        }
        .run()?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.extend_from_slice(b"POPREP01");
        wal::blob(&mut bytes, &attempt.encode()?)?;
        self.wal.append(&bytes, &mut lease)?;
        self.book = next_book;
        self.attempt = Some(attempt);
        self.phase = Phase::Prepared;
        self.delivery = None;
        self.lease = Some(lease);
        Ok(Preparation::Ready(self.cursor()?))
    }
    pub fn work(&self, cursor: Cursor, material: &Material<'_>) -> Result<Option<Work>> {
        self.require(cursor)?;
        if self.phase != Phase::Prepared {
            return Err(Error::Phase);
        }
        let a = self.attempt.as_ref().ok_or(Error::Phase)?;
        if a.custody != material.fingerprint(&self.pins)? {
            return Err(Error::Pins);
        }
        if a.lane() == Lane::Control {
            return Ok(None);
        }
        Ok(Some(Work {
            stamp: hash(&[b"DCS/Progress-owner/current-work/v1", &a.encode()?]),
            object: self.pins.binding.application_descriptor().source_object(),
            inputs: a
                .inventory
                .load(&self.ingress, &self.pins, material, &a.request)?,
            ingress: self.ingress.clone(),
            gate: self.gate.clone(),
        }))
    }
    pub fn submit(
        &mut self,
        cursor: Cursor,
        computed: Option<Computed>,
        signer: &SigningKey,
        now: u64,
        mining_attempts: u64,
    ) -> Result<Submission> {
        self.require(cursor)?;
        if self.phase != Phase::Prepared {
            return Err(Error::Phase);
        }
        let a = self.attempt.as_ref().ok_or(Error::Phase)?;
        if signer.verifying_key().to_bytes() != self.pins.binding.journal_genesis().owner {
            return Err(Error::Pins);
        }
        let catalog = match (a.lane(), computed) {
            (Lane::Control, None) => None,
            (Lane::Predicate, Some(c)) => {
                if c.stamp != hash(&[b"DCS/Progress-owner/current-work/v1", &a.encode()?]) {
                    return Err(Error::Pins);
                }
                let claim =
                    a.inventory
                        .require_catalog(&self.ingress, &self.pins, c.record.catalog())?;
                let checked = c.record.checked();
                if claim.graph_identity() != checked.product().identity()
                    || claim.response().sha256()
                        != &<[u8; 32]>::from(Sha256::digest(checked.encrypted_response()))
                    || claim.response().bytes() != checked.encrypted_response().len() as u64
                {
                    return Err(Error::Pins);
                }
                Some(c.record.catalog())
            }
            _ => return Err(Error::Phase),
        };
        let manifest = match catalog {
            Some(c) => Manifest::predicate(a.next_root, a.result_root, c, a.inventory.id(18)?),
            None => Manifest::control(
                a.next_root,
                a.result_root,
                a.inventory.id(3)?,
                a.inventory.id(18)?,
            ),
        }
        .map_err(crypto)?;
        let app = app(&self.pins.binding)?;
        let parent = self
            .history
            .checked_parent()
            .map_err(crypto)?
            .ok_or(Error::Phase)?;
        let mut t = AuthorizedTransition {
            parent: parent.head().block,
            request: a.request.encode().map_err(crypto)?,
            updates: vec![ShardUpdate {
                id: app.source_spec().control_id,
                old: parent.control().heads(app.source_spec()),
                new: registry200_journal::Control::Active {
                    enrollment: a.request.inner().enrollment,
                    registry: a.next_root,
                }
                .heads(app.source_spec()),
            }],
            proof: manifest.encode(),
            owner_signature: [0; 64],
        };
        t.sign(app.genesis(), signer);
        let body = Body::Transition(t);
        let mut header = self
            .history
            .candidate_header(&body, now, now)
            .map_err(crypto)?;
        header.mine(mining_attempts).map_err(crypto)?;
        let encoded = body
            .encode(&self.pins.binding.journal_genesis().profile)
            .map_err(crypto)?;
        if encoded.len() > MAX_BODY_BYTES {
            return Err(Error::ResourceLimit);
        }
        let block = CandidateBlock::new(header, encoded).map_err(crypto)?;
        OperationExpectation::transition(
            &self.pins.binding,
            parent,
            self.history.context().map_err(crypto)?,
            &a.request,
            manifest,
            &body,
        )
        .map_err(crypto)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.extend_from_slice(b"POSUBM01");
        put_catalog(&mut bytes, catalog);
        wal::blob(&mut bytes, &block.encode())?;
        self.wal
            .append(&bytes, self.lease.as_mut().ok_or(Error::Phase)?)?;
        self.attempt.as_mut().ok_or(Error::Phase)?.catalog = catalog;
        self.block = Some(block);
        self.phase = Phase::Submitted;
        self.pending_submission(self.cursor()?)?.ok_or(Error::Phase)
    }
    pub fn pending_submission(&self, cursor: Cursor) -> Result<Option<Submission>> {
        self.require(cursor)?;
        if self.phase != Phase::Submitted {
            return Ok(None);
        }
        Ok(Some(Submission {
            cursor,
            block: CandidateBlock::decode(&self.block.as_ref().ok_or(Error::Phase)?.encode())
                .map_err(crypto)?,
        }))
    }
    pub fn complete(
        &mut self,
        cursor: Cursor,
        qc: &Checkpoint,
        material: &Material<'_>,
        fetched: FetchedSource<'_>,
    ) -> Result<&Outcome> {
        self.require(cursor)?;
        if self.phase != Phase::Submitted {
            return Err(Error::Phase);
        }
        let _permit = self.gate.try_acquire().map_err(|_| Error::Busy)?;
        let result = self.complete_checked(qc, material, fetched);
        if result.is_err() {
            self.wal.poison();
        }
        result?;
        self.delivery.as_ref().ok_or(Error::Phase)
    }
    fn complete_checked(
        &mut self,
        qc: &Checkpoint,
        material: &Material<'_>,
        fetched: FetchedSource<'_>,
    ) -> Result<()> {
        let (bank, book, outcome) = Completion {
            pins: &self.pins,
            history: &mut self.history,
            ingress: &self.ingress,
            old: &self.bank,
            book: &self.book,
            attempt: self.attempt.as_ref().ok_or(Error::Phase)?,
            block: self.block.as_ref().ok_or(Error::Phase)?,
            checkpoint: qc,
            material,
            fetched,
            record: self.wal.sequence + 1,
        }
        .check()?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.extend_from_slice(b"POCOMM01");
        wal::blob(&mut bytes, &qc.encode())?;
        bytes.extend_from_slice(bank.encode()?.as_ref());
        bytes.extend_from_slice(book.encode().as_ref());
        self.wal
            .append(&bytes, self.lease.as_mut().ok_or(Error::Phase)?)?;
        // This is the sole flight-free publication point. All previous state is
        // kept on any pre-sync failure; the poisoned owner cannot issue again.
        self.bank = bank;
        self.book = book;
        self.install_outcome(outcome);
        Ok(())
    }
    fn install_outcome(&mut self, outcome: Outcome) {
        if matches!(outcome, Outcome::Waiting) {
            self.phase = Phase::Idle;
            self.attempt = None;
            self.block = None;
            self.lease = None;
        } else {
            self.phase = Phase::Terminal;
        }
        self.delivery = Some(outcome);
    }
    pub fn acknowledge(&mut self, cursor: Cursor) -> Result<Cursor> {
        self.require(cursor)?;
        if self.phase != Phase::Terminal {
            return Err(Error::Phase);
        }
        let call = self.book.flight.ok_or(Error::Phase)?;
        let book = self.book.acknowledge(call)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.extend_from_slice(b"POACK001");
        bytes.extend_from_slice(call.encode().as_ref());
        bytes.extend_from_slice(book.encode().as_ref());
        self.wal
            .append(&bytes, self.lease.as_mut().ok_or(Error::Phase)?)?;
        self.book = book;
        self.phase = Phase::Idle;
        self.attempt = None;
        self.block = None;
        self.delivery = None;
        self.lease = None;
        self.cursor()
    }
    /// Import an actual Empty QC while idle. Parked client calls are retained;
    /// this grants no operation result and never re-evaluates their predicates.
    pub fn advance_empty(
        &mut self,
        cursor: Cursor,
        qc: &Checkpoint,
        block: &CandidateBlock,
        material: &Material<'_>,
        fetched: FetchedSource<'_>,
    ) -> Result<Cursor> {
        self.require(cursor)?;
        if self.phase != Phase::Idle
            || Body::decode(block.body(), &self.pins.binding.journal_genesis().profile)
                .map_err(crypto)?
                != Body::Empty
        {
            return Err(Error::Phase);
        }
        let _permit = self.gate.try_acquire().map_err(|_| Error::Busy)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.extend_from_slice(b"POEMPT01");
        wal::blob(&mut bytes, &block.encode())?;
        wal::blob(&mut bytes, &qc.encode())?;
        let mut lease = self.wal.reserve(1, (bytes.len() + wal::OVERHEAD) as u64)?;
        let checked = (|| {
            self.apply_empty(qc, block, material, fetched)?;
            self.wal.append(&bytes, &mut lease)
        })();
        if checked.is_err() {
            self.wal.poison();
            lease.retain_conservatively();
        }
        checked?;
        self.cursor()
    }
    fn apply_empty(
        &mut self,
        qc: &Checkpoint,
        block: &CandidateBlock,
        material: &Material<'_>,
        fetched: FetchedSource<'_>,
    ) -> Result<()> {
        if self.phase != Phase::Idle
            || Body::decode(block.body(), &self.pins.binding.journal_genesis().profile)
                .map_err(crypto)?
                != Body::Empty
        {
            return Err(Error::Phase);
        }
        let source = material.source(&self.pins, again(&fetched))?;
        let loaded = source.load(fetched).map_err(crypto)?;
        let mut plain: Zeroizing<[u8; 2348]> = Zeroizing::new(
            loaded
                .plain
                .as_slice()
                .try_into()
                .map_err(|_| Error::Shape)?,
        );
        self.bank.require_parent(
            &self.pins,
            self.history
                .checked_parent()
                .map_err(crypto)?
                .ok_or(Error::Phase)?,
            &loaded.draft,
            &plain,
        )?;
        let parent = self.history.apply(qc, block).map_err(crypto)?;
        self.bank
            .require_parent(&self.pins, &parent, &loaded.draft, &plain)?;
        plain.zeroize();
        self.book.audit(&self.bank, &self.pins)
    }
    fn restore_lease(&mut self) -> Result<()> {
        let (records, bytes) = match self.phase {
            Phase::Idle => return Ok(()),
            Phase::Prepared => (3, SUB_RESERVE + COMMIT_RESERVE + ACK_RESERVE),
            Phase::Submitted => (2, COMMIT_RESERVE + ACK_RESERVE),
            Phase::Terminal => (1, ACK_RESERVE),
        };
        self.lease = Some(self.wal.reserve(records, bytes)?);
        Ok(())
    }
    fn replay(
        &mut self,
        bytes: &[u8],
        record: u64,
        material: &Material<'_>,
        fetched: FetchedSource<'_>,
    ) -> Result<()> {
        let mut r = Reader::new(bytes);
        match &r.array::<8>()? {
            b"POPREP01" => {
                if self.phase != Phase::Idle {
                    return Err(Error::Phase);
                }
                let a = Attempt::decode(r.blob(ATTEMPT_CAP)?)?;
                if a.custody != material.fingerprint(&self.pins)? || a.before != self.stamp()? {
                    return Err(Error::Pins);
                }
                let resume = self.book.parked[a.call.slot].is_some();
                let book = self.book.start(a.call, resume)?;
                let source = material.source(&self.pins, again(&fetched))?;
                let loaded = source.load(fetched).map_err(crypto)?;
                self.bank.require_parent(
                    &self.pins,
                    self.history
                        .checked_parent()
                        .map_err(crypto)?
                        .ok_or(Error::Phase)?,
                    &loaded.draft,
                    &loaded
                        .plain
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::Shape)?,
                )?;
                self.book = book;
                self.attempt = Some(a);
                self.phase = Phase::Prepared;
                self.delivery = None;
            }
            b"POSUBM01" => {
                if self.phase != Phase::Prepared {
                    return Err(Error::Phase);
                }
                let catalog = read_catalog(&mut r)?;
                let block = CandidateBlock::decode(r.blob(BLOCK_CAP)?).map_err(crypto)?;
                let a = self.attempt.as_mut().ok_or(Error::Phase)?;
                a.catalog = catalog;
                if (a.lane() == Lane::Predicate) != catalog.is_some() {
                    return Err(Error::Encoding);
                }
                if let Some(c) = catalog {
                    a.inventory.require_catalog(&self.ingress, &self.pins, c)?;
                }
                let body = Body::decode(block.body(), &self.pins.binding.journal_genesis().profile)
                    .map_err(crypto)?;
                OperationExpectation::transition(
                    &self.pins.binding,
                    self.history
                        .checked_parent()
                        .map_err(crypto)?
                        .ok_or(Error::Phase)?,
                    self.history.context().map_err(crypto)?,
                    &a.request,
                    a.manifest()?,
                    &body,
                )
                .map_err(crypto)?;
                self.block = Some(block);
                self.phase = Phase::Submitted;
            }
            b"POCOMM01" => {
                if self.phase != Phase::Submitted {
                    return Err(Error::Phase);
                }
                let qc = Checkpoint::decode(r.blob(MAX_CHECKPOINT_BYTES)?).map_err(crypto)?;
                let encoded_bank = Bank::decode(r.take(state::BANK_BYTES)?)?;
                let encoded_book = Book::decode(r.take(state::BOOK_BYTES)?, &self.pins)?;
                let (bank, book, outcome) = Completion {
                    pins: &self.pins,
                    history: &mut self.history,
                    ingress: &self.ingress,
                    old: &self.bank,
                    book: &self.book,
                    attempt: self.attempt.as_ref().ok_or(Error::Phase)?,
                    block: self.block.as_ref().ok_or(Error::Phase)?,
                    checkpoint: &qc,
                    material,
                    fetched,
                    record,
                }
                .check()?;
                if bank.encode()?.as_ref() != encoded_bank.encode()?.as_ref()
                    || book != encoded_book
                {
                    return Err(Error::Pins);
                }
                self.bank = bank;
                self.book = book;
                self.install_outcome(outcome);
            }
            b"POACK001" => {
                if self.phase != Phase::Terminal {
                    return Err(Error::Phase);
                }
                let call = RawCall::decode(r.take(state::CALL_BYTES)?)?.ok_or(Error::Encoding)?;
                let book = self.book.acknowledge(call)?;
                if book != Book::decode(r.take(state::BOOK_BYTES)?, &self.pins)? {
                    return Err(Error::Pins);
                }
                self.book = book;
                self.phase = Phase::Idle;
                self.attempt = None;
                self.block = None;
                self.delivery = None;
            }
            b"POEMPT01" => {
                let block = CandidateBlock::decode(r.blob(BLOCK_CAP)?).map_err(crypto)?;
                let qc = Checkpoint::decode(r.blob(MAX_CHECKPOINT_BYTES)?).map_err(crypto)?;
                self.apply_empty(&qc, &block, material, fetched)?;
            }
            _ => return Err(Error::Encoding),
        }
        r.end()?;
        self.book.audit(&self.bank, &self.pins)
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        if self.wal.live().is_err()
            && let Some(lease) = self.lease.take()
        {
            lease.retain_conservatively();
        }
    }
}
fn put_catalog(b: &mut Vec<u8>, id: Option<CatalogId>) {
    if let Some(id) = id {
        b.extend(id.blob_id().sha256());
        b.extend(id.blob_id().bytes().to_le_bytes());
    } else {
        b.extend([0; 40]);
    }
}
fn read_catalog(r: &mut Reader<'_>) -> Result<Option<CatalogId>> {
    let b = r.array::<40>()?;
    if b == [0; 40] {
        return Ok(None);
    }
    Ok(Some(
        CatalogId::from_blob(
            protocol_storage::BlobId::new(
                b[..32].try_into().unwrap(),
                u64::from_le_bytes(b[32..].try_into().unwrap()),
            )
            .map_err(storage)?,
        )
        .map_err(crypto)?,
    ))
}

#[cfg(test)]
impl Owner {
    pub(super) fn test_checkpoint(&self, block: &CandidateBlock) -> Checkpoint {
        super::tests::checkpoint(&self.pins.binding, self.history.context().unwrap(), block)
    }
    pub(super) fn test_fault(&mut self, fault: wal::Fault) {
        self.wal.fault = Some(fault);
    }
}
