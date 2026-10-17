//! Explicit PUBLIC NONSECRET source, controllers and owner. No live execution API.
use super::super::{
    fixture::Fixture as SourceFixture,
    model::{Command, Operation},
    wire,
};
use super::{
    Application, Error, Hash, PrivateVerifier, Result,
    owner::{Inputs, Prepared, PrivateState, Produced, ValidatedParent},
};
use crate::backend::Error as BackendError;
use ed25519_dalek::SigningKey;
use std::path::PathBuf;
use version_journal::{
    Body, DurableJournal, Freshness, Genesis, HeadRef, Header, Journal, ProtocolProfile, Target,
};

pub(super) const SOURCE_ID: u64 = 7;
pub(super) const CONTROL_ID: u64 = 8;
pub(super) struct Fixture {
    pub(super) application: Application,
    pub(super) genesis: Genesis,
    pub(super) source: SourceFixture,
}
impl Fixture {
    pub(super) fn new() -> Result<Self> {
        Self::with_quota(version_journal::MAX_JOURNAL_BYTES)
    }
    /// A smaller test quota is pinned BEFORE genesis/proofs, never changed after generation.
    pub(super) fn with_quota(quota: u64) -> Result<Self> {
        let source = super::backend(SourceFixture::new())?;
        let application = Application::new([0xAC; 32], SOURCE_ID, CONTROL_ID, &source.source)?;
        let genesis = Genesis {
            network_id: application.network,
            database: application.database,
            owner: Self::owner().verifying_key().to_bytes(),
            application_commitment: application.id(),
            timestamp: 1000,
            profile: ProtocolProfile {
                initial_target: Target([255; 32]),
                pow_limit: Target([255; 32]),
                block_spacing_secs: 10,
                retarget_interval: 100,
                max_future_secs: 60,
                confirmation_depth: 1,
                max_headers: 128,
                max_shards: 2,
                max_updates: 2,
                max_body_bytes: version_journal::MAX_BODY_BYTES as u32,
                max_request_bytes: 4096,
                max_proof_bytes: wire::maximum_bundle_bytes() as u32,
                max_journal_bytes: quota,
            },
            initial_shards: application.initial_shards(),
        };
        application.require_genesis(&genesis)?;
        Ok(Self {
            application,
            genesis,
            source,
        })
    }
    pub(super) fn owner() -> SigningKey {
        SigningKey::from_bytes(&[0x68; 32])
    }
    pub(super) fn verifier(&self) -> Result<PrivateVerifier> {
        PrivateVerifier::new(self.application.clone(), &self.genesis)
    }
    pub(super) fn inputs(&self) -> Inputs<'_> {
        Inputs {
            app: &self.application,
            source: &self.source.source,
            source_witness: &self.source.source_witness,
            opening: &self.source.witness,
        }
    }
    pub(super) fn bootstrap(
        &self,
        journal: &Journal,
        parent: HeadRef,
        nonce: Hash,
    ) -> Result<Produced> {
        let accepted = ValidatedParent::read(&self.application, journal, parent)?;
        self.inputs()
            .bootstrap(&accepted, nonce)?
            .prove(&self.genesis, &Self::owner())
    }
    pub(super) fn prepare(
        &self,
        journal: &Journal,
        parent: HeadRef,
        state: &PrivateState,
        command: Command,
        nonce: Hash,
    ) -> Result<Prepared<'_>> {
        let accepted = ValidatedParent::read(&self.application, journal, parent)?;
        self.inputs().transition(&accepted, state, command, nonce)
    }
    pub(super) fn transition(
        &self,
        journal: &Journal,
        parent: HeadRef,
        state: &PrivateState,
        command: Command,
        nonce: Hash,
    ) -> Result<Produced> {
        self.prepare(journal, parent, state, command, nonce)?
            .prove(&self.genesis, &Self::owner())
    }
}
/// Directory owns one journal path. No recursive deletion or unrelated file cleanup.
pub(super) struct OwnedDirectory {
    pub(super) path: PathBuf,
}
impl OwnedDirectory {
    pub(super) fn new() -> Result<Self> {
        for attempt in 0..100u32 {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| Error::InvalidTimestamp)?
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "dcs-lifecycle-journal-{}-{stamp}-{attempt}",
                std::process::id()
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => {
                    return Ok(Self {
                        path: path.canonicalize()?,
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(Error::ExistingPath)
    }
    pub(super) fn journal(&self) -> PathBuf {
        self.path.join("journal")
    }
}
impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.journal());
        let _ = std::fs::remove_dir(&self.path);
    }
}
pub(super) fn candidate(
    journal: &Journal,
    parent: Hash,
    body: &Body,
    timestamp: u64,
) -> Result<Header> {
    let mut header = journal.candidate(parent, body, timestamp)?;
    header.mine(1024)?;
    Ok(header)
}
#[cfg(test)]
pub(super) fn append(
    journal: &mut Journal,
    verifier: &impl version_journal::TransitionVerifier,
    parent: Hash,
    body: &Body,
    timestamp: u64,
) -> Result<Header> {
    let header = candidate(journal, parent, body, timestamp)?;
    journal.import_block(
        header.clone(),
        &body.encode(journal.profile())?,
        10000,
        verifier,
    )?;
    Ok(header)
}
/// Seven transitions under the unchanged 256MiB profile. No Body/proof-vector cache.
pub(super) fn main_command(index: usize, state: &PrivateState) -> Command {
    let sequence = state
        .registry
        .transactions
        .first()
        .map_or(0, |t| t.sequence);
    let operation = [
        Operation::Begin,
        Operation::Savepoint,
        Operation::Acquire,
        Operation::RollbackTo,
        Operation::Release,
        Operation::FailCurrent,
        Operation::End,
    ][index];
    let mut command = Command::control(operation, 1, 1, sequence);
    if matches!(
        operation,
        Operation::Savepoint | Operation::RollbackTo | Operation::Release
    ) {
        command.name = [0x53; 32];
    }
    if operation == Operation::Acquire {
        command.mask = [255; 32];
        command.mode = 4;
        command.limit = 2;
        command.projection = 3;
    }
    command
}
pub(super) fn gate(mode: &str) -> std::result::Result<(), BackendError> {
    if !matches!(mode, "security" | "prove") {
        return Err(BackendError::Shape);
    }
    let f = Fixture::new().map_err(|_| BackendError::Shape)?;
    if mode == "security" {
        let journal = Journal::new(f.genesis.clone()).map_err(|_| BackendError::Shape)?;
        let parent = journal.genesis_head();
        let accepted = ValidatedParent::read(&f.application, &journal, parent)
            .map_err(|_| BackendError::Shape)?;
        let bootstrap = f
            .inputs()
            .bootstrap(&accepted, [0xB1; 32])
            .map_err(|_| BackendError::Shape)?;
        crate::security(
            bootstrap.source_statement(),
            "public-nonsecret-lifecycle-journal-canonical-source",
        )?;
        let s = bootstrap.statement().map_err(|_| BackendError::Shape)?;
        crate::security(&s, "public-nonsecret-lifecycle-journal-bootstrap")?;
        // Analytical only: construct the private empty commitment, not a trace/proof/append.
        let state = PrivateState {
            registry: super::super::model::Registry::default(),
            salt: f.source.witness.salts[4],
        };
        let registry = super::super::statement::encoded(s.next);
        // A typed transition can be analyzed directly from the exact same empty opening.
        let source = f.source.source([0xB2; 32]);
        let enrollment = super::super::statement::encoded(s.expected.enrollment);
        let mut e = super::backend(super::super::statement::Expected::transition(
            &source,
            parent.genesis,
            parent.block,
            enrollment,
            super::super::statement::encoded(s.next),
            [0; 32],
        ))
        .map_err(|_| BackendError::Shape)?;
        let mut w = f.source.witness.clone();
        w.old = state.registry;
        w.salts[2] = state.salt;
        w.command = Some(Command::control(Operation::Begin, 1, 1, 0));
        let old = crate::opening::statement::decode_digest(registry)?;
        let command = super::super::statement::digest(&super::super::statement::command_fields(
            &e,
            &w,
            w.command.as_ref().unwrap(),
        ));
        e.phase = super::super::statement::Phase::Transition { old, command };
        crate::security(
            &w.statement(&e)?,
            "public-nonsecret-lifecycle-journal-transition",
        )?;
        return Ok(());
    }
    let genesis_bytes = f.genesis.encode().map_err(|_| BackendError::Shape)?.len();
    let started = std::time::Instant::now();
    let result = (|| -> Result<(Vec<usize>, u64, usize)> {
        let directory = OwnedDirectory::new()?;
        let path = directory.journal();
        let verifier = f.verifier()?;
        let namespace = [0xD4; 32];
        let mut durable = DurableJournal::create(&path, f.genesis.clone(), namespace)?;
        let parent = durable.journal().genesis_head();
        let Produced {
            body,
            private: mut state,
            ..
        } = f.bootstrap(durable.journal(), parent, [0xB1; 32])?;
        let mut sizes = Vec::with_capacity(8);
        let bytes = body.encode(durable.journal().profile())?;
        sizes.push(bytes.len());
        let h = candidate(durable.journal(), parent.block, &body, 1001)?;
        durable.append_block(h, &bytes, 10000, &verifier)?;
        drop(bytes);
        drop(body);
        for index in 0..7 {
            let parent = durable.journal().best_validated();
            let command = main_command(index, &state);
            let produced = f.transition(
                durable.journal(),
                parent,
                &state,
                command,
                [0xB2 + index as u8; 32],
            )?;
            if (index == 6 && produced.outcome != 3)
                || (index != 6 && produced.outcome != 0)
                || (index == 2
                    && (produced.returned != [true, true, false, false]
                        || produced.skipped != [false; 4]))
            {
                return Err(Error::InvalidTransition);
            }
            let bytes = produced.body.encode(durable.journal().profile())?;
            sizes.push(bytes.len());
            let h = candidate(
                durable.journal(),
                parent.block,
                &produced.body,
                1002 + index as u64,
            )?;
            durable.append_block(h, &bytes, 10000, &verifier)?;
            state = produced.private;
        }
        if !state.registry.transactions.is_empty()
            || state.registry.revision != 7
            || state.registry.allocator != 1
        {
            return Err(Error::InvalidTransition);
        }
        let tip = durable.journal().best_validated();
        let h = candidate(durable.journal(), tip.block, &Body::Empty, 1009)?;
        let empty_bytes = Body::Empty.encode(durable.journal().profile())?;
        durable.append_block(h, &empty_bytes, 10000, &verifier)?;
        if durable.journal().resolve(Freshness::LatestConfirmed)?.block != tip.block {
            return Err(Error::StaleHead);
        }
        let disk = durable.disk_bytes();
        let final_tip = durable.journal().best_validated();
        drop(durable);
        let reopened = DurableJournal::open(&path, f.genesis.clone(), namespace, 10000, &verifier)?;
        if reopened.journal().best_validated() != final_tip || reopened.disk_bytes() != disk {
            return Err(Error::InvalidTransition);
        }
        Ok((sizes, disk, empty_bytes.len()))
    })()
    .map_err(|_| BackendError::Verification)?;
    println!(
        "{{\"stage\":\"verified_experimental_lifecycle200_journal\",\"body_bytes\":{:?},\"transition_count\":7,\"reopened_proof_pairs\":8,\"durable_bytes\":{},\"genesis_bytes\":{},\"empty_confirmation_bytes\":{},\"whole_lineage_and_reopen_ms\":{},\"owner_authorized\":true,\"live_sql_grant\":false,\"finality\":false}}",
        result.0,
        result.1,
        genesis_bytes,
        result.2,
        started.elapsed().as_secs_f64() * 1000.0
    );
    Ok(())
}
