//! Independent Word/Source, owner, confirmed-work roster and consensus pins.
use super::{CANDIDATE_BYTES, Error, Hash, Result};
use crate::digest;
use registry200_joint::word::{Application, Descriptor};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use version_journal::Genesis as JournalGenesis;
use work_finality::{
    Genesis as WorkGenesis,
    consensus::{Context, Rules},
};
pub fn profile_digest() -> Hash {
    digest(b"dcs/registry200-finality/word-durable/v1", &[
        &registry200_joint::word::contract_digest(), &protocol_storage::participant_profile_digest(),
        b"DCSWCV01/DCSWCQ01/actual-owner-Word-EMPTY265-Control309/immutable-Source-verified-at-open/no-Predicate-no-SQL",
        b"fixed-roster-real-work/QC-WAL-before-floor/floor-before-next-slot/bounded-replay/no-quorum-no-finalization",
        b"same-drive-native-handoff-exact-state-pointer-context-floor/no-serialized-verdict/full-native-Word-before-vote-import-reopen-duplicate",
        &(CANDIDATE_BYTES as u64).to_le_bytes(), &version_journal::MAX_JOURNAL_BYTES.to_le_bytes(),
    ])
}
#[derive(Clone)]
pub struct Binding {
    id: Hash,
    rules: Rules,
    work: WorkGenesis,
    journal: JournalGenesis,
    descriptor: Descriptor,
    source: Arc<[u8]>,
    initial: Context,
}
impl Binding {
    /// Metadata/pins only. Actual Source verification occurs in every participant
    /// create/open before its closed application owner is usable.
    pub fn new(
        public_network: Hash,
        rules: Rules,
        work: WorkGenesis,
        journal: JournalGenesis,
        descriptor: Descriptor,
        source: &[u8],
    ) -> Result<Self> {
        if source.is_empty() || source.len() > super::MAX_SOURCE_CERTIFICATE_BYTES {
            return Err(Error::ResourceLimit);
        }
        if !rules.is_multi_slot()
            || rules.application_id() != profile_digest()
            || rules.max_value_bytes() != CANDIDATE_BYTES
            || journal.network_id != public_network
        {
            return Err(Error::Binding);
        }
        let descriptor = Descriptor::decode(&descriptor.encode())?;
        let _ = Application::new(descriptor.clone(), &journal)?;
        let work = WorkGenesis::decode(
            &work
                .encode()
                .map_err(work_finality::consensus::Error::from)?,
            work.id(),
        )
        .map_err(work_finality::consensus::Error::from)?;
        let journal_id = journal.id()?;
        let id = digest(
            b"dcs/registry200-finality/word-binding/v1",
            &[
                &profile_digest(),
                &public_network,
                rules.id().as_bytes(),
                &work.id(),
                &journal_id,
                &descriptor.encode(),
                &(source.len() as u64).to_le_bytes(),
                &Sha256::digest(source),
            ],
        );
        let previous = digest(
            b"dcs/registry200-finality/word-bootstrap/v1",
            &[&id, &journal_id],
        );
        let initial = Context::new(
            rules.clone(),
            public_network,
            &work,
            journal_id,
            1,
            previous,
        )?;
        Ok(Self {
            id,
            rules,
            work,
            journal,
            descriptor,
            source: Arc::from(source),
            initial,
        })
    }
    pub fn id(&self) -> Hash {
        self.id
    }
    pub fn rules(&self) -> &Rules {
        &self.rules
    }
    pub fn work_genesis(&self) -> &WorkGenesis {
        &self.work
    }
    pub fn journal_genesis(&self) -> &JournalGenesis {
        &self.journal
    }
    pub fn application_descriptor(&self) -> &Descriptor {
        &self.descriptor
    }
    pub fn initial_context(&self) -> &Context {
        &self.initial
    }
    pub(crate) fn source_bytes(&self) -> &[u8] {
        &self.source
    }
    pub(crate) fn namespace(&self) -> Hash {
        digest(
            b"dcs/registry200-finality/word-journal-namespace/v1",
            &[&profile_digest(), &self.id],
        )
    }
    pub(crate) fn require_durable(&self) -> Result<()> {
        if self.rules.application_id() != profile_digest() {
            return Err(Error::Binding);
        }
        Ok(())
    }
}
