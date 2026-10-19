use super::{CANDIDATE_BYTES, Error, Hash, Result};
use crate::digest;
use registry200_joint::{Application, Descriptor, SetupClaim};
use version_journal::Genesis as JournalGenesis;
use work_finality::{
    Genesis as WorkGenesis,
    consensus::{Context, Rules},
};

/// Algorithm identity selected before bootstrap work. Participant capacity is
/// local policy, not a substitute RulesId or a term in this fixed algorithm.
pub fn profile_digest() -> Hash {
    digest(b"dcs/registry200-finality/joint-application/v1", &[
        &registry200_joint::contract_digest(),
        &protocol_storage::participant_profile_digest(),
        b"DCSJCV01/binding32-slot64-previous32-header192;DCSJCQ01/candidate272-round64-QClen32-EOF",
        b"new-Joint-App-G/old-SourceSpec-inner-only/actual-owner-PoW-Body-all-Joint-proofs-QC/Empty-allowed",
        b"keyless-history-not-durable-floor/fixed-roster/semantic-successor/no-QC-cache/no-generic-Journal-authority/no-SQL-grant",
        &(CANDIDATE_BYTES as u64).to_le_bytes(),
        &(work_finality::MAX_CERTIFICATE_BYTES as u64).to_le_bytes(),
        &version_journal::MAX_JOURNAL_BYTES.to_le_bytes(),
    ])
}

/// Distinct signer/floor contract selected BEFORE Work bootstrap. The keyless
/// relation/profile remains unchanged; no old RulesId is silently relabelled.
pub fn durable_profile_digest() -> Hash {
    digest(b"dcs/registry200-finality/joint-durable/v1", &[
        &profile_digest(),
        b"fixed-JointVerifier/all-proof-replay-before-vote-import-reopen/no-cached-authority",
        b"DCSJFL01/DCSJFR01/DCSJFM01/participant-four-files/metadata-last/precharge/fsync",
        b"decision-WAL-before-floor/floor-before-install-and-advance/semantic-successor/strict-tail/no-repair",
        b"bounded-historical-contexts/last-admissible-header/no-quorum-no-lock-or-End/no-SQL-grant",
        &(CANDIDATE_BYTES as u64).to_le_bytes(),
        &version_journal::MAX_JOURNAL_BYTES.to_le_bytes(),
    ])
}

/// Independently authenticated public installation pins. Network metadata may
/// not nominate a binding, source object, Key33, setup, roster, or easier Rules.
#[derive(Clone)]
pub struct JointBinding {
    id: Hash,
    rules: Rules,
    work: WorkGenesis,
    journal: JournalGenesis,
    descriptor: Descriptor,
    setup: SetupClaim,
    initial: Context,
}
impl JointBinding {
    pub fn new(
        public_network: Hash,
        rules: Rules,
        work: WorkGenesis,
        journal: JournalGenesis,
        descriptor: Descriptor,
        setup: SetupClaim,
    ) -> Result<Self> {
        Self::checked(
            public_network,
            rules,
            work,
            journal,
            descriptor,
            setup,
            Purpose::Keyless,
        )
    }
    pub fn for_durable(
        public_network: Hash,
        rules: Rules,
        work: WorkGenesis,
        journal: JournalGenesis,
        descriptor: Descriptor,
        setup: SetupClaim,
    ) -> Result<Self> {
        Self::checked(
            public_network,
            rules,
            work,
            journal,
            descriptor,
            setup,
            Purpose::Durable,
        )
    }
    fn checked(
        public_network: Hash,
        rules: Rules,
        work: WorkGenesis,
        journal: JournalGenesis,
        descriptor: Descriptor,
        setup: SetupClaim,
        purpose: Purpose,
    ) -> Result<Self> {
        let profile = purpose.profile();
        if !rules.is_multi_slot()
            || rules.application_id() != profile
            || rules.max_value_bytes() != CANDIDATE_BYTES
            || journal.network_id != public_network
        {
            return Err(Error::Binding);
        }
        let descriptor = Descriptor::decode(&descriptor.encode())?;
        let _ = Application::new(descriptor.clone(), &journal)?;
        let setup = SetupClaim::decode(&setup.encode())?;
        // SetupClaim has no proof authority; actual full hash/anchor checks
        // occur in JointVerifier::new before any history object can escape.
        let work = WorkGenesis::decode(
            &work
                .encode()
                .map_err(work_finality::consensus::Error::from)?,
            work.id(),
        )
        .map_err(work_finality::consensus::Error::from)?;
        let journal_id = journal.id()?;
        let id = digest(
            b"dcs/registry200-finality/joint-binding/v1",
            &[
                &profile,
                &public_network,
                rules.id().as_bytes(),
                &work.id(),
                &journal_id,
                &descriptor.encode(),
                &setup.encode(),
            ],
        );
        let previous = digest(
            b"dcs/registry200-finality/joint-bootstrap/v1",
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
            setup,
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
    pub fn setup_claim(&self) -> &SetupClaim {
        &self.setup
    }
    pub fn initial_context(&self) -> &Context {
        &self.initial
    }
    pub(super) fn require_durable(&self) -> Result<()> {
        if self.rules.application_id() != durable_profile_digest() {
            return Err(Error::Binding);
        }
        Ok(())
    }
    pub(super) fn namespace(&self) -> Hash {
        digest(
            b"dcs/registry200-finality/joint-journal-namespace/v1",
            &[&durable_profile_digest(), &self.id],
        )
    }
    pub(crate) fn application(&self) -> Result<Application> {
        Ok(Application::new(self.descriptor.clone(), &self.journal)?)
    }
}
enum Purpose {
    Keyless,
    Durable,
}
impl Purpose {
    fn profile(&self) -> Hash {
        match self {
            Self::Keyless => profile_digest(),
            Self::Durable => durable_profile_digest(),
        }
    }
}
