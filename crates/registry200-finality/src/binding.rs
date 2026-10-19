use crate::{Error, Hash, Result, digest};
use registry200_journal::{Application, ApplicationDescriptor};
use version_journal::{Genesis as JournalGenesis, Header};
use work_finality::{
    Genesis as WorkGenesis,
    consensus::{Context, Rules},
};

pub const DESCRIPTOR_BYTES: usize = 8 + 32 + 8 + 32 + version_journal::HEADER_BYTES;

/// Algorithm identity, selected before bootstrap work. It excludes the derived
/// roster, both Genesis ids, every candidate, QC and signature.
pub fn profile_digest() -> Hash {
    digest(b"dcs/registry200-finality/profile/v1", &[
        b"original-Registry200/immutable-source/owner-before-Source-first-child/one-control-CAS",
        b"DCSRFV01/binding32/slot64/previous32/header192/strict-EOF",
        b"actual-parent/canonical-body/owner/PoW/proof-reverify-even-cached/Empty-allowed",
        b"semantic-decision-excludes-QC-round-signerset/durable-decision-floor-advance",
        b"DCSRFL01/DCSRFR01/hash-chain/fsync/strict-tail/no-migration/no-activation/no-SQL-grant",
        &(work_finality::MAX_CERTIFICATE_BYTES as u64).to_le_bytes(),
        &version_journal::MAX_JOURNAL_BYTES.to_le_bytes(),
    ])
}

/// Independently selected immutable composition pins. Network bytes cannot
/// nominate a new Binding by claiming that they were verified elsewhere.
#[derive(Clone)]
pub struct Binding {
    id: Hash,
    rules: Rules,
    work: WorkGenesis,
    journal: JournalGenesis,
    descriptor: ApplicationDescriptor,
    initial: Context,
}
impl Binding {
    pub fn new(
        public_network: Hash,
        rules: Rules,
        work: WorkGenesis,
        journal: JournalGenesis,
        descriptor: ApplicationDescriptor,
    ) -> Result<Self> {
        if !rules.is_multi_slot()
            || rules.max_value_bytes() != DESCRIPTOR_BYTES
            || journal.network_id != public_network
        {
            return Err(Error::InvalidBinding);
        }
        // Decode/revalidate the complete application, including its proof-wire
        // contract and canonical source geometry; public mutable App fields do
        // not bypass this check.
        let descriptor = ApplicationDescriptor::decode(&descriptor.encode())?;
        let app = descriptor.application()?;
        app.require_genesis(&journal)?;
        // Application is pinned through the complete RulesId BEFORE work. A
        // caller must use the exact closed algorithm identity, not an opaque
        // substitute callback's rules.
        if rules.application_id() != profile_digest() {
            return Err(Error::InvalidBinding);
        }
        let journal_id = journal.id()?;
        let work = WorkGenesis::decode(
            &work
                .encode()
                .map_err(work_finality::consensus::Error::from)?,
            work.id(),
        )
        .map_err(work_finality::consensus::Error::from)?;
        let id = digest(
            b"dcs/registry200-finality/binding/v1",
            &[
                &profile_digest(),
                &public_network,
                rules.id().as_bytes(),
                &work.id(),
                &journal_id,
                &descriptor.encode(),
            ],
        );
        let previous = digest(
            b"dcs/registry200-finality/bootstrap-floor/v1",
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
            initial,
        })
    }
    pub fn id(&self) -> Hash {
        self.id
    }
    pub fn initial_context(&self) -> &Context {
        &self.initial
    }
    pub fn journal_genesis(&self) -> &JournalGenesis {
        &self.journal
    }
    pub fn work_genesis(&self) -> &WorkGenesis {
        &self.work
    }
    pub fn rules(&self) -> &Rules {
        &self.rules
    }
    pub fn application_descriptor(&self) -> &ApplicationDescriptor {
        &self.descriptor
    }
    pub(crate) fn application(&self) -> Result<Application> {
        Ok(self.descriptor.application()?)
    }
    pub(crate) fn namespace(&self) -> Hash {
        digest(
            b"dcs/registry200-finality/journal-namespace/v1",
            &[&profile_digest(), &self.id],
        )
    }
}

/// Public canonical candidate metadata, NOT an accepted decision or proof token.
/// The body is resolved from the owned journal and unconditionally reverified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub(crate) binding: Hash,
    pub(crate) slot: u64,
    pub(crate) previous: Hash,
    pub(crate) header: Header,
}
impl Descriptor {
    pub(crate) fn for_context(binding: &Binding, context: &Context, header: Header) -> Self {
        Self {
            binding: binding.id(),
            slot: context.slot(),
            previous: context.previous_decision(),
            header,
        }
    }
    pub fn header(&self) -> &Header {
        &self.header
    }
    pub fn slot(&self) -> u64 {
        self.slot
    }
    pub fn encode(&self) -> [u8; DESCRIPTOR_BYTES] {
        let mut b = [0; DESCRIPTOR_BYTES];
        b[..8].copy_from_slice(b"DCSRFV01");
        b[8..40].copy_from_slice(&self.binding);
        b[40..48].copy_from_slice(&self.slot.to_le_bytes());
        b[48..80].copy_from_slice(&self.previous);
        b[80..].copy_from_slice(&self.header.encode());
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != DESCRIPTOR_BYTES || &b[..8] != b"DCSRFV01" {
            return Err(Error::InvalidEncoding);
        }
        let x = Self {
            binding: b[8..40].try_into().unwrap(),
            slot: u64::from_le_bytes(b[40..48].try_into().unwrap()),
            previous: b[48..80].try_into().unwrap(),
            header: Header::decode(&b[80..])?,
        };
        if x.slot == 0 || x.encode() != b {
            return Err(Error::InvalidEncoding);
        }
        Ok(x)
    }
}
