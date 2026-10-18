//! Independently pinned application and stable Registry200 control heads.
use super::{Error, Hash, Result};
use registry200_proof::lifecycle::statement::encoded;
use registry200_proof::{
    source::{Relation, statement as source},
    wire,
};
use sha2::{Digest, Sha256};
use version_journal::{Genesis, HeadPair, ShardState};

const MAGIC: &[u8; 8] = b"DCSLCH01";
#[derive(Clone)]
pub struct Application {
    pub network: Hash,
    pub database: [u8; 16],
    pub source_id: u64,
    pub control_id: u64,
    pub source: HeadPair,
    pub key: Hash,
    id: Hash,
}
impl Application {
    pub fn new(
        network: Hash,
        source_id: u64,
        control_id: u64,
        initial: &source::Statement,
    ) -> Result<Self> {
        let _ = registry200_proof::admission::CanonicalSource::checked_claim(initial)
            .map_err(|_| Error::WrongDomain)?;
        if initial.relation != Relation::CanonicalIndex
            || source_id == control_id
            || initial.heads[0][8..40] != initial.heads[1][8..40]
        {
            return Err(Error::WrongDomain);
        }
        ApplicationDescriptor::checked(
            network,
            source_id,
            control_id,
            HeadPair {
                data: initial.heads[0],
                index: initial.heads[1],
            },
            encoded(initial.key_commitment),
        )?
        .application()
    }

    pub fn id(&self) -> Hash {
        self.id
    }
    pub fn initial_shards(&self) -> Vec<ShardState> {
        let mut shards = vec![
            ShardState {
                id: self.source_id,
                heads: self.source,
            },
            ShardState {
                id: self.control_id,
                heads: Control::Pending.heads(self),
            },
        ];
        shards.sort_unstable_by_key(|s| s.id);
        shards
    }
    pub fn require_genesis(&self, g: &Genesis) -> Result<()> {
        g.validate()?;
        let canonical = ApplicationDescriptor::from_application(self)?.application()?;
        if canonical.id() != self.id || canonical.database != self.database {
            return Err(Error::WrongDomain);
        }
        if g.network_id != self.network
            || g.database != self.database
            || g.application_commitment != self.id
            || g.initial_shards != self.initial_shards()
        {
            return Err(Error::WrongDomain);
        }
        Ok(())
    }
    pub fn require_source(&self, s: &source::Statement) -> Result<()> {
        if s.relation != Relation::CanonicalIndex
            || s.heads != [self.source.data, self.source.index]
            || encoded(s.key_commitment) != self.key
        {
            return Err(Error::WrongDomain);
        }
        Ok(())
    }
    pub fn control(&self, shards: &[ShardState]) -> Result<HeadPair> {
        if shards.len() != 2 || shards[0].id >= shards[1].id {
            return Err(Error::InvalidTransition);
        }
        let source = shards
            .iter()
            .find(|s| s.id == self.source_id)
            .ok_or(Error::InvalidTransition)?;
        let control = shards
            .iter()
            .find(|s| s.id == self.control_id)
            .ok_or(Error::InvalidTransition)?;
        if source.heads != self.source {
            return Err(Error::WrongDomain);
        }
        Control::decode(self, control.heads)?;
        Ok(control.heads)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    Pending,
    Active { enrollment: Hash, registry: Hash },
}
impl Control {
    pub fn heads(self, app: &Application) -> HeadPair {
        let (phase, registry, enrollment) = match self {
            Self::Pending => (0, [0; 32], [0; 32]),
            Self::Active {
                enrollment,
                registry,
            } => (1, registry, enrollment),
        };
        let head = |component, root: Hash| {
            let mut bytes = [0; 112];
            bytes[..8].copy_from_slice(MAGIC);
            bytes[8..24].copy_from_slice(&app.database);
            bytes[24] = component;
            bytes[25] = phase;
            bytes[32..64].copy_from_slice(&app.id);
            bytes[64..96].copy_from_slice(&root);
            bytes
        };
        HeadPair {
            data: head(1, registry),
            index: head(2, enrollment),
        }
    }
    pub fn decode(app: &Application, heads: HeadPair) -> Result<Self> {
        let registry: Hash = heads.data[64..96].try_into().unwrap();
        let enrollment: Hash = heads.index[64..96].try_into().unwrap();
        let value = match heads.data[25] {
            0 if registry == [0; 32] && enrollment == [0; 32] => Self::Pending,
            1 => {
                let _ = source::decode_digest(registry).map_err(|_| Error::InvalidEncoding)?;
                let _ = source::decode_digest(enrollment).map_err(|_| Error::InvalidEncoding)?;
                Self::Active {
                    enrollment,
                    registry,
                }
            }
            _ => return Err(Error::InvalidEncoding),
        };
        if value.heads(app) != heads {
            return Err(Error::InvalidEncoding);
        }
        Ok(value)
    }
}

/// Fixed original application pins. Candidate bytes supply no proof or authorization.
#[derive(Clone)]
pub struct ApplicationDescriptor {
    network: Hash,
    source_id: u64,
    control_id: u64,
    source: HeadPair,
    key: Hash,
}
pub const DESCRIPTOR_BYTES: usize = 312;
const DESCRIPTOR_MAGIC: &[u8; 8] = b"DCSLFA01";
impl ApplicationDescriptor {
    pub fn checked(
        network: Hash,
        source_id: u64,
        control_id: u64,
        source: HeadPair,
        key: Hash,
    ) -> Result<Self> {
        if source_id == control_id {
            return Err(Error::WrongDomain);
        }
        let data = compact_store::Commitment::decode(&source.data, source::limits())
            .map_err(|_| Error::InvalidEncoding)?;
        let index = compact_store::Commitment::decode(&source.index, source::limits())
            .map_err(|_| Error::InvalidEncoding)?;
        if data.database() != index.database()
            || data.key_domain() != index.key_domain()
            || data.layout()
                != (compact_store::Layout {
                    schema: registry200_proof::source::DATA_SCHEMA,
                    row_width: 3,
                    rows_per_page: 256,
                    row_count: 4,
                })
            || index.layout()
                != (compact_store::Layout {
                    schema: registry200_proof::source::INDEX_SCHEMA,
                    row_width: 1,
                    rows_per_page: 4096,
                    row_count: 2336,
                })
        {
            return Err(Error::WrongDomain);
        }
        let _ = source::decode_digest(key).map_err(|_| Error::InvalidEncoding)?;
        Ok(Self {
            network,
            source_id,
            control_id,
            source,
            key,
        })
    }
    pub fn from_application(a: &Application) -> Result<Self> {
        Self::checked(a.network, a.source_id, a.control_id, a.source, a.key)
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(DESCRIPTOR_BYTES);
        b.extend_from_slice(DESCRIPTOR_MAGIC);
        b.extend_from_slice(&self.network);
        b.extend_from_slice(&self.source_id.to_le_bytes());
        b.extend_from_slice(&self.control_id.to_le_bytes());
        b.extend_from_slice(&self.source.data);
        b.extend_from_slice(&self.source.index);
        b.extend_from_slice(&self.key);
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != DESCRIPTOR_BYTES || &b[..8] != DESCRIPTOR_MAGIC {
            return Err(Error::InvalidEncoding);
        }
        let x = Self::checked(
            b[8..40].try_into().unwrap(),
            u64::from_le_bytes(b[40..48].try_into().unwrap()),
            u64::from_le_bytes(b[48..56].try_into().unwrap()),
            HeadPair {
                data: b[56..168].try_into().unwrap(),
                index: b[168..280].try_into().unwrap(),
            },
            b[280..312].try_into().unwrap(),
        )?;
        if x.encode() != b {
            return Err(Error::InvalidEncoding);
        }
        Ok(x)
    }
    pub fn application(&self) -> Result<Application> {
        // Same immutable hash as Application::new; no G/q/C_open/C_cmd and no fixed point.
        let database = self.source.data[8..24].try_into().unwrap();
        let mut h = Sha256::new();
        h.update(b"DCS/PRIVATE-LIFECYCLE-JOURNAL/v1/N4-T2-D2/owner-authorized/no-live-grant");
        h.update(b"Pending-before-genesis/stableActive/registry200/enrollment64/Request2716/intent-before-Copen-Ccmd");
        h.update(self.network);
        h.update(database);
        h.update(self.source_id.to_le_bytes());
        h.update(self.control_id.to_le_bytes());
        h.update(self.source.data);
        h.update(self.source.index);
        h.update(self.key);
        h.update(wire::contract_digest());
        Ok(Application {
            network: self.network,
            database,
            source_id: self.source_id,
            control_id: self.control_id,
            source: self.source,
            key: self.key,
            id: h.finalize().into(),
        })
    }
}
