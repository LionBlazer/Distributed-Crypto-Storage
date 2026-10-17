//! Independently pinned application and stable Registry200 control heads.
use super::{Error, Hash, Result};
use crate::opening::registry_lifecycle::statement::encoded;
use crate::opening::{Relation, registry_lifecycle::wire, statement as source};
use sha2::{Digest, Sha256};
use version_journal::{Genesis, HeadPair, ShardState};

const MAGIC: &[u8; 8] = b"DCSLCH01";
#[derive(Clone)]
pub(super) struct Application {
    pub(super) network: Hash,
    pub(super) database: [u8; 16],
    pub(super) source_id: u64,
    pub(super) control_id: u64,
    pub(super) source: HeadPair,
    pub(super) key: Hash,
    id: Hash,
}
impl Application {
    pub(super) fn new(
        network: Hash,
        source_id: u64,
        control_id: u64,
        initial: &source::Statement,
    ) -> Result<Self> {
        if initial.relation != Relation::CanonicalIndex
            || source_id == control_id
            || initial.heads[0][8..40] != initial.heads[1][8..40]
        {
            return Err(Error::WrongDomain);
        }
        let database = initial.heads[0][8..24].try_into().unwrap();
        let source = HeadPair {
            data: initial.heads[0],
            index: initial.heads[1],
        };
        let key = encoded(initial.key_commitment);
        let mut h = Sha256::new();
        h.update(b"DCS/PRIVATE-LIFECYCLE-JOURNAL/v1/N4-T2-D2/owner-authorized/no-live-grant");
        h.update(b"Pending-before-genesis/stableActive/registry200/enrollment64/Request2716/intent-before-Copen-Ccmd");
        h.update(network);
        h.update(database);
        h.update(source_id.to_le_bytes());
        h.update(control_id.to_le_bytes());
        h.update(source.data);
        h.update(source.index);
        h.update(key);
        h.update(wire::contract_digest());
        Ok(Self {
            network,
            database,
            source_id,
            control_id,
            source,
            key,
            id: h.finalize().into(),
        })
    }
    pub(super) fn id(&self) -> Hash {
        self.id
    }
    pub(super) fn initial_shards(&self) -> Vec<ShardState> {
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
    pub(super) fn require_genesis(&self, g: &Genesis) -> Result<()> {
        g.validate()?;
        if g.network_id != self.network
            || g.database != self.database
            || g.application_commitment != self.id
            || g.initial_shards != self.initial_shards()
        {
            return Err(Error::WrongDomain);
        }
        Ok(())
    }
    pub(super) fn require_source(&self, s: &source::Statement) -> Result<()> {
        if s.relation != Relation::CanonicalIndex
            || s.heads != [self.source.data, self.source.index]
            || encoded(s.key_commitment) != self.key
        {
            return Err(Error::WrongDomain);
        }
        Ok(())
    }
    pub(super) fn control(&self, shards: &[ShardState]) -> Result<HeadPair> {
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
pub(super) enum Control {
    Pending,
    Active { enrollment: Hash, registry: Hash },
}
impl Control {
    pub(super) fn heads(self, app: &Application) -> HeadPair {
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
    pub(super) fn decode(app: &Application, heads: HeadPair) -> Result<Self> {
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
