//! Stable private-control heads. No query, parent or nonce enters their encoding.
use super::{Error, Hash, Result};
use crate::backend::profile_digest;
use crate::opening::{Relation, locking::statement::encoded, statement as source};
use crate::primitive::Kind;
use sha2::{Digest, Sha256};
use version_journal::{Genesis, HeadPair, ShardState};

const MAGIC: &[u8; 8] = b"DCSPCH01";
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
        if initial.relation != Relation::CanonicalIndex || source_id == control_id {
            return Err(Error::WrongDomain);
        }
        let database = initial.heads[0][8..24].try_into().unwrap();
        if initial.heads[0][8..40] != initial.heads[1][8..40] {
            return Err(Error::WrongDomain);
        }
        let source = HeadPair {
            data: initial.heads[0],
            index: initial.heads[1],
        };
        let key = encoded(initial.key_commitment);
        let mut h = Sha256::new();
        h.update(b"DCS/PRIVATE-JOURNAL/N4-T2/v1/owner-authorized/no-live-grant");
        h.update(b"Pending-before-genesis/Active-stable/enroll64/registry112/wire-DCSLKPW1/intent-before-Copen");
        h.update(network);
        h.update(database);
        h.update(source_id.to_le_bytes());
        h.update(control_id.to_le_bytes());
        h.update(source.data);
        h.update(source.index);
        h.update(key);
        for kind in [
            Kind::CanonicalIndexOpening,
            Kind::RegistryBootstrap,
            Kind::LockingSelection,
        ] {
            h.update(profile_digest(kind));
        }
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
    pub(super) fn require_genesis(&self, genesis: &Genesis) -> Result<()> {
        genesis.validate()?;
        if genesis.network_id != self.network
            || genesis.database != self.database
            || genesis.application_commitment != self.id
            || genesis.initial_shards != self.initial_shards()
        {
            return Err(Error::WrongDomain);
        }
        Ok(())
    }
    pub(super) fn require_source(&self, statement: &source::Statement) -> Result<()> {
        if statement.relation != Relation::CanonicalIndex
            || statement.heads != [self.source.data, self.source.index]
            || encoded(statement.key_commitment) != self.key
        {
            return Err(Error::WrongDomain);
        }
        Ok(())
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
        let phase = heads.data[25];
        let registry: Hash = heads.data[64..96].try_into().unwrap();
        let enrollment: Hash = heads.index[64..96].try_into().unwrap();
        let value = match phase {
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
