//! Independent mathematical expectations. No current-head, writer or SQL admission token.
use crate::{admission::CanonicalSource, lifecycle, source};
use bfv_hiding_stark::{Error, Val};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::default_goldilocks_poseidon2_12;
use p3_symmetric::Permutation;
pub const CONTEXT: usize = 116;
pub const PUBLIC_VALUES: usize = 128;
pub const COMMAND_FIELDS: usize = 160;
pub const IMAGE_FIELDS: usize = 192;
pub const COMMAND_DOMAIN: [u8; 16] = *b"DCS/WRITECMD/v1!";
pub const IMAGE_DOMAIN: [u8; 16] = *b"DCS/WRITEIMG/v1!";
/// Independently supplied public parent labels. Construction does not validate Journal history.
#[derive(Clone)]
pub struct Parent {
    pub genesis: [u8; 32],
    pub application: [u8; 32],
    pub block: [u8; 32],
    pub enrollment: [u8; 32],
    pub registry: [u8; 32],
}
#[derive(Clone)]
pub struct Expected {
    source: CanonicalSource,
    parent: Parent,
    sql_identity: [u8; 32],
    registry: [Val; 4],
    enrollment: [Val; 4],
    command: [Val; 4],
}
impl Expected {
    pub fn checked(
        source: &CanonicalSource,
        parent: Parent,
        sql_identity: [u8; 32],
        command: [u8; 32],
    ) -> Result<Self, Error> {
        Ok(Self {
            source: CanonicalSource::checked_claim(source.claim())?,
            registry: source::statement::decode_digest(parent.registry)?,
            enrollment: source::statement::decode_digest(parent.enrollment)?,
            command: source::statement::decode_digest(command)?,
            parent,
            sql_identity,
        })
    }
    pub fn source(&self) -> &source::Statement {
        self.source.claim()
    }
    pub fn parent(&self) -> &Parent {
        &self.parent
    }
    pub fn sql_identity(&self) -> [u8; 32] {
        self.sql_identity
    }
    pub fn registry(&self) -> [Val; 4] {
        self.registry
    }
    pub fn enrollment(&self) -> [Val; 4] {
        self.enrollment
    }
    pub fn command(&self) -> [Val; 4] {
        self.command
    }
    pub fn context(&self) -> Vec<Val> {
        let s = self.source();
        let out = source::statement::words(&super::profile_digest())
            .chain(source::statement::words(&s.request))
            .chain(s.heads.iter().flat_map(|h| source::statement::words(h)))
            .chain(s.key_commitment)
            .chain(s.open_commitment)
            .chain(source::statement::words(&self.parent.genesis))
            .chain(source::statement::words(&self.parent.block))
            .chain(self.enrollment)
            .chain(source::statement::words(&self.parent.application))
            .chain(source::statement::words(&self.sql_identity))
            .collect::<Vec<_>>();
        assert_eq!(out.len(), CONTEXT);
        out
    }
    pub fn lifecycle_anchor(&self) -> Result<lifecycle::statement::Expected, Error> {
        lifecycle::statement::Expected::bootstrap(
            self.source(),
            self.parent.genesis,
            self.parent.block,
            self.parent.enrollment,
        )
    }
    pub fn require_same(&self, other: &Self) -> Result<(), Error> {
        let a = self.source();
        let b = other.source();
        if self.context() != other.context()
            || self.registry != other.registry
            || self.command != other.command
            || a.relation != b.relation
            || a.packets != b.packets
        {
            return Err(Error::Shape);
        }
        Ok(())
    }
}
/// Mutable low-level output claim. A real proof is still mandatory.
#[derive(Clone)]
pub struct Statement {
    pub expected: Expected,
    pub image: [Val; 4],
}
impl Statement {
    pub fn values(&self) -> Vec<Val> {
        self.expected
            .context()
            .into_iter()
            .chain(self.expected.registry)
            .chain(self.expected.command)
            .chain(self.image)
            .collect()
    }
    pub fn require_expected(&self, e: &Expected) -> Result<(), Error> {
        self.expected.require_same(e)
    }
}
fn sponge(fields: &[Val]) -> [Val; 4] {
    let p = default_goldilocks_poseidon2_12();
    let mut state = [Val::ZERO; 12];
    for block in fields.as_chunks::<8>().0 {
        state[..8].copy_from_slice(block);
        p.permute_mut(&mut state);
    }
    state[..4].try_into().unwrap()
}
/// Exact new command stream; never the existing seven-operation Command160.
pub fn command_digest(fields: &[Val; COMMAND_FIELDS]) -> [Val; 4] {
    sponge(fields)
}
/// Complete ordered logical image; never a CSTORE, AEAD, index or BFV output root.
pub fn image_digest(fields: &[Val; IMAGE_FIELDS]) -> [Val; 4] {
    sponge(fields)
}
