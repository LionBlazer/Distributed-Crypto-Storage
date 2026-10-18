//! Independent full public bindings. The low-level statements are claims, not authority.
use super::{Role, profile_digest};
use crate::{admission::CanonicalSource, source};
use bfv_hiding_stark::{Error, Val};
use p3_field::PrimeField64;
use sha2::{Digest, Sha256};
#[derive(Clone)]
pub struct BfvBinding {
    full_setup: [u8; 32],
    key: bfv_key_transform::Statement,
}
impl BfvBinding {
    /// Full setup origin and actual Key proof are separate caller prerequisites.
    pub fn new(full_setup: [u8; 32], key: bfv_key_transform::Statement) -> Self {
        Self { full_setup, key }
    }
    pub fn full_setup(&self) -> [u8; 32] {
        self.full_setup
    }
    pub fn key(&self) -> &bfv_key_transform::Statement {
        &self.key
    }
}
#[derive(Clone)]
pub struct Expected {
    role: Role,
    source: CanonicalSource,
    bfv: BfvBinding,
    sql_identity: [u8; 32],
    public_nonce: [u8; 32],
    command: [Val; 4],
}
fn feed(h: &mut Sha256, values: impl IntoIterator<Item = Val>) {
    for v in values {
        h.update(v.as_canonical_u64().to_le_bytes());
    }
}
impl Expected {
    pub fn source(source: &CanonicalSource, bfv: BfvBinding) -> Result<Self, Error> {
        let source = CanonicalSource::checked_claim(source.claim())?;
        if bfv.key.public_values().len() != 33
            || bfv.key.expected.descriptor.database.as_slice() != &source.claim().heads[0][8..24]
        {
            return Err(Error::Shape);
        }
        Ok(Self {
            role: Role::SourceAllOriginal,
            source,
            bfv,
            sql_identity: [0; 32],
            public_nonce: [0; 32],
            command: [Val::default(); 4],
        })
    }
    pub fn private_mask(
        source: &CanonicalSource,
        bfv: BfvBinding,
        sql_identity: [u8; 32],
        public_nonce: [u8; 32],
        command: [u8; 32],
    ) -> Result<Self, Error> {
        let mut e = Self::source(source, bfv)?;
        e.role = Role::PrivateMask;
        e.sql_identity = sql_identity;
        e.public_nonce = public_nonce;
        e.command = source::statement::decode_digest(command)?;
        Ok(e)
    }
    pub fn role(&self) -> Role {
        self.role
    }
    pub fn source_claim(&self) -> &source::Statement {
        self.source.claim()
    }
    pub fn bfv(&self) -> &BfvBinding {
        &self.bfv
    }
    pub fn sql_identity(&self) -> [u8; 32] {
        self.sql_identity
    }
    pub fn public_nonce(&self) -> [u8; 32] {
        self.public_nonce
    }
    pub fn command(&self) -> [Val; 4] {
        self.command
    }
    /// Acyclic command context. Contains neither Cmask nor Cw nor proof bytes.
    pub fn base_context(&self) -> [Val; 8] {
        let mut h = Sha256::new();
        h.update(b"DCS/COEFFICIENT-ENCODING/base-context/v1");
        h.update(profile_digest(self.role));
        feed(&mut h, self.source_claim().values());
        h.update(self.bfv.full_setup);
        feed(&mut h, self.bfv.key.public_values());
        for bytes in self
            .source_claim()
            .heads
            .iter()
            .map(|b| b.as_slice())
            .chain(self.source_claim().packets.iter().map(|b| b.as_slice()))
        {
            h.update((bytes.len() as u64).to_le_bytes());
            h.update(bytes);
        }
        if self.role == Role::PrivateMask {
            h.update(self.sql_identity);
            h.update(self.public_nonce);
        }
        source::statement::words(&<[u8; 32]>::from(h.finalize()))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
    /// Formation-compatible context excludes its own Cw. Query may bind Cmask here.
    pub fn encoding_context(&self) -> [Val; 8] {
        let mut h = Sha256::new();
        h.update(b"DCS/COEFFICIENT-ENCODING/full8192W-context/v1");
        h.update(profile_digest(self.role));
        feed(&mut h, self.base_context());
        if self.role == Role::PrivateMask {
            feed(&mut h, self.command);
        }
        source::statement::words(&<[u8; 32]>::from(h.finalize()))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
    pub fn require_same(&self, other: &Self) -> Result<(), Error> {
        if self.role != other.role
            || self.source_claim().values() != other.source_claim().values()
            || self.source_claim().heads != other.source_claim().heads
            || self.source_claim().packets != other.source_claim().packets
            || self.bfv.full_setup != other.bfv.full_setup
            || self.bfv.key.public_values() != other.bfv.key.public_values()
            || self.sql_identity != other.sql_identity
            || self.public_nonce != other.public_nonce
            || self.command != other.command
        {
            return Err(Error::Shape);
        }
        Ok(())
    }
}
#[derive(Clone)]
pub struct Statement {
    pub expected: Expected,
    pub encoded: [Val; 4],
}
impl Statement {
    pub fn values(&self) -> Vec<Val> {
        let e = &self.expected;
        let mut out = source::statement::words(&profile_digest(e.role))
            .chain(e.source_claim().values())
            .chain(source::statement::words(&e.bfv.full_setup))
            .chain(e.bfv.key.public_values())
            .chain(e.encoding_context())
            .chain(self.encoded)
            .collect::<Vec<_>>();
        if e.role == Role::PrivateMask {
            out.extend(source::statement::words(&e.sql_identity));
            out.extend(source::statement::words(&e.public_nonce));
            out.extend(e.command);
        }
        assert_eq!(out.len(), e.role.public_values());
        out
    }
    /// Complete public producer label, including Cw; not a verification or admission token.
    pub fn producer_identity(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"DCS/COEFFICIENT-ENCODING/complete-producer/v1");
        feed(&mut h, self.values());
        h.finalize().into()
    }
    pub fn require_expected(&self, e: &Expected) -> Result<(), Error> {
        self.expected.require_same(e)
    }
}
