//! Independent complete public claims. Candidate key labels certify no key or setup.
use super::{Role, profile_digest};
use crate::{admission::CanonicalSource, source};
use bfv_hiding_stark::{Error, Val};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use sha2::{Digest, Sha256};
/// Independently supplied metadata for a FUTURE same-secret Formation relation.
/// No Key33/CsHat, raw private key, setup verification or security authority is present.
#[derive(Clone)]
pub struct KeyBinding {
    database: [u8; 16],
    key_domain: [u8; 16],
    epoch: u32,
    key_id: [u8; 32],
    coefficients: [Val; 4],
}
impl KeyBinding {
    pub fn new(
        database: [u8; 16],
        key_domain: [u8; 16],
        epoch: u32,
        key_id: [u8; 32],
        coefficients: [u8; 32],
    ) -> Result<Self, Error> {
        Ok(Self {
            database,
            key_domain,
            epoch,
            key_id,
            coefficients: source::statement::decode_digest(coefficients)?,
        })
    }
    pub fn values(&self) -> Vec<Val> {
        let values = source::statement::words(&self.database)
            .chain(source::statement::words(&self.key_domain))
            .chain([Val::from_u32(self.epoch)])
            .chain(source::statement::words(
                &super::candidate_parameter_digest(),
            ))
            .chain(source::statement::words(&self.key_id))
            .chain(self.coefficients)
            .collect::<Vec<_>>();
        assert_eq!(values.len(), 29);
        values
    }
}
#[derive(Clone)]
pub struct Expected {
    role: Role,
    source: CanonicalSource,
    key: KeyBinding,
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
    pub fn source(source: &CanonicalSource, key: KeyBinding) -> Result<Self, Error> {
        let source = CanonicalSource::checked_claim(source.claim())?;
        if key.database.as_slice() != &source.claim().heads[0][8..24] {
            return Err(Error::Shape);
        }
        Ok(Self {
            role: Role::SourceAllOriginal,
            source,
            key,
            sql_identity: [0; 32],
            public_nonce: [0; 32],
            command: [Val::default(); 4],
        })
    }
    pub fn private_mask(
        source: &CanonicalSource,
        key: KeyBinding,
        sql_identity: [u8; 32],
        public_nonce: [u8; 32],
        command: [u8; 32],
    ) -> Result<Self, Error> {
        let mut e = Self::source(source, key)?;
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
    pub fn key_binding(&self) -> &KeyBinding {
        &self.key
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
        h.update(b"DCS/TWO-LANE-ENCODING/base-context/v1");
        h.update(profile_digest(self.role));
        feed(&mut h, self.source_claim().values());
        feed(&mut h, self.key.values());
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
    /// NEW encoding context excludes its own Cw. This is not the old Formation ABI.
    pub fn encoding_context(&self) -> [Val; 8] {
        let mut h = Sha256::new();
        h.update(b"DCS/TWO-LANE-ENCODING/full4096W-context/v1");
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
            || self.key.values() != other.key.values()
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
            .chain(e.key.values())
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
        h.update(b"DCS/TWO-LANE-ENCODING/complete-producer/v1");
        feed(&mut h, self.values());
        h.finalize().into()
    }
    pub fn require_expected(&self, e: &Expected) -> Result<(), Error> {
        self.expected.require_same(e)
    }
}
