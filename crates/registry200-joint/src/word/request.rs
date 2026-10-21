//! Independent unverified intent pins, with canonical complete native field values.
use super::{Application, Error, Evidence, Hash, Result, contract_digest};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use registry200_proof::{Val, registry_progress::word::Claims};
use sha2::{Digest, Sha256};
pub const REQUEST_BYTES: usize = 368;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    Bootstrap,
    Control,
}
impl Lane {
    pub(super) fn tag(self) -> u8 {
        match self {
            Self::Bootstrap => 0,
            Self::Control => 1,
        }
    }
    pub(super) fn decode(n: u8) -> Result<Self> {
        match n {
            0 => Ok(Self::Bootstrap),
            1 => Ok(Self::Control),
            _ => Err(Error::InvalidEncoding),
        }
    }
}
#[derive(Clone)]
pub struct Request {
    lane: Lane,
    app: Hash,
    parent: Hash,
    nonce: Hash,
    enrollment: [Val; 4],
    claims: Claims,
}
impl Request {
    pub fn bootstrap(
        a: &Application,
        parent: Hash,
        nonce: Hash,
        enrollment: [Val; 4],
        next: [Val; 4],
    ) -> Self {
        Self {
            lane: Lane::Bootstrap,
            app: a.id(),
            parent,
            nonce,
            enrollment,
            claims: Claims {
                old: [Val::ZERO; 4],
                command: [Val::ZERO; 4],
                statement: [Val::ZERO; 4],
                next,
                result: [Val::ZERO; 4],
                blind_sql: [Val::ZERO; 8],
            },
        }
    }
    pub fn control(
        a: &Application,
        parent: Hash,
        nonce: Hash,
        enrollment: [Val; 4],
        claims: Claims,
    ) -> Result<Self> {
        let r = Self {
            lane: Lane::Control,
            app: a.id(),
            parent,
            nonce,
            enrollment,
            claims,
        };
        r.require_shape()?;
        Ok(r)
    }
    pub fn lane(&self) -> Lane {
        self.lane
    }
    pub fn parent(&self) -> Hash {
        self.parent
    }
    pub fn enrollment(&self) -> [Val; 4] {
        self.enrollment
    }
    pub fn claims(&self) -> Claims {
        self.claims
    }
    fn require_shape(&self) -> Result<()> {
        let c = self.claims;
        if c.statement != [Val::ZERO; 4]
            || self.lane == Lane::Bootstrap
                && (c.old != [Val::ZERO; 4]
                    || c.command != [Val::ZERO; 4]
                    || c.result != [Val::ZERO; 4]
                    || c.blind_sql != [Val::ZERO; 8])
        {
            return Err(Error::InvalidEncoding);
        }
        Ok(())
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(REQUEST_BYTES);
        b.extend(b"DCSWRQ01");
        b.push(self.lane.tag());
        b.extend([0; 7]);
        b.extend(self.app);
        b.extend(self.parent);
        b.extend(self.nonce);
        for v in self
            .enrollment
            .into_iter()
            .chain(self.claims.old)
            .chain(self.claims.command)
            .chain(self.claims.statement)
            .chain(self.claims.next)
            .chain(self.claims.result)
            .chain(self.claims.blind_sql)
        {
            b.extend(v.as_canonical_u64().to_le_bytes());
        }
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != REQUEST_BYTES || &b[..8] != b"DCSWRQ01" || b[9..16] != [0; 7] {
            return Err(Error::InvalidEncoding);
        }
        let mut v = [Val::ZERO; 32];
        for (v, b) in v.iter_mut().zip(b[112..].as_chunks::<8>().0) {
            let n = u64::from_le_bytes(*b);
            if n >= Val::ORDER_U64 {
                return Err(Error::InvalidEncoding);
            }
            *v = Val::from_u64(n);
        }
        let r = Self {
            lane: Lane::decode(b[8])?,
            app: b[16..48].try_into().unwrap(),
            parent: b[48..80].try_into().unwrap(),
            nonce: b[80..112].try_into().unwrap(),
            enrollment: v[..4].try_into().unwrap(),
            claims: Claims {
                old: v[4..8].try_into().unwrap(),
                command: v[8..12].try_into().unwrap(),
                statement: v[12..16].try_into().unwrap(),
                next: v[16..20].try_into().unwrap(),
                result: v[20..24].try_into().unwrap(),
                blind_sql: v[24..32].try_into().unwrap(),
            },
        };
        r.require_shape()?;
        if r.encode() != b {
            return Err(Error::InvalidEncoding);
        }
        Ok(r)
    }
    pub(super) fn require_application(&self, a: &Application) -> Result<()> {
        self.require_shape()?;
        if self.app != a.id() {
            return Err(Error::WrongDomain);
        }
        Ok(())
    }
}
/// Caller-retained intent identity only, never authentication, proof or QC status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationId(Hash);
impl OperationId {
    pub fn new(a: &Application, r: &Request, e: &[u8]) -> Result<Self> {
        r.require_application(a)?;
        Evidence::split(r.lane, e)?;
        let mut h = Sha256::new();
        h.update(b"DCS/WORD-JOURNAL/operation/v1");
        h.update(contract_digest());
        h.update(a.id());
        h.update(a.genesis());
        h.update(r.encode());
        h.update((e.len() as u64).to_le_bytes());
        h.update(Sha256::digest(e));
        Ok(Self(h.finalize().into()))
    }
    pub fn bytes(self) -> Hash {
        self.0
    }
}
