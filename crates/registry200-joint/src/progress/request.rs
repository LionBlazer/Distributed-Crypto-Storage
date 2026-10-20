//! New outer request and unverified operation identity. Old intent q is unchanged.
use super::{Application, Error, Manifest, Result, contract_digest};
use registry200_journal::{Operation, Request as InnerRequest, intent_query};
use sha2::{Digest, Sha256};
const MAGIC: &[u8; 8] = b"DCSPRQ02";
pub const REQUEST_BYTES: usize = 48 + registry200_journal::REQUEST_BYTES;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    Bootstrap,
    Control,
    Predicate,
}
impl Lane {
    pub(super) fn tag(self) -> u8 {
        match self {
            Self::Bootstrap => 0,
            Self::Control => 1,
            Self::Predicate => 2,
        }
    }
    pub(super) fn decode(tag: u8) -> Result<Self> {
        match tag {
            0 => Ok(Self::Bootstrap),
            1 => Ok(Self::Control),
            2 => Ok(Self::Predicate),
            _ => Err(Error::Encoding),
        }
    }
}
pub struct Request {
    lane: Lane,
    application: [u8; 32],
    inner: InnerRequest,
}
impl Request {
    pub fn new(a: &Application, lane: Lane, inner: InnerRequest) -> Result<Self> {
        let x = Self {
            lane,
            application: a.id(),
            inner,
        };
        x.require_application(a)?;
        let _ = x.encode()?;
        Ok(x)
    }
    pub fn lane(&self) -> Lane {
        self.lane
    }
    pub fn inner(&self) -> &InnerRequest {
        &self.inner
    }
    fn require_lane(&self) -> Result<()> {
        if (self.inner.operation == Operation::Bootstrap) != (self.lane == Lane::Bootstrap) {
            return Err(Error::Domain);
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.require_lane()?;
        let mut b = Vec::with_capacity(REQUEST_BYTES);
        b.extend_from_slice(MAGIC);
        b.push(self.lane.tag());
        b.extend_from_slice(&[0; 7]);
        b.extend_from_slice(&self.application);
        b.extend(self.inner.encode()?);
        Ok(b)
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != REQUEST_BYTES || &b[..8] != MAGIC || b[9..16] != [0; 7] {
            return Err(Error::Encoding);
        }
        let x = Self {
            lane: Lane::decode(b[8])?,
            application: b[16..48].try_into().unwrap(),
            inner: InnerRequest::decode(&b[48..])?,
        };
        x.require_lane()?;
        if x.encode()?.as_slice() != b {
            return Err(Error::Encoding);
        }
        Ok(x)
    }
    pub(super) fn require_application(&self, a: &Application) -> Result<()> {
        self.require_lane()?;
        let r = &self.inner;
        if self.application != a.id()
            || r.application != a.source_spec().id()
            || r.genesis != a.genesis()
            || r.query
                != intent_query(
                    a.source_spec(),
                    a.genesis(),
                    r.parent,
                    r.nonce,
                    r.enrollment,
                    r.operation,
                )
        {
            return Err(Error::Domain);
        }
        Ok(())
    }
}
/// Canonical UNVERIFIED association metadata. It authenticates neither an owner
/// nor proofs, Header, QC, finality, or the current head. Own expectations must
/// come from the caller's independently retained original Request+Manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationId([u8; 32]);
impl OperationId {
    pub fn new(a: &Application, r: &Request, m: &Manifest) -> Result<Self> {
        r.require_application(a)?;
        if r.lane() != m.lane() {
            return Err(Error::Domain);
        }
        let request = r.encode()?;
        let manifest = m.encode();
        let mut h = Sha256::new();
        h.update(b"DCS/REGISTRY-PROGRESS-JOINT/operation/v2");
        h.update(contract_digest());
        h.update(a.id());
        h.update(a.genesis());
        h.update((request.len() as u64).to_le_bytes());
        h.update(request);
        h.update((manifest.len() as u64).to_le_bytes());
        h.update(manifest);
        Ok(Self(h.finalize().into()))
    }
    pub fn bytes(self) -> [u8; 32] {
        self.0
    }
}
