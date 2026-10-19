//! Owner-signed outer request; the old inner preproof intent is unchanged.
use crate::{Application, Error, Result};
use registry200_journal::{Operation, Request as InnerRequest, intent_query};
use version_journal::Hash;
const MAGIC: &[u8; 8] = b"DCSJRQ01";
pub const REQUEST_BYTES: usize = 48 + registry200_journal::REQUEST_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    Bootstrap,
    Control,
    Acquire,
}
impl Lane {
    pub(crate) fn tag(self) -> u8 {
        match self {
            Self::Bootstrap => 0,
            Self::Control => 1,
            Self::Acquire => 2,
        }
    }
    pub(crate) fn decode(tag: u8) -> Result<Self> {
        match tag {
            0 => Ok(Self::Bootstrap),
            1 => Ok(Self::Control),
            2 => Ok(Self::Acquire),
            _ => Err(Error::Encoding),
        }
    }
}
pub struct Request {
    lane: Lane,
    application: Hash,
    inner: InnerRequest,
}
impl Request {
    /// Pure canonical request construction. This neither verifies a proof nor
    /// authorizes a mutation. The actual Journal authenticates the complete body.
    pub fn new(application: &Application, lane: Lane, inner: InnerRequest) -> Result<Self> {
        let x = Self {
            lane,
            application: application.id(),
            inner,
        };
        x.require_application(application)?;
        let _ = x.encode()?;
        Ok(x)
    }
    pub fn lane(&self) -> Lane {
        self.lane
    }
    pub fn inner(&self) -> &InnerRequest {
        &self.inner
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
        if x.encode()? != b {
            return Err(Error::Encoding);
        }
        Ok(x)
    }
    fn require_lane(&self) -> Result<()> {
        let bootstrap = self.inner.operation == Operation::Bootstrap;
        if bootstrap != (self.lane == Lane::Bootstrap) {
            return Err(Error::Domain);
        }
        Ok(())
    }
    pub(crate) fn require_application(&self, a: &Application) -> Result<()> {
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
