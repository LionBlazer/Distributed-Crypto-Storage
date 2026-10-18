//! Bounded DCSCEP01 Source/encoding proof pairs. Application admission is separate.
mod frame;
use super::statement::{Expected, Statement};
use crate::{admission::CanonicalSource, fixed::Backend, source};
use bfv_hiding_stark::{Config, Error as BackendError, codec};
pub use frame::{BorrowedFrame, HEADER, MAX_CHILD, MAX_FRAME, MAX_SOURCE};
use p3_uni_stark::Proof;

const SEQUENCE: usize = 16_384;
const SOURCE_SLOTS: usize = 24 * 1024 * 1024;
const CHILD_SLOTS: usize = 16 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Encoding,
    ResourceLimit,
    Shape,
    Verification,
    Proof(BackendError),
}
impl From<BackendError> for Error {
    fn from(e: BackendError) -> Self {
        Self::Proof(e)
    }
}
impl From<codec::Error> for Error {
    fn from(e: codec::Error) -> Self {
        match e {
            codec::Error::Encoding => Self::Encoding,
            codec::Error::ResourceLimit => Self::ResourceLimit,
            codec::Error::Shape => Self::Shape,
        }
    }
}

/// A complete verified mathematical statement, including Cw. It retains no proofs,
/// backend, private witness or keys and grants no SQL, freshness or Key authority.
pub struct VerifiedEncoding {
    statement: Statement,
}
impl VerifiedEncoding {
    pub fn statement(&self) -> &Statement {
        &self.statement
    }
}

/// Canonical serialization for producers; serialization alone does not verify a proof.
pub fn encode_source(s: &source::Statement, p: &Proof<Config>) -> Result<Vec<u8>, Error> {
    let checked = CanonicalSource::checked_claim(s)?;
    codec::serialize(p, &Backend::source(checked.claim())?.shape, MAX_SOURCE).map_err(Into::into)
}

/// Frames a child under its complete Expected. Neither input proof is verified here.
pub fn encode_with_source(
    e: &Expected,
    s: &Statement,
    source: &[u8],
    p: &Proof<Config>,
) -> Result<Vec<u8>, Error> {
    s.require_expected(e)?;
    let child = codec::serialize(p, &Backend::encoding(s)?.shape, MAX_CHILD)?;
    frame::join(
        e,
        source::statement::encode_digest(s.encoded),
        source,
        &child,
    )
}

/// Verifies the actual canonical Source proof before constructing or decoding the
/// encoding verifier. Both proofs and backends are dropped before returning.
/// Each relation keeps its original individual security floor; composition is separate.
pub fn verify(e: &Expected, bytes: &[u8]) -> Result<VerifiedEncoding, Error> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let f = BorrowedFrame::parse(e, bytes)?;
        let s = Statement {
            expected: e.clone(),
            encoded: source::statement::decode_digest(f.encoded())?,
        };
        verify_source(e, f.source())?;
        let backend = Backend::encoding(&s)?;
        let proof = codec::decode(f.child(), &backend.shape, SEQUENCE, CHILD_SLOTS)?;
        backend.verify(&proof)?;
        Ok(VerifiedEncoding { statement: s })
    }))
    .map_err(|_| Error::Verification)?
}

// Shared actual verification, never a cached Boolean/receipt. All decoded Source
// allocations and its backend die at this function boundary, including on error.
pub(super) fn verify_source(e: &Expected, bytes: &[u8]) -> Result<(), Error> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if bytes.is_empty() || bytes.len() > MAX_SOURCE {
            return Err(Error::ResourceLimit);
        }
        let backend = Backend::source(e.source_claim())?;
        let proof = codec::decode(bytes, &backend.shape, SEQUENCE, SOURCE_SLOTS)?;
        backend.verify(&proof)?;
        Ok(())
    }))
    .map_err(|_| Error::Verification)?
}
