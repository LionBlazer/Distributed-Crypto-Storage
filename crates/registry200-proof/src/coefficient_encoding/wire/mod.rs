//! Bounded DCSCEP01 Source/encoding proof pairs. Application admission is separate.
mod frame;
use super::statement::{Expected, Statement};
use crate::{admission::CanonicalSource, fixed::Backend, source};
use bfv_hiding_stark::{Config, Error as BackendError, codec};
pub use frame::{BorrowedFrame, HEADER, MAX_CHILD, MAX_FRAME, MAX_SOURCE};
use p3_uni_stark::Proof;

const SEQUENCE: usize = 16_384;
const CHILD_SLOTS: usize = 16 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Encoding,
    ResourceLimit,
    Shape,
    Verification,
    Proof(BackendError),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Encoding => "Noncanonical coefficient proof encoding",
            Self::ResourceLimit => "Coefficient proof resource limit",
            Self::Shape => "Coefficient proof shape mismatch",
            Self::Verification => "Coefficient proof verification failed",
            Self::Proof(_) => "Coefficient proof backend rejected the relation",
        })
    }
}
impl std::error::Error for Error {}
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
impl From<crate::wire::Error> for Error {
    fn from(e: crate::wire::Error) -> Self {
        match e {
            crate::wire::Error::Encoding => Self::Encoding,
            crate::wire::Error::ResourceLimit => Self::ResourceLimit,
            crate::wire::Error::Profile | crate::wire::Error::Shape => Self::Shape,
            crate::wire::Error::Verification => Self::Verification,
            crate::wire::Error::Proof(e) => Self::Proof(e),
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
        source::verification::verify(e.source_claim(), f.source())?;
        let backend = Backend::encoding(&s)?;
        let proof = codec::decode(f.child(), &backend.shape, SEQUENCE, CHILD_SLOTS)?;
        backend.verify(&proof)?;
        Ok(VerifiedEncoding { statement: s })
    }))
    .map_err(|_| Error::Verification)?
}
