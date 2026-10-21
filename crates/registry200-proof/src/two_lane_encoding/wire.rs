//! New bounded child frame. The original Source is a separate mandatory byte argument.
use super::{
    profile_digest,
    statement::{Expected, Statement},
};
use crate::{BackendError, fixed::Backend, source};
use bfv_hiding_stark::{Config, codec};
use p3_uni_stark::Proof;
use sha2::{Digest, Sha512};
pub const HEADER: usize = 152;
pub const MAX_CHILD: usize = 12 * 1024 * 1024;
pub const MAX_SOURCE: usize = crate::wire::frame::MAX_SOURCE_BYTES;
pub(crate) const SEQUENCE: usize = 16_384;
pub(crate) const CHILD_SLOTS: usize = 16 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"DCS2LE01";
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
        match self {
            Self::Encoding => f.write_str("Noncanonical two-lane evidence"),
            Self::ResourceLimit => f.write_str("Two-lane evidence resource limit"),
            Self::Shape => f.write_str("Two-lane evidence shape mismatch"),
            Self::Verification => f.write_str("Two-lane prerequisite verification failed"),
            Self::Proof(e) => write!(f, "Two-lane proof rejected: {e}"),
        }
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
            crate::wire::Error::ResourceLimit => Self::ResourceLimit,
            _ => Self::Verification,
        }
    }
}
fn expected_identity(e: &Expected) -> [u8; 64] {
    use p3_field::{PrimeCharacteristicRing, PrimeField64};
    let mut h = Sha512::new();
    h.update(b"DCS/two-lane-child/complete-Expected/v1/excludes-own-Cw");
    for value in (Statement {
        expected: e.clone(),
        encoded: [crate::Val::ZERO; 4],
    })
    .values()
    {
        h.update(value.as_canonical_u64().to_le_bytes());
    }
    for bytes in e
        .source_claim()
        .heads
        .iter()
        .map(|x| x.as_slice())
        .chain(e.source_claim().packets.iter().map(Vec::as_slice))
    {
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(bytes);
    }
    h.finalize().into()
}
/// Unverified bounded claim inspection only, without Source/child verification.
pub struct BorrowedFrame<'a> {
    statement: Statement,
    child: &'a [u8],
}
impl<'a> BorrowedFrame<'a> {
    pub fn parse(e: &Expected, bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < HEADER || bytes.len() > MAX_CHILD {
            return Err(Error::ResourceLimit);
        }
        if &bytes[..8] != MAGIC
            || bytes[8] != e.role().tag()
            || bytes[9..16] != [0; 7]
            || bytes[16..48] != profile_digest(e.role())
            || bytes[48..112] != expected_identity(e)
            || bytes[148..HEADER] != [0; 4]
        {
            return Err(Error::Shape);
        }
        let len = u32::from_le_bytes(bytes[144..148].try_into().unwrap()) as usize;
        if len == 0 || len > MAX_CHILD - HEADER || len.checked_add(HEADER) != Some(bytes.len()) {
            return Err(Error::Encoding);
        }
        let encoded = source::statement::decode_digest(bytes[112..144].try_into().unwrap())?;
        Ok(Self {
            statement: Statement {
                expected: e.clone(),
                encoded,
            },
            child: &bytes[HEADER..],
        })
    }
    pub fn statement(&self) -> &Statement {
        &self.statement
    }
    pub fn child(&self) -> &'a [u8] {
        self.child
    }
}
/// Actual fixed Source-first mathematical verification. No success cache or callback.
pub struct VerifiedEncoding {
    statement: Statement,
}
impl VerifiedEncoding {
    pub fn statement(&self) -> &Statement {
        &self.statement
    }
}
pub fn verify(
    e: &Expected,
    original_source: &[u8],
    bytes: &[u8],
) -> Result<VerifiedEncoding, Error> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let frame = BorrowedFrame::parse(e, bytes)?;
        source::verification::verify(e.source_claim(), original_source)?;
        let statement = frame.statement;
        let backend = Backend::two_lane_encoding(&statement)?;
        let proof = codec::decode(frame.child, &backend.shape, SEQUENCE, CHILD_SLOTS)?;
        backend.verify(&proof)?;
        Ok(VerifiedEncoding { statement })
    }))
    .map_err(|_| Error::Verification)?
}
pub(crate) fn encode(
    e: &Expected,
    statement: &Statement,
    proof: &Proof<Config>,
) -> Result<Vec<u8>, Error> {
    statement.require_expected(e)?;
    let payload = codec::serialize(
        proof,
        &Backend::two_lane_encoding(statement)?.shape,
        MAX_CHILD - HEADER,
    )?;
    if payload.is_empty() {
        return Err(Error::Encoding);
    }
    let mut bytes = Vec::with_capacity(HEADER + payload.len());
    bytes.extend_from_slice(MAGIC);
    bytes.push(e.role().tag());
    bytes.extend([0; 7]);
    bytes.extend(profile_digest(e.role()));
    bytes.extend(expected_identity(e));
    bytes.extend(source::statement::encode_digest(statement.encoded));
    bytes.extend((payload.len() as u32).to_le_bytes());
    bytes.extend([0; 4]);
    bytes.extend(payload);
    Ok(bytes)
}
