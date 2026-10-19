//! Detached bounded evidence. No SignedBody reservation, SQL admission or cached prerequisites.
use super::{Expected, TAG, circuit::Witness, profile_digest};
use crate::{BackendError, coefficient_encoding, fixed::Backend, source};
use bfv_hiding_stark::{Config, codec};
use p3_uni_stark::Proof;

pub const HEADER: usize = 120;
pub const MAX_PROOF_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_FRAME: usize = HEADER + MAX_PROOF_BYTES;
pub const MAX_SEQUENCE_ELEMENTS: usize = 16_384;
pub const MAX_TOTAL_ELEMENTS: usize = 16 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"DCSPAL01";

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Encoding,
    ResourceLimit,
    Shape,
    Verification,
    Proof(BackendError),
    Prerequisite,
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
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Predicate Acquire link: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Existing separate canonical Source/Query and Source/Lifecycle proof pairs.
/// Their Source bytes must agree exactly. No bytes are copied or receipt accepted.
pub struct Prerequisites<'a> {
    pub query: &'a [u8],
    pub lifecycle: &'a [u8],
}

fn header(e: &Expected, length: usize) -> Result<Vec<u8>, Error> {
    if length == 0 || length > MAX_PROOF_BYTES {
        return Err(Error::ResourceLimit);
    }
    let mut out = Vec::with_capacity(HEADER);
    out.extend_from_slice(MAGIC);
    out.push(TAG);
    out.extend_from_slice(&[0; 7]);
    out.extend_from_slice(&profile_digest());
    out.extend_from_slice(&e.identity());
    out.extend_from_slice(&(length as u32).to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    Ok(out)
}
/// Pure canonical preflight, not proof verification or authority.
pub fn payload<'a>(e: &Expected, bytes: &'a [u8]) -> Result<&'a [u8], Error> {
    if bytes.len() > MAX_FRAME {
        return Err(Error::ResourceLimit);
    }
    if bytes.len() < HEADER {
        return Err(Error::Encoding);
    }
    let n = u32::from_le_bytes(bytes[112..116].try_into().unwrap()) as usize;
    if bytes[..HEADER] != header(e, n)? {
        return Err(Error::Shape);
    }
    if HEADER.checked_add(n) != Some(bytes.len()) {
        return Err(Error::Encoding);
    }
    Ok(&bytes[HEADER..])
}
/// Bounded serialization only. An encoded object is not a verified link;
/// `verify` always rechecks the real prerequisite pairs and this proof.
pub fn encode(e: &Expected, proof: &Proof<Config>) -> Result<Vec<u8>, Error> {
    let backend = Backend::predicate_acquire(e)?;
    let bytes = codec::serialize(proof, &backend.shape, MAX_PROOF_BYTES)?;
    let mut out = header(e, bytes.len())?;
    out.extend(bytes);
    Ok(out)
}

fn verify_prerequisites(e: &Expected, p: &Prerequisites<'_>) -> Result<(), Error> {
    {
        let q = coefficient_encoding::wire::BorrowedFrame::parse(&e.query().expected, p.query)
            .map_err(|_| Error::Prerequisite)?;
        let l = crate::wire::frame::Frame::parse(crate::wire::frame::Role::Transition, p.lifecycle)
            .map_err(|_| Error::Prerequisite)?;
        let roots: Vec<_> = source::statement::encode_digest(e.lifecycle().next)
            .into_iter()
            .chain(source::statement::encode_digest(e.lifecycle().result))
            .collect();
        if q.source() != l.source
            || q.encoded() != source::statement::encode_digest(e.query().encoded)
            || l.outputs != roots
        {
            return Err(Error::Prerequisite);
        }
    }
    {
        // Both existing frontends really reverify Source first, then drop its
        // decoded proof/backend before child allocation. No proof objects survive.
        let q = coefficient_encoding::wire::verify(&e.query().expected, p.query)
            .map_err(|_| Error::Prerequisite)?;
        if q.statement().values() != e.query().values()
            || q.statement().producer_identity() != e.query().producer_identity()
        {
            return Err(Error::Prerequisite);
        }
    }
    let l = crate::wire::verify_claim(&e.lifecycle().expected, p.lifecycle)
        .map_err(|_| Error::Prerequisite)?;
    l.require_expected(&e.lifecycle().expected)
        .map_err(|_| Error::Prerequisite)?;
    if l.values() != e.lifecycle().values() {
        return Err(Error::Prerequisite);
    }
    Ok(())
}

pub struct Evidence {
    expected: Expected,
    bytes: Vec<u8>,
}
impl Evidence {
    pub fn expected(&self) -> &Expected {
        &self.expected
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn into_parts(self) -> (Expected, Vec<u8>) {
        (self.expected, self.bytes)
    }
}
/// Source/Query/Lifecycle cryptography precedes link assessment, trace and proof.
/// Construction of Expected/Witness alone is never prerequisite evidence.
pub fn prove(e: &Expected, w: &Witness, parents: &Prerequisites<'_>) -> Result<Evidence, Error> {
    w.require_expected(e)?;
    verify_prerequisites(e, parents)?;
    let backend = Backend::predicate_acquire(e)?;
    let proof = backend.prove(w.trace(e)?)?;
    backend.verify(&proof)?;
    let bytes = encode(e, &proof)?;
    Ok(Evidence {
        expected: e.clone(),
        bytes,
    })
}

/// Complete mathematical linkage only. No key authority, input16/FHE proof,
/// signed Registry admission, finalized state or SQL/row-lock permission follows.
pub struct VerifiedLink {
    expected: Expected,
}
impl VerifiedLink {
    pub fn expected(&self) -> &Expected {
        &self.expected
    }
}
pub fn verify(
    e: &Expected,
    parents: &Prerequisites<'_>,
    bytes: &[u8],
) -> Result<VerifiedLink, Error> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let bytes = payload(e, bytes)?;
        verify_prerequisites(e, parents)?;
        let backend = Backend::predicate_acquire(e)?;
        let proof = codec::decode(
            bytes,
            &backend.shape,
            MAX_SEQUENCE_ELEMENTS,
            MAX_TOTAL_ELEMENTS,
        )?;
        backend.verify(&proof)?;
        Ok(VerifiedLink {
            expected: e.clone(),
        })
    }))
    .map_err(|_| Error::Verification)?
}
