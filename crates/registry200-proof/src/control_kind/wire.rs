//! Detached bounded link, with original Source-first pair verification on every path.
use super::{Expected, TAG, circuit::Witness, profile_digest};
use crate::{BackendError, fixed::Backend};
use bfv_hiding_stark::{Config, codec};
use p3_uni_stark::Proof;

pub const HEADER: usize = 120;
pub const MAX_PROOF_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_FRAME: usize = HEADER + MAX_PROOF_BYTES;
pub const MAX_SEQUENCE_ELEMENTS: usize = 16_384;
pub const MAX_TOTAL_ELEMENTS: usize = 16 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"DCSPCL01";
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
        write!(f, "Control kind link: {self:?}")
    }
}
impl std::error::Error for Error {}
/// The complete existing DCSLFPW1 Transition pair, including original Source proof.
pub struct Prerequisites<'a> {
    pub lifecycle: &'a [u8],
}
fn header(e: &Expected, n: usize) -> Result<Vec<u8>, Error> {
    if n == 0 || n > MAX_PROOF_BYTES {
        return Err(Error::ResourceLimit);
    }
    let mut out = Vec::with_capacity(HEADER);
    out.extend_from_slice(MAGIC);
    out.push(TAG);
    out.extend_from_slice(&[0; 7]);
    out.extend_from_slice(&profile_digest());
    out.extend_from_slice(&e.identity());
    out.extend_from_slice(&(n as u32).to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    Ok(out)
}
/// Pure canonical frame preflight. It verifies no mathematical claim.
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
/// Serialization is not verification, a Control lane decision or an admission token.
pub fn encode(e: &Expected, p: &Proof<Config>) -> Result<Vec<u8>, Error> {
    let backend = Backend::control_kind(e)?;
    let bytes = codec::serialize(p, &backend.shape, MAX_PROOF_BYTES)?;
    let mut out = header(e, bytes.len())?;
    out.extend(bytes);
    Ok(out)
}
fn prerequisites(e: &Expected, p: &Prerequisites<'_>) -> Result<(), Error> {
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
pub fn prove(e: &Expected, w: &Witness, p: &Prerequisites<'_>) -> Result<Evidence, Error> {
    w.require_expected(e)?;
    prerequisites(e, p)?;
    let backend = Backend::control_kind(e)?;
    let proof = backend.prove(w.trace(e)?)?;
    backend.verify(&proof)?;
    Ok(Evidence {
        expected: e.clone(),
        bytes: encode(e, &proof)?,
    })
}
/// Mathematical non-Acquire linkage only. No Journal/finality/SQL permission.
pub struct VerifiedLink {
    expected: Expected,
}
impl VerifiedLink {
    pub fn expected(&self) -> &Expected {
        &self.expected
    }
}
pub fn verify(e: &Expected, p: &Prerequisites<'_>, bytes: &[u8]) -> Result<VerifiedLink, Error> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let bytes = payload(e, bytes)?;
        prerequisites(e, p)?;
        let backend = Backend::control_kind(e)?;
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
