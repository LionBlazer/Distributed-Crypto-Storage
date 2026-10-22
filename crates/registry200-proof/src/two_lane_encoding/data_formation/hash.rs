//! Distinct SHA-suite immutable DATA composition; native mathematics only.
//! The opaque Owner preparation never exposes its key or private MAIN.
use super::{Expected, data, gold};
use crate::{source, two_lane_encoding};
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub enum Error {
    Binding,
    Resource,
    Source(source::hash::Error),
    Encoding(two_lane_encoding::wire::Error),
    Formation(gold::Error),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "hash DATA composition rejected: {self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = core::result::Result<T, Error>;

pub fn profile_digest() -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"DCS/research/hash-Source-Role3-DATA/v1/no-live-admission\0");
    hash.update(super::dense_profile_digest());
    hash.update(source::hash::profile_digest());
    hash.update(two_lane_encoding::hash::profile_digest());
    hash.update(data::hash::profile_digest());
    hash.finalize().into()
}

/// Borrowed unverified SHA frames; old-suite bytes are never a fallback.
pub struct Prerequisites<'a> {
    state: &'a [u8],
    child: &'a [u8],
}
impl<'a> Prerequisites<'a> {
    pub fn checked(state: &'a [u8], child: &'a [u8]) -> Result<Self> {
        if state.is_empty()
            || state.len() > two_lane_encoding::wire::MAX_SOURCE
            || child.is_empty()
            || child.len() > two_lane_encoding::hash::MAX_EVIDENCE_BYTES
        {
            return Err(Error::Resource);
        }
        Ok(Self { state, child })
    }
    fn verify(&self, expected: &Expected) -> Result<()> {
        let source = expected
            .source
            .expected
            .version_source()
            .map_err(|_| Error::Binding)?;
        source::hash::verify(source, self.state).map_err(Error::Source)?;
        // The independent full Statement includes Cw, all Key29 and Source images.
        two_lane_encoding::hash::verify(&expected.source, self.child).map_err(Error::Encoding)
    }
}

/// Consumes the same protected owner preparation only after fresh Source/Role3
/// native checks. A caller-supplied flag/configuration cannot replace either.
pub fn prove_prepared(
    expected: &Expected,
    request: &data::Request,
    prerequisites: Prerequisites<'_>,
    prepared: data::Prepared,
) -> Result<Vec<u8>> {
    expected
        .require_request(request)
        .map_err(|_| Error::Binding)?;
    prerequisites.verify(expected)?;
    data::hash::prove(&expected.core, prepared).map_err(Error::Formation)
}

/// Move-only retained immutable DATA theorem of this candidate suite only.
/// No proof, key, SDK state, freshness, old-suite token or query verdict survives.
/// ```compile_fail
/// use registry200_proof::two_lane_encoding::data_formation::hash::CheckedData;
/// fn forge() { let _ = CheckedData {}; }
/// ```
/// ```compile_fail
/// use registry200_proof::two_lane_encoding::data_formation::hash::CheckedData;
/// fn duplicate(value: &CheckedData) -> CheckedData { value.clone() }
/// ```
pub struct CheckedData {
    expected: Expected,
}
impl CheckedData {
    pub fn expected(&self) -> &Expected {
        &self.expected
    }
    pub fn require_expected(&self, expected: &Expected) -> Result<()> {
        self.expected
            .require_same(expected)
            .map_err(|_| Error::Binding)
    }
}

/// Fresh actual Source + Role3 + dense DATA native checks on every cold call.
pub fn verify(
    expected: &Expected,
    request: &data::Request,
    prerequisites: Prerequisites<'_>,
    bytes: &[u8],
) -> Result<CheckedData> {
    if bytes.is_empty() || bytes.len() > data::hash::MAX_EVIDENCE_BYTES {
        return Err(Error::Resource);
    }
    expected
        .require_request(request)
        .map_err(|_| Error::Binding)?;
    prerequisites.verify(expected)?;
    data::hash::verify(&expected.core, bytes).map_err(Error::Formation)?;
    Ok(CheckedData {
        expected: expected.clone(),
    })
}
