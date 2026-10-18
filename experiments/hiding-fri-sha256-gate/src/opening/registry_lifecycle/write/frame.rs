//! Distinct bounded Source+WriteImage evidence. It is not an accepted Journal Body.
use super::{
    Pair,
    statement::{Expected, Statement},
};
use crate::{
    backend::{Backend, Error as BackendError, profile_digest},
    opening::{
        proof_codec::{self, Topology},
        statement as source,
    },
    primitive::{Kind, PublicStatement},
};
use p3_air::BaseAir;
#[derive(Debug, PartialEq, Eq)]
pub(in crate::opening::registry_lifecycle) enum Error {
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
impl From<proof_codec::Error> for Error {
    fn from(e: proof_codec::Error) -> Self {
        match e {
            proof_codec::Error::Encoding => Self::Encoding,
            proof_codec::Error::ResourceLimit => Self::ResourceLimit,
            proof_codec::Error::Shape => Self::Shape,
        }
    }
}
pub(in crate::opening::registry_lifecycle) const MAGIC: [u8; 8] = *b"DCSRWI01";
pub(in crate::opening::registry_lifecycle) const HEADER: usize = 120;
pub(in crate::opening::registry_lifecycle) const MAX_FRAME: usize = 32 * 1024 * 1024;
pub(in crate::opening::registry_lifecycle) const MAX_SOURCE: usize = 20 * 1024 * 1024;
pub(in crate::opening::registry_lifecycle) const MAX_CHILD: usize = 12_578_091;
const SEQUENCE: usize = 16_384;
const SOURCE_SLOTS: usize = 24 * 1024 * 1024;
const CHILD_SLOTS: usize = 16 * 1024 * 1024;
struct Checked {
    backend: Backend,
    shape: Topology,
}
impl Checked {
    fn new(s: &impl PublicStatement) -> Result<Self, Error> {
        let wanted = match s.kind() {
            Kind::CanonicalIndexOpening => (11521, 691),
            Kind::RegistryWriteImage => (registry200_proof::write::layout::WIDTH, 128),
            _ => return Err(Error::Shape),
        };
        let backend = Backend::new(s)?;
        let (_, air) = backend.checked_public_air();
        if (air.width(), air.num_public_values()) != wanted
            || air.preprocessed_width() != 0
            || air.main_next_row_columns().is_empty()
            || backend.report.degree > 5
            || !(2..=16).contains(&backend.report.quotient_chunks)
        {
            return Err(Error::Shape);
        }
        let shape = Topology::checked(wanted.0, backend.report.quotient_chunks)?;
        Ok(Self { backend, shape })
    }
}
pub(in crate::opening::registry_lifecycle) struct Frame<'a> {
    pub image: [u8; 32],
    pub source: &'a [u8],
    pub child: &'a [u8],
}
pub(in crate::opening::registry_lifecycle) fn join(
    image: [u8; 32],
    source: &[u8],
    child: &[u8],
) -> Result<Vec<u8>, Error> {
    let _ = source::decode_digest(image)?;
    if source.is_empty() || source.len() > MAX_SOURCE || child.is_empty() || child.len() > MAX_CHILD
    {
        return Err(Error::ResourceLimit);
    }
    let size = HEADER
        .checked_add(source.len())
        .and_then(|n| n.checked_add(child.len()))
        .ok_or(Error::ResourceLimit)?;
    if size > MAX_FRAME {
        return Err(Error::ResourceLimit);
    }
    let mut out = Vec::with_capacity(size);
    out.extend(MAGIC);
    out.extend([0xA1, 0, 0, 0, 0, 0, 0, 0]);
    out.extend(profile_digest(Kind::CanonicalIndexOpening));
    out.extend(profile_digest(Kind::RegistryWriteImage));
    out.extend(
        u32::try_from(source.len())
            .map_err(|_| Error::ResourceLimit)?
            .to_le_bytes(),
    );
    out.extend(
        u32::try_from(child.len())
            .map_err(|_| Error::ResourceLimit)?
            .to_le_bytes(),
    );
    out.extend(image);
    out.extend(source);
    out.extend(child);
    Ok(out)
}
impl<'a> Frame<'a> {
    pub(in crate::opening::registry_lifecycle) fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_FRAME {
            return Err(Error::ResourceLimit);
        }
        if bytes.len() < HEADER {
            return Err(Error::Encoding);
        }
        if bytes[..8] != MAGIC
            || bytes[8..16] != [0xA1, 0, 0, 0, 0, 0, 0, 0]
            || bytes[16..48] != profile_digest(Kind::CanonicalIndexOpening)
            || bytes[48..80] != profile_digest(Kind::RegistryWriteImage)
        {
            return Err(Error::Shape);
        }
        let a = u32::from_le_bytes(bytes[80..84].try_into().unwrap()) as usize;
        let b = u32::from_le_bytes(bytes[84..88].try_into().unwrap()) as usize;
        if a == 0 || a > MAX_SOURCE || b == 0 || b > MAX_CHILD {
            return Err(Error::ResourceLimit);
        }
        let mid = HEADER.checked_add(a).ok_or(Error::ResourceLimit)?;
        let end = mid.checked_add(b).ok_or(Error::ResourceLimit)?;
        if end != bytes.len() {
            return Err(Error::Encoding);
        }
        let image = bytes[88..120].try_into().unwrap();
        let _ = source::decode_digest(image)?;
        Ok(Self {
            image,
            source: &bytes[HEADER..mid],
            child: &bytes[mid..end],
        })
    }
}
pub(in crate::opening::registry_lifecycle) fn encode(
    e: &Expected,
    s: &Statement,
    p: &Pair,
) -> Result<Vec<u8>, Error> {
    s.require_expected(e)?;
    let source = proof_codec::serialize(&p.source, &Checked::new(e.source())?.shape, MAX_SOURCE)?;
    let child = proof_codec::serialize(&p.child, &Checked::new(s)?.shape, MAX_CHILD)?;
    join(source::encode_digest(s.image), &source, &child)
}
pub(in crate::opening::registry_lifecycle) fn decode_and_verify(
    e: &Expected,
    bytes: &[u8],
) -> Result<Statement, Error> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let frame = Frame::parse(bytes)?;
        let s = Statement {
            expected: e.clone(),
            image: source::decode_digest(frame.image)?,
        };
        {
            let checked = Checked::new(e.source())?;
            let proof = proof_codec::decode(frame.source, &checked.shape, SEQUENCE, SOURCE_SLOTS)?;
            checked.backend.verify(e.source(), &proof)?;
        }
        let checked = Checked::new(&s)?;
        let proof = proof_codec::decode(frame.child, &checked.shape, SEQUENCE, CHILD_SLOTS)?;
        checked.backend.verify(&s, &proof)?;
        Ok(s)
    }))
    .map_err(|_| Error::Verification)?
}
