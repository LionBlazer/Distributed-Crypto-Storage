//! New two-proof bounded pair. No Key proof, Formation, Journal Body or SQL admission.
use super::{Expected, Statement};
use crate::{
    backend::{Backend, Config, Error as BackendError, profile_digest},
    opening::{
        proof_codec::{self, Topology},
        statement as source,
    },
    primitive::{Kind, PublicStatement},
};
use p3_air::BaseAir;
use p3_uni_stark::Proof;
use registry200_proof::coefficient_encoding::Role;
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Error {
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
pub(super) const HEADER: usize = 184;
pub(super) const MAX_FRAME: usize = 32 * 1024 * 1024;
pub(super) const MAX_SOURCE: usize = 20 * 1024 * 1024;
pub(super) const MAX_CHILD: usize = 12_578_091;
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
            Kind::SourceCoefficientEncoding => (2000, 752),
            Kind::PrivateMaskCoefficientEncoding => (1288, 772),
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
pub(super) struct Frame<'a> {
    pub encoded: [u8; 32],
    pub source: &'a [u8],
    pub child: &'a [u8],
}
fn header(e: &Expected, encoded: [u8; 32], a: usize, b: usize) -> Result<Vec<u8>, Error> {
    let _ = source::decode_digest(encoded)?;
    if a == 0
        || a > MAX_SOURCE
        || b == 0
        || b > MAX_CHILD
        || HEADER
            .checked_add(a)
            .and_then(|x| x.checked_add(b))
            .is_none_or(|x| x > MAX_FRAME)
    {
        return Err(Error::ResourceLimit);
    }
    let kind = if e.role() == Role::SourceAllOriginal {
        Kind::SourceCoefficientEncoding
    } else {
        Kind::PrivateMaskCoefficientEncoding
    };
    let mut out = Vec::with_capacity(HEADER);
    out.extend(b"DCSCEP01");
    out.extend([e.role().tag(), 0, 0, 0, 0, 0, 0, 0]);
    out.extend(profile_digest(Kind::CanonicalIndexOpening));
    out.extend(profile_digest(kind));
    // Full context8 is SHA256 represented as8u32: serialize32, never truncate4Gold.
    for v in e.encoding_context() {
        use p3_field::PrimeField64;
        let x = u32::try_from(v.as_canonical_u64()).map_err(|_| Error::Shape)?;
        out.extend(x.to_le_bytes());
    }
    out.extend(source::encode_digest(e.command()));
    out.extend(encoded);
    out.extend((a as u32).to_le_bytes());
    out.extend((b as u32).to_le_bytes());
    assert_eq!(out.len(), HEADER);
    Ok(out)
}
impl<'a> Frame<'a> {
    pub fn parse(e: &Expected, bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_FRAME {
            return Err(Error::ResourceLimit);
        }
        if bytes.len() < HEADER {
            return Err(Error::Encoding);
        }
        let a = u32::from_le_bytes(bytes[176..180].try_into().unwrap()) as usize;
        let b = u32::from_le_bytes(bytes[180..184].try_into().unwrap()) as usize;
        let encoded = bytes[144..176].try_into().unwrap();
        if bytes[..HEADER] != header(e, encoded, a, b)? {
            return Err(Error::Shape);
        }
        let mid = HEADER.checked_add(a).ok_or(Error::ResourceLimit)?;
        if mid.checked_add(b) != Some(bytes.len()) {
            return Err(Error::Encoding);
        }
        Ok(Self {
            encoded,
            source: &bytes[HEADER..mid],
            child: &bytes[mid..],
        })
    }
}
pub(super) fn join(e: &Expected, encoded: [u8; 32], a: &[u8], b: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = header(e, encoded, a.len(), b.len())?;
    out.extend(a);
    out.extend(b);
    Ok(out)
}
pub(super) fn source_bytes(s: &source::Statement, p: &Proof<Config>) -> Result<Vec<u8>, Error> {
    proof_codec::serialize(p, &Checked::new(s)?.shape, MAX_SOURCE).map_err(Into::into)
}
pub(super) fn encode_with_source(
    e: &Expected,
    s: &Statement,
    a: &[u8],
    p: &Proof<Config>,
) -> Result<Vec<u8>, Error> {
    s.require_expected(e)?;
    let b = proof_codec::serialize(p, &Checked::new(s)?.shape, MAX_CHILD)?;
    join(e, source::encode_digest(s.encoded), a, &b)
}
pub(super) fn decode_and_verify(e: &Expected, bytes: &[u8]) -> Result<Statement, Error> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let f = Frame::parse(e, bytes)?;
        let s = Statement {
            expected: e.clone(),
            encoded: source::decode_digest(f.encoded)?,
        };
        {
            let c = Checked::new(e.source_claim())?;
            let p = proof_codec::decode(f.source, &c.shape, SEQUENCE, SOURCE_SLOTS)?;
            c.backend.verify(e.source_claim(), &p)?;
        }
        let c = Checked::new(&s)?;
        let p = proof_codec::decode(f.child, &c.shape, SEQUENCE, CHILD_SLOTS)?;
        c.backend.verify(&s, &p)?;
        Ok(s)
    }))
    .map_err(|_| Error::Verification)?
}
