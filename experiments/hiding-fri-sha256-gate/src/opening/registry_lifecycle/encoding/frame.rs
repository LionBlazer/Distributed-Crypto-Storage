//! Distinct bounded THREE-component encoding evidence, never a Journal Body.
use super::super::{CompositeProof, statement as lifecycle};
use super::statement::{Expected, Statement};
use crate::backend::{Config, Error as BackendError, analyze, profile_digest};
use crate::opening::{
    proof_codec::{self, Topology},
    statement::decode_digest,
};
use crate::primitive::{Kind, PublicStatement};
use p3_air::BaseAir;
use p3_uni_stark::Proof;
#[derive(Debug, PartialEq, Eq)]
pub(in crate::opening) enum Error {
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
pub(super) const MAGIC: [u8; 8] = *b"DCSLFE01";
pub(super) const HEADER: usize = 212;
pub(super) const MAX_FRAME: usize = 48 * 1024 * 1024;
pub(super) const MAX_SOURCE: usize = 20 * 1024 * 1024;
pub(super) const MAX_PARENT: usize = 12_578_091;
pub(super) const MAX_ENCODING: usize = 12 * 1024 * 1024;
const SEQUENCE: usize = 16384;
const SLOTS: [usize; 3] = [24 * 1024 * 1024, 16 * 1024 * 1024, 16 * 1024 * 1024];
pub(super) struct Frame<'a> {
    pub roots: &'a [u8],
    pub parts: [&'a [u8]; 3],
}
fn topology(s: &impl PublicStatement) -> Result<Topology, Error> {
    let dimensions = match s.kind() {
        Kind::CanonicalIndexOpening => (11521, 691),
        Kind::RegistryLifecycle => (6741, 116),
        Kind::RegistryLifecycleEncoding => (super::air::WIDTH, 136),
        _ => return Err(Error::Shape),
    };
    let air = s.air();
    let (_, report) = analyze(&air)?;
    let report = report.require_target()?;
    if (air.width(), air.num_public_values()) != dimensions
        || air.preprocessed_width() != 0
        || air.main_next_row_columns().is_empty()
        || report.degree > 5
        || !(2..=16).contains(&report.quotient_chunks)
    {
        return Err(Error::Shape);
    }
    Topology::checked(dimensions.0, report.quotient_chunks).map_err(Error::from)
}
pub(super) fn join(roots: [[u8; 32]; 3], parts: [&[u8]; 3]) -> Result<Vec<u8>, Error> {
    let caps = [MAX_SOURCE, MAX_PARENT, MAX_ENCODING];
    let mut size = HEADER;
    for (part, cap) in parts.iter().zip(caps) {
        if part.is_empty() || part.len() > cap {
            return Err(Error::ResourceLimit);
        }
        size = size.checked_add(part.len()).ok_or(Error::ResourceLimit)?;
    }
    if size > MAX_FRAME {
        return Err(Error::ResourceLimit);
    }
    let mut out = Vec::with_capacity(size);
    out.extend(MAGIC);
    for kind in [
        Kind::CanonicalIndexOpening,
        Kind::RegistryLifecycle,
        Kind::RegistryLifecycleEncoding,
    ] {
        out.extend(profile_digest(kind));
    }
    for root in roots {
        out.extend(root);
    }
    for part in parts {
        out.extend(
            u32::try_from(part.len())
                .map_err(|_| Error::ResourceLimit)?
                .to_le_bytes(),
        );
    }
    for part in parts {
        out.extend(part);
    }
    Ok(out)
}
impl<'a> Frame<'a> {
    pub(super) fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < HEADER {
            return Err(Error::Encoding);
        }
        if bytes.len() > MAX_FRAME {
            return Err(Error::ResourceLimit);
        }
        if bytes[..8] != MAGIC {
            return Err(Error::Shape);
        }
        for (i, kind) in [
            Kind::CanonicalIndexOpening,
            Kind::RegistryLifecycle,
            Kind::RegistryLifecycleEncoding,
        ]
        .into_iter()
        .enumerate()
        {
            if bytes[8 + 32 * i..40 + 32 * i] != profile_digest(kind) {
                return Err(Error::Shape);
            }
        }
        let mut pos = HEADER;
        let mut parts = [&bytes[0..0]; 3];
        for (i, cap) in [MAX_SOURCE, MAX_PARENT, MAX_ENCODING]
            .into_iter()
            .enumerate()
        {
            let len =
                u32::from_le_bytes(bytes[200 + i * 4..204 + i * 4].try_into().unwrap()) as usize;
            if len == 0 || len > cap {
                return Err(Error::ResourceLimit);
            }
            let end = pos.checked_add(len).ok_or(Error::ResourceLimit)?;
            parts[i] = bytes.get(pos..end).ok_or(Error::Encoding)?;
            pos = end;
        }
        if pos != bytes.len() {
            return Err(Error::Encoding);
        }
        Ok(Self {
            roots: &bytes[104..200],
            parts,
        })
    }
}
pub(in crate::opening) fn encode(
    e: &Expected,
    s: &Statement,
    parent: &CompositeProof,
    proof: &Proof<Config>,
) -> Result<Vec<u8>, Error> {
    s.require_expected(e)?;
    let source = proof_codec::serialize(
        parent.source.as_ref().ok_or(Error::Verification)?,
        &topology(&e.parent.source)?,
        MAX_SOURCE,
    )?;
    let life = proof_codec::serialize(&parent.child, &topology(&e.producer)?, MAX_PARENT)?;
    let encoded = proof_codec::serialize(proof, &topology(s)?, MAX_ENCODING)?;
    join(
        [
            lifecycle::encoded(e.producer.next),
            lifecycle::encoded(e.producer.result),
            lifecycle::encoded(s.encoded),
        ],
        [&source, &life, &encoded],
    )
}
pub(in crate::opening) fn decode_and_verify(
    e: &Expected,
    bytes: &[u8],
) -> Result<Statement, Error> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        e.require_contract()?;
        let frame = Frame::parse(bytes)?;
        if frame.roots[..32] != lifecycle::encoded(e.producer.next)
            || frame.roots[32..64] != lifecycle::encoded(e.producer.result)
        {
            return Err(Error::Shape);
        }
        let s = Statement::new(
            e.clone(),
            decode_digest(frame.roots[64..96].try_into().unwrap())?,
        );
        let source = proof_codec::decode(
            frame.parts[0],
            &topology(&e.parent.source)?,
            SEQUENCE,
            SLOTS[0],
        )?;
        let child =
            proof_codec::decode(frame.parts[1], &topology(&e.producer)?, SEQUENCE, SLOTS[1])?;
        let proof = proof_codec::decode(frame.parts[2], &topology(&s)?, SEQUENCE, SLOTS[2])?;
        let parent = CompositeProof {
            source: Some(source),
            child,
        };
        super::verify(e, &s, Some(&parent), &proof)?;
        Ok(s)
    }))
    .map_err(|_| Error::Verification)?
}
