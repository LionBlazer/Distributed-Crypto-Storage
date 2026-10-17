//! Canonical bounded transport of actual private-control SDK proofs.
//! Expected source/control authority is supplied by the caller, never this frame.
mod shape;
#[cfg(test)]
pub(in crate::opening) mod tests;

use crate::backend::{Config, Error as BackendError, profile_digest};
use crate::primitive::Kind;
use p3_uni_stark::Proof;
pub(super) use shape::Shape;

pub(super) const MAX_SOURCE_BYTES: usize = 20 * 1024 * 1024;
pub(super) const MAX_CHILD_BYTES: usize = 5 * 1024 * 1024;
pub(super) const MAX_BUNDLE_BYTES: usize = 26 * 1024 * 1024;
const MAX_SEQUENCE_ELEMENTS: usize = 16384;
const SOURCE_SLOTS: usize = 24 * 1024 * 1024;
const CHILD_SLOTS: usize = 8 * 1024 * 1024;
const HEADER: usize = 88;
const MAGIC: &[u8; 8] = b"DCSLKPW1";

#[derive(Debug, PartialEq, Eq)]
pub(in crate::opening) enum Error {
    Encoding,
    ResourceLimit,
    Profile,
    Shape,
    Proof(BackendError),
    Verification,
}
impl From<BackendError> for Error {
    fn from(value: BackendError) -> Self {
        Self::Proof(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Role {
    Bootstrap,
    Locking,
}
impl Role {
    fn tag(self) -> u8 {
        match self {
            Self::Bootstrap => 1,
            Self::Locking => 2,
        }
    }
    fn kind(self) -> Kind {
        match self {
            Self::Bootstrap => Kind::RegistryBootstrap,
            Self::Locking => Kind::LockingSelection,
        }
    }
    fn outputs(self) -> usize {
        match self {
            Self::Bootstrap => 1,
            Self::Locking => 3,
        }
    }
}

/// Borrowed component boundaries are checked before any SDK deserialization.
pub(super) struct Frame<'a> {
    pub(super) outputs: &'a [u8],
    pub(super) source: &'a [u8],
    pub(super) child: &'a [u8],
}
impl<'a> Frame<'a> {
    pub(super) fn parse(role: Role, bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_BUNDLE_BYTES {
            return Err(Error::ResourceLimit);
        }
        let prefix = bytes.get(..HEADER).ok_or(Error::Encoding)?;
        if &prefix[..8] != MAGIC
            || prefix[8] != role.tag()
            || prefix[9..16] != [0; 7]
            || prefix[16..48] != profile_digest(Kind::CanonicalIndexOpening)
            || prefix[48..80] != profile_digest(role.kind())
        {
            return Err(Error::Profile);
        }
        let source_len =
            u32::from_le_bytes(prefix[80..84].try_into().map_err(|_| Error::Encoding)?) as usize;
        let child_len =
            u32::from_le_bytes(prefix[84..88].try_into().map_err(|_| Error::Encoding)?) as usize;
        if source_len == 0 || child_len == 0 {
            return Err(Error::Encoding);
        }
        if source_len > MAX_SOURCE_BYTES || child_len > MAX_CHILD_BYTES {
            return Err(Error::ResourceLimit);
        }
        let outputs_end = HEADER + role.outputs() * 32;
        let source_end = outputs_end
            .checked_add(source_len)
            .ok_or(Error::ResourceLimit)?;
        let end = source_end
            .checked_add(child_len)
            .ok_or(Error::ResourceLimit)?;
        if end != bytes.len() {
            return Err(Error::Encoding);
        }
        Ok(Self {
            outputs: bytes.get(HEADER..outputs_end).ok_or(Error::Encoding)?,
            source: bytes.get(outputs_end..source_end).ok_or(Error::Encoding)?,
            child: bytes.get(source_end..end).ok_or(Error::Encoding)?,
        })
    }
}

fn serialize(proof: &Proof<Config>, shape: &Shape, cap: usize) -> Result<Vec<u8>, Error> {
    shape.check(proof)?;
    let bytes = postcard::to_allocvec(proof).map_err(|_| Error::Encoding)?;
    if bytes.len() > cap {
        return Err(Error::ResourceLimit);
    }
    Ok(bytes)
}

pub(super) fn encode(
    role: Role,
    outputs: &[[u8; 32]],
    source: &Proof<Config>,
    source_shape: &Shape,
    child: &Proof<Config>,
    child_shape: &Shape,
) -> Result<Vec<u8>, Error> {
    if outputs.len() != role.outputs() {
        return Err(Error::Shape);
    }
    let source = serialize(source, source_shape, MAX_SOURCE_BYTES)?;
    let child = serialize(child, child_shape, MAX_CHILD_BYTES)?;
    join(role, outputs, &source, &child)
}

fn join(role: Role, outputs: &[[u8; 32]], source: &[u8], child: &[u8]) -> Result<Vec<u8>, Error> {
    if outputs.len() != role.outputs() || source.is_empty() || child.is_empty() {
        return Err(Error::Shape);
    }
    if source.len() > MAX_SOURCE_BYTES || child.len() > MAX_CHILD_BYTES {
        return Err(Error::ResourceLimit);
    }
    let len = HEADER
        .checked_add(outputs.len() * 32)
        .and_then(|v| v.checked_add(source.len()))
        .and_then(|v| v.checked_add(child.len()))
        .ok_or(Error::ResourceLimit)?;
    if len > MAX_BUNDLE_BYTES {
        return Err(Error::ResourceLimit);
    }
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(MAGIC);
    out.push(role.tag());
    out.extend_from_slice(&[0; 7]);
    out.extend_from_slice(&profile_digest(Kind::CanonicalIndexOpening));
    out.extend_from_slice(&profile_digest(role.kind()));
    out.extend_from_slice(&(source.len() as u32).to_le_bytes());
    out.extend_from_slice(&(child.len() as u32).to_le_bytes());
    for root in outputs {
        out.extend_from_slice(root);
    }
    out.extend_from_slice(source);
    out.extend_from_slice(child);
    Ok(out)
}

fn decode(bytes: &[u8], shape: &Shape, slots: usize) -> Result<Proof<Config>, Error> {
    let (proof, trailing) = bounded_postcard::take_from_bytes::<Proof<Config>>(
        bytes,
        bounded_postcard::Limits {
            max_sequence_elements: MAX_SEQUENCE_ELEMENTS,
            max_total_elements: slots,
        },
    )
    .map_err(|e| match e {
        bounded_postcard::Error::ResourceLimit => Error::ResourceLimit,
        bounded_postcard::Error::Encoding => Error::Encoding,
    })?;
    if !trailing.is_empty() {
        return Err(Error::Encoding);
    }
    shape.check(&proof)?;
    if postcard::to_allocvec(&proof).map_err(|_| Error::Encoding)? != bytes {
        return Err(Error::Encoding);
    }
    Ok(proof)
}

pub(super) fn decode_pair(
    frame: &Frame<'_>,
    source: &Shape,
    child: &Shape,
) -> Result<(Proof<Config>, Proof<Config>), Error> {
    // Independent component budgets sum to 32 Mi container slots; ALL nested
    // tuples/arrays/sequences in a component share its budget before Vec reserve.
    Ok((
        decode(frame.source, source, SOURCE_SLOTS)?,
        decode(frame.child, child, CHILD_SLOTS)?,
    ))
}

pub(super) fn guarded<T>(f: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).map_err(|_| Error::Verification)?
}

/// PUBLIC NONSECRET CLI report. The outer resource observer owns process timing/RAM.
pub(super) fn measured(
    role: &str,
    frame: &[u8],
    decode_and_verify: impl FnOnce() -> Result<(), Error>,
) -> Result<(), BackendError> {
    let parsed_role = match role {
        "bootstrap" => Role::Bootstrap,
        "locking" => Role::Locking,
        _ => return Err(BackendError::Shape),
    };
    let view = Frame::parse(parsed_role, frame).map_err(|_| BackendError::Verification)?;
    let started = std::time::Instant::now();
    decode_and_verify().map_err(|_| BackendError::Verification)?;
    println!(
        "{{\"stage\":\"verified_experimental_private_control_wire\",\"role\":\"{}\",\"source_proof_bytes\":{},\"child_proof_bytes\":{},\"bundle_bytes\":{},\"fresh_decode_and_verification_ms\":{},\"live_sql_grant\":false}}",
        role,
        view.source.len(),
        view.child.len(),
        frame.len(),
        started.elapsed().as_secs_f64() * 1000.0
    );
    Ok(())
}
