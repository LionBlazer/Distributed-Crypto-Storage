//! Distinct Registry200 transport envelope. No request codec or Journal admission.
use super::Error;
use crate::{lifecycle, source};
pub const MAX_SOURCE_BYTES: usize = 20 * 1024 * 1024;
pub const MAX_REQUEST_BYTES: usize = 4096;
pub const BODY_OVERHEAD: usize = 117 + MAX_REQUEST_BYTES + 456;
pub const MAX_BUNDLE_BYTES: usize = version_journal::MAX_BODY_BYTES - BODY_OVERHEAD;
const MAX_HEADER: usize = 88 + 64;
pub const MAX_CHILD_BYTES: usize = MAX_BUNDLE_BYTES - MAX_SOURCE_BYTES - MAX_HEADER;
pub const COMMON_HEADER: usize = 88;
const MAGIC: &[u8; 8] = b"DCSLFPW1";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Bootstrap,
    Transition,
}
impl Role {
    pub fn tag(self) -> u8 {
        match self {
            Self::Bootstrap => 1,
            Self::Transition => 2,
        }
    }
    pub fn is_bootstrap(self) -> bool {
        self == Self::Bootstrap
    }
    pub fn output_count(self) -> usize {
        match self {
            Self::Bootstrap => 1,
            Self::Transition => 2,
        }
    }
}
/// One update and a nonempty request no larger than4096 bytes are the explicit
/// transport reservation. This does not validate the meaning of that update.
pub fn body_length(request: usize, frame: usize) -> Result<usize, Error> {
    if request == 0 || request > MAX_REQUEST_BYTES || frame > MAX_BUNDLE_BYTES {
        return Err(Error::ResourceLimit);
    }
    let length = 117usize
        .checked_add(request)
        .and_then(|n| n.checked_add(456))
        .and_then(|n| n.checked_add(frame))
        .ok_or(Error::ResourceLimit)?;
    if length > version_journal::MAX_BODY_BYTES {
        return Err(Error::ResourceLimit);
    }
    Ok(length)
}
pub struct Frame<'a> {
    pub outputs: &'a [u8],
    pub source: &'a [u8],
    pub child: &'a [u8],
}
impl<'a> Frame<'a> {
    pub fn parse(role: Role, bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_BUNDLE_BYTES {
            return Err(Error::ResourceLimit);
        }
        let header = bytes.get(..COMMON_HEADER).ok_or(Error::Encoding)?;
        if &header[..8] != MAGIC
            || header[8] != role.tag()
            || header[9..16] != [0; 7]
            || header[16..48] != source::profile_digest(source::Relation::CanonicalIndex)
            || header[48..80] != lifecycle::profile_digest(role.is_bootstrap())
        {
            return Err(Error::Profile);
        }
        let source =
            u32::from_le_bytes(header[80..84].try_into().map_err(|_| Error::Encoding)?) as usize;
        let child =
            u32::from_le_bytes(header[84..88].try_into().map_err(|_| Error::Encoding)?) as usize;
        if source == 0 || child == 0 {
            return Err(Error::Encoding);
        }
        if source > MAX_SOURCE_BYTES || child > MAX_CHILD_BYTES {
            return Err(Error::ResourceLimit);
        }
        let output_end = COMMON_HEADER + 32 * role.output_count();
        let source_end = output_end.checked_add(source).ok_or(Error::ResourceLimit)?;
        let end = source_end.checked_add(child).ok_or(Error::ResourceLimit)?;
        if end != bytes.len() {
            return Err(Error::Encoding);
        }
        Ok(Self {
            outputs: bytes
                .get(COMMON_HEADER..output_end)
                .ok_or(Error::Encoding)?,
            source: bytes.get(output_end..source_end).ok_or(Error::Encoding)?,
            child: bytes.get(source_end..end).ok_or(Error::Encoding)?,
        })
    }
}
pub fn join(role: Role, roots: &[[u8; 32]], source: &[u8], child: &[u8]) -> Result<Vec<u8>, Error> {
    if roots.len() != role.output_count() || source.is_empty() || child.is_empty() {
        return Err(Error::Shape);
    }
    if source.len() > MAX_SOURCE_BYTES || child.len() > MAX_CHILD_BYTES {
        return Err(Error::ResourceLimit);
    }
    let length = COMMON_HEADER
        .checked_add(32 * roots.len())
        .and_then(|n| n.checked_add(source.len()))
        .and_then(|n| n.checked_add(child.len()))
        .ok_or(Error::ResourceLimit)?;
    if length > MAX_BUNDLE_BYTES {
        return Err(Error::ResourceLimit);
    }
    let mut bytes = Vec::with_capacity(length);
    bytes.extend_from_slice(MAGIC);
    bytes.push(role.tag());
    bytes.extend_from_slice(&[0; 7]);
    bytes.extend_from_slice(&source::profile_digest(source::Relation::CanonicalIndex));
    bytes.extend_from_slice(&lifecycle::profile_digest(role.is_bootstrap()));
    bytes.extend_from_slice(&(source.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(child.len() as u32).to_le_bytes());
    for root in roots {
        bytes.extend_from_slice(root);
    }
    bytes.extend_from_slice(source);
    bytes.extend_from_slice(child);
    Ok(bytes)
}

/// Fingerprint input comes from this policy, rather than a consumer copy of its limits.
pub fn contract(h: &mut sha2::Sha256) {
    use sha2::Digest;
    h.update(MAGIC);
    for role in [Role::Bootstrap, Role::Transition] {
        h.update([role.tag()]);
        h.update((role.output_count() as u64).to_le_bytes());
        h.update(lifecycle::profile_digest(role.is_bootstrap()));
    }
    for n in [
        COMMON_HEADER,
        MAX_HEADER,
        MAX_SOURCE_BYTES,
        MAX_REQUEST_BYTES,
        BODY_OVERHEAD,
        MAX_BUNDLE_BYTES,
        MAX_CHILD_BYTES,
    ] {
        h.update((n as u64).to_le_bytes());
    }
}
