//! Exact borrowed DCSCEP01 grammar. Parsed metadata is not verified proof authority.
use super::{Error, Expected};
use crate::{
    coefficient_encoding::profile_digest,
    source::{
        self,
        statement::{decode_digest, encode_digest},
    },
};

pub const HEADER: usize = 184;
pub const MAX_FRAME: usize = 32 * 1024 * 1024;
pub const MAX_SOURCE: usize = 20 * 1024 * 1024;
pub const MAX_CHILD: usize = 12_578_091;

/// Borrowed, canonically framed proof bytes. Parsing never verifies either proof.
pub struct BorrowedFrame<'a> {
    encoded: [u8; 32],
    source: &'a [u8],
    child: &'a [u8],
}
fn header(e: &Expected, encoded: [u8; 32], a: usize, b: usize) -> Result<Vec<u8>, Error> {
    let _ = decode_digest(encoded)?;
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
    let mut out = Vec::with_capacity(HEADER);
    out.extend(b"DCSCEP01");
    out.extend([e.role().tag(), 0, 0, 0, 0, 0, 0, 0]);
    out.extend(source::profile_digest(source::Relation::CanonicalIndex));
    out.extend(profile_digest(e.role()));
    // Full context8 is SHA256 represented as8u32, never truncated to four Golds.
    for v in e.encoding_context() {
        use p3_field::PrimeField64;
        let x = u32::try_from(v.as_canonical_u64()).map_err(|_| Error::Shape)?;
        out.extend(x.to_le_bytes());
    }
    out.extend(encode_digest(e.command()));
    out.extend(encoded);
    out.extend((a as u32).to_le_bytes());
    out.extend((b as u32).to_le_bytes());
    assert_eq!(out.len(), HEADER);
    Ok(out)
}
impl<'a> BorrowedFrame<'a> {
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
    pub fn encoded(&self) -> [u8; 32] {
        self.encoded
    }
    pub fn source(&self) -> &'a [u8] {
        self.source
    }
    pub fn child(&self) -> &'a [u8] {
        self.child
    }
}
pub(super) fn join(e: &Expected, encoded: [u8; 32], a: &[u8], b: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = header(e, encoded, a.len(), b.len())?;
    out.extend(a);
    out.extend(b);
    Ok(out)
}
