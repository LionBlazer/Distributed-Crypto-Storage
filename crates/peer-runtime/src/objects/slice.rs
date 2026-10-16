//! Private bounded-slice decoding, not object or custody admission.
use super::RawBundle;
use serde::Deserialize;
use std::io;

// Deserialize borrows every payload directly from one immutable input. The
// ordinary public RawBundle Deserialize implementation remains unchanged.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBundleSlice<'a> {
    version: u16,
    nonce: [u8; 32],
    #[serde(borrow)]
    data_head: &'a [u8],
    #[serde(borrow)]
    index_head: &'a [u8],
    #[serde(borrow)]
    data: &'a [u8],
    #[serde(borrow)]
    index: &'a [u8],
}
impl<'a> RawBundleSlice<'a> {
    fn parse(bytes: &'a [u8]) -> io::Result<Self> {
        // Only slice decode may call this path. SliceReader checks each announced
        // length against remaining bytes before lending a payload; reject_trailing
        // checks the end before any owned payload is allocated.
        crate::wire::decode(bytes)
    }
    fn into_owned(self) -> RawBundle {
        RawBundle {
            version: self.version,
            nonce: self.nonce,
            data_head: self.data_head.to_vec(),
            index_head: self.index_head.to_vec(),
            data: self.data.to_vec(),
            index: self.index.to_vec(),
        }
    }
}
pub(crate) fn decode(bytes: &[u8]) -> io::Result<RawBundle> {
    Ok(RawBundleSlice::parse(bytes)?.into_owned())
}

#[cfg(test)]
mod tests;
