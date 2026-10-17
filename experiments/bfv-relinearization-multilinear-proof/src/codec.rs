//! Fresh caller-owned bounded Postcard budget, before canonical SDK decoding.
use crate::{Error, MAX_PROOF_DECODE_ELEMENTS, MAX_PROOF_SEQUENCE_ELEMENTS};
use serde::Deserialize;
pub(crate) fn decode<'de, T: Deserialize<'de>>(bytes: &'de [u8]) -> Result<T, Error> {
    let (value, trailing) = bounded_postcard::take_from_bytes(
        bytes,
        bounded_postcard::Limits {
            max_sequence_elements: MAX_PROOF_SEQUENCE_ELEMENTS,
            max_total_elements: MAX_PROOF_DECODE_ELEMENTS,
        },
    )
    .map_err(|e| match e {
        bounded_postcard::Error::ResourceLimit => Error::ProofResourceLimit,
        bounded_postcard::Error::Encoding => Error::ProofEncoding,
    })?;
    if !trailing.is_empty() {
        return Err(Error::TrailingProofBytes);
    }
    Ok(value)
}
