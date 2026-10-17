//! Consumer-owned policy over the shared bounded Postcard decoder.
use crate::{Error, MAX_PROOF_DECODE_ELEMENTS, MAX_PROOF_SEQUENCE_ELEMENTS};
use serde::Deserialize;

pub(crate) fn take_from_bytes<'de, T: Deserialize<'de>>(
    bytes: &'de [u8],
) -> Result<(T, &'de [u8]), Error> {
    bounded_postcard::take_from_bytes(
        bytes,
        bounded_postcard::Limits {
            max_sequence_elements: MAX_PROOF_SEQUENCE_ELEMENTS,
            max_total_elements: MAX_PROOF_DECODE_ELEMENTS,
        },
    )
    .map_err(|error| match error {
        bounded_postcard::Error::ResourceLimit => Error::ProofResourceLimit,
        bounded_postcard::Error::Encoding => Error::ProofEncoding,
    })
}
