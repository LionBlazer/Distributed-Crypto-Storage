//! Per-role consumer policy around the shared bounded Postcard decoder.
use crate::{Error, MAX_PROOF_SEQUENCE_ELEMENTS, max_proof_decode_elements};
use bfv_relinearization_circuit::Role;
use serde::Deserialize;
pub(crate) fn take_from_bytes<'de, T: Deserialize<'de>>(
    role: Role,
    bytes: &'de [u8],
) -> Result<(T, &'de [u8]), Error> {
    bounded_postcard::take_from_bytes(
        bytes,
        bounded_postcard::Limits {
            max_sequence_elements: MAX_PROOF_SEQUENCE_ELEMENTS,
            max_total_elements: max_proof_decode_elements(role),
        },
    )
    .map_err(|error| match error {
        bounded_postcard::Error::Encoding => Error::ProofEncoding,
        bounded_postcard::Error::ResourceLimit => Error::ProofResourceLimit,
    })
}
