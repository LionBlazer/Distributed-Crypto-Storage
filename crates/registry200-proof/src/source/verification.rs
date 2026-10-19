//! Shared actual canonical Source verification; no cached success or decoded proof escapes.
use super::Statement;
use crate::{
    admission::CanonicalSource,
    fixed::Backend,
    wire::{Error, MAX_SEQUENCE_ELEMENTS, SOURCE_SLOTS, frame::MAX_SOURCE_BYTES},
};
use bfv_hiding_stark::codec;

/// The original Source topology, field count and byte limits. All allocations and
/// the backend die at this boundary, also on error or an SDK panic.
pub(crate) fn verify(statement: &Statement, bytes: &[u8]) -> Result<(), Error> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if bytes.is_empty() || bytes.len() > MAX_SOURCE_BYTES {
            return Err(Error::ResourceLimit);
        }
        let checked = CanonicalSource::checked_claim(statement)?;
        let backend = Backend::source(checked.claim())?;
        let proof = codec::decode(bytes, &backend.shape, MAX_SEQUENCE_ELEMENTS, SOURCE_SLOTS)?;
        backend.verify(&proof)?;
        Ok(())
    }))
    .map_err(|_| Error::Verification)?
}
