//! Actual-owner BFV formation linked to full Registry200 encoding evidence; no SQL admission.
pub(in crate::opening::registry_lifecycle) mod fixture;
pub(in crate::opening) mod job;
mod statement;
#[cfg(test)]
mod tests;
use super::encoding;
use crate::backend::Error;
use bfv_ciphertext_formation::{Evidence, Prerequisites, VerifiedFormation};
use bfv_query_core::{BfvKeyAnchor, OwnerFormationJob, PublicSetup};
pub(in crate::opening) use statement::Expected;
fn verify_encoding(expected: &Expected, bytes: &[u8]) -> Result<(), Error> {
    let decoded = encoding::decode_and_verify(expected.encoding.formation_expected(), bytes)?;
    expected.require_decoded(&decoded)
}
fn prove_with_factory(
    expected: &Expected,
    encoding_bytes: &[u8],
    factory: impl FnOnce() -> Result<Evidence, Error>,
) -> Result<Evidence, Error> {
    verify_encoding(expected, encoding_bytes)?; // Actual whole Source/Lifecycle/Encoding and FULL136 BEFORE factory.
    factory()
}
pub(in crate::opening) fn prove(
    expected: &Expected,
    encoding_bytes: &[u8],
    job: &mut OwnerFormationJob<'_>,
    prerequisites: &Prerequisites<'_>,
) -> Result<Evidence, Error> {
    prove_with_factory(expected, encoding_bytes, || {
        job.prove(&expected.mathematical, prerequisites)
            .map_err(|_| Error::Verification)
    })
}
pub(in crate::opening) fn verify(
    setup: &PublicSetup,
    anchor: &BfvKeyAnchor,
    expected: &Expected,
    encoding_bytes: &[u8],
    prerequisites: &Prerequisites<'_>,
    formation_bytes: &[u8],
) -> Result<VerifiedFormation, Error> {
    verify_encoding(expected, encoding_bytes)?;
    setup
        .verify_ciphertext_formation(
            anchor,
            &expected.mathematical,
            prerequisites,
            formation_bytes,
        )
        .map_err(|_| Error::Verification)
}
pub(super) fn gate(mode: &str) -> Result<(), Error> {
    fixture::gate(mode)
}
