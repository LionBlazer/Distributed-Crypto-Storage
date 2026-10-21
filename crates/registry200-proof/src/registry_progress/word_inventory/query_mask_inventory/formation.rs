//! Test-only protected owner adapter and old two-proof comparison fixture.
//! Actual public associations belong to word::read::query.
use super::{Expected as MaskExpected, backend, writer};
use crate::Val;
use crate::registry_progress::word::read::query as association;
pub(super) use association::encoding_context;
use bfv_ciphertext_formation::gold::{self, data, query};

#[cfg(test)]
#[path = "formation_tests.rs"]
mod tests;

#[derive(Debug)]
pub(super) enum Error {
    Binding,
    Resource,
    Mask(backend::Error),
    Formation(gold::Error),
}
impl From<backend::Error> for Error {
    fn from(error: backend::Error) -> Self {
        Self::Mask(error)
    }
}
impl From<gold::Error> for Error {
    fn from(error: gold::Error) -> Self {
        Self::Formation(error)
    }
}
pub(super) type Result<T> = core::result::Result<T, Error>;

/// Independently retained original endpoints. Construction performs no verification.
pub(super) struct Expected {
    mask: MaskExpected,
    formation: data::Expected,
    fused: query::Expected,
}
impl Expected {
    pub(super) fn checked(
        request: &gold::Request,
        installed: &data::Expected,
        statement: [Val; 4],
        vector: [Val; 4],
    ) -> Result<Self> {
        let context = encoding_context(request, installed, statement).map_err(|e| match e {
            association::Error::Binding => Error::Binding,
            association::Error::Formation(e) => Error::Formation(e),
        })?;
        let mask = MaskExpected::checked(statement, vector, context, request.nonce())
            .map_err(|_| Error::Binding)?;
        let fused =
            association::expected(request, installed, statement, vector).map_err(|e| match e {
                association::Error::Binding => Error::Binding,
                association::Error::Formation(e) => Error::Formation(e),
            })?;
        Ok(Self {
            mask,
            formation: fused.core_expected().clone(),
            fused,
        })
    }
}

/// One distinct UNVERIFIED fused mathematical frame. No accepted flag.
pub(super) struct Evidence {
    formation: Vec<u8>,
}
pub(super) fn produce(
    expected: &Expected,
    opening: writer::Opening,
    secret: gold::SecretOpening,
) -> Result<Evidence> {
    let prepared = opening.into_fused(&expected.mask, &expected.fused, secret)?;
    let formation = query::prove(&expected.fused, prepared)?.into_bytes();
    Ok(Evidence { formation })
}

/// The independently prepared native verifier is mandatory on EVERY receiving call.
/// This mathematical relation supplies no DATA/Word/freshness/SQL authority.
pub(super) fn verify(expected: &Expected, evidence: &Evidence) -> Result<()> {
    verify_bytes(expected, &evidence.formation)
}
pub(super) fn verify_bytes(expected: &Expected, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > query::MAX_EVIDENCE_BYTES {
        return Err(Error::Resource);
    }
    query::verify(&expected.fused, bytes)?;
    Ok(())
}
