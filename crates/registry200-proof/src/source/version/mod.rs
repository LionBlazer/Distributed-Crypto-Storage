//! Closed mathematical StateCertificate capability. No version freshness or application admission.
//! The existing StateCertificate AIR/profile and consumer version-tag bytes are preserved.
#[cfg(test)]
mod tests;

use super::{Relation, Statement, circuit::Witness, profile_digest, statement::encode_digest};
pub use crate::wire::Error;
use crate::{BackendError, fixed::Backend};
use bfv_hiding_stark::codec;
use compact_store::Commitment;
use sha2::{Digest, Sha256};
use std::panic::{AssertUnwindSafe, catch_unwind};

/// Existing Source codec budgets; no caller-selected geometry, codec or security policy.
pub const MAX_CERTIFICATE_BYTES: usize = crate::wire::frame::MAX_SOURCE_BYTES;

/// Immutable independent PUBLIC expectation, not a checked proof or a fresh-head token.
/// Both heads, C_key and C_state must be independently authorized/retained by the caller.
/// There is deliberately no caller-supplied request or unchecked Statement constructor.
#[derive(Clone)]
pub struct SourceVersionExpected {
    statement: Statement,
}
impl SourceVersionExpected {
    pub fn checked(
        images: [&[u8]; 2],
        heads: [&Commitment; 2],
        key_commitment: [u8; 32],
        state_commitment: [u8; 32],
    ) -> Result<Self, BackendError> {
        let mut statement = Statement::checked_relation(
            Relation::StateCertificate,
            images,
            heads,
            [0; 32],
            key_commitment,
            state_commitment,
        )?;
        statement.request = version_tag(&statement);
        Ok(Self { statement })
    }

    /// Deterministic image/key identity, not authorization or proof of currentness.
    /// C_state is intentionally excluded from this tag to keep its definition acyclic.
    /// A verifier must retain the complete expectation, not compare this tag alone.
    pub fn version_id(&self) -> [u8; 32] {
        self.statement.request
    }

    pub fn state_commitment(&self) -> [u8; 32] {
        encode_digest(self.statement.open_commitment)
    }

    /// Read-only low-level PUBLIC mathematical claim; cloning it mints no capability.
    pub fn statement(&self) -> &Statement {
        &self.statement
    }
}

// Exact existing opening::state::version_tag transcript. C_state is excluded;
// the actual AIR still binds its independently retained complete public value.
fn version_tag(statement: &Statement) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"DCS/experimental/version-state-tag/N4/v1");
    hash.update(profile_digest(Relation::StateCertificate));
    for (head, packet) in statement.heads.iter().zip(&statement.packets) {
        hash.update(((head.len() + packet.len()) as u64).to_le_bytes());
        hash.update(head);
        hash.update(packet);
    }
    hash.update(encode_digest(statement.key_commitment));
    hash.finalize().into()
}

/// UNVERIFIED producer output. Proving/encoding supplies no verification status.
/// A receiver must use its own independent Expected and call verify().
pub struct UnverifiedStateCertificate {
    expected: SourceVersionExpected,
    bytes: Vec<u8>,
}
impl UnverifiedStateCertificate {
    pub fn expected(&self) -> &SourceVersionExpected {
        &self.expected
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Move-only mathematical result from fresh native verification. No proof, keys,
/// decoded SDK objects, cache, freshness, BFV Formation or SQL authority is retained.
///
/// Consumer code cannot fabricate its actual private field:
/// ```compile_fail
/// use registry200_proof::source::version::{SourceVersionExpected, VerifiedSourceVersion};
/// fn forge(expected: SourceVersionExpected) -> VerifiedSourceVersion {
///     VerifiedSourceVersion { expected }
/// }
/// ```
/// It cannot duplicate the result by cloning it:
/// ```compile_fail
/// use registry200_proof::source::version::VerifiedSourceVersion;
/// fn duplicate(value: &VerifiedSourceVersion) -> VerifiedSourceVersion {
///     value.clone()
/// }
/// ```
pub struct VerifiedSourceVersion {
    expected: SourceVersionExpected,
}
impl VerifiedSourceVersion {
    pub fn expected(&self) -> &SourceVersionExpected {
        &self.expected
    }
}

/// Assess the real fixed packed AIR before trace allocation, genuinely prove and
/// canonically encode. No expensive self-verification or Verified result is hidden
/// here: the UNVERIFIED output must reach the independent receiving verifier.
/// The existing Canonical source::prove retains its original self-verify contract.
pub fn prove(
    expected: &SourceVersionExpected,
    witness: &Witness,
) -> Result<UnverifiedStateCertificate, Error> {
    catch_unwind(AssertUnwindSafe(
        || -> Result<UnverifiedStateCertificate, Error> {
            let backend = Backend::source_version(expected)?;
            let proof = backend.prove(witness.trace(expected.statement())?)?;
            let bytes = codec::serialize(&proof, &backend.shape, MAX_CERTIFICATE_BYTES)?;
            Ok(UnverifiedStateCertificate {
                expected: expected.clone(),
                bytes,
            })
        },
    ))
    .map_err(|_| Error::Proof(BackendError::Proving))?
}

/// Bounded canonical decode plus the actual fixed StateCertificate native verifier.
/// Every invocation reconstructs/assesses the exact AIR under fresh OS configuration;
/// nothing supplied by the bytes can select an Expected, verifier, profile or cache.
pub fn verify(
    expected: &SourceVersionExpected,
    bytes: &[u8],
) -> Result<VerifiedSourceVersion, Error> {
    if bytes.is_empty() || bytes.len() > MAX_CERTIFICATE_BYTES {
        return Err(Error::ResourceLimit);
    }
    catch_unwind(AssertUnwindSafe(
        || -> Result<VerifiedSourceVersion, Error> {
            let backend = Backend::source_version(expected)?;
            let proof = codec::decode(
                bytes,
                &backend.shape,
                crate::wire::MAX_SEQUENCE_ELEMENTS,
                crate::wire::SOURCE_SLOTS,
            )?;
            backend.verify(&proof)?;
            Ok(VerifiedSourceVersion {
                expected: expected.clone(),
            })
        },
    ))
    .map_err(|_| Error::Verification)?
}
