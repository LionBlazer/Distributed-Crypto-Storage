//! Fixed SHA Predicate mathematics; separate from the original Word proof format.
//! Native verification supplies no quantitative composed-security claim, Source
//! authentication, current head, finality, SQL acceptance or lock authority.
use super::{Expected, PrivateInputs, Result, Role};
use crate::registry_progress::word_inventory::{hash_backend, hash_wire};

pub const MAX_EVIDENCE_BYTES: usize = hash_wire::MAX_FRAME_BYTES;

/// Fixed new suite and framing identity; original Word profiles are unchanged.
pub fn profile_digest() -> [u8; 32] {
    hash_wire::profile()
}

/// Producer bytes are unverified; no checked or accepted flag is serialized.
pub struct UnverifiedEvidence {
    bytes: Vec<u8>,
}

impl UnverifiedEvidence {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Move-only result of actual SHA-suite native verification of the original
/// Predicate equations. It is not the original `word::VerifiedWord`, and there
/// is no conversion to that result or an operation-admission capability.
/// ```compile_fail
/// use registry200_proof::registry_progress::word::{Expected, hash::CheckedWord};
/// fn forge(expected: Expected) -> CheckedWord { CheckedWord { expected } }
/// ```
/// ```compile_fail
/// use registry200_proof::registry_progress::word::hash::CheckedWord;
/// fn duplicate(word: &CheckedWord) { let _: CheckedWord = word.clone(); }
/// ```
pub struct CheckedWord {
    expected: Expected,
}

impl CheckedWord {
    pub fn expected(&self) -> &Expected {
        &self.expected
    }
}

/// Immutable Predicate-only public setup, with no retained input or RNG.
pub struct Prover {
    inner: hash_backend::ProverSetup,
}

impl Prover {
    pub fn new() -> Result<Self> {
        Ok(Self {
            inner: hash_backend::ProverSetup::new()?,
        })
    }

    /// Consume the SAME opaque original Word inputs; no private trace escapes.
    pub fn produce(
        &self,
        expected: &Expected,
        inputs: PrivateInputs,
    ) -> Result<UnverifiedEvidence> {
        if expected.role() != Role::Predicate {
            return Err(super::Error::Binding);
        }
        Ok(UnverifiedEvidence {
            bytes: self.inner.produce(&expected.inner, &inputs.inner)?,
        })
    }
}

/// The receiver independently reconstructs the fixed Predicate public setup.
pub struct Verifier {
    inner: hash_backend::VerifierSetup,
}

impl Verifier {
    pub fn new() -> Result<Self> {
        Ok(Self {
            inner: hash_backend::VerifierSetup::new()?,
        })
    }

    pub fn verify(&self, expected: &Expected, bytes: &[u8]) -> Result<CheckedWord> {
        if expected.role() != Role::Predicate {
            return Err(super::Error::Binding);
        }
        self.inner.verify(&expected.inner, bytes)?;
        Ok(CheckedWord {
            expected: expected.clone(),
        })
    }
}
