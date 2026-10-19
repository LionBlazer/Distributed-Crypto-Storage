//! Bounded owner-side inputs for the existing private N4 coefficient relation.
//! This is mathematical proof production, never SQL admission or a freshness grant.
mod compiler;
mod produce;
mod source;
pub use compiler::CompiledPrivatePredicate;
pub use source::{
    CompiledLockingSelect, FetchedSource, LockingActor, LockingCompletion, LockingConflict,
    LockingControl, LockingParent, LockingPreparation, NonAdmittedLocking, PreparedLockingInputs,
    SourceOwner, StagedLockingTransition,
};

use bfv_mul_relin_proof::{InputEvidence, Provenance};
use bfv_query_core::{BfvKeyAnchor, Owner, PreparedPrivateCoefficientPredicate, PublicSetup};

/// Actual owner-local BFV capability and independently pinned original public setup.
/// None of these references may be replaced by metadata supplied by a proving peer.
pub struct BfvContext<'a> {
    pub owner: &'a Owner,
    pub setup: &'a PublicSetup,
    pub anchor: &'a BfvKeyAnchor,
}

/// Fifteen public wire frames, not one aggregate transport envelope.
///
/// The two pairs contain the SAME Source bytes. Thus the collection contains
/// sixteen distinct proof roles: Key, Source, two Encodings, ten Basis and two
/// Formations. Private fields prevent unlabelled replacement through this API;
/// every downstream consumer must still perform actual proof verification.
pub struct InputProofFrames {
    key: Vec<u8>,
    encodings: [Vec<u8>; 2],
    bases: [[Vec<u8>; 5]; 2],
    formations: [Vec<u8>; 2],
}
impl InputProofFrames {
    /// Borrow the existing Core input16 contract; no proof or buffer is copied.
    pub fn as_input_evidence(&self) -> InputEvidence<'_> {
        InputEvidence {
            key: &self.key,
            encodings: self.encodings.each_ref().map(Vec::as_slice),
            bases: self
                .bases
                .each_ref()
                .map(|bases| bases.each_ref().map(Vec::as_slice)),
            formations: self.formations.each_ref().map(Vec::as_slice),
        }
    }

    /// The Core's canonical fifteen-frame order, with its original role caps.
    pub fn frames(&self) -> [&[u8]; 15] {
        self.as_input_evidence().frames()
    }

    /// Checked sum of all fifteen bounded frames, including both Source copies.
    /// This is not permission to send the sum as a transport frame or Journal Body.
    pub fn byte_len(&self) -> std::result::Result<usize, bfv_mul_relin_proof::Error> {
        self.as_input_evidence().byte_len()
    }
}

/// Actual encrypted request/pending binding and public mathematical evidence.
/// No plaintext rows, query mask, private blind, opening or prover is retained.
/// The caller must prove/verify the encrypted output and independently establish
/// agreed-head freshness before accepting a result.
pub struct ProducedInputs {
    provenance: Provenance,
    prepared: PreparedPrivateCoefficientPredicate,
    proofs: InputProofFrames,
}
impl ProducedInputs {
    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }
    pub fn request(&self) -> &[u8] {
        &self.prepared.request
    }
    pub fn proofs(&self) -> &InputProofFrames {
        &self.proofs
    }
    pub fn into_parts(
        self,
    ) -> (
        Provenance,
        PreparedPrivateCoefficientPredicate,
        InputProofFrames,
    ) {
        (self.provenance, self.prepared, self.proofs)
    }
}

fn cryptography(error: impl std::fmt::Display) -> crate::Error {
    crate::Error::Cryptography(error.to_string())
}
fn invalid(message: &str) -> crate::Error {
    crate::Error::InvalidInput(message.to_owned())
}
fn random_salt() -> crate::Result<[u64; 4]> {
    bfv_key_transform::random_salt().map_err(cryptography)
}

#[cfg(test)]
mod tests;
