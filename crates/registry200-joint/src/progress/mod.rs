//! Distinct Registry208 application. Mathematical consistency is not a lock grant.
mod depot;
mod descriptor;
mod manifest;
mod request;
mod verifier;
pub use depot::{
    MAX_SETUP_BYTES, MAX_SETUP_CLAIM_BYTES, ProgressDepot, ProgressEvidenceIngress, SetupClaim,
};
pub use descriptor::{Application, DESCRIPTOR_BYTES, Descriptor};
pub use manifest::{MANIFEST_BYTES, Manifest, ManifestReference, ManifestRole};
pub use request::{Lane, OperationId, REQUEST_BYTES, Request};
use sha2::{Digest, Sha256};
pub use verifier::{ProgressVerifier, VerifiedOperation};

#[derive(Debug)]
pub enum Error {
    Encoding,
    Domain,
    ResourceLimit,
    Transition,
    Verification,
    Journal(version_journal::Error),
    Storage(bfv_product_evidence::Error),
}
impl From<version_journal::Error> for Error {
    fn from(e: version_journal::Error) -> Self {
        Self::Journal(e)
    }
}
impl From<bfv_product_evidence::Error> for Error {
    fn from(e: bfv_product_evidence::Error) -> Self {
        Self::Storage(e)
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Progress application rejected: {self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = core::result::Result<T, Error>;

/// Immutable NEW application contract. No legacy wire/profile is reinterpreted.
pub fn contract_digest() -> [u8; 32] {
    use registry200_proof::registry_progress as core;
    let mut h = Sha256::new();
    h.update(b"DCS/REGISTRY-PROGRESS-JOINT/v2/N4-T2-fixed-source-fixed-Key33/no-SQL-no-finality");
    h.update(b"Registry208-Statement96-Progress48-Result160/Bootstrap803-Control815-Predicate896/WAIT-NOWAIT-SKIP-one-hidden-bank/no-public-status");
    h.update(b"new-Application-and-G/inner-SourceSpec-unchanged-intent_query/owner-signed-whole-body-external/sticky-enrollment-single-Control-CAS/actual-full-replay-every-call/no-legacy-Life-Link-result-casts");
    h.update(b"DCSPAD02:contract32-spec312-object32-setup25632-setup51264-anchor140-Key33u64-zero12/DCSPRQ02:lane1-zero7-App32-inner2716/DCSPMF02:contract32-lane1-zero7-next32-result32-2(hash32-len64)/DCSPST02:App32-len64-count1-zero7-1or2(hash32-len64)/EOF");
    h.update(core::bootstrap_profile_digest());
    h.update(core::transition::profile_digest(false));
    h.update(core::transition::profile_digest(true));
    h.update(bfv_product_evidence::profile_digest());
    h.update(bfv_mul_relin_proof::profile_digest());
    h.update(bfv_key_transform::profile_digest());
    for n in [
        DESCRIPTOR_BYTES,
        REQUEST_BYTES,
        MANIFEST_BYTES,
        MAX_SETUP_BYTES,
        MAX_SETUP_CLAIM_BYTES,
        protocol_storage::MAX_BLOB_BYTES as usize,
    ] {
        h.update((n as u64).to_le_bytes());
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests;
