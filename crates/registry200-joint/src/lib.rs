//! Fixed N4 hidden-predicate/control composition over retained genuine proofs.
//! Construction, content identities and historical computation are not SQL grants.
#![forbid(unsafe_code)]

mod acquire;
mod depot;
mod descriptor;
mod manifest;
mod request;
mod verifier;

pub use acquire::{AcquireExpected, CheckedAcquire};
pub use depot::{
    JointDepot, JointEvidenceIngress, MAX_SETUP_BYTES, MAX_SETUP_CLAIM_BYTES, SetupClaim,
};
pub use descriptor::{Application, DESCRIPTOR_BYTES, Descriptor};
pub use manifest::{MANIFEST_BYTES, Manifest, ManifestReference, ManifestRole};
pub use request::{Lane, REQUEST_BYTES, Request};
pub use verifier::JointVerifier;

use sha2::{Digest, Sha256};

#[derive(Debug)]
pub enum Error {
    Encoding,
    Domain,
    ResourceLimit,
    Transition,
    Verification,
    Poisoned,
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
        write!(f, "Joint Registry200 rejected: {self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = core::result::Result<T, Error>;

/// New application contract; none of the original primitive profiles are changed.
pub fn contract_digest() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"DCS/REGISTRY200-JOINT/v1/N4-T2-D2/owner-only/immutable-source/fixed-Key33");
    h.update(b"Bootstrap=Source-Life;Control=Source-Life-private-NonAcquire;Acquire=all-input16-output118-and-Source-Life-privateMask-Link/no-read-lane");
    h.update(b"inner-SourceSpec-id/outer-new-App-and-G/unchanged-intent_query/single-Control-CAS/sticky-enrollment/full-local-replay-before-admission/no-QC-cache-authority");
    h.update(b"DCSJAD01:contract32-spec312-object32-setupSHA25632-setupSHA51264-anchor140-Key33u64-reserved12/DCSJRQ01:lane1-zero7-App32-inner2716/DCSJMF01:contract32-lane1-zero7-next32-result32-3(hash32-len64)/DCSJSP01:App32-len64-count1-zero7-1or2(hash32-len64)/canonicalGold/LE/EOF");
    h.update(registry200_proof::wire::contract_digest());
    h.update(registry200_proof::control_kind::profile_digest());
    h.update(registry200_proof::predicate_acquire::profile_digest());
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
