//! Owner-journal composition for immutable SourceVersion and original Word proofs.
//! Historical verified mathematics is never a current lock, QC or SQL capability.
mod descriptor;
mod evidence;
pub mod predicate;
mod request;
mod state;
#[cfg(test)]
mod tests;
mod verifier;
pub use descriptor::{Application, Descriptor, MAX_DESCRIPTOR_BYTES};
pub use evidence::{Evidence, MAX_EVIDENCE_BYTES};
pub use request::{Lane, OperationId, REQUEST_BYTES, Request};
use sha2::{Digest, Sha256};
pub use state::Control;
pub use verifier::{VerifiedOperation, Verifier};
pub use version_journal::{Error, Hash, Result};
/// Distinct application contract. Predicate needs full FHE/result admission first.
pub fn contract_digest() -> Hash {
    let mut h = Sha256::new();
    h.update(b"DCS/WORD-JOURNAL/v1/immutable-SourceVersion/EMPTY265-Control309");
    h.update(b"DCSWAD01-full-Source-heads-packets-key-state/network-shard-ids;DCSWCH01;DCSWRQ01;DCSWJE01");
    h.update(b"owner-whole-body-parent-CAS/sticky-enrollment/retain-actual-immutable-Source/native-Word-every-operation/no-Predicate-no-QC-no-currentness-no-SQL");
    h.update(registry200_proof::source::profile_digest(
        registry200_proof::source::Relation::StateCertificate,
    ));
    h.update(registry200_proof::registry_progress::word::profile_digest());
    h.update(registry200_proof::registry_progress::word::wire_profile_digest());
    h.update(registry200_proof::registry_progress::word::bootstrap::profile_digest());
    for n in [MAX_DESCRIPTOR_BYTES, MAX_EVIDENCE_BYTES, REQUEST_BYTES] {
        h.update((n as u64).to_le_bytes());
    }
    h.finalize().into()
}
