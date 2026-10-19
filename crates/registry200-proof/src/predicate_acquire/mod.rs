//! Private Cmd48/Acquire Cmd160/successful Result144 linkage. No SQL or lock grant.
pub mod air;
pub mod circuit;
pub mod layout;
pub mod statement;
pub mod wire;
use sha2::{Digest, Sha256};
pub use statement::Expected;
pub use wire::{Evidence, Prerequisites, VerifiedLink, prove, verify};

pub const PUBLIC_VALUES: usize = 8 + 772 + 116;
pub const TAG: u8 = 1;
pub fn profile_digest() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"DCS/private-predicate-acquire-link/v1/no-SQL-no-finality");
    h.update(crate::coefficient_encoding::profile_digest(
        crate::coefficient_encoding::Role::PrivateMask,
    ));
    h.update(crate::lifecycle::profile_digest(false));
    h.update(b"PV896=profile8-fullQueryEncoding772-fullLifecycle116/shared-private-mask256/Cmd48-then-Cmd160-then-Result144/Acquire1-outcome0/sameTx64/controllers256/rev64-seq64/window0..4/projection1..3/no-DATA/no-native-transition");
    h.update(b"P2-overwrite8-cap4/reset0-6-26/end5-25-43/H512/persistent-private-bank-through-padding/bool733/salts12/source-and-query-and-lifecycle-proofs-mandatory/detached-DCSPAL01/not-SignedBody");
    for n in [
        PUBLIC_VALUES,
        layout::WIDTH,
        layout::BANK,
        layout::END,
        wire::HEADER,
        wire::MAX_PROOF_BYTES,
        wire::MAX_FRAME,
        wire::MAX_SEQUENCE_ELEMENTS,
        wire::MAX_TOTAL_ELEMENTS,
    ] {
        h.update((n as u64).to_le_bytes());
    }
    h.finalize().into()
}

/// Actual assessment of this fixed AIR; no fixture, trace or proof is constructed.
pub fn analyze(e: &Expected) -> Result<bfv_hiding_stark::SecurityReport, crate::BackendError> {
    let (_, report) = bfv_hiding_stark::analyze(&air::PredicateAcquireAir::new(e))?;
    report.require_target()
}

#[cfg(test)]
mod tests;
