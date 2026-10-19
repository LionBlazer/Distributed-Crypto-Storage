//! Hidden non-Acquire Cmd160 membership under an actual Source/Lifecycle pair.
pub mod air;
pub mod circuit;
pub mod layout;
pub mod statement;
pub mod wire;
use sha2::{Digest, Sha256};
pub use statement::Expected;
pub use wire::{Evidence, Prerequisites, VerifiedLink, prove, verify};

pub const PUBLIC_VALUES: usize = 8 + 691 + 116;
pub const TAG: u8 = 1;
pub fn profile_digest() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"DCS/private-control-kind-link/v1/no-SQL-no-finality");
    h.update(crate::source::profile_digest(
        crate::source::Relation::CanonicalIndex,
    ));
    h.update(crate::lifecycle::profile_digest(false));
    h.update(crate::lifecycle::statement::COMMAND_DOMAIN);
    h.update(b"PV815=profile8-fullSource691-fullLifecycle116/Cmd160-original-v2-prefix/private-six-onehot-opcodes0-2-3-4-5-6/no-Acquire/no-Bootstrap/no-opcode-disclosure");
    h.update(b"canonical-Gold-private-fields110..158/zero159/actual-Lifecycle-owns-suffix-semantics/P2-overwrite8-cap4/reset0/end19/H512/immutable-private-bank-and-carry-through511");
    h.update(b"mandatory-genuine-Source-first-Lifecycle-pair-before-Link-decode-or-trace/DCSPCL01-detached-not-SignedBody/no-receipt");
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
/// Actual fixed-AIR assessment only; this constructs no private trace or proof.
pub fn analyze(e: &Expected) -> Result<bfv_hiding_stark::SecurityReport, crate::BackendError> {
    let (_, report) = bfv_hiding_stark::analyze(&air::ControlKindAir::new(e))?;
    report.require_target()
}
#[cfg(test)]
mod tests;
