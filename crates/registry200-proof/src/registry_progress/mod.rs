//! Fixed-source statement progress. Mathematical evidence is never SQL admission.
pub mod bootstrap;
mod bootstrap_air;
pub mod circuit;
pub mod control_result_opening;
mod equations;
mod fields;
pub mod result_opening;
pub mod statement;
pub mod transition;
mod transition_air;
mod transition_fields;
mod transition_layout;
mod transition_trace;
pub use bootstrap::{BootstrapEvidence, BootstrapWitness, prove_bootstrap, verify_bootstrap};
use sha2::{Digest, Sha256};
pub use statement::{BootstrapExpected, BootstrapStatement};

pub const REGISTRY_FIELDS: usize = 208;
pub const STATEMENT_FIELDS: usize = 96;
pub const PROGRESS_FIELDS: usize = 48;
pub const RESULT_FIELDS: usize = 160;
pub const BOOTSTRAP_VALUES: usize = 803;
pub const CONTROL_VALUES: usize = 815;
pub const PREDICATE_VALUES: usize = 896;

/// New EMPTY bootstrap role; legacy Lifecycle profiles remain unchanged.
pub fn bootstrap_profile_digest() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"DCS/registry-statement-progress/bootstrap/v1/Source680-Enrollment64-EMPTYRegistry208/no-live-grant");
    h.update(crate::source::profile_digest(
        crate::source::Relation::CanonicalIndex,
    ));
    h.update(crate::lifecycle::statement::enrollment_profile());
    h.update(registry_profile_digest());
    h.update(b"PV803=profile8-fullSource691-context100-next4/Source680-85/Enrollment64-8/Registry208-26/reset0-85-93/119absorbs/H512/P2-overwrite8-cap4/immutable-bank-through511/zero-base-progress-padding/all32-IDs-from-Source/controllers-nonzero");
    h.update(b"DCSPGB01/tag1/detached/no-Source-duplication/Source-first-fresh-before-child/selfverify/no-receipt");
    for n in [
        REGISTRY_FIELDS,
        BOOTSTRAP_VALUES,
        bootstrap::WIDTH,
        512,
        bootstrap::HEADER,
        bootstrap::MAX_PROOF_BYTES,
        bootstrap::MAX_FRAME,
        bootstrap::MAX_SEQUENCE_ELEMENTS,
        bootstrap::MAX_TOTAL_ELEMENTS,
    ] {
        h.update((n as u64).to_le_bytes());
    }
    h.finalize().into()
}
pub fn registry_profile_digest() -> [u8; 32] {
    Sha256::digest(b"DCS/registry-statement-progress/Registry208/v1/old-body194-new-prefix/two-present-root5/zero4/stable-id-carry/no-legacy-padding-cast").into()
}
pub fn statement_profile_digest() -> [u8; 32] {
    Sha256::digest(b"DCS/registry-statement-progress/Statement96/v2/scope512-enroll4-client256-call64-tx64-principal-controller256-invocation256-blindSQL256-snapshot256-mask256-mode-waitCodes0WAIT1NOWAIT2SKIP-window-projection/salt4/zero1").into()
}
pub fn progress_profile_digest() -> [u8; 32] {
    Sha256::digest(b"DCS/registry-statement-progress/Progress48/v1/statement4-tx64-principal-call64-microstep64-cursor-visited4-selected4-block-holder64-mode-revision64/salt4/zero4").into()
}

#[cfg(test)]
mod model_tests;

#[cfg(test)]
mod air_snapshot_tests;

// Fixed internal Word mathematics behind the explicit public facade.
pub mod word;
mod word_inventory;
