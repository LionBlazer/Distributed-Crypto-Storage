//! Fixed lifecycle circuit/public claims, without a native state-transition oracle.
pub mod acquire;
pub mod air;
pub mod bootstrap;
pub mod control;
pub mod layout;
pub mod opening;
pub mod predicate;
pub mod ranges;
pub mod registry;
pub mod statement;
use sha2::{Digest, Sha256};
pub fn profile(h: &mut Sha256, bootstrap: bool) {
    h.update(b"DCS/private-registry-lifecycle/v2/N4-T2-D2/owner-authorized-externally/canonical-source-first/no-live-grant");
    h.update(statement::enrollment_profile());
    h.update(statement::registry_profile());
    if bootstrap {
        h.update(b"Source680/Enrollment64/EMPTYRegistry200/revision0/allocator0/no112cast");
    } else {
        h.update(b"Source680/Enrollment64/Old200/Command160/New200/Result144/181absorbs");
        h.update(b"Begin/Acquire/FailCurrent/Savepoint/RollbackTo/Release/End/u64-limb-carries-and-borrows/newest-exact-name/compact-by-ID/failed-EndAbort/no-MVCC/no-controller-signature");
    }
    for n in [
        if bootstrap {
            bootstrap::WIDTH
        } else {
            layout::WIDTH
        },
        if bootstrap {
            statement::BOOTSTRAP_VALUES
        } else {
            statement::STEP_VALUES
        },
        512,
        2,
        4,
        2,
    ] {
        h.update((n as u64).to_le_bytes());
    }
}
pub fn conflicts(request: u8, held: u8) -> bool {
    match request {
        1 => held == 4,
        2 => held >= 3,
        3 => held >= 2,
        4 => held != 0,
        _ => false,
    }
}
pub fn profile_digest(bootstrap: bool) -> [u8; 32] {
    let name = if bootstrap {
        "registry-lifecycle-bootstrap"
    } else {
        "registry-lifecycle"
    };
    let mut h = bfv_hiding_stark::profile_start(
        b"dcs/experiment/hiding-source-primitive-profile/v1",
        name.as_bytes(),
    );
    profile(&mut h, bootstrap);
    bfv_hiding_stark::profile_finish(
        h,
        if bootstrap {
            bootstrap::WIDTH
        } else {
            layout::WIDTH
        },
        2,
    )
}
