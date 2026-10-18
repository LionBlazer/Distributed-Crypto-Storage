//! Fixed AddAmount eligibility and full logical afterimage, without mutation admission.
pub mod air;
pub mod layout;
pub mod statement;
use sha2::{Digest, Sha256};
pub fn profile(h: &mut Sha256) {
    h.update(b"DCS/Registry200/write-image/v1/N4-T2-D2/Source680-Enrollment64-Registry200-AddAmount160-Image192");
    h.update(b"exact-age-mask/all-selected-own-held3-or4/active-controller-u64-limbs/successor-room/no-registry-mutation/u16-global-overflow-reject/original-ordinal-full-ID8/no-AEAD-BFV-SQL-grant");
    h.update(crate::source::profile_digest(
        crate::source::Relation::CanonicalIndex,
    ));
    h.update(crate::lifecycle::statement::enrollment_profile());
    h.update(crate::lifecycle::statement::registry_profile());
    h.update(statement::COMMAND_DOMAIN);
    h.update(statement::IMAGE_DOMAIN);
    for n in [
        layout::WIDTH,
        statement::PUBLIC_VALUES,
        512,
        162,
        256,
        4,
        2,
        2,
    ] {
        h.update((n as u64).to_le_bytes());
    }
}
pub fn profile_digest() -> [u8; 32] {
    let mut h = bfv_hiding_stark::profile_start(
        b"dcs/experiment/hiding-source-primitive-profile/v1",
        b"registry-write-image",
    );
    profile(&mut h);
    bfv_hiding_stark::profile_finish(h, layout::WIDTH, 2)
}
