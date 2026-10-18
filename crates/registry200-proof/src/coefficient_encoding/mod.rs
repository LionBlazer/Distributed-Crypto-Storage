//! Two private-witness coefficient encodings. Neither role grants SQL admission.
pub mod air;
pub mod commitment;
pub mod layout;
pub mod statement;
pub mod wire;
use sha2::{Digest, Sha256};
pub const N: usize = 8192;
pub const T: u64 = 114689;
pub const SCALE: u64 = 78307;
pub const COMMAND_FIELDS: usize = 48;
pub const COMMAND_DOMAIN: [u8; 16] = *b"DCS/COEFMASK/v1!";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    SourceAllOriginal,
    PrivateMask,
}
impl Role {
    pub fn name(self) -> &'static str {
        match self {
            Self::SourceAllOriginal => "source-all-original-coefficient-encoding",
            Self::PrivateMask => "private-mask-coefficient-encoding",
        }
    }
    pub fn width(self) -> usize {
        match self {
            Self::SourceAllOriginal => layout::SOURCE_WIDTH,
            Self::PrivateMask => layout::QUERY_WIDTH,
        }
    }
    pub fn public_values(self) -> usize {
        match self {
            Self::SourceAllOriginal => 752,
            Self::PrivateMask => 772,
        }
    }
    pub fn tag(self) -> u8 {
        match self {
            Self::SourceAllOriginal => 1,
            Self::PrivateMask => 2,
        }
    }
}
pub fn profile(role: Role, h: &mut Sha256) {
    h.update(b"DCS/private-coefficient-encoding/v1/N4/poly/no-SQL-admission/");
    h.update(role.name());
    h.update(crate::source::profile_digest(
        crate::source::Relation::CanonicalIndex,
    ));
    h.update(bfv_key_transform::profile_digest());
    h.update(COMMAND_DOMAIN);
    h.update(b"PV-common=profile8-Source691-fullSetup8-Key33-context8-Cw4;query-append=blindSQL8-publicNonce8-Cmask4;Source680-full-originals-ordinal4-ID8-table8;maskCmd48;main-private;W=78307*m-mod114689;source-lanes3i+f-stride512-at-age;query-reverse255-n;all8192;root8208=context8-salt4-zero4-W8192;overwrite8-cap4-reset0;row0-triple-middle-double-row511-triple;source0..84/query0..5;no-selected-SIMD/no-Formation/no-key-authority");
    for n in [
        N,
        T as usize,
        SCALE as usize,
        512,
        COMMAND_FIELDS,
        role.width(),
        role.public_values(),
        layout::P2,
        layout::PERIODICS,
    ] {
        h.update((n as u64).to_le_bytes());
    }
}
pub fn profile_digest(role: Role) -> [u8; 32] {
    let mut h = bfv_hiding_stark::profile_start(
        b"dcs/experiment/hiding-source-primitive-profile/v1",
        role.name().as_bytes(),
    );
    profile(role, &mut h);
    bfv_hiding_stark::profile_finish(h, role.width(), 2)
}
