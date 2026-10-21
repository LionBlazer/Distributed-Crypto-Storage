//! Closed two-lane Source/mask encodings. Metadata is not Key, Formation or SQL authority.
pub mod air;
pub mod circuit;
pub mod commitment;
pub mod formation;
pub mod layout;
pub mod product;
mod prover;
pub mod statement;
pub mod wire;
pub use prover::{Evidence, prove};
use sha2::{Digest, Sha256};
pub const N: usize = 4096;
pub const Q: [u64; 2] = [1073692673, 1073668097];
pub const T: u64 = 65537;
pub const SCALE: u64 = 16389;
pub const COMMAND_FIELDS: usize = 48;
pub const COMMAND_DOMAIN: [u8; 16] = *b"DCS/2LANEMASK/v1";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    SourceAllOriginal,
    PrivateMask,
    VersionSourceAllOriginal,
}
impl Role {
    pub(super) fn is_source(self) -> bool {
        matches!(
            self,
            Self::SourceAllOriginal | Self::VersionSourceAllOriginal
        )
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::SourceAllOriginal => "two-lane-source-all-original",
            Self::PrivateMask => "two-lane-private-mask",
            Self::VersionSourceAllOriginal => "two-lane-version-source-all-original",
        }
    }
    pub fn width(self) -> usize {
        match self {
            Self::SourceAllOriginal | Self::VersionSourceAllOriginal => layout::SOURCE_WIDTH,
            Self::PrivateMask => layout::QUERY_WIDTH,
        }
    }
    pub fn public_values(self) -> usize {
        match self {
            Self::SourceAllOriginal | Self::VersionSourceAllOriginal => 740,
            Self::PrivateMask => 760,
        }
    }
    pub fn tag(self) -> u8 {
        match self {
            Self::SourceAllOriginal => 1,
            Self::PrivateMask => 2,
            Self::VersionSourceAllOriginal => 3,
        }
    }
}
/// Fixed parameter label only: this certifies no secret, setup, noise or security property.
pub fn candidate_parameter_digest() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"DCS/two-lane-encoding/candidate-BFV-metadata/v1/no-Key-no-Formation-no-security-authority");
    for n in [N as u64, Q[0], Q[1], T, SCALE, 10, 20] {
        h.update(n.to_le_bytes());
    }
    h.finalize().into()
}
pub fn profile_digest(role: Role) -> [u8; 32] {
    let mut h = bfv_hiding_stark::profile_start(
        b"dcs/experiment/hiding-source-primitive-profile/v1",
        role.name().as_bytes(),
    );
    h.update(b"DCS/two-lane-private-encoding/v1/N4-PB-no-admission");
    h.update(role.name());
    h.update(crate::source::profile_digest(
        if role == Role::VersionSourceAllOriginal {
            crate::source::Relation::StateCertificate
        } else {
            crate::source::Relation::CanonicalIndex
        },
    ));
    if role == Role::VersionSourceAllOriginal {
        h.update(b"DCS/two-lane-version-data/v1/StateCertificate-Cstate680;sealed-SourceVersionExpected;actual-version-proof-before-producer-and-receiver;no-query-q-cast;no-old-pair-or-Formation;producer-unverified-no-selfverify");
    }
    h.update(candidate_parameter_digest());
    h.update(COMMAND_DOMAIN);
    h.update(b"Source691-fresh-native-before-child;metadata29=database4-domain4-epoch1-param8-keyID8-Cs4-no-Key33-no-CsHat;PV740or760;source2i+f-stride512-at-age-weights256+age/amount;reversed256mask;all4096-scaled16389-mod65537;root4112=context8-salt4-zero4-W4096;overwrite-rate8-cap4;row0-context+salt;middle-delayedW;row511-delayedW+lastW;Source680-85blocks-or-Cmd48-6;49bitweights17+17+15;8eq11;separate-originalSource-and-child/no-cached-authority");
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
        wire::HEADER,
        wire::MAX_CHILD,
        wire::MAX_SOURCE,
        wire::SEQUENCE,
        wire::CHILD_SLOTS,
    ] {
        h.update((n as u64).to_le_bytes());
    }
    bfv_hiding_stark::profile_finish(h, role.width(), 2)
}
#[cfg(test)]
mod tests;
