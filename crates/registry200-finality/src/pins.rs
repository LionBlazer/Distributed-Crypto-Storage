//! Closed installation namespaces for the two actual application owners.
//! There is no caller-selected profile, format, verifier, or accepting hook.
use crate::joint::JointBinding;
use crate::{Binding, Hash};
use version_journal::Genesis;
use work_finality::consensus::Context;

#[derive(Clone, Copy)]
pub(crate) enum Pins<'a> {
    Original(&'a Binding),
    Joint(&'a JointBinding),
}
#[derive(Clone, Copy)]
pub(crate) enum Format {
    Original,
    Joint,
}
impl<'a> Pins<'a> {
    pub(crate) fn id(self) -> Hash {
        match self {
            Self::Original(b) => b.id(),
            Self::Joint(b) => b.id(),
        }
    }
    pub(crate) fn context(self) -> &'a Context {
        match self {
            Self::Original(b) => b.initial_context(),
            Self::Joint(b) => b.initial_context(),
        }
    }
    pub(crate) fn genesis(self) -> &'a Genesis {
        match self {
            Self::Original(b) => b.journal_genesis(),
            Self::Joint(b) => b.journal_genesis(),
        }
    }
    pub(crate) fn format(self) -> Format {
        match self {
            Self::Original(_) => Format::Original,
            Self::Joint(_) => Format::Joint,
        }
    }
}
impl Format {
    pub(crate) fn profile(self) -> Hash {
        match self {
            Self::Original => crate::profile_digest(),
            Self::Joint => crate::joint::durable_profile_digest(),
        }
    }
    pub(crate) fn floor_magic(self) -> &'static [u8; 8] {
        match self {
            Self::Original => b"DCSRFL01",
            Self::Joint => b"DCSJFL01",
        }
    }
    pub(crate) fn record_magic(self) -> &'static [u8; 8] {
        match self {
            Self::Original => b"DCSRFR01",
            Self::Joint => b"DCSJFR01",
        }
    }
    pub(crate) fn header_check(self) -> &'static [u8] {
        match self {
            Self::Original => b"dcs/registry200-finality/floor-header-check/v1",
            Self::Joint => b"dcs/registry200-finality/joint-floor-header-check/v1",
        }
    }
    pub(crate) fn header_hash(self) -> &'static [u8] {
        match self {
            Self::Original => b"dcs/registry200-finality/floor-header/v1",
            Self::Joint => b"dcs/registry200-finality/joint-floor-header/v1",
        }
    }
    pub(crate) fn record_hash(self) -> &'static [u8] {
        match self {
            Self::Original => b"dcs/registry200-finality/floor-record/v1",
            Self::Joint => b"dcs/registry200-finality/joint-floor-record/v1",
        }
    }
    pub(crate) fn metadata_magic(self) -> &'static [u8; 8] {
        match self {
            Self::Original => b"DCSRFM01",
            Self::Joint => b"DCSJFM01",
        }
    }
    pub(crate) fn storage_profile(self) -> Hash {
        match self {
            Self::Original => crate::participant::participant_storage_profile_digest(),
            Self::Joint => crate::joint::participant_storage_profile_digest(),
        }
    }
    pub(crate) fn file_domain(self) -> &'static [u8] {
        match self {
            Self::Original => b"dcs/registry200-finality/participant-file-id/v1",
            Self::Joint => b"dcs/registry200-finality/joint-participant-file-id/v1",
        }
    }
    pub(crate) fn metadata_hash(self) -> &'static [u8] {
        match self {
            Self::Original => b"dcs/registry200-finality/participant-metadata/v1",
            Self::Joint => b"dcs/registry200-finality/joint-participant-metadata/v1",
        }
    }
}
