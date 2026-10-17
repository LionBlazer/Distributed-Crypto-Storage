//! Private dispatch for source research relations sharing one backend.
use std::borrow::Cow;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_matrix::dense::RowMajorMatrix;

use crate::air::CompressionAir;
use crate::backend::Val;
use crate::chacha::air::ChaChaAir;
use crate::poly1305::air::Poly1305Air;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Sha256,
    HChaCha20,
    ChaCha20,
    Poly1305Raw,
    Poly1305Padded,
    PairOpening,
    CanonicalIndexOpening,
    SelectionOpening,
    PackedCanonicalIndexOpening,
    FactorizedPackedCanonicalIndexOpening,
    StateCertificate,
    VersionSelection,
    SelectedEncoding,
    LockingSelection,
    VersionLockingSelection,
    BfvKeyTransform,
    BfvBasisConvolution,
    BfvLocalFormation,
    LockReturnedEncoding,
    BfvLockReturnedFormation,
    RegistryBootstrap,
    RegistryLifecycleBootstrap,
    RegistryLifecycle,
    RegistryLifecycleEncoding,
}

impl Kind {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::HChaCha20 => "hchacha20",
            Self::ChaCha20 => "chacha20",
            Self::Poly1305Raw => "poly1305-raw",
            Self::Poly1305Padded => "poly1305-padded",
            Self::PairOpening => "pair-opening",
            Self::CanonicalIndexOpening => "canonical-index-opening",
            Self::SelectionOpening => "selection-opening",
            Self::PackedCanonicalIndexOpening => "packed-canonical-index-opening",
            Self::FactorizedPackedCanonicalIndexOpening => {
                "factorized-packed-canonical-index-opening"
            }
            Self::StateCertificate => "state-certificate",
            Self::VersionSelection => "version-selection",
            Self::SelectedEncoding => "selected-encoding",
            Self::LockingSelection => "locking-selection",
            Self::VersionLockingSelection => "version-locking-selection",
            Self::BfvKeyTransform => "bfv-key-transform",
            Self::BfvBasisConvolution => "bfv-basis-convolution",
            Self::BfvLocalFormation => "bfv-local-formation",
            Self::LockReturnedEncoding => "lock-returned-encoding",
            Self::BfvLockReturnedFormation => "bfv-lock-returned-formation",
            Self::RegistryBootstrap => "registry-bootstrap",
            Self::RegistryLifecycleBootstrap => "registry-lifecycle-bootstrap",
            Self::RegistryLifecycle => "registry-lifecycle",
            Self::RegistryLifecycleEncoding => "registry-lifecycle-encoding",
        }
    }
}

pub(crate) trait PublicStatement {
    fn kind(&self) -> Kind;
    fn air(&self) -> PrimitiveAir;
    fn public_values(&self) -> Vec<Val>;
}

/// Existing public fixtures can generate their own trace; verifier statements cannot.
pub(crate) trait PrimitiveStatement: PublicStatement {
    fn trace(&self) -> RowMajorMatrix<Val>;
}

/// The enum keeps SDK constraint-folder bounds inside this standalone binary.
/// It is not a plugin interface or a production accepting-proof abstraction.
pub(crate) enum PrimitiveAir {
    Sha256(CompressionAir),
    ChaCha(ChaChaAir),
    Poly1305(Box<Poly1305Air>),
    Opening(Box<crate::opening::air::OpeningAir>),
    Selection(Box<crate::opening::selection::air::SelectionAir>),
    Encoding(Box<crate::opening::selection::encoding::air::EncodingAir>),
    Locking(Box<crate::opening::locking::air::LockingAir>),
    KeyTransform(Box<crate::opening::key_transform::air::TransformAir>),
    BasisConvolution(Box<crate::opening::basis_convolution::air::ConvolutionAir>),
    LocalFormation(Box<crate::opening::local_formation::air::LocalAir>),
    RegistryBootstrap(Box<crate::opening::registry_bootstrap::air::BootstrapAir>),
    LifecycleBootstrap(Box<crate::opening::registry_lifecycle::bootstrap::BootstrapAir>),
    Lifecycle(Box<crate::opening::registry_lifecycle::air::LifecycleAir>),
    LifecycleEncoding(Box<crate::opening::registry_lifecycle::encoding::air::EncodingAir>),
}

impl BaseAir<Val> for PrimitiveAir {
    fn width(&self) -> usize {
        match self {
            Self::Sha256(air) => air.width(),
            Self::ChaCha(air) => air.width(),
            Self::Poly1305(air) => air.width(),
            Self::Opening(air) => air.width(),
            Self::Selection(air) => air.width(),
            Self::Encoding(air) => air.width(),
            Self::Locking(air) => air.width(),
            Self::KeyTransform(air) => air.width(),
            Self::BasisConvolution(air) => air.width(),
            Self::LocalFormation(air) => air.width(),
            Self::RegistryBootstrap(air) => air.width(),
            Self::LifecycleBootstrap(air) => air.width(),
            Self::Lifecycle(air) => air.width(),
            Self::LifecycleEncoding(air) => air.width(),
        }
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        match self {
            Self::Sha256(air) => air.main_next_row_columns(),
            Self::ChaCha(air) => air.main_next_row_columns(),
            Self::Poly1305(air) => air.main_next_row_columns(),
            Self::Opening(air) => air.main_next_row_columns(),
            Self::Selection(air) => air.main_next_row_columns(),
            Self::Encoding(air) => air.main_next_row_columns(),
            Self::Locking(air) => air.main_next_row_columns(),
            Self::KeyTransform(air) => air.main_next_row_columns(),
            Self::BasisConvolution(air) => air.main_next_row_columns(),
            Self::LocalFormation(air) => air.main_next_row_columns(),
            Self::RegistryBootstrap(air) => air.main_next_row_columns(),
            Self::LifecycleBootstrap(air) => air.main_next_row_columns(),
            Self::Lifecycle(air) => air.main_next_row_columns(),
            Self::LifecycleEncoding(air) => air.main_next_row_columns(),
        }
    }

    fn num_public_values(&self) -> usize {
        match self {
            Self::Sha256(air) => air.num_public_values(),
            Self::ChaCha(air) => air.num_public_values(),
            Self::Poly1305(air) => air.num_public_values(),
            Self::Opening(air) => air.num_public_values(),
            Self::Selection(air) => air.num_public_values(),
            Self::Encoding(air) => air.num_public_values(),
            Self::Locking(air) => air.num_public_values(),
            Self::KeyTransform(air) => air.num_public_values(),
            Self::BasisConvolution(air) => air.num_public_values(),
            Self::LocalFormation(air) => air.num_public_values(),
            Self::RegistryBootstrap(air) => air.num_public_values(),
            Self::LifecycleBootstrap(air) => air.num_public_values(),
            Self::Lifecycle(air) => air.num_public_values(),
            Self::LifecycleEncoding(air) => air.num_public_values(),
        }
    }

    fn num_periodic_columns(&self) -> usize {
        match self {
            Self::Sha256(air) => air.num_periodic_columns(),
            Self::ChaCha(air) => air.num_periodic_columns(),
            Self::Poly1305(air) => air.num_periodic_columns(),
            Self::Opening(air) => air.num_periodic_columns(),
            Self::Selection(air) => air.num_periodic_columns(),
            Self::Encoding(air) => air.num_periodic_columns(),
            Self::Locking(air) => air.num_periodic_columns(),
            Self::KeyTransform(air) => air.num_periodic_columns(),
            Self::BasisConvolution(air) => air.num_periodic_columns(),
            Self::LocalFormation(air) => air.num_periodic_columns(),
            Self::RegistryBootstrap(air) => air.num_periodic_columns(),
            Self::LifecycleBootstrap(air) => air.num_periodic_columns(),
            Self::Lifecycle(air) => air.num_periodic_columns(),
            Self::LifecycleEncoding(air) => air.num_periodic_columns(),
        }
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        match self {
            Self::Sha256(air) => air.periodic_columns(),
            Self::ChaCha(air) => air.periodic_columns(),
            Self::Poly1305(air) => air.periodic_columns(),
            Self::Opening(air) => air.periodic_columns(),
            Self::Selection(air) => air.periodic_columns(),
            Self::Encoding(air) => air.periodic_columns(),
            Self::Locking(air) => air.periodic_columns(),
            Self::KeyTransform(air) => air.periodic_columns(),
            Self::BasisConvolution(air) => air.periodic_columns(),
            Self::LocalFormation(air) => air.periodic_columns(),
            Self::RegistryBootstrap(air) => air.periodic_columns(),
            Self::LifecycleBootstrap(air) => air.periodic_columns(),
            Self::Lifecycle(air) => air.periodic_columns(),
            Self::LifecycleEncoding(air) => air.periodic_columns(),
        }
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        match self {
            Self::Sha256(air) => air.max_constraint_degree(),
            Self::ChaCha(air) => air.max_constraint_degree(),
            Self::Poly1305(air) => air.max_constraint_degree(),
            Self::Opening(air) => air.max_constraint_degree(),
            Self::Selection(air) => air.max_constraint_degree(),
            Self::Encoding(air) => air.max_constraint_degree(),
            Self::Locking(air) => air.max_constraint_degree(),
            Self::KeyTransform(air) => air.max_constraint_degree(),
            Self::BasisConvolution(air) => air.max_constraint_degree(),
            Self::LocalFormation(air) => air.max_constraint_degree(),
            Self::RegistryBootstrap(air) => air.max_constraint_degree(),
            Self::LifecycleBootstrap(air) => air.max_constraint_degree(),
            Self::Lifecycle(air) => air.max_constraint_degree(),
            Self::LifecycleEncoding(air) => air.max_constraint_degree(),
        }
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for PrimitiveAir {
    fn eval(&self, builder: &mut AB) {
        match self {
            Self::Sha256(air) => air.eval(builder),
            Self::ChaCha(air) => air.eval(builder),
            Self::Poly1305(air) => air.eval(builder),
            Self::Opening(air) => air.eval(builder),
            Self::Selection(air) => air.eval(builder),
            Self::Encoding(air) => air.eval(builder),
            Self::Locking(air) => air.eval(builder),
            Self::KeyTransform(air) => air.eval(builder),
            Self::BasisConvolution(air) => air.eval(builder),
            Self::LocalFormation(air) => air.eval(builder),
            Self::RegistryBootstrap(air) => air.eval(builder),
            Self::LifecycleBootstrap(air) => air.eval(builder),
            Self::Lifecycle(air) => air.eval(builder),
            Self::LifecycleEncoding(air) => air.eval(builder),
        }
    }
}
