//! Private dispatch for the public-fixture relations sharing one backend.
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
}

impl Kind {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::HChaCha20 => "hchacha20",
            Self::ChaCha20 => "chacha20",
            Self::Poly1305Raw => "poly1305-raw",
            Self::Poly1305Padded => "poly1305-padded",
        }
    }
}

pub(crate) trait PrimitiveStatement {
    fn kind(&self) -> Kind;
    fn air(&self) -> PrimitiveAir;
    fn trace(&self) -> RowMajorMatrix<Val>;
    fn public_values(&self) -> Vec<Val>;
}

/// The enum keeps SDK constraint-folder bounds inside this standalone binary.
/// It is not a plugin interface or a production accepting-proof abstraction.
pub(crate) enum PrimitiveAir {
    Sha256(CompressionAir),
    ChaCha(ChaChaAir),
    Poly1305(Box<Poly1305Air>),
}

impl BaseAir<Val> for PrimitiveAir {
    fn width(&self) -> usize {
        match self {
            Self::Sha256(air) => air.width(),
            Self::ChaCha(air) => air.width(),
            Self::Poly1305(air) => air.width(),
        }
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        match self {
            Self::Sha256(air) => air.main_next_row_columns(),
            Self::ChaCha(air) => air.main_next_row_columns(),
            Self::Poly1305(air) => air.main_next_row_columns(),
        }
    }

    fn num_public_values(&self) -> usize {
        match self {
            Self::Sha256(air) => air.num_public_values(),
            Self::ChaCha(air) => air.num_public_values(),
            Self::Poly1305(air) => air.num_public_values(),
        }
    }

    fn num_periodic_columns(&self) -> usize {
        match self {
            Self::Sha256(air) => air.num_periodic_columns(),
            Self::ChaCha(air) => air.num_periodic_columns(),
            Self::Poly1305(air) => air.num_periodic_columns(),
        }
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        match self {
            Self::Sha256(air) => air.periodic_columns(),
            Self::ChaCha(air) => air.periodic_columns(),
            Self::Poly1305(air) => air.periodic_columns(),
        }
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        match self {
            Self::Sha256(air) => air.max_constraint_degree(),
            Self::ChaCha(air) => air.max_constraint_degree(),
            Self::Poly1305(air) => air.max_constraint_degree(),
        }
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for PrimitiveAir {
    fn eval(&self, builder: &mut AB) {
        match self {
            Self::Sha256(air) => air.eval(builder),
            Self::ChaCha(air) => air.eval(builder),
            Self::Poly1305(air) => air.eval(builder),
        }
    }
}
