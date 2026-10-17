//! Fixed full-degree public PowerBasis RNS scaling, never SQL/key/proof authority.
#![forbid(unsafe_code)]
mod codec;
mod constants;
mod math;
#[cfg(feature = "plonky3")]
pub mod plonky3;
#[cfg(test)]
mod tests;

pub use codec::{
    Aux, AuxiliaryRow, Evaluation, Output, Request, decode_aux, decode_output, decode_request,
    encode_request,
};
pub use constants::{CoefficientConstants, SignedMagnitude, constants, profile_digest};
pub use math::evaluate_with_certificate;

pub use bfv_linear_circuit::{DEGREE, MODULI};
pub const PLAINTEXT: u64 = 114689;
pub const AUXILIARY_MODULI: [u64; 5] = [
    4611686018427322369,
    4611686018427289601,
    4611686018426454017,
    4611686018426257409,
    4611686018425815041,
];
pub const EXTENDED_MODULI: [u64; 10] = [
    MODULI[0],
    MODULI[1],
    MODULI[2],
    MODULI[3],
    MODULI[4],
    AUXILIARY_MODULI[0],
    AUXILIARY_MODULI[1],
    AUXILIARY_MODULI[2],
    AUXILIARY_MODULI[3],
    AUXILIARY_MODULI[4],
];
pub const AUXILIARY_ROW_BYTES: usize = 315;
pub const CARRIES: usize = 56;
pub(crate) const BASE: i128 = 1 << 16;
pub(crate) const CARRY_OFFSET: i128 = 1 << 24;
pub(crate) const W_OFFSET: u64 = 1 << 45;
pub(crate) const K_OFFSET: u128 = 1 << 64;

/// A single natural-order PowerBasis polynomial, not a serialized ciphertext or NTT claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    Extend5To10 = 1,
    Scale10To5 = 2,
}
impl Role {
    pub const fn input_moduli(self) -> &'static [u64] {
        match self {
            Self::Extend5To10 => &MODULI,
            Self::Scale10To5 => &EXTENDED_MODULI,
        }
    }
    pub const fn output_moduli(self) -> &'static [u64] {
        match self {
            Self::Extend5To10 => &EXTENDED_MODULI,
            Self::Scale10To5 => &MODULI,
        }
    }
    pub const fn computed_moduli(self) -> &'static [u64; 5] {
        match self {
            Self::Extend5To10 => &AUXILIARY_MODULI,
            Self::Scale10To5 => &MODULI,
        }
    }
    pub const fn input_coefficients(self) -> usize {
        self.input_moduli().len() * DEGREE
    }
    pub const fn output_coefficients(self) -> usize {
        self.output_moduli().len() * DEGREE
    }
    pub const fn request_bytes(self) -> usize {
        80 + self.input_coefficients() * 8
    }
    pub const fn output_bytes(self) -> usize {
        112 + self.output_coefficients() * 8
    }
    pub const fn aux_bytes(self) -> usize {
        144 + DEGREE * AUXILIARY_ROW_BYTES
    }
    pub const fn preprocessed_width(self) -> usize {
        4 * self.input_moduli().len() + 124
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Shape,
    Profile,
    Binding,
    NonCanonicalResidue,
    AuxiliaryRange,
    Arithmetic,
    MissingPreprocessing,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BFV scale circuit rejected {self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
