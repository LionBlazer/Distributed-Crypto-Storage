//! Full fixed-degree public ciphertext-derived native NTT relations, never SQL authority.
#![forbid(unsafe_code)]
mod codec;
mod math;
mod parameters;
#[cfg(feature = "plonky3")]
pub mod plonky3;
#[cfg(test)]
mod tests;
pub use bfv_fixed_geometry::{DEGREE, EXTENDED_MODULI};
pub use codec::{
    Aux, AuxiliaryRow, Evaluation, Output, Request, Stage, decode_aux, decode_output,
    decode_request, encode_request,
};
pub use math::evaluate_with_certificate;
pub use parameters::{Parameters, parameters, profile_digest};
pub const AUXILIARY_ROW_BYTES: usize = 45;
pub const CARRIES: usize = 7;
pub(crate) const BASE: i128 = 1 << 16;
pub(crate) const CARRY_OFFSET: i128 = 1 << 24;
pub(crate) const QUOTIENT_OFFSET: u128 = 1 << 64;
/// Index into the immutable Q5||P5 basis, never caller-provided modulus/root data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Basis(u8);
impl Basis {
    pub fn new(index: u8) -> Result<Self> {
        if index < 10 {
            Ok(Self(index))
        } else {
            Err(Error::Shape)
        }
    }
    pub const fn index(self) -> u8 {
        self.0
    }
    pub const fn modulus(self) -> u64 {
        EXTENDED_MODULI[self.0 as usize]
    }
}
/// Native SDK forward output order is preserved; it is not a natural NTT reordering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Direction {
    Forward = 1,
    Inverse = 2,
}
impl Direction {
    pub const fn stages(self) -> usize {
        match self {
            Self::Forward => 13,
            Self::Inverse => 14,
        }
    }
    pub const fn request_bytes(self) -> usize {
        80 + DEGREE * 8
    }
    pub const fn output_bytes(self) -> usize {
        112 + DEGREE * 8
    }
    pub const fn aux_bytes(self) -> usize {
        144 + self.stages() * DEGREE * AUXILIARY_ROW_BYTES
    }
    pub const fn preprocessed_width(self) -> usize {
        32 * self.stages()
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
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BFV NTT circuit rejected {self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
