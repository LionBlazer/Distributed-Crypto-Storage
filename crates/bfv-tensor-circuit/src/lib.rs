//! Complete public NTT-domain BFV tensor arithmetic, never relinearization or SQL authority.
#![forbid(unsafe_code)]
#[cfg(any(feature = "plonky3", feature = "multistark"))]
mod air_equation;
mod codec;
mod math;
#[cfg(feature = "multistark")]
pub mod multistark;
#[cfg(feature = "plonky3")]
pub mod plonky3;
mod profile;
#[cfg(test)]
mod tests;
pub use bfv_fixed_geometry::{DEGREE, EXTENDED_MODULI};
pub use codec::{
    Aux, AuxiliaryRow, Evaluation, Output, Request, decode_aux, decode_output, decode_request,
    encode_request,
};
pub use math::evaluate_with_certificate;
pub use profile::profile_digest;
pub const INPUT_POLYNOMIALS: usize = 4;
pub const OUTPUT_POLYNOMIALS: usize = 3;
pub const AUXILIARY_ROW_BYTES: usize = 108;
pub const CARRIES: usize = 7;
pub const PREPROCESSED_WIDTH: usize = 61;
pub(crate) const BASE: i128 = 1 << 16;
pub(crate) const CARRY_OFFSET: i128 = 1 << 24;
/// The fixed mathematical relation, ordered as d0,d1,d2 and a0,a1,b0,b1.
pub(crate) const TERMS: [&[(usize, usize)]; 3] = [&[(0, 2)], &[(0, 3), (1, 2)], &[(1, 3)]];
/// Selects exactly one immutable Q5||P5 modulus, not an arbitrary caller parameter.
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
    pub const fn request_bytes(self) -> usize {
        80 + INPUT_POLYNOMIALS * DEGREE * 8
    }
    pub const fn output_bytes(self) -> usize {
        112 + OUTPUT_POLYNOMIALS * DEGREE * 8
    }
    pub const fn aux_bytes(self) -> usize {
        144 + DEGREE * AUXILIARY_ROW_BYTES
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
        write!(f, "BFV tensor circuit rejected {self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
