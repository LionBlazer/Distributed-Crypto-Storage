//! Fixed public arithmetic stages of level0/0 relinearization, never the complete operation.
#![forbid(unsafe_code)]
mod codec;
mod math;
#[cfg(feature = "plonky3")]
pub mod plonky3;
mod profile;
pub mod routing;
#[cfg(test)]
mod tests;
pub use bfv_fixed_geometry::{DEGREE, MODULI};
pub use codec::{
    AccumulationRow, Aux, Evaluation, Output, Request, decode_aux, decode_output, decode_request,
    encode_request,
};
pub use math::evaluate_with_certificate;
pub use profile::profile_digest;
pub const EMBEDDING_AUXILIARY_ROW_BYTES: usize = 25;
pub const ACCUMULATION_AUXILIARY_ROW_BYTES: usize = 260;
pub const CARRIES: usize = 5;
pub(crate) const BASE: i128 = 1 << 16;
pub(crate) const CARRY_OFFSET: i128 = 1 << 24;
const fn embedding_bounds() -> [[u8; 5]; 5] {
    let mut out = [[0; 5]; 5];
    let mut i = 0;
    while i < 5 {
        let mut j = 0;
        while j < 5 {
            let bound = (MODULI[i] - 1) / MODULI[j];
            assert!(bound <= 2);
            out[i][j] = bound as u8;
            j += 1;
        }
        i += 1;
    }
    out
}
pub const EMBEDDING_QUOTIENT_BOUNDS: [[u8; 5]; 5] = embedding_bounds();
const fn accumulator_input_moduli() -> [u64; 85] {
    let mut out = [0; 85];
    let mut i = 0;
    while i < 85 {
        out[i] = MODULI[i / 17];
        i += 1;
    }
    out
}
const fn embedding_output_moduli() -> [u64; 25] {
    let mut out = [0; 25];
    let mut i = 0;
    while i < 25 {
        out[i] = MODULI[i % 5];
        i += 1;
    }
    out
}
const fn accumulator_output_moduli() -> [u64; 10] {
    let mut out = [0; 10];
    let mut i = 0;
    while i < 10 {
        out[i] = MODULI[i / 2];
        i += 1;
    }
    out
}
const ACCUMULATOR_INPUT_MODULI: [u64; 85] = accumulator_input_moduli();
const EMBEDDING_OUTPUT_MODULI: [u64; 25] = embedding_output_moduli();
const ACCUMULATOR_OUTPUT_MODULI: [u64; 10] = accumulator_output_moduli();
// These strict bounds justify every scalar field embedding and 48-bit limb split.
const _: () = {
    assert!(DEGREE == 8192);
    let mut i = 0;
    while i < 5 {
        assert!(MODULI[i] < (1u64 << 44));
        let mut j = 0;
        while j < 5 {
            assert!(EMBEDDING_QUOTIENT_BOUNDS[i][j] <= 2);
            j += 1;
        }
        i += 1;
    }
};

/// Both roles require complete level0/0 Q5 vectors. No key import or NTT is executed here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    Embed = 1,
    AccumulateAndAdd = 2,
}
impl Role {
    pub const fn input_moduli(self) -> &'static [u64] {
        match self {
            Self::Embed => &MODULI,
            Self::AccumulateAndAdd => &ACCUMULATOR_INPUT_MODULI,
        }
    }
    pub const fn output_moduli(self) -> &'static [u64] {
        match self {
            Self::Embed => &EMBEDDING_OUTPUT_MODULI,
            Self::AccumulateAndAdd => &ACCUMULATOR_OUTPUT_MODULI,
        }
    }
    pub const fn input_coefficients(self) -> usize {
        self.input_moduli().len() * DEGREE
    }
    pub const fn output_coefficients(self) -> usize {
        self.output_moduli().len() * DEGREE
    }
    pub const fn request_bytes(self) -> usize {
        112 + self.input_coefficients() * 8
    }
    pub const fn output_bytes(self) -> usize {
        144 + self.output_coefficients() * 8
    }
    pub const fn auxiliary_row_bytes(self) -> usize {
        match self {
            Self::Embed => EMBEDDING_AUXILIARY_ROW_BYTES,
            Self::AccumulateAndAdd => ACCUMULATION_AUXILIARY_ROW_BYTES,
        }
    }
    pub const fn aux_bytes(self) -> usize {
        176 + DEGREE * self.auxiliary_row_bytes()
    }
    pub const fn preprocessed_width(self) -> usize {
        match self {
            Self::Embed => 55,
            Self::AccumulateAndAdd => 365,
        }
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
        write!(f, "Relinearization arithmetic stage rejected {self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
