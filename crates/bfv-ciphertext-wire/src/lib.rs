//! Borrowed canonical wire preflight for the fixed level-zero BFV ciphertext.
//! Passing this gate is not SDK deserialization, encryption evidence or key authority.
#![forbid(unsafe_code)]

mod preflight;

pub use preflight::validate;

/// Complete ciphertext wire limit, checked before parsing any protobuf field.
pub const MAX_CIPHERTEXT_BYTES: usize = 512 * 1024;
/// Packed power-basis coefficient bytes in one polynomial, including all five moduli.
pub const PACKED_POLYNOMIAL_BYTES: usize = packed_polynomial_bytes();
/// Maximum canonical two-polynomial wire, including true variable-time metadata.
pub const MAX_CANONICAL_UNSEEDED_BYTES: usize =
    bfv_fixed_geometry::CIPHERTEXT_COMPONENTS * (PACKED_POLYNOMIAL_BYTES + 11 + 4);

const fn packed_polynomial_bytes() -> usize {
    let mut bits = 0usize;
    let mut index = 0;
    while index < bfv_fixed_geometry::MODULI.len() {
        bits += (u64::BITS - (bfv_fixed_geometry::MODULI[index] - 1).leading_zeros()) as usize;
        index += 1;
    }
    bfv_fixed_geometry::DEGREE * bits / 8
}

const _: () = assert!(PACKED_POLYNOMIAL_BYTES == 223232);
const _: () = assert!(MAX_CANONICAL_UNSEEDED_BYTES == 446494);
const _: () = assert!(MAX_CANONICAL_UNSEEDED_BYTES <= MAX_CIPHERTEXT_BYTES);

/// Failure before SDK decoding. No error contains or retains the submitted wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    ResourceLimit,
    InvalidEncoding,
}
impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ResourceLimit => f.write_str("BFV ciphertext wire exceeds its fixed byte limit"),
            Self::InvalidEncoding => f.write_str("Invalid canonical fixed BFV ciphertext wire"),
        }
    }
}
impl std::error::Error for WireError {}

#[cfg(test)]
mod tests;
