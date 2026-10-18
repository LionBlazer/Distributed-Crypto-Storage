//! Canonical public seeded key sources; no proof, secret access or key authority.
#![forbid(unsafe_code)]

mod cursor;
mod material;
mod prepared;
mod seed;

pub use material::{UnverifiedSeededRelinearizationKey, decode_seeded};
pub use prepared::{PreparedKey, PreparedKeyError};
pub use seed::UnverifiedExpandedSeededKey;

use bfv_fixed_geometry::{DEGREE, MODULI};
use std::fmt;

/// Ordered decomposition rows and original target bases of level zero.
pub const KEY_COMPONENTS: usize = 5;
/// Fixed packed PowerBasis bytes in each public c0 polynomial.
pub const PACKED_POLYNOMIAL_BYTES: usize = DEGREE * (43 + 43 + 44 + 44 + 44) / 8;
/// Largest canonical Rq envelope: repr2 + degree3 + coefficients tag/length4 + bool2.
pub const MAX_POLYNOMIAL_BYTES: usize = PACKED_POLYNOMIAL_BYTES + 11;
/// Exact maximum seeded level-zero key: five length-delimited Rq, seed32 and outer ksk.
pub const MAX_KEY_BYTES: usize = KEY_COMPONENTS * (MAX_POLYNOMIAL_BYTES + 4) + 34 + 4;

const _: () = assert!(DEGREE == 8192 && MODULI.len() == KEY_COMPONENTS);
const _: () = assert!(PACKED_POLYNOMIAL_BYTES == 223_232 && MAX_KEY_BYTES == 1_116_273);
const _: () = {
    let widths = [43, 43, 44, 44, 44];
    let mut index = 0;
    while index < KEY_COMPONENTS {
        assert!(u64::BITS - (MODULI[index] - 1).leading_zeros() == widths[index]);
        index += 1;
    }
};
const COEFFICIENTS: usize = KEY_COMPONENTS * DEGREE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The complete setup identity differs from the caller's independent expected identity.
    SetupMismatch,
    /// The fixed seeded-key or polynomial byte limit is exceeded.
    ByteLimit,
    /// The original protobuf is malformed, noncanonical or outside the fixed role.
    CanonicalEncoding,
    /// A packed public residue is not in its original coefficient modulus.
    Residue,
    /// The compiled fixed public modulus configuration could not be constructed.
    FixedParameters,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "public seeded key rejected: {self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests;
