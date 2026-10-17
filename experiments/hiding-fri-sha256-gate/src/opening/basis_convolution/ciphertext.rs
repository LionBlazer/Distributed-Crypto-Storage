//! Exact shared canonical full-ciphertext decoder.
pub(in crate::opening) use bfv_basis_convolution::{
    CanonicalCiphertext, VARIANCE, parameters, setup_digest,
};
#[cfg(test)]
pub(in crate::opening) use bfv_basis_convolution::{
    MAX_CANONICAL_UNSEEDED_BYTES, MAX_CIPHERTEXT_BYTES, MAX_PARAMETER_BYTES, MODULI, PLAINTEXT,
};
