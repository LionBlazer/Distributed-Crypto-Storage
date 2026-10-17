//! Same fixed shared KeyAir; experimental Kind admission remains in this adapter.
pub(crate) use bfv_key_transform::circuit::TransformAir;
pub(crate) use bfv_key_transform::circuit::WIDTH;
#[cfg(test)]
pub(super) use bfv_key_transform::circuit::{CHECKPOINT, P2, RANGE, SALTS, VECTOR};
