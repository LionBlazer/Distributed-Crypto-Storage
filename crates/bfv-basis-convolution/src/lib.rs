//! Exact one-basis negacyclic convolution with canonical complete public ciphertext binding.
#![forbid(unsafe_code)]
mod ciphertext;
pub mod circuit;
mod evidence;
mod preflight;
mod statement;
mod witness;
use bfv_hiding_stark::TRACE_HEIGHT;
pub use bfv_key_transform::{BLOCKS, GADGETS, HASH_ROWS, N, psi, reverse};
pub use ciphertext::*;
pub use evidence::*;
use p3_field::PrimeField64;
use sha2::{Digest, Sha256};
pub use statement::{
    Expected, INPUT_ROOT, OUTPUT_ROOT, PUBLIC_VALUES, PublicInput, Statement, words,
};
pub use witness::ProverWitness;
const _: () = assert!(N == bfv_fixed_geometry::DEGREE);
pub const MULTIPLY_ROW: usize = 206;
pub const FIRST_STAGE: usize = 207;
pub const SCALE_ROW: usize = 220;
pub const OUTPUT_ROW: usize = 221;
pub const OUTPUT_DOMAIN: &[u8] = b"DCS/BFV-BASIS-NEGACYCLIC-RESIDUES/v1";
pub fn hash_phase(row: usize) -> Option<(usize, usize)> {
    if row < HASH_ROWS {
        Some((0, row))
    } else if (OUTPUT_ROW..OUTPUT_ROW + HASH_ROWS).contains(&row) {
        Some((1, row - OUTPUT_ROW))
    } else {
        None
    }
}
pub fn profile(h: &mut Sha256) {
    h.update(b"BFV-one-basis-convolution/full-canonical-ciphertext/Goldilocks/v1");
    h.update(OUTPUT_DOMAIN);
    h.update(b"original-KeyTransform-role1/raw-natural-Shat/input0..205/hold205/multiply-rev13-206/inverseDIT207..219/scale-untwist220/output221..426");
    h.update(b"five-unconditional-P2/context8-salt4-zero4-vector8192/last-active-checkpoint/degree-bound5");
    h.update(b"fixed-upstream-params/N8192/t114689/variance10/five-qi/level0/two-Ntt/canonical-roundtrip/full-ct-SHA256/basis0..4");
    for q in ciphertext::MODULI {
        h.update(q.to_le_bytes());
    }
    for x in [
        N,
        GADGETS,
        BLOCKS,
        HASH_ROWS,
        MULTIPLY_ROW,
        FIRST_STAGE,
        SCALE_ROW,
        OUTPUT_ROW,
        circuit::WIDTH,
        statement::PUBLIC_VALUES,
        TRACE_HEIGHT,
    ] {
        h.update((x as u64).to_le_bytes());
    }
    h.update(psi().as_canonical_u64().to_le_bytes());
}
pub fn profile_digest() -> [u8; 32] {
    let mut hash = bfv_hiding_stark::profile_start(
        b"dcs/experiment/hiding-source-primitive-profile/v1",
        b"bfv-basis-convolution",
    );
    profile(&mut hash);
    bfv_hiding_stark::profile_finish(hash, circuit::WIDTH, 2)
}
#[cfg(test)]
mod tests;
