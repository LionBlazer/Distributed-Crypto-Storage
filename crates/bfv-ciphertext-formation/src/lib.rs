//! Bounded-noise BFV ciphertext formation under exact independently supplied producer commitments.
#![forbid(unsafe_code)]
pub mod circuit;
pub mod gold;
mod evidence;
mod statement;
mod witness;
pub use bfv_basis_convolution::{MODULI as Q, N};
pub use evidence::*;
use sha2::{Digest, Sha256};
pub use statement::{EncodedCommitment, Expected, Statement};
pub use witness::{EncodedOpening, ProverWitness};
pub const STREAMS: usize = 7;
pub const PUBLIC_VALUES: usize = 44;
pub const DELTA: [u64; 5] = [
    2868552913433,
    2398181390884,
    1315015483772,
    5109279048220,
    8726683229755,
];
pub const NOISE_DOMAIN: &[u8] = b"DCS/BFV-CIPHERTEXT-FORMATION-NOISE/v1";
pub fn root_offset(stream: usize) -> usize {
    match stream {
        0..=4 => 20 + 4 * stream,
        5 => 16,
        _ => 40,
    }
}
pub fn profile(h: &mut Sha256) {
    h.update(b"DCS/BFV-ciphertext-formation/full8192/signed-integer/v1/no-SQL-admission");
    h.update(bfv_basis_convolution::profile_digest());
    h.update(NOISE_DOMAIN);
    h.update(b"original-five-Basis-contexts/rawGold/original-encoded-context/rawW/new-noise/raw-signedGold");
    h.update(b"R=z63-2^62/k=z20-2^19/e=z6-20+slack40/W17+slack114688/shared-e-all5");
    h.update(b"7streams/21unconditional-P2/row0-prefix+0..7-carry8..15/row1carry+16..31/last-g1");
    for v in Q.into_iter().chain(DELTA).chain([
        N as u64,
        512,
        circuit::WIDTH as u64,
        44,
        592,
        5,
        114689,
        78307,
    ]) {
        h.update(v.to_le_bytes());
    }
    h.update(b"full-producer-identity/exact-original-context/complete-KeyPV33/full-setup-label/full-canonical-params+CT/q/ordered-five-BasisPV62");
}
pub fn profile_digest() -> [u8; 32] {
    let mut h = bfv_hiding_stark::profile_start(
        b"dcs/experiment/hiding-source-primitive-profile/v1",
        b"bfv-ciphertext-formation",
    );
    profile(&mut h);
    bfv_hiding_stark::profile_finish(h, circuit::WIDTH, 2)
}
#[cfg(test)]
mod tests;
