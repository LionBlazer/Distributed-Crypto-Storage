use crate::*;
use p3_field::PrimeField64;
use sha2::{Digest, Sha256};
/// Begin the exact suite envelope with a caller-owned protocol namespace/name.
pub fn profile_start(namespace: &[u8], name: &[u8]) -> Sha256 {
    let mut hash = Sha256::new();
    hash.update(namespace);
    hash.update(b"p3-0.8.0/a21e3ed42905040ad49c519e402f018381c12d0c");
    hash.update(b"Goldilocks/Poseidon2-12/rate8/digest4/cap0/arity2");
    hash.update(name);
    hash
}
/// Finish the unchanged fixed-suite envelope after the caller's relation payload.
pub fn profile_finish(mut hash: Sha256, width: usize, opening_points: usize) -> [u8; 32] {
    hash.update(b"rand0.10.3/StdRng/independent-OS-seeds");
    hash.update(b"no-preprocessing/no-grinding/final-poly-log0/fri-arity-log1");
    for value in [
        TRACE_LOG_HEIGHT,
        LOG_BLOWUP,
        QUERIES,
        EXTENSION_DEGREE,
        RANDOM_CODEWORDS,
        SALT_ELEMENTS,
        SECURITY_BITS,
        MODULUS_BITS,
        width,
        opening_points,
    ] {
        hash.update((value as u64).to_le_bytes());
    }
    hash.update(Val::ORDER_U64.to_le_bytes());
    hash.finalize().into()
}
