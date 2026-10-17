//! Fixed salted BFV-secret coefficient commitment and genuine hiding transform proof.
#![forbid(unsafe_code)]
pub mod circuit;
mod evidence;
mod statement;
mod witness;
use bfv_hiding_stark::{TRACE_HEIGHT, Val};
pub use evidence::{
    Evidence, HEADER_BYTES, MAX_PROOF_BYTES, MAX_SEQUENCE_ELEMENTS, MAX_TOTAL_ELEMENTS,
    VerifiedTransform, prove, prove_statement, verify,
};
use p3_field::{PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use sha2::{Digest, Sha256};
pub use statement::{Expected, PUBLIC_VALUES, SetupDescriptor, Statement};
pub use witness::{ProverWitness, input_commitment, random_salt};

pub const LOG_N: usize = 13;
pub const N: usize = 1 << LOG_N;
pub const FIELDS: usize = 16 + N;
pub const BLOCKS: usize = FIELDS / 8;
pub const GADGETS: usize = 5;
pub const HASH_ROWS: usize = BLOCKS.div_ceil(GADGETS);
pub const TWIST_ROW: usize = 206;
pub const FIRST_STAGE: usize = 207;
pub const OUTPUT_ROW: usize = FIRST_STAGE + LOG_N;
pub const INPUT_DOMAIN: &[u8] = b"DCS/BFV-SECRET-COEFFICIENTS/v1";
pub const OUTPUT_DOMAIN: &[u8] = b"DCS/BFV-SECRET-ODD-EVALUATIONS/v1";

pub fn psi() -> Val {
    Val::two_adic_generator(LOG_N + 1)
}
pub fn reverse(index: usize) -> usize {
    index.reverse_bits() >> (usize::BITS as usize - LOG_N)
}
pub fn signed(value: i8) -> Val {
    if value >= 0 {
        Val::from_u8(value as u8)
    } else {
        -Val::from_u8(value.unsigned_abs())
    }
}
pub fn hash_phase(row: usize) -> Option<(usize, usize)> {
    if row < HASH_ROWS {
        Some((0, row))
    } else if (OUTPUT_ROW..OUTPUT_ROW + HASH_ROWS).contains(&row) {
        Some((1, row - OUTPUT_ROW))
    } else {
        None
    }
}
pub fn profile(hash: &mut Sha256) {
    hash.update(b"BFV-key-transform/two-independent-salted-roots/Goldilocks/v1");
    hash.update(INPUT_DOMAIN);
    hash.update(OUTPUT_DOMAIN);
    hash.update(b"natural-signed-s/z=s+20/0..40/twist-psi^rev13/DIT13/natural-odd-evaluations");
    hash.update(b"root8208=contextSHA8-salt4-zero4-vector8192/P2-overwrite8-cap4-reset0");
    hash.update(b"input0..205/hold205/twist206/stages207..219/output220..425/padding-hold");
    hash.update(b"five-unconditional-P2/last-active-checkpoint/range40x12/degree-bound5");
    for x in [
        N,
        LOG_N,
        FIELDS,
        BLOCKS,
        GADGETS,
        HASH_ROWS,
        TWIST_ROW,
        FIRST_STAGE,
        OUTPUT_ROW,
        circuit::WIDTH,
        PUBLIC_VALUES,
        TRACE_HEIGHT,
    ] {
        hash.update((x as u64).to_le_bytes());
    }
    hash.update(psi().as_canonical_u64().to_le_bytes());
}

/// Unchanged historical relation/suite digest; it is not setup authorization.
pub fn profile_digest() -> [u8; 32] {
    let mut hash = bfv_hiding_stark::profile_start(
        b"dcs/experiment/hiding-source-primitive-profile/v1",
        b"bfv-key-transform",
    );
    profile(&mut hash);
    bfv_hiding_stark::profile_finish(hash, circuit::WIDTH, 2)
}

#[cfg(test)]
mod tests;
