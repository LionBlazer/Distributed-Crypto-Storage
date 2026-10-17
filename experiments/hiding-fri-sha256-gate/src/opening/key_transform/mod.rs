//! Nonaccepting full-size BFV-secret transform prerequisite; no Owner key API.
pub(crate) mod air;
pub(in crate::opening) mod statement;
#[cfg(test)]
mod tests;
pub(in crate::opening) mod trace;

use crate::backend::{Backend, Config, Error, TRACE_HEIGHT, Val};
use p3_field::{PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_uni_stark::Proof;
use rand::{
    RngExt, SeedableRng,
    rngs::{StdRng, SysRng},
};
use sha2::{Digest, Sha256};
use statement::{Expected, SetupDescriptor, Statement};
use trace::Witness;

pub(super) const LOG_N: usize = 13;
pub(super) const N: usize = 1 << LOG_N;
pub(super) const FIELDS: usize = 16 + N;
pub(super) const BLOCKS: usize = FIELDS / 8;
pub(super) const GADGETS: usize = 5;
pub(super) const HASH_ROWS: usize = BLOCKS.div_ceil(GADGETS);
pub(super) const TWIST_ROW: usize = 206;
pub(super) const FIRST_STAGE: usize = 207;
pub(super) const OUTPUT_ROW: usize = FIRST_STAGE + LOG_N;
pub(super) const INPUT_DOMAIN: &[u8] = b"DCS/BFV-SECRET-COEFFICIENTS/v1";
pub(super) const OUTPUT_DOMAIN: &[u8] = b"DCS/BFV-SECRET-ODD-EVALUATIONS/v1";

pub(super) fn psi() -> Val {
    Val::two_adic_generator(LOG_N + 1)
}
pub(super) fn reverse(index: usize) -> usize {
    index.reverse_bits() >> (usize::BITS as usize - LOG_N)
}
pub(super) fn signed(value: i8) -> Val {
    if value >= 0 {
        Val::from_u8(value as u8)
    } else {
        -Val::from_u8(value.unsigned_abs())
    }
}
pub(super) fn hash_phase(row: usize) -> Option<(usize, usize)> {
    if row < HASH_ROWS {
        Some((0, row))
    } else if (OUTPUT_ROW..OUTPUT_ROW + HASH_ROWS).contains(&row) {
        Some((1, row - OUTPUT_ROW))
    } else {
        None
    }
}
pub(crate) fn profile(hash: &mut Sha256) {
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
        air::WIDTH,
        statement::PUBLIC_VALUES,
        TRACE_HEIGHT,
    ] {
        hash.update((x as u64).to_le_bytes());
    }
    hash.update(psi().as_canonical_u64().to_le_bytes());
}
pub(in crate::opening) fn verify(
    expected: &Expected,
    statement: &Statement,
    proof: &Proof<Config>,
) -> Result<(), Error> {
    statement.require_expected(expected)?;
    Backend::new(statement)?.verify(statement, proof)
}
fn salt(rng: &mut StdRng) -> [Val; 4] {
    core::array::from_fn(|_| rng.random::<Val>())
}
fn public_fixture(input_salt: [Val; 4], output_salt: [Val; 4]) -> (Statement, Witness) {
    // Explicitly PUBLIC NONSECRET, not an extracted Owner key or entropy sample.
    let coefficients = (0..N)
        .map(|i| ((i * 17 + i / 19) % 41) as i8 - 20)
        .collect();
    let witness = Witness::new(coefficients, input_salt, output_salt).unwrap();
    let descriptor = SetupDescriptor {
        database: [0x42; 16],
        key_domain: [0x71; 16],
        public_setup_digest: [0x95; 32],
        key_epoch: 1,
    };
    (witness.statement(descriptor), witness)
}
pub(crate) fn gate(mode: &str) -> Result<(), Error> {
    if mode == "security" {
        // No witness, transform, trace, FFT commitment or proof is generated.
        let expected = Expected {
            descriptor: SetupDescriptor {
                database: [0x42; 16],
                key_domain: [0x71; 16],
                public_setup_digest: [0x95; 32],
                key_epoch: 1,
            },
            coefficients: [Val::ZERO; 4],
        };
        return crate::security(
            &Statement {
                expected,
                transformed: [Val::ZERO; 4],
            },
            "public-shape",
        );
    }
    if mode != "prove" {
        return Err(Error::Shape);
    }
    let mut rng = StdRng::try_from_rng(&mut SysRng).map_err(|_| Error::Randomness)?;
    let (statement, witness) = public_fixture(salt(&mut rng), salt(&mut rng));
    let backend =
        crate::prepare_gate(&statement, mode, "public-nonsecret-key")?.ok_or(Error::Shape)?;
    let started = std::time::Instant::now();
    let proof = backend.prove_with_trace(&statement, || witness.trace(&statement))?;
    let proving = started.elapsed();
    let started = std::time::Instant::now();
    verify(&statement.expected, &statement, &proof)?;
    println!(
        "{{\"stage\":\"verified_experimental_bfv_key_transform\",\"proving_ms\":{},\"verification_ms\":{}}}",
        proving.as_secs_f64() * 1000.0,
        started.elapsed().as_secs_f64() * 1000.0
    );
    Ok(())
}

#[cfg(test)]
fn fixture_descriptor_for_test() -> SetupDescriptor {
    SetupDescriptor {
        database: [0x42; 16],
        key_domain: [0x71; 16],
        public_setup_digest: [0x95; 32],
        key_epoch: 1,
    }
}
