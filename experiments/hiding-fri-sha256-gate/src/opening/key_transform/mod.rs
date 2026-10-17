//! Nonaccepting full-size BFV-secret transform prerequisite; no Owner key API.
pub(crate) mod air;
pub(in crate::opening) mod statement;
#[cfg(test)]
mod tests;
pub(in crate::opening) mod trace;

#[cfg(test)]
use crate::backend::TRACE_HEIGHT;
use crate::backend::{Backend, Config, Error, Val};
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::Proof;
use rand::{
    RngExt, SeedableRng,
    rngs::{StdRng, SysRng},
};
use sha2::Sha256;
use statement::{Expected, SetupDescriptor, Statement};
use trace::Witness;

pub(super) use bfv_key_transform::{BLOCKS, GADGETS, HASH_ROWS, N, psi, reverse, signed};
#[cfg(test)]
pub(super) use bfv_key_transform::{FIRST_STAGE, OUTPUT_ROW};
pub(crate) fn profile(hash: &mut Sha256) {
    bfv_key_transform::profile(hash);
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
