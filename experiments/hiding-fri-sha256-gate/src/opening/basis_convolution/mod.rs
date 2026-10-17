//! Public nonsecret fixture gate for one FULL ciphertext basis; not BFV formation acceptance.
pub(crate) mod air;
pub(in crate::opening) mod ciphertext;
pub(in crate::opening) mod statement;
#[cfg(test)]
mod tests;
pub(in crate::opening) mod trace;

use crate::backend::{Backend, Config, Error, TRACE_HEIGHT, Val};
use crate::opening::key_transform::{
    self, statement::SetupDescriptor, trace::Witness as KeyWitness,
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_uni_stark::Proof;
use rand::{
    RngExt, SeedableRng,
    rngs::{StdRng, SysRng},
};
use sha2::{Digest, Sha256};
use statement::{Expected, Statement};
use trace::Witness;

pub(super) use key_transform::{BLOCKS, GADGETS, HASH_ROWS, N, psi, reverse};
pub(super) const MULTIPLY_ROW: usize = 206;
pub(super) const FIRST_STAGE: usize = 207;
pub(super) const SCALE_ROW: usize = 220;
pub(super) const OUTPUT_ROW: usize = 221;
pub(super) const OUTPUT_DOMAIN: &[u8] = b"DCS/BFV-BASIS-NEGACYCLIC-RESIDUES/v1";
pub(super) fn hash_phase(row: usize) -> Option<(usize, usize)> {
    if row < HASH_ROWS {
        Some((0, row))
    } else if (OUTPUT_ROW..OUTPUT_ROW + HASH_ROWS).contains(&row) {
        Some((1, row - OUTPUT_ROW))
    } else {
        None
    }
}
pub(crate) fn profile(h: &mut Sha256) {
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
        air::WIDTH,
        statement::PUBLIC_VALUES,
        TRACE_HEIGHT,
    ] {
        h.update((x as u64).to_le_bytes());
    }
    h.update(psi().as_canonical_u64().to_le_bytes());
}
struct CompositeProof {
    key: Option<Proof<Config>>,
    convolution: Proof<Config>,
}
pub(in crate::opening) fn prove_child(
    expected: &Expected,
    statement: &Statement,
    key: &Proof<Config>,
    factory: impl FnOnce() -> Result<p3_matrix::dense::RowMajorMatrix<Val>, Error>,
) -> Result<Proof<Config>, Error> {
    statement.require_expected(expected)?;
    key_transform::verify(&expected.key().expected, expected.key(), key)?;
    Backend::new(statement)?.prove_with_trace(statement, factory)
}
pub(in crate::opening) fn verify_child(
    expected: &Expected,
    statement: &Statement,
    key: &Proof<Config>,
    proof: &Proof<Config>,
) -> Result<(), Error> {
    statement.require_expected(expected)?;
    key_transform::verify(&expected.key().expected, expected.key(), key)?;
    Backend::new(statement)?.verify(statement, proof)
}
fn prove_with_trace(
    expected: &Expected,
    statement: &Statement,
    key: &KeyWitness,
    factory: impl FnOnce() -> Result<p3_matrix::dense::RowMajorMatrix<Val>, Error>,
) -> Result<CompositeProof, Error> {
    statement.require_expected(expected)?;
    let source = expected.key();
    let b = Backend::new(source)?;
    let key_proof = b.prove_with_trace(source, || key.trace(source))?;
    // Admission is actual cryptographic source verification, never a trusted marker.
    drop(b);
    let convolution = prove_child(expected, statement, &key_proof, factory)?;
    Ok(CompositeProof {
        key: Some(key_proof),
        convolution,
    })
}
fn verify(expected: &Expected, statement: &Statement, proof: &CompositeProof) -> Result<(), Error> {
    statement.require_expected(expected)?;
    let key = proof.key.as_ref().ok_or(Error::Shape)?;
    verify_child(expected, statement, key, &proof.convolution)
}
fn salt(rng: &mut StdRng) -> [Val; 4] {
    core::array::from_fn(|_| rng.random::<Val>())
}

/// NO supplied key or exporter: this function creates an explicitly PUBLIC NONSECRET fixture.
fn public_fixture(
    output_salt: [Val; 4],
    key_salts: [[Val; 4]; 2],
    basis: usize,
    caller_noise_seed: [u8; 32],
) -> Result<(Statement, Witness, KeyWitness), Error> {
    public_fixture_from_original(
        PublicFixtureInput {
            original: [255, 0, 255, 128, 0, 65535, 256, 255, 1, 1, 1, 1],
            descriptor: SetupDescriptor {
                database: [0x42; 16],
                key_domain: [0x71; 16],
                public_setup_digest: ciphertext::setup_digest(),
                key_epoch: 1,
            },
            request: [0x72; 32],
            caller_noise_seed,
        },
        output_salt,
        key_salts,
        basis,
    )
}
/// Experimental PUBLIC NONSECRET fixture only: key seed is fixed internally, never imported.
pub(in crate::opening) struct PublicFixtureInput {
    pub(in crate::opening) original: [u64; 12],
    pub(in crate::opening) descriptor: SetupDescriptor,
    pub(in crate::opening) request: [u8; 32],
    pub(in crate::opening) caller_noise_seed: [u8; 32],
}
pub(in crate::opening) fn public_fixture_from_original(
    input: PublicFixtureInput,
    output_salt: [Val; 4],
    key_salts: [[Val; 4]; 2],
    basis: usize,
) -> Result<(Statement, Witness, KeyWitness), Error> {
    let (statement, witness, key, _) = build_public_fixture(
        input,
        output_salt,
        key_salts,
        basis,
        FixturePublicMaterial::Omitted,
    )?;
    Ok((statement, witness, key))
}
// Fixture construction request only, never a proof/authority flag.
enum FixturePublicMaterial {
    Omitted,
    Rows16,
}
/// Only this explicitly nonsecret fixture owns its client key. No key bytes,
/// references, import/export or key callback are exposed to the peer/job module.
pub(in crate::opening) struct PublicFixtureClient {
    key: fhe::bfv::SecretKey,
    parameters: std::sync::Arc<fhe::bfv::BfvParameters>,
    setup: bfv_query_core::PublicSetup,
}
impl PublicFixtureClient {
    pub(in crate::opening) fn setup(&self) -> &bfv_query_core::PublicSetup {
        &self.setup
    }
    /// Client fixture completion ONLY. Caller must first check the exact BFV proof;
    /// this decoder itself never establishes source/computation/SQL acceptance.
    pub(in crate::opening) fn decrypt_product_unverified(
        &self,
        output: &[u8],
    ) -> Result<Vec<u64>, Error> {
        use fhe::bfv::{Ciphertext, Encoding};
        use fhe_math::rq::{Poly, Representation, traits::TryConvertFrom};
        use fhe_traits::{FheDecoder, FheDecrypter};
        let (_, coefficients) =
            bfv_product_circuit::decode_output(output).map_err(|_| Error::Shape)?;
        let context = self
            .parameters
            .context_at_level(0)
            .map_err(|_| Error::Shape)?;
        let polys = coefficients
            .as_chunks::<{ 5 * N }>()
            .0
            .iter()
            .map(|row| Poly::try_convert_from(row.to_vec(), context, true, Representation::Ntt))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::Shape)?;
        let ct = Ciphertext::new(polys, &self.parameters).map_err(|_| Error::Shape)?;
        let pt = self.key.try_decrypt(&ct).map_err(|_| Error::Shape)?;
        Vec::<u64>::try_decode(&pt, Encoding::simd()).map_err(|_| Error::Shape)
    }
}
pub(in crate::opening) fn public_fixture_with_setup(
    input: PublicFixtureInput,
    output_salt: [Val; 4],
    key_salts: [[Val; 4]; 2],
    basis: usize,
) -> Result<(Statement, Witness, KeyWitness, PublicFixtureClient), Error> {
    let (s, w, key, client) = build_public_fixture(
        input,
        output_salt,
        key_salts,
        basis,
        FixturePublicMaterial::Rows16,
    )?;
    Ok((s, w, key, client.ok_or(Error::Shape)?))
}
fn build_public_fixture(
    input: PublicFixtureInput,
    output_salt: [Val; 4],
    key_salts: [[Val; 4]; 2],
    basis: usize,
    material: FixturePublicMaterial,
) -> Result<(Statement, Witness, KeyWitness, Option<PublicFixtureClient>), Error> {
    use fhe::bfv::{Ciphertext, Encoding, Plaintext, SecretKey};
    use fhe_traits::{
        DeserializeParametrized, FheDecoder, FheDecrypter, FheEncoder, FheEncrypter, Serialize,
    };
    use rand09::SeedableRng;
    let par = ciphertext::parameters();
    let mut key_rng = rand09::rngs::StdRng::from_seed([0x53; 32]);
    let mut replay = key_rng.clone();
    let key = SecretKey::random(&par, &mut key_rng);
    let s =
        fhe_util::sample_vec_cbd(N, ciphertext::VARIANCE, &mut replay).map_err(|_| Error::Shape)?;
    if fhe::proto::bfv::SecretKey::from(&key).coeffs != s {
        return Err(Error::Shape);
    }
    let encoded_key = key.to_bytes();
    let restored = SecretKey::from_bytes(&encoded_key, &par).map_err(|_| Error::Shape)?;
    if restored.to_bytes() != encoded_key || fhe::proto::bfv::SecretKey::from(&restored).coeffs != s
    {
        return Err(Error::Shape);
    }
    if input.original[..4].iter().any(|v| *v > 255)
        || input.original[4..8].iter().any(|v| *v > 65535)
        || input.original[8..].iter().any(|v| *v > 1)
    {
        return Err(Error::Shape);
    }
    let mut slots = vec![0u64; N];
    slots[..4].copy_from_slice(&input.original[..4]);
    slots[4096..4100].copy_from_slice(&input.original[4..8]);
    slots[512..516].copy_from_slice(&input.original[8..]);
    let pt = Plaintext::try_encode(slots.as_slice(), Encoding::simd(), &par)
        .map_err(|_| Error::Shape)?;
    // The caller seed controls CBD noise only. Upstream independently samples A from its OS RNG.
    let mut noise = rand09::rngs::StdRng::from_seed(input.caller_noise_seed);
    let ct: Ciphertext = key.try_encrypt(&pt, &mut noise).map_err(|_| Error::Shape)?;
    let decoded: Vec<u64> = Vec::try_decode(
        &key.try_decrypt(&ct).map_err(|_| Error::Shape)?,
        Encoding::simd(),
    )
    .map_err(|_| Error::Shape)?;
    if decoded != slots {
        return Err(Error::Shape);
    }
    let key_witness = KeyWitness::new(
        s.into_iter()
            .map(i8::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::Shape)?,
        key_salts[0],
        key_salts[1],
    )?;
    let descriptor = input.descriptor;
    let key_statement = key_witness.statement(descriptor);
    let expected = Expected::new(
        key_statement,
        &par.to_bytes(),
        &ct.to_bytes(),
        input.request,
        basis,
    )?;
    let witness = Witness::new(&key_witness, output_salt);
    let statement = witness.statement(expected);
    let client = match material {
        FixturePublicMaterial::Omitted => None,
        FixturePublicMaterial::Rows16 => {
            use fhe::bfv::{EvaluationKeyBuilder, RelinearizationKey};
            let relin = RelinearizationKey::new(&key, &mut rand09::rng())
                .map_err(|_| Error::Shape)?
                .to_bytes();
            let mut builder = EvaluationKeyBuilder::new(&key).map_err(|_| Error::Shape)?;
            for shift in [1, 2, 4, 8, 16, 32, 64] {
                builder
                    .enable_column_rotation(shift)
                    .map_err(|_| Error::Shape)?;
            }
            let rotations = builder
                .build(&mut rand09::rng())
                .map_err(|_| Error::Shape)?
                .to_bytes();
            drop(builder);
            let setup = bfv_query_core::PublicSetup::from_public_material(
                bfv_query_core::Geometry::Rows16,
                &par.to_bytes(),
                &relin,
                &rotations,
            )
            .map_err(|_| Error::Shape)?;
            Some(PublicFixtureClient {
                key,
                parameters: par,
                setup,
            })
        }
    };
    Ok((statement, witness, key_witness, client))
}
pub(crate) fn gate(mode: &str) -> Result<(), Error> {
    if mode == "security" {
        // Same real PUBLIC NONSECRET encryption fixture; no AIR trace, proof or PCS commitment.
        let (statement, _, _) = public_fixture([Val::ZERO; 4], [[Val::ZERO; 4]; 2], 0, [0x45; 32])?;
        return crate::security(&statement, "public-nonsecret-upstream-ciphertext");
    }
    if mode != "prove" {
        return Err(Error::Shape);
    }
    let mut rng = StdRng::try_from_rng(&mut SysRng).map_err(|_| Error::Randomness)?;
    let (statement, witness, key) = public_fixture(
        salt(&mut rng),
        [salt(&mut rng), salt(&mut rng)],
        0,
        [0x45; 32],
    )?;
    crate::security(&statement, "public-nonsecret-upstream-ciphertext")?;
    let started = std::time::Instant::now();
    let proof = prove_with_trace(&statement.expected, &statement, &key, || {
        witness.trace(&statement)
    })?;
    let proving = started.elapsed();
    let started = std::time::Instant::now();
    verify(&statement.expected, &statement, &proof)?;
    println!(
        "{{\"stage\":\"verified_experimental_bfv_basis_convolution\",\"proving_ms\":{},\"verification_ms\":{}}}",
        proving.as_secs_f64() * 1000.0,
        started.elapsed().as_secs_f64() * 1000.0
    );
    Ok(())
}
