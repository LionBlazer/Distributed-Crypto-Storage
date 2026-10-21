//! Explicit PUBLIC NONSECRET example. No peer service or production consumer.
use crate::{
    Error, Result,
    geometry::{N, Q, T},
    statement::Statement,
};
use fhe::bfv::{BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, Plaintext, SecretKey};
use fhe_traits::{
    DeserializeParametrized, FheDecoder, FheDecrypter, FheEncoder, FheEncrypter, Serialize,
};
use rand::RngCore;
use std::{sync::Arc, time::Instant};
use zeroize::Zeroizing;

pub(crate) struct Example {
    pub(crate) statement: Statement,
    pub(crate) preparation_ms: f64,
    pub(crate) product_ms: f64,
    parameters: Arc<BfvParameters>,
    key: SecretKey,
    expected_public_coefficients: Zeroizing<Vec<u64>>,
    // The SAME buffers actually supplied to SDK encryption, client-owned only.
    private_inputs: [Zeroizing<Vec<u64>>; 2],
}
impl Example {
    /// Client-only decryption of the actual completed ciphertext. The explicit
    /// public oracle checks all coefficients; it never supplies a peer answer.
    pub(crate) fn complete(&self) -> Result<()> {
        let ciphertext = Ciphertext::from_bytes(self.statement.output_wire(), &self.parameters)
            .map_err(|_| Error::Backend)?;
        let plaintext: Plaintext = self
            .key
            .try_decrypt(&ciphertext)
            .map_err(|_| Error::Backend)?;
        let plaintext = Zeroizing::new(plaintext);
        let values = Zeroizing::new(
            Vec::<u64>::try_decode(&*plaintext, Encoding::poly()).map_err(|_| Error::Backend)?,
        );
        if *values != *self.expected_public_coefficients {
            return Err(Error::Arithmetic);
        }
        Ok(())
    }
}
pub(crate) fn example() -> Result<Example> {
    let began = Instant::now();
    let parameters = BfvParametersBuilder::new()
        .set_degree(N)
        .set_plaintext_modulus(T)
        .set_moduli(&Q)
        .set_variance(10)
        .build_arc()
        .map_err(|_| Error::Backend)?;
    let key = SecretKey::random(&parameters, &mut rand::rng());
    let mut source = Zeroizing::new(vec![0; N]);
    let mut mask = Zeroizing::new(vec![0; N]);
    for (i, (age, amount)) in [(0usize, 65535u64), (1, 0), (128, 255), (255, 65534)]
        .into_iter()
        .enumerate()
    {
        source[2 * i * 512 + age] = 256 + age as u64;
        source[(2 * i + 1) * 512 + age] = amount;
    }
    for age in 128..256 {
        mask[255 - age] = 1;
    }
    // An independent full-ring oracle belongs only to this public fixture.
    let mut expected_public_coefficients = Zeroizing::new(vec![0; N]);
    for (i, &x) in source.iter().enumerate().filter(|(_, x)| **x != 0) {
        for (j, &y) in mask.iter().enumerate().filter(|(_, y)| **y != 0) {
            let term = (u128::from(x) * u128::from(y) % u128::from(T)) as u64;
            let at = (i + j) % N;
            let value = expected_public_coefficients[at];
            expected_public_coefficients[at] = if i + j < N {
                (value + term) % T
            } else {
                (value + T - term) % T
            };
        }
    }
    let mut operands = Vec::with_capacity(2);
    for values in [&*source, &*mask] {
        let plaintext = Zeroizing::new(
            Plaintext::try_encode(values.as_slice(), Encoding::poly(), &parameters)
                .map_err(|_| Error::Backend)?,
        );
        let encrypted: Ciphertext = key
            .try_encrypt(&*plaintext, &mut rand::rng())
            .map_err(|_| Error::Backend)?;
        // Exact same real polynomial components; only remove public seed compression.
        operands.push(
            Ciphertext::new(encrypted.iter().cloned().collect(), &parameters)
                .map_err(|_| Error::Backend)?,
        );
    }
    let preparation_ms = began.elapsed().as_secs_f64() * 1000.;
    let began = Instant::now();
    let product = &operands[0] * &operands[1];
    let product_ms = began.elapsed().as_secs_f64() * 1000.;
    if product.len() != 3 {
        return Err(Error::Shape);
    }
    let mut binding = [0; 32];
    rand::rng().fill_bytes(&mut binding);
    let statement = Statement::new(
        binding,
        [operands[0].to_bytes(), operands[1].to_bytes()],
        product.to_bytes(),
    )?;
    Ok(Example {
        statement,
        preparation_ms,
        product_ms,
        parameters,
        key,
        expected_public_coefficients,
        private_inputs: [source, mask],
    })
}

pub(crate) struct PrivateWitnessObservation {
    pub(crate) preparation_ms: f64,
    pub(crate) sdk_product_ms: f64,
    pub(crate) witness_build_ms: f64,
    pub(crate) witness_check_ms: f64,
    pub(crate) whole_local_ms: f64,
}
/// Explicit owner-local diagnostic only. Key bytes/witness never leave this frame.
/// Reusing example includes its actual SDK product in the total observation.
pub(crate) fn audit_private_witness() -> Result<PrivateWitnessObservation> {
    let began = Instant::now();
    let example = example()?;
    let raw = [
        example.private_inputs[0].as_slice(),
        example.private_inputs[1].as_slice(),
    ];
    let key_bytes = Zeroizing::new(example.key.to_bytes());
    let build = Instant::now();
    let witness = crate::gold_formation::Witness::from_sdk_key(&example.statement, raw, key_bytes)?;
    let witness_build_ms = build.elapsed().as_secs_f64() * 1000.;
    let check = Instant::now();
    witness.check(&example.statement, raw)?;
    let witness_check_ms = check.elapsed().as_secs_f64() * 1000.;
    let preparation_ms = example.preparation_ms;
    let sdk_product_ms = example.product_ms;
    drop(witness);
    drop(example);
    Ok(PrivateWitnessObservation {
        preparation_ms,
        sdk_product_ms,
        witness_build_ms,
        witness_check_ms,
        whole_local_ms: began.elapsed().as_secs_f64() * 1000.,
    })
}

pub(crate) struct PrivateGraphObservation {
    pub(crate) preparation_ms: f64,
    pub(crate) sdk_product_ms: f64,
    pub(crate) witness_build_ms: f64,
    pub(crate) graph: crate::gold_formation::GraphObservation,
    pub(crate) whole_local_ms: f64,
}

/// One owner-local full graph diagnostic with the original SDK encryption inputs.
/// The guarded secret, trace and all private products die before the observation.
pub(crate) fn audit_private_graph() -> Result<PrivateGraphObservation> {
    let began = Instant::now();
    let example = example()?;
    let raw = [
        example.private_inputs[0].as_slice(),
        example.private_inputs[1].as_slice(),
    ];
    let key_bytes = Zeroizing::new(example.key.to_bytes());
    let build = Instant::now();
    let witness = crate::gold_formation::Witness::from_sdk_key(&example.statement, raw, key_bytes)?;
    let witness_build_ms = build.elapsed().as_secs_f64() * 1000.;
    let graph = witness.audit_graph(&example.statement, raw)?;
    let preparation_ms = example.preparation_ms;
    let sdk_product_ms = example.product_ms;
    drop(witness);
    drop(example);
    Ok(PrivateGraphObservation {
        preparation_ms,
        sdk_product_ms,
        witness_build_ms,
        graph,
        whole_local_ms: began.elapsed().as_secs_f64() * 1000.,
    })
}
