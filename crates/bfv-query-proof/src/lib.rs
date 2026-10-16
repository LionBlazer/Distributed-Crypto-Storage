//! Genuine STARK evidence for complete canonical BFV addition and ciphertext ×
//! public-polynomial multiplication. This arithmetic layer never accepts SQL,
//! selects records, authorizes changes or establishes a current agreed version.
#![forbid(unsafe_code)]

mod circuit;
mod codec;
mod dispatch;
mod preprocessing;

pub use dispatch::{backend_kind, compiled_kind, initialize_backend};
pub use proof_acceleration::Kind as BackendKind;
/// Identifies the complete canonical arithmetic, serialized proof and security profile.
/// Application trust anchors must bind this as well as their FHE parameters.
pub const PROOF_PROFILE_ID: [u8; 32] = proof_acceleration::abi::PROFILE_ID;

const _: () = {
    assert!(bfv_linear_circuit::DEGREE.is_power_of_two());
    assert!(
        bfv_linear_circuit::COEFFICIENTS
            == 2 * bfv_linear_circuit::MODULI.len() * bfv_linear_circuit::DEGREE
    );
};

use circuit::{Config, Statement, certificate, config, statement, witness};
use p3_uni_stark::{Proof, prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};
use preprocessing::{PREPROCESSING_CACHE, PreprocessingCache, cache_key};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

/// Fixed-profile frame cap, checked before decoding SDK-owned nested vectors.
pub const MAX_PROOF_BYTES: usize = 2 * 1024 * 1024;
/// Bound applied to each sequence before invoking its allocating consumer.
pub const MAX_PROOF_SEQUENCE_ELEMENTS: usize = 4096;
/// Shared decoded-container slot budget, including fixed arrays and nested tuples.
/// These are decoder bounds, not a whole-process memory guarantee.
pub const MAX_PROOF_DECODE_ELEMENTS: usize = 1024 * 1024;

/// The exact public arithmetic relation attested by the checked evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Addition,
    PublicPolynomialProduct,
}
impl Operation {
    fn from_input(input: &[u8]) -> Result<Self, Error> {
        match input.get(..8) {
            Some(b"BFVLADQ1") => Ok(Self::Addition),
            Some(b"BFVPMUQ1") => Ok(Self::PublicPolynomialProduct),
            _ => Err(Error::StatementShape),
        }
    }
    fn lanes(self) -> usize {
        // One full NTT polynomial per lane: two components, five fixed moduli.
        // Its modulus is an AIR constant instead of a repeated public column.
        2 * bfv_linear_circuit::MODULI.len()
    }
    fn height(self) -> usize {
        bfv_linear_circuit::DEGREE
    }
    fn log_height(self) -> usize {
        self.height().ilog2() as usize
    }
    fn witness_columns(self) -> usize {
        self.lanes()
    }
    fn public_columns(self) -> usize {
        match self {
            Self::Addition => 3 * self.lanes(),
            Self::PublicPolynomialProduct => 10 * self.lanes(),
        }
    }
    fn certificate_bytes(self) -> usize {
        match self {
            Self::Addition => 0,
            Self::PublicPolynomialProduct => 12 * bfv_linear_circuit::COEFFICIENTS,
        }
    }
    fn public_values(self) -> usize {
        match self {
            Self::Addition => 16,
            Self::PublicPolynomialProduct => 24,
        }
    }
    fn proof_magic(self) -> &'static [u8; 8] {
        match self {
            Self::Addition => b"BFVP3A03",
            Self::PublicPolynomialProduct => b"BFVP3M04",
        }
    }
    fn evaluate(self, input: &[u8]) -> Result<Vec<u8>, Error> {
        match self {
            Self::Addition => {
                bfv_linear_circuit::evaluate(input).map_err(|_| Error::StatementShape)
            }
            Self::PublicPolynomialProduct => {
                bfv_product_circuit::evaluate(input).map_err(|_| Error::StatementShape)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    StatementShape,
    RequestBinding,
    NonCanonicalResidue,
    ProofLength,
    ProofEncoding,
    ProofResourceLimit,
    TrailingProofBytes,
    SecurityProfile,
    Preprocessing,
    Proving,
    Verification,
    /// A present selected kernel failed loading or the versioned ABI contract.
    BackendUnavailable,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BFV query arithmetic proof rejected {self:?}")
    }
}
impl std::error::Error for Error {}

#[derive(Debug, Clone, Copy)]
pub struct ProverTimings {
    pub encrypted_operation: Duration,
    pub public_preprocessing: Duration,
    pub proving_and_encoding: Duration,
    pub total: Duration,
}

/// Owns serialized proof and complete encrypted output, never secret keys.
pub struct GeneratedOperation {
    operation: Operation,
    output: Vec<u8>,
    proof: Vec<u8>,
    timings: ProverTimings,
}
impl GeneratedOperation {
    pub fn operation(&self) -> Operation {
        self.operation
    }
    pub fn output(&self) -> &[u8] {
        &self.output
    }
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }
    pub fn timings(&self) -> ProverTimings {
        self.timings
    }
}

#[derive(Debug, Clone, Copy)]
pub struct VerifierTimings {
    /// Parse/range checks and locally derived or reused exact public commitment.
    pub public_preprocessing: Duration,
    pub proof_verification: Duration,
    /// Includes bounded decoding and all phases above, without a prover-owned key.
    pub total: Duration,
}

/// Constructible only by successful serialized-proof verification. The marker
/// binds every coefficient and the original opaque request identity. It attests
/// arithmetic only: SQL-plan coverage, authorization and freshness are separate.
#[derive(Debug)]
pub struct CheckedOperation {
    operation: Operation,
    input_digest: [u8; 32],
    output_digest: [u8; 32],
    timings: VerifierTimings,
}
impl CheckedOperation {
    pub fn operation(&self) -> Operation {
        self.operation
    }
    pub fn input_digest(&self) -> [u8; 32] {
        self.input_digest
    }
    pub fn output_digest(&self) -> [u8; 32] {
        self.output_digest
    }
    pub fn timings(&self) -> VerifierTimings {
        self.timings
    }
    /// Rebind already verified evidence to the consumer's exact trusted statement.
    /// This performs only identity hashing, never arithmetic or proof verification.
    /// A checked marker for another request, result or operation cannot be reused.
    pub fn matches_statement(&self, trusted_input: &[u8], claimed_output: &[u8]) -> bool {
        trusted_input.len() == bfv_linear_circuit::REQUEST_BYTES
            && claimed_output.len() == bfv_linear_circuit::OUTPUT_BYTES
            && Operation::from_input(trusted_input) == Ok(self.operation)
            && self.input_digest == <[u8; 32]>::from(Sha256::digest(trusted_input))
            && self.output_digest == <[u8; 32]>::from(Sha256::digest(claimed_output))
    }
}

/// Executes the canonical FHE arithmetic and proves all 81,920 NTT residues,
/// with the unchanged BFV profile and identical cryptographic settings in tests.
pub fn prove(input: &[u8]) -> Result<GeneratedOperation, Error> {
    dispatch::prove(input)
}

fn prove_engine(input: &[u8]) -> Result<GeneratedOperation, Error> {
    prove_with_cache(input, &PREPROCESSING_CACHE)
}

fn prove_with_cache(input: &[u8], cache: &PreprocessingCache) -> Result<GeneratedOperation, Error> {
    let total = Instant::now();
    let operation = Operation::from_input(input)?;
    let started = Instant::now();
    let output = operation.evaluate(input)?;
    let encrypted_operation = started.elapsed();
    let started = Instant::now();
    let certificate = certificate(operation, input)?;
    let Statement {
        air,
        values,
        hashes,
    } = statement(operation, input, &output, &certificate)?;
    let cfg = config(&air)?;
    let (preprocessed, verifier_key) = setup_preprocessed(&cfg, &air, operation.log_height())
        .map_err(|_| Error::Preprocessing)?
        .ok_or(Error::Preprocessing)?;
    // This key certifies only the locally derived public preprocessing. It is
    // safe to retain before proving, and never marks any proof/result accepted.
    cache.insert(cache_key(operation, &hashes), operation, verifier_key);
    let public_preprocessing = started.elapsed();
    let started = Instant::now();
    let proof = prove_with_preprocessed(
        &cfg,
        &air,
        witness(operation, input)?,
        &values,
        Some(&preprocessed),
    )
    .map_err(|_| Error::Proving)?;
    let payload = postcard::to_allocvec(&proof).map_err(|_| Error::ProofEncoding)?;
    let magic = operation.proof_magic();
    if payload.len() + magic.len() + certificate.len() > MAX_PROOF_BYTES {
        return Err(Error::ProofLength);
    }
    let mut wire = Vec::with_capacity(magic.len() + certificate.len() + payload.len());
    wire.extend_from_slice(magic);
    wire.extend_from_slice(&certificate);
    wire.extend_from_slice(&payload);
    Ok(GeneratedOperation {
        operation,
        output,
        proof: wire,
        timings: ProverTimings {
            encrypted_operation,
            public_preprocessing,
            proving_and_encoding: started.elapsed(),
            total: total.elapsed(),
        },
    })
}

/// Verifies the serialized proof against the caller's independently trusted exact
/// canonical request and the peer's claimed encrypted result. This function never
/// executes either canonical operation, derives a quotient or computes a product.
/// It never takes a peer-supplied verification/preprocessing key.
pub fn verify(input: &[u8], output: &[u8], wire: &[u8]) -> Result<CheckedOperation, Error> {
    dispatch::verify(input, output, wire)
}

fn verify_engine(input: &[u8], output: &[u8], wire: &[u8]) -> Result<CheckedOperation, Error> {
    verify_with_cache(input, output, wire, &PREPROCESSING_CACHE)
}

fn verify_with_cache(
    input: &[u8],
    output: &[u8],
    wire: &[u8],
    cache: &PreprocessingCache,
) -> Result<CheckedOperation, Error> {
    let total = Instant::now();
    let operation = Operation::from_input(input)?;
    let magic = operation.proof_magic();
    if wire.len() <= magic.len() || wire.len() > MAX_PROOF_BYTES {
        return Err(Error::ProofLength);
    }
    if &wire[..magic.len()] != magic {
        return Err(Error::ProofEncoding);
    }
    let certificate_end = magic.len() + operation.certificate_bytes();
    if wire.len() <= certificate_end {
        return Err(Error::ProofLength);
    }
    let certificate = &wire[magic.len()..certificate_end];
    let payload = &wire[certificate_end..];
    let (proof, trailing): (Proof<Config>, _) = codec::take_from_bytes(payload)?;
    if !trailing.is_empty() {
        return Err(Error::TrailingProofBytes);
    }
    if postcard::to_allocvec(&proof).map_err(|_| Error::ProofEncoding)? != payload {
        return Err(Error::ProofEncoding);
    }
    if proof.degree_bits != operation.log_height() {
        return Err(Error::Verification);
    }
    let started = Instant::now();
    let Statement {
        air,
        values: expected_values,
        hashes,
    } = statement(operation, input, output, certificate)?;
    // Shape/range and security checks always run, including on a cache hit.
    let cfg = config(&air)?;
    let key = cache_key(operation, &hashes);
    let verifier_key = match cache.get(key, operation) {
        Some(verifier_key) => verifier_key,
        None => {
            let (_, verifier_key) = setup_preprocessed(&cfg, &air, operation.log_height())
                .map_err(|_| Error::Preprocessing)?
                .ok_or(Error::Preprocessing)?;
            cache.insert(key, operation, verifier_key.clone());
            verifier_key
        }
    };
    let public_preprocessing = started.elapsed();
    let started = Instant::now();
    // Some SDK rejection paths can panic for malformed internal proof shapes.
    // Keep the peer-facing arithmetic boundary fail-closed without exposing that
    // panic as network-process termination. Decoder budgets apply before this.
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_with_preprocessed(&cfg, &air, &proof, &expected_values, Some(&verifier_key))
    }))
    .map_err(|_| Error::Verification)?
    .map_err(|_| Error::Verification)?;
    Ok(CheckedOperation {
        operation,
        input_digest: hashes[0],
        output_digest: hashes[1],
        timings: VerifierTimings {
            public_preprocessing,
            proof_verification: started.elapsed(),
            total: total.elapsed(),
        },
    })
}
