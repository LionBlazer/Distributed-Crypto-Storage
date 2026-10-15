//! Opt-in STARK research for one exact homomorphic BFV addition.
//! The checked marker attests only this arithmetic statement, never accepted SQL.
#![forbid(unsafe_code)]

mod circuit;

use circuit::{Config, config, statement};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{Proof, prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

/// Fixed-profile proof frame cap, checked before deserializing any SDK vectors.
pub const MAX_PROOF_BYTES: usize = 1024 * 1024;
const PROOF_MAGIC: &[u8; 8] = b"BFVP3A01";
// Eight independent equations share each row. Every original residue is retained.
const LANES: usize = 8;
const TRACE_HEIGHT: usize = bfv_linear_circuit::COEFFICIENTS
    .div_ceil(LANES)
    .next_power_of_two();
const LOG_HEIGHT: usize = TRACE_HEIGHT.ilog2() as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    StatementShape,
    RequestBinding,
    NonCanonicalResidue,
    ProofLength,
    ProofEncoding,
    TrailingProofBytes,
    SecurityProfile,
    Preprocessing,
    Proving,
    Verification,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BFV addition proof rejected {self:?}")
    }
}
impl std::error::Error for Error {}

#[derive(Debug, Clone, Copy)]
pub struct ProverTimings {
    pub encrypted_addition: Duration,
    pub public_preprocessing: Duration,
    pub proving_and_encoding: Duration,
    pub total: Duration,
}

/// Serialized proof and complete encrypted output; no plaintext or secret key.
pub struct GeneratedAddition {
    output: Vec<u8>,
    proof: Vec<u8>,
    timings: ProverTimings,
}
impl GeneratedAddition {
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
    /// Parsing and independently committing the exact public input/claimed output.
    pub public_preprocessing: Duration,
    pub proof_verification: Duration,
    /// Includes bounded proof decoding and both phases above; no cached prover key.
    pub total: Duration,
}

/// Unforgeable through this API, but ONLY evidence of the fixed BFV addition.
/// The digests identify the exact byte arrays checked by `verify`.
/// No SQL selection completeness, authorization, agreement or freshness follows.
#[derive(Debug)]
pub struct CheckedAddition {
    input_digest: [u8; 32],
    output_digest: [u8; 32],
    timings: VerifierTimings,
}
impl CheckedAddition {
    pub fn input_digest(&self) -> [u8; 32] {
        self.input_digest
    }
    pub fn output_digest(&self) -> [u8; 32] {
        self.output_digest
    }
    pub fn timings(&self) -> VerifierTimings {
        self.timings
    }
}

/// Executes actual ciphertext addition and proves every canonical NTT residue.
pub fn prove(input: &[u8]) -> Result<GeneratedAddition, Error> {
    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks;

    let total = Instant::now();
    let started = Instant::now();
    let output = bfv_linear_circuit::evaluate(input).map_err(|_| Error::StatementShape)?;
    let encrypted_addition = started.elapsed();
    let started = Instant::now();
    let (air, values) = statement(input, &output)?;
    let cfg = config(&air)?;
    let (preprocessed, _) = setup_preprocessed(&cfg, &air, LOG_HEIGHT)
        .map_err(|_| Error::Preprocessing)?
        .ok_or(Error::Preprocessing)?;
    let public_preprocessing = started.elapsed();
    let started = Instant::now();
    let n = bfv_linear_circuit::COEFFICIENTS;
    let mut witness = vec![Goldilocks::ZERO; TRACE_HEIGHT * LANES];
    for (i, carry) in witness.iter_mut().enumerate().take(n) {
        let a = u64::from_le_bytes(input[40 + i * 8..48 + i * 8].try_into().unwrap());
        let b = u64::from_le_bytes(
            input[40 + (n + i) * 8..48 + (n + i) * 8]
                .try_into()
                .unwrap(),
        );
        let q = bfv_linear_circuit::MODULI[(i / bfv_linear_circuit::DEGREE) % 5];
        *carry = Goldilocks::from_bool(a + b >= q);
    }
    let proof = prove_with_preprocessed(
        &cfg,
        &air,
        RowMajorMatrix::new(witness, LANES),
        &values,
        Some(&preprocessed),
    )
    .map_err(|_| Error::Proving)?;
    let payload = postcard::to_allocvec(&proof).map_err(|_| Error::ProofEncoding)?;
    if payload.len() + PROOF_MAGIC.len() > MAX_PROOF_BYTES {
        return Err(Error::ProofLength);
    }
    let mut wire = Vec::with_capacity(PROOF_MAGIC.len() + payload.len());
    wire.extend_from_slice(PROOF_MAGIC);
    wire.extend_from_slice(&payload);
    Ok(GeneratedAddition {
        output,
        proof: wire,
        timings: ProverTimings {
            encrypted_addition,
            public_preprocessing,
            proving_and_encoding: started.elapsed(),
            total: total.elapsed(),
        },
    })
}

/// Verifies serialized proof against the caller's TRUSTED exact canonical request.
/// This path never calls `evaluate` or reconstructs the ciphertext addition.
/// The verifier derives its own preprocessing key, including the claimed output;
/// a peer-supplied key is never an input to this API.
pub fn verify(input: &[u8], output: &[u8], wire: &[u8]) -> Result<CheckedAddition, Error> {
    let total = Instant::now();
    if wire.len() <= PROOF_MAGIC.len() || wire.len() > MAX_PROOF_BYTES {
        return Err(Error::ProofLength);
    }
    if &wire[..PROOF_MAGIC.len()] != PROOF_MAGIC {
        return Err(Error::ProofEncoding);
    }
    let payload = &wire[PROOF_MAGIC.len()..];
    let (proof, trailing): (Proof<Config>, _) =
        postcard::take_from_bytes(payload).map_err(|_| Error::ProofEncoding)?;
    if !trailing.is_empty() {
        return Err(Error::TrailingProofBytes);
    }
    // Reject alternative/overlong encodings as well as trailing bytes.
    if postcard::to_allocvec(&proof).map_err(|_| Error::ProofEncoding)? != payload {
        return Err(Error::ProofEncoding);
    }
    let started = Instant::now();
    let (air, expected_values) = statement(input, output)?;
    let cfg = config(&air)?;
    let (_, verifier_key) = setup_preprocessed(&cfg, &air, LOG_HEIGHT)
        .map_err(|_| Error::Preprocessing)?
        .ok_or(Error::Preprocessing)?;
    let public_preprocessing = started.elapsed();
    let started = Instant::now();
    verify_with_preprocessed(&cfg, &air, &proof, &expected_values, Some(&verifier_key))
        .map_err(|_| Error::Verification)?;
    Ok(CheckedAddition {
        input_digest: Sha256::digest(input).into(),
        output_digest: Sha256::digest(output).into(),
        timings: VerifierTimings {
            public_preprocessing,
            proof_verification: started.elapsed(),
            total: total.elapsed(),
        },
    })
}
