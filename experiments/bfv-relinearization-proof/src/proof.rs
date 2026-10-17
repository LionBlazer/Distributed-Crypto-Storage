//! The consumer builds both preprocessing commitments independently.
use crate::{
    Error,
    backend::{self, Config, Val},
    max_proof_bytes,
};
use bfv_relinearization_circuit::plonky3::prepare;
use bfv_relinearization_circuit::{Aux, Output, Request, Role, decode_aux};
use p3_air::BaseAir;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{Proof, prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

const MAGIC: &[u8; 8] = b"BFVRLP01";
const HEADER_BYTES: usize = 112;

#[derive(Debug, Clone, Copy)]
pub struct ProverTimings {
    pub arithmetic_and_certificate: Duration,
    pub public_preprocessing: Duration,
    pub proving_and_encoding: Duration,
    pub total: Duration,
}
#[derive(Debug, Clone, Copy)]
pub struct VerifierTimings {
    pub public_preprocessing: Duration,
    pub proof_verification: Duration,
    pub total: Duration,
}
pub struct Generated {
    pub output: Output,
    pub proof: Vec<u8>,
    pub timings: ProverTimings,
}
/// This marker attests one public relinearization arithmetic stage only; it cannot become a production
/// CheckedOperation, a MulRelin result, or an accepted SQL answer.
#[derive(Debug)]
pub struct CheckedStage {
    role: Role,
    keyset_context: [u8; 32],
    input_digest: [u8; 32],
    output_digest: [u8; 32],
    pub timings: VerifierTimings,
}
impl CheckedStage {
    pub fn role(&self) -> Role {
        self.role
    }
    pub fn keyset_context(&self) -> [u8; 32] {
        self.keyset_context
    }
    pub fn matches(&self, input: &Request, output: &Output) -> bool {
        self.role == input.role()
            && output.role() == input.role()
            && self.keyset_context == input.keyset_context()
            && output.keyset_context() == input.keyset_context()
            && self.input_digest == <[u8; 32]>::from(Sha256::digest(input.encode()))
            && self.output_digest == <[u8; 32]>::from(Sha256::digest(output.encode()))
    }
}
fn header(request: &Request) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_BYTES);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&backend::profile_digest(request.role()));
    bytes.extend_from_slice(&request.binding());
    bytes.extend_from_slice(&request.keyset_context());
    bytes.extend([
        request.role() as u8,
        match request.role() {
            Role::Embed => 1,
            Role::AccumulateAndAdd => 2,
        },
        request.role().input_moduli().len() as u8,
        request.role().output_moduli().len() as u8,
        0,
        0,
        0,
        0,
    ]);
    bytes
}
pub(crate) fn statement(
    input: &Request,
    output: &Output,
    auxiliary: &Aux,
) -> Result<(backend::BoundAir, Vec<Val>), Error> {
    let (air, mut values) = prepare(input, output, auxiliary)
        .map_err(|_| Error::Statement)?
        .into_parts();
    let air = backend::BoundAir::new(air);
    if !air.inner().is_prepared() {
        return Err(Error::Preprocessing);
    }
    // Eight exact LE u32 words, delegated to the shared policy-free wrapper helper.
    values.extend(bfv_arithmetic_stark::profile_words(
        backend::profile_digest(input.role()),
    ));
    Ok((air, values))
}

pub fn prove(input: &Request) -> Result<Generated, Error> {
    let total = Instant::now();
    let started = Instant::now();
    let evaluated = bfv_relinearization_circuit::evaluate_with_certificate(input)
        .map_err(|_| Error::Statement)?;
    let arithmetic_and_certificate = started.elapsed();
    let started = Instant::now();
    let (air, values) = statement(input, &evaluated.output, &evaluated.aux)?;
    let (cfg, _) = backend::config(&air, input.role())?;
    let (prover, _) = setup_preprocessed(&cfg, &air, backend::LOG_HEIGHT)
        .map_err(|_| Error::Preprocessing)?
        .ok_or(Error::Preprocessing)?;
    let public_preprocessing = started.elapsed();
    let started = Instant::now();
    let main = RowMajorMatrix::new(vec![Val::ZERO; backend::HEIGHT * air.width()], air.width());
    let proof = prove_with_preprocessed(&cfg, &air, main, &values, Some(&prover))
        .map_err(|_| Error::Proving)?;
    let frame = encode_frame(input, &evaluated.aux, &proof)?;
    Ok(Generated {
        output: evaluated.output,
        proof: frame,
        timings: ProverTimings {
            arithmetic_and_certificate,
            public_preprocessing,
            proving_and_encoding: started.elapsed(),
            total: total.elapsed(),
        },
    })
}

pub(crate) fn encode_frame(
    input: &Request,
    auxiliary: &Aux,
    proof: &Proof<Config>,
) -> Result<Vec<u8>, Error> {
    let payload = postcard::to_allocvec(proof).map_err(|_| Error::ProofEncoding)?;
    let auxiliary = auxiliary.encode();
    if auxiliary.len() != input.role().aux_bytes() {
        return Err(Error::Statement);
    }
    let size = HEADER_BYTES
        .checked_add(auxiliary.len())
        .and_then(|n| n.checked_add(payload.len()))
        .filter(|&n| n <= max_proof_bytes(input.role()))
        .ok_or(Error::ProofLength)?;
    let mut frame = header(input);
    frame.reserve(size - frame.len());
    frame.extend_from_slice(&auxiliary);
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Does not call evaluate_with_certificate, reduce inputs, multiply/divide, derive quotients, run NTT or key switching.
/// Public preprocessing is rebuilt from trusted full vectors and bounded aux.
pub fn verify(input: &Request, output: &Output, frame: &[u8]) -> Result<CheckedStage, Error> {
    let total = Instant::now();
    let split = HEADER_BYTES
        .checked_add(input.role().aux_bytes())
        .ok_or(Error::ProofLength)?;
    if frame.len() <= split || frame.len() > max_proof_bytes(input.role()) {
        return Err(Error::ProofLength);
    }
    if frame[..HEADER_BYTES] != header(input) {
        return Err(Error::Frame);
    }
    let aux = decode_aux(&frame[HEADER_BYTES..split]).map_err(|_| Error::Statement)?;
    let payload = &frame[split..];
    let (proof, trailing): (Proof<Config>, _) =
        crate::codec::take_from_bytes(input.role(), payload)?;
    if !trailing.is_empty() {
        return Err(Error::TrailingProofBytes);
    }
    if postcard::to_allocvec(&proof).map_err(|_| Error::ProofEncoding)? != payload {
        return Err(Error::ProofEncoding);
    }
    if proof.degree_bits != backend::LOG_HEIGHT {
        return Err(Error::Verification);
    }
    let started = Instant::now();
    let (air, values) = statement(input, output, &aux)?;
    let (cfg, _) = backend::config(&air, input.role())?;
    let (_, key) = setup_preprocessed(&cfg, &air, backend::LOG_HEIGHT)
        .map_err(|_| Error::Preprocessing)?
        .ok_or(Error::Preprocessing)?;
    let public_preprocessing = started.elapsed();
    let started = Instant::now();
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_with_preprocessed(&cfg, &air, &proof, &values, Some(&key))
    }))
    .map_err(|_| Error::Verification)?
    .map_err(|_| Error::Verification)?;
    Ok(CheckedStage {
        role: input.role(),
        keyset_context: input.keyset_context(),
        input_digest: Sha256::digest(input.encode()).into(),
        output_digest: Sha256::digest(output.encode()).into(),
        timings: VerifierTimings {
            public_preprocessing,
            proof_verification: started.elapsed(),
            total: total.elapsed(),
        },
    })
}
