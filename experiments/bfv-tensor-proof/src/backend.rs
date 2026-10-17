//! Tensor profile/report ownership around the shared fixed linked SDK configuration.
use crate::Error;
pub(crate) use bfv_arithmetic_stark::{Config, Val};
pub use bfv_arithmetic_stark::{HEIGHT, LOG_HEIGHT};
use bfv_tensor_circuit::{Basis, plonky3::TensorAir};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Fixed profile suffix only; role and preparation checks stay in this consumer.
pub(crate) type BoundAir = bfv_arithmetic_stark::ProfileAir<TensorAir>;

#[derive(Debug, Clone, Serialize)]
pub struct SecurityReport {
    pub stage: &'static str,
    pub basis_index: u8,
    pub modulus: u64,
    pub trace_height: usize,
    pub main_width: usize,
    pub public_width: usize,
    pub public_values: usize,
    pub constraints: usize,
    pub degree: usize,
    pub quotient_chunks: usize,
    pub batched_functions: usize,
    pub extension_degree: usize,
    pub queries: usize,
    pub blowup: usize,
    pub unique_decoding_bits: usize,
    pub list_decoding_bits: usize,
    pub public_preprocessing_bytes: usize,
    pub main_trace_bytes: usize,
    pub main_lde_bytes: usize,
    pub public_lde_bytes: usize,
}

pub fn profile_digest(basis: Basis) -> [u8; 32] {
    use bfv_arithmetic_stark::{
        EXTENSION_DEGREE, LINKED_P3_DESCRIPTOR, LOG_BLOWUP, MIN_SECURITY_BITS, QUERIES,
    };
    let mut h = Sha256::new();
    h.update(b"dcs/experiment/public-tensor-stark/v1");
    h.update(bfv_tensor_circuit::profile_digest(basis));
    h.update(LINKED_P3_DESCRIPTOR);
    h.update(b"finalpoly0/fri-max-log-arity1/pow-batch0,commit0,query0/OODpow0/fieldbits319/collision128/one-current-opening/no-next/no-zk");
    h.update(b"N8192/NTT-native/full-a0,a1,b0,b1/d0,d1,d2/public-preprocessing/no-hiding");
    for value in [
        HEIGHT,
        LOG_HEIGHT,
        EXTENSION_DEGREE,
        LOG_BLOWUP,
        QUERIES,
        MIN_SECURITY_BITS,
        crate::MAX_PROOF_BYTES,
        crate::MAX_PROOF_SEQUENCE_ELEMENTS,
        crate::MAX_PROOF_DECODE_ELEMENTS,
    ] {
        h.update((value as u64).to_le_bytes());
    }
    h.finalize().into()
}
/// Actual symbolic analysis only: no matrix, arithmetic, trace, setup or proof.
pub fn analyze(basis: Basis) -> Result<SecurityReport, Error> {
    let (_, report) = config(&BoundAir::new(TensorAir::shape(basis)), basis)?;
    Ok(report)
}
pub(crate) fn config(air: &BoundAir, basis: Basis) -> Result<(Config, SecurityReport), Error> {
    use bfv_arithmetic_stark::{EXTENSION_DEGREE, LOG_BLOWUP, QUERIES};
    let (cfg, a) = bfv_arithmetic_stark::checked_config(air).ok_or(Error::SecurityProfile)?;
    // These are the exact fixed arithmetic dimensions and decoder's quotient bound.
    // Constraint counts and actual degrees still come from the SDK evaluator.
    if a.main_width != 1
        || a.public_width != 61
        || a.public_values != 40
        || a.degree > 2
        || a.quotient_chunks > 8
    {
        return Err(Error::SecurityProfile);
    }
    let report = SecurityReport {
        stage: "security_public_tensor",
        basis_index: basis.index(),
        modulus: basis.modulus(),
        trace_height: HEIGHT,
        main_width: a.main_width,
        public_width: a.public_width,
        public_values: a.public_values,
        constraints: a.constraints,
        degree: a.degree,
        quotient_chunks: a.quotient_chunks,
        batched_functions: a.batched_functions,
        extension_degree: EXTENSION_DEGREE,
        queries: QUERIES,
        blowup: 1 << LOG_BLOWUP,
        unique_decoding_bits: a.unique_decoding_bits,
        list_decoding_bits: a.list_decoding_bits,
        public_preprocessing_bytes: HEIGHT * a.public_width * 8,
        main_trace_bytes: HEIGHT * a.main_width * 8,
        main_lde_bytes: (1 << LOG_BLOWUP) * HEIGHT * a.main_width * 8,
        public_lde_bytes: (1 << LOG_BLOWUP) * HEIGHT * a.public_width * 8,
    };
    Ok((cfg, report))
}
