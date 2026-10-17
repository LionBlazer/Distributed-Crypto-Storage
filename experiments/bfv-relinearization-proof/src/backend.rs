//! Relinearization stage profile/report ownership around the shared fixed linked SDK configuration.
use crate::Error;
pub(crate) use bfv_arithmetic_stark::{Config, Val};
pub use bfv_arithmetic_stark::{HEIGHT, LOG_HEIGHT};
use bfv_relinearization_circuit::{Role, plonky3::ArithmeticAir};
use serde::Serialize;
use sha2::{Digest, Sha256};
pub(crate) type BoundAir = bfv_arithmetic_stark::ProfileAir<ArithmeticAir>;
pub fn role_name(role: Role) -> &'static str {
    match role {
        Role::Embed => "embed",
        Role::AccumulateAndAdd => "accumulate-and-add",
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityReport {
    pub stage: &'static str,
    pub role: &'static str,
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

pub fn profile_digest(role: Role) -> [u8; 32] {
    use bfv_arithmetic_stark::{
        EXTENSION_DEGREE, LINKED_P3_DESCRIPTOR, LOG_BLOWUP, MIN_SECURITY_BITS, QUERIES,
    };
    let mut h = Sha256::new();
    h.update(b"dcs/experiment/public-relinearization-arithmetic-stark/v1");
    h.update(bfv_relinearization_circuit::profile_digest(role));
    h.update(LINKED_P3_DESCRIPTOR);
    h.update(b"finalpoly0/fri-max-log-arity1/pow-batch0,commit0,query0/OODpow0/fieldbits319/collision128/one-current-opening/no-next/no-zk");
    h.update(b"N8192/Q5/level0-0/logbase0/Embed5-25-PB/Accumulate85-10-NTT/public-preprocessing/no-hiding/binding32/keycontext32-not-authority");
    for value in [
        HEIGHT,
        LOG_HEIGHT,
        EXTENSION_DEGREE,
        LOG_BLOWUP,
        QUERIES,
        MIN_SECURITY_BITS,
        crate::max_proof_bytes(role),
        crate::MAX_PROOF_SEQUENCE_ELEMENTS,
        crate::max_proof_decode_elements(role),
    ] {
        h.update((value as u64).to_le_bytes());
    }
    h.finalize().into()
}
/// Actual symbolic analysis only: no matrix, arithmetic, trace, setup or proof.
pub fn analyze(role: Role) -> Result<SecurityReport, Error> {
    let (_, report) = config(&BoundAir::new(ArithmeticAir::shape(role)), role)?;
    Ok(report)
}
pub(crate) fn config(air: &BoundAir, role: Role) -> Result<(Config, SecurityReport), Error> {
    use bfv_arithmetic_stark::{EXTENSION_DEGREE, LOG_BLOWUP, QUERIES};
    let (cfg, a) = bfv_arithmetic_stark::checked_config(air).ok_or(Error::SecurityProfile)?;
    // These are the exact fixed arithmetic dimensions and decoder's quotient bound.
    // Constraint counts and actual degrees still come from the SDK evaluator.
    if a.main_width != 1
        || a.public_width != role.preprocessed_width()
        || a.public_values != 32 + bfv_arithmetic_stark::PROFILE_WORDS
        || a.degree
            > match role {
                Role::Embed => 1,
                Role::AccumulateAndAdd => 2,
            }
        || a.quotient_chunks > 8
    {
        return Err(Error::SecurityProfile);
    }
    let report = SecurityReport {
        stage: "security_public_relinearization_arithmetic",
        role: role_name(role),
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
