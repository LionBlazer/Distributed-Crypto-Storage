//! Fixed, linked Plonky3 configuration and actual symbolic shape analysis.
use bfv_ntt_circuit::{Basis, Direction, plonky3::NttAir};
use p3_air::BaseAir;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::Error;
pub use bfv_arithmetic_stark::HEIGHT;
pub(crate) use bfv_arithmetic_stark::{Config, LOG_HEIGHT, Val};

/// Fixed profile suffix only; role and preparation checks stay in this consumer.
pub(crate) type BoundAir = bfv_arithmetic_stark::ProfileAir<NttAir>;

#[derive(Debug, Clone, Serialize)]
pub struct SecurityReport {
    pub stage: &'static str,
    pub direction: &'static str,
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

pub fn direction_name(direction: Direction) -> &'static str {
    match direction {
        Direction::Forward => "forward",
        Direction::Inverse => "inverse",
    }
}
pub(crate) fn direction_tag(direction: Direction) -> u8 {
    match direction {
        Direction::Forward => 1,
        Direction::Inverse => 2,
    }
}
/// Domain separation includes the exact arithmetic profile and this consumer's
/// codec/configuration. It does not change any existing BFV proof profile.
pub fn profile_digest(direction: Direction, basis: Basis) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"dcs/experiment/public-ntt-stark/v1");
    hash.update(bfv_ntt_circuit::profile_digest(direction, basis));
    hash.update(b"p3-0.8.0/a21e3ed42905040ad49c519e402f018381c12d0c/Goldilocks/Poseidon2-12/rate8/digest4/cap0/arity2");
    hash.update(b"N8192/fixed-native-root/SDK-order/inverse-N^-1/public-preprocessing/no-hiding");
    for value in [
        HEIGHT,
        LOG_HEIGHT,
        5,
        3,
        192,
        0,
        0,
        0,
        crate::MAX_PROOF_BYTES,
        crate::MAX_PROOF_SEQUENCE_ELEMENTS,
        crate::MAX_PROOF_DECODE_ELEMENTS,
    ] {
        hash.update((value as u64).to_le_bytes());
    }
    hash.finalize().into()
}

/// No trace, NTT/butterfly evaluation, preprocessing allocation, or commitment is made
/// by this path. The same AIR evaluator is analyzed by the pinned SDK.
pub fn analyze(direction: Direction, basis: Basis) -> Result<SecurityReport, Error> {
    let (_, report) = config(
        &BoundAir::new(NttAir::shape(direction, basis)),
        direction,
        basis,
    )?;
    Ok(report)
}

pub(crate) fn config(
    air: &BoundAir,
    direction: Direction,
    basis: Basis,
) -> Result<(Config, SecurityReport), Error> {
    let (config, analysis) =
        bfv_arithmetic_stark::checked_config(air).ok_or(Error::SecurityProfile)?;
    let report = SecurityReport {
        stage: "security_public_ntt",
        direction: direction_name(direction),
        basis_index: basis.index(),
        modulus: basis.modulus(),
        trace_height: HEIGHT,
        main_width: air.width(),
        public_width: air.preprocessed_width(),
        public_values: air.num_public_values(),
        constraints: analysis.constraints,
        degree: analysis.degree,
        quotient_chunks: analysis.quotient_chunks,
        batched_functions: analysis.batched_functions,
        extension_degree: 5,
        queries: 192,
        blowup: 8,
        unique_decoding_bits: analysis.unique_decoding_bits,
        list_decoding_bits: analysis.list_decoding_bits,
        public_preprocessing_bytes: HEIGHT * air.preprocessed_width() * 8,
        main_trace_bytes: HEIGHT * air.width() * 8,
        main_lde_bytes: 8 * HEIGHT * air.width() * 8,
        public_lde_bytes: 8 * HEIGHT * air.preprocessed_width() * 8,
    };
    Ok((config, report))
}
