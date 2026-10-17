//! Fixed public arithmetic STARK configuration; callers retain proof and role ownership.
#![forbid(unsafe_code)]

use p3_air::{Air, symbolic::SymbolicAirBuilder};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks, default_goldilocks_poseidon2_12};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{AirLayout, OpeningShape, ProvenSecurity, StarkConfig, StarkSecurityParams};

pub type Val = Goldilocks;
pub type Challenge = BinomialExtensionField<Val, 5>;
type Perm = Poseidon2Goldilocks<12>;
type Hash = PaddingFreeSponge<Perm, 12, 8, 4>;
type Compress = TruncatedPermutation<Perm, 2, 4, 12>;
type Mmcs = MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, Hash, Compress, 2, 4>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, Mmcs>;
type Challenger = DuplexChallenger<Val, Perm, 12, 8>;
type Pcs = TwoAdicFriPcs<Val, Radix2DitParallel<Val>, Mmcs, ChallengeMmcs>;
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;

pub const HEIGHT: usize = bfv_fixed_geometry::DEGREE;
pub const LOG_HEIGHT: usize = 13;
pub const EXTENSION_DEGREE: usize = 5;
pub const LOG_BLOWUP: usize = 3;
pub const QUERIES: usize = 192;
pub const MIN_SECURITY_BITS: usize = 128;
/// Linked SDK/hash/MMCS identity. Numeric configuration is fixed separately below.
/// This is not an operation profile, application domain, or proof acceptance token.
pub const LINKED_P3_DESCRIPTOR: &[u8] = b"p3-0.8.0/a21e3ed42905040ad49c519e402f018381c12d0c/Goldilocks/Poseidon2-12/rate8/digest4/cap0/arity2";

/// Actual SDK analysis of the supplied AIR at the fixed height, including all
/// committed/preprocessed widths and actual current/next opening multiplicity.
/// It is metadata, not proof verification or a composed security claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityAnalysis {
    pub main_width: usize,
    pub public_width: usize,
    pub public_values: usize,
    pub constraints: usize,
    pub degree: usize,
    pub quotient_chunks: usize,
    pub batched_functions: usize,
    pub unique_decoding_bits: usize,
    pub list_decoding_bits: usize,
}

/// Construct the unchanged linked configuration and analyze this exact compiled
/// AIR. No trace, preprocessing commitment, witness, or proof is constructed.
/// Returns None for Boolean/boundary assumptions or either individual SDK bound
/// below 128 bits. Consumers map rejection into their own error contract and
/// remain responsible for requiring prepared data before prover/verifier setup.
pub fn checked_config<A>(air: &A) -> Option<(Config, SecurityAnalysis)>
where
    A: Air<SymbolicAirBuilder<Val, Challenge>>,
{
    if air.assumes_boolean_trace() || !air.public_boundary_io().is_empty() {
        return None;
    }
    let perm = default_goldilocks_poseidon2_12();
    let mmcs = Mmcs::new(Hash::new(perm.clone()), Compress::new(perm.clone()), 0);
    let fri = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: QUERIES,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: ChallengeMmcs::new(mmcs.clone()),
    };
    let max_combo = 1 + usize::from(
        !air.main_next_row_columns().is_empty() || !air.preprocessed_next_row_columns().is_empty(),
    );
    let parameters = StarkSecurityParams::from_air::<Val, Challenge, _>(
        fri.security_regime(),
        air,
        AirLayout::from_air::<Val>(air),
        TwoAdicMultiplicativeCoset::new(Val::ONE, LOG_HEIGHT).unwrap(),
        319,
        128,
        max_combo,
        OpeningShape::new(),
        fri.grinding_sites(),
    );
    let bound = ProvenSecurity::compute(&parameters, HEIGHT);
    if bound.unique_decoding_bits < MIN_SECURITY_BITS
        || bound.list_decoding_bits < MIN_SECURITY_BITS
    {
        return None;
    }
    let analysis = SecurityAnalysis {
        main_width: air.width(),
        public_width: air.preprocessed_width(),
        public_values: air.num_public_values(),
        constraints: parameters.num_constraints,
        degree: parameters.air_max_constraint_degree,
        quotient_chunks: parameters.num_quotient_chunks,
        batched_functions: parameters.num_batched_functions,
        unique_decoding_bits: bound.unique_decoding_bits,
        list_decoding_bits: bound.list_decoding_bits,
    };
    Some((
        Config::new(
            Pcs::new(Radix2DitParallel::default(), mmcs, fri),
            Challenger::new(perm),
        ),
        analysis,
    ))
}

#[cfg(test)]
mod tests;
