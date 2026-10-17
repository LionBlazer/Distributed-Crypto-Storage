//! Fixed, linked Plonky3 configuration and actual symbolic shape analysis.
use bfv_scale_circuit::{Role, plonky3::ScaleAir};
use p3_air::{Air, AirBuilder, BaseAir, BoundaryPublic};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks, default_goldilocks_poseidon2_12};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{AirLayout, OpeningShape, ProvenSecurity, StarkConfig, StarkSecurityParams};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::borrow::Cow;

use crate::Error;
pub(crate) type Val = Goldilocks;
type Perm = Poseidon2Goldilocks<12>;
type Hash = PaddingFreeSponge<Perm, 12, 8, 4>;
type Compress = TruncatedPermutation<Perm, 2, 4, 12>;
type Mmcs = MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, Hash, Compress, 2, 4>;
type Challenge = BinomialExtensionField<Val, 5>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, Mmcs>;
type Challenger = DuplexChallenger<Val, Perm, 12, 8>;
type Pcs = TwoAdicFriPcs<Val, Radix2DitParallel<Val>, Mmcs, ChallengeMmcs>;
pub(crate) type Config = StarkConfig<Pcs, Challenge, Challenger>;
pub const HEIGHT: usize = 8192;
pub(crate) const LOG_HEIGHT: usize = 13;

/// Consumer transcript binding only. All arithmetic and preprocessing remain
/// owned by the exact library AIR; this adds eight fixed profile public words.
pub(crate) struct BoundAir(pub(crate) ScaleAir);
impl BoundAir {
    pub(crate) fn is_prepared(&self) -> bool {
        self.0.is_prepared()
    }
}
impl BaseAir<Val> for BoundAir {
    fn width(&self) -> usize {
        self.0.width()
    }
    fn preprocessed_width(&self) -> usize {
        self.0.preprocessed_width()
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        self.0.preprocessed_trace()
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        self.0.main_next_row_columns()
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        self.0.preprocessed_next_row_columns()
    }
    fn num_public_values(&self) -> usize {
        self.0.num_public_values() + 8
    }
    fn num_constraints(&self) -> Option<usize> {
        self.0.num_constraints()
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        self.0.max_constraint_degree()
    }
    fn num_periodic_columns(&self) -> usize {
        self.0.num_periodic_columns()
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        self.0.periodic_columns()
    }
    fn public_boundary_io(&self) -> &[BoundaryPublic] {
        self.0.public_boundary_io()
    }
    fn assumes_boolean_trace(&self) -> bool {
        self.0.assumes_boolean_trace()
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for BoundAir {
    fn eval(&self, builder: &mut AB) {
        self.0.eval(builder);
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

pub fn role_name(role: Role) -> &'static str {
    match role {
        Role::Extend5To10 => "extend-5-to-10",
        Role::Scale10To5 => "scale-10-to-5",
    }
}
pub(crate) fn role_tag(role: Role) -> u8 {
    match role {
        Role::Extend5To10 => 1,
        Role::Scale10To5 => 2,
    }
}

/// Domain separation includes the exact arithmetic profile and this consumer's
/// codec/configuration. It does not change any existing BFV proof profile.
pub fn profile_digest(role: Role) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"dcs/experiment/public-rns-scaling-stark/v1");
    hash.update(bfv_scale_circuit::profile_digest(role));
    hash.update(b"p3-0.8.0/a21e3ed42905040ad49c519e402f018381c12d0c/Goldilocks/Poseidon2-12/rate8/digest4/cap0/arity2");
    hash.update(b"NaturalPowerBasis/full8192/public-preprocessing/no-NTT/no-hiding");
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

/// No trace, scaler evaluation, preprocessing allocation, or commitment is made
/// by this path. The same AIR evaluator is analyzed by the pinned SDK.
pub fn analyze(role: Role) -> Result<SecurityReport, Error> {
    let (_, report) = config(&BoundAir(ScaleAir::shape(role)), role)?;
    Ok(report)
}

pub(crate) fn config(air: &BoundAir, role: Role) -> Result<(Config, SecurityReport), Error> {
    if air.assumes_boolean_trace() || !air.public_boundary_io().is_empty() {
        return Err(Error::SecurityProfile);
    }
    let perm = default_goldilocks_poseidon2_12();
    let mmcs = Mmcs::new(Hash::new(perm.clone()), Compress::new(perm.clone()), 0);
    let fri = FriParameters {
        log_blowup: 3,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 192,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: ChallengeMmcs::new(mmcs.clone()),
    };
    let parameters = StarkSecurityParams::from_air::<Val, Challenge, _>(
        fri.security_regime(),
        air,
        AirLayout::from_air::<Val>(air),
        TwoAdicMultiplicativeCoset::new(Val::ONE, LOG_HEIGHT).unwrap(),
        319,
        128,
        1,
        OpeningShape::new(),
        fri.grinding_sites(),
    );
    let bound = ProvenSecurity::compute(&parameters, HEIGHT);
    if bound.unique_decoding_bits < 128 || bound.list_decoding_bits < 128 {
        return Err(Error::SecurityProfile);
    }
    let report = SecurityReport {
        stage: "security_public_rns_scaling",
        role: role_name(role),
        trace_height: HEIGHT,
        main_width: air.width(),
        public_width: air.preprocessed_width(),
        public_values: air.num_public_values(),
        constraints: parameters.num_constraints,
        degree: parameters.air_max_constraint_degree,
        quotient_chunks: parameters.num_quotient_chunks,
        batched_functions: parameters.num_batched_functions,
        extension_degree: 5,
        queries: 192,
        blowup: 8,
        unique_decoding_bits: bound.unique_decoding_bits,
        list_decoding_bits: bound.list_decoding_bits,
        public_preprocessing_bytes: HEIGHT * air.preprocessed_width() * 8,
        main_trace_bytes: HEIGHT * air.width() * 8,
        main_lde_bytes: 8 * HEIGHT * air.width() * 8,
        public_lde_bytes: 8 * HEIGHT * air.preprocessed_width() * 8,
    };
    Ok((
        Config::new(
            Pcs::new(Radix2DitParallel::default(), mmcs, fri),
            Challenger::new(perm),
        ),
        report,
    ))
}
