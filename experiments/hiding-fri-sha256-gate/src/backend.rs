use p3_air::BaseAir;
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_fri::{FriParameters, HidingFriPcs};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks, default_goldilocks_poseidon2_12};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_sha256_air::NUM_SHA256_COLS;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{
    AirLayout, OpeningShape, Proof, ProvenSecurity, StarkConfig, StarkSecurityParams, prove, verify,
};
use rand::SeedableRng;
use rand::rngs::{StdRng, SysRng};
use sha2::{Digest, Sha256};

use crate::primitive::{Kind, PrimitiveAir, PrimitiveStatement, PublicStatement};
use crate::{chacha, poly1305};

pub(crate) type Val = Goldilocks;
type Perm = Poseidon2Goldilocks<12>;
type Hash = PaddingFreeSponge<Perm, 12, 8, 4>;
type Compress = TruncatedPermutation<Perm, 2, 4, 12>;
type Mmcs = MerkleTreeHidingMmcs<
    <Val as Field>::Packing,
    <Val as Field>::Packing,
    Hash,
    Compress,
    StdRng,
    2,
    4,
    SALT_ELEMENTS,
>;
pub(crate) type Challenge = BinomialExtensionField<Val, EXTENSION_DEGREE>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, Mmcs>;
pub(crate) type Challenger = DuplexChallenger<Val, Perm, 12, 8>;
pub(crate) type Pcs = HidingFriPcs<Val, Radix2DitParallel<Val>, Mmcs, ChallengeMmcs, StdRng>;
pub(crate) type Config = StarkConfig<Pcs, Challenge, Challenger>;

pub(crate) const TRACE_LOG_HEIGHT: usize = 9;
pub(crate) const TRACE_HEIGHT: usize = 1 << TRACE_LOG_HEIGHT;
pub(crate) const PROOF_DEGREE_BITS: usize = TRACE_LOG_HEIGHT + 1;
pub(crate) const LOG_BLOWUP: usize = 3;
pub(crate) const QUERIES: usize = 192;
pub(crate) const EXTENSION_DEGREE: usize = 5;
pub(crate) const RANDOM_CODEWORDS: usize = 5;
const SALT_ELEMENTS: usize = 4;
const SECURITY_BITS: usize = 128;
const MODULUS_BITS: usize = 319;

const _: () = {
    assert!(TRACE_HEIGHT.is_power_of_two());
    assert!(RANDOM_CODEWORDS >= EXTENSION_DEGREE);
    assert!(NUM_SHA256_COLS == 7728);
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    Randomness,
    HidingBudget,
    SecurityProfile,
    Shape,
    Proving,
    Verification,
}
impl core::fmt::Display for Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{self:?}")
    }
}
impl std::error::Error for Error {}

#[derive(Debug, Clone, Copy)]
pub(crate) struct AllocationEstimate {
    pub(crate) trace_bytes: usize,
    pub(crate) masked_trace_bytes: usize,
    pub(crate) main_lde_bytes: usize,
}
impl AllocationEstimate {
    pub(crate) fn for_width(width: usize) -> Self {
        let element_bytes = core::mem::size_of::<Val>();
        Self {
            trace_bytes: TRACE_HEIGHT * width * element_bytes,
            masked_trace_bytes: 2 * TRACE_HEIGHT * (width + RANDOM_CODEWORDS) * element_bytes,
            main_lde_bytes: (2 << LOG_BLOWUP)
                * TRACE_HEIGHT
                * (width + RANDOM_CODEWORDS)
                * element_bytes,
        }
    }
}

/// The report describes this exact experimental wrapper, not the production proof profile.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SecurityReport {
    pub(crate) unique_decoding_bits: usize,
    pub(crate) list_decoding_bits: usize,
    pub(crate) constraints: usize,
    pub(crate) degree: usize,
    pub(crate) quotient_chunks: usize,
    pub(crate) batched_functions: usize,
}
impl SecurityReport {
    fn from_parameters(parameters: &StarkSecurityParams) -> Self {
        // Hiding doubles the committed polynomial degree. An analysis at the
        // original TRACE_LOG_HEIGHT would analyze the wrong proof domain.
        let bound = ProvenSecurity::compute_from_proof(PROOF_DEGREE_BITS, parameters);
        Self {
            unique_decoding_bits: bound.unique_decoding_bits,
            list_decoding_bits: bound.list_decoding_bits,
            constraints: parameters.num_constraints,
            degree: parameters.air_max_constraint_degree,
            quotient_chunks: parameters.num_quotient_chunks,
            batched_functions: parameters.num_batched_functions,
        }
    }

    pub(crate) fn require_target(self) -> Result<Self, Error> {
        if self.unique_decoding_bits < SECURITY_BITS || self.list_decoding_bits < SECURITY_BITS {
            return Err(Error::SecurityProfile);
        }
        Ok(self)
    }
}

pub(crate) fn profile_digest(kind: Kind) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"dcs/experiment/hiding-source-primitive-profile/v1");
    hash.update(b"p3-0.8.0/a21e3ed42905040ad49c519e402f018381c12d0c");
    hash.update(b"Goldilocks/Poseidon2-12/rate8/digest4/cap0/arity2");
    hash.update(kind.name());
    let (width, opening_points) = match kind {
        Kind::PairOpening => {
            crate::opening::profile(&mut hash);
            (crate::opening::air::WIDTH, 2)
        }
        Kind::Sha256 => {
            hash.update(b"SHA256-compression/one-public-case/repeat512/u32-big-endian");
            (NUM_SHA256_COLS, 1)
        }
        Kind::HChaCha20 | Kind::ChaCha20 => {
            hash.update(b"ChaCha20/20rounds/80quarter-rounds/u32-little-endian/bit-carry-v1");
            hash.update(b"input-constants-fixed/state512-next-columns/full-width-next-opening");
            hash.update(b"HChaCha-extract0..4,12..16-no-feedforward/ChaCha-feedforward16");
            for value in chacha::SCHEDULE
                .into_iter()
                .flatten()
                .chain(chacha::HCHACHA_OUTPUT)
                .chain([
                    16,
                    12,
                    8,
                    7,
                    chacha::QUARTER_ROUNDS,
                    chacha::air::PERIODIC_COLUMNS,
                ])
            {
                hash.update((value as u64).to_le_bytes());
            }
            for word in chacha::CONSTANTS {
                hash.update(word.to_le_bytes());
            }
            for row in 0..TRACE_HEIGHT {
                for step in 0..chacha::SCHEDULE.len() {
                    hash.update([u8::from(row < chacha::QUARTER_ROUNDS && row % 8 == step)]);
                }
            }
            (chacha::air::WIDTH, 2)
        }
        Kind::Poly1305Raw | Kind::Poly1305Padded => {
            hash.update(b"Poly1305/radix26/canonical-every-state/cyclic-carry32/v1");
            hash.update(b"public-raw-key-clamp-every-row/LE128-tag-plus-S/mod2^128");
            hash.update(b"raw-tail-append8L/padded-segments-zero-tail-full-hibit/no-empty-block");
            hash.update(
                b"segment-count-and-original-lengths-bound/first-H0/final-tag/degree-bound3",
            );
            hash.update(poly1305::CLAMP);
            for value in [
                poly1305::LIMBS,
                poly1305::LIMB_BITS,
                poly1305::MAX_BLOCKS,
                poly1305::MAX_SEGMENTS,
                poly1305::MAX_BYTES,
                poly1305::air::WIDTH,
                poly1305::statement::PUBLIC_VALUES,
            ] {
                hash.update((value as u64).to_le_bytes());
            }
            for row in 0..TRACE_HEIGHT {
                for block in 0..poly1305::MAX_BLOCKS {
                    hash.update([u8::from(row == block)]);
                }
            }
            (poly1305::air::WIDTH, 2)
        }
    };
    hash.update(b"rand0.10.3/StdRng/independent-OS-seeds");
    hash.update(b"no-preprocessing/no-grinding/final-poly-log0/fri-arity-log1");
    for value in [
        TRACE_LOG_HEIGHT,
        LOG_BLOWUP,
        QUERIES,
        EXTENSION_DEGREE,
        RANDOM_CODEWORDS,
        SALT_ELEMENTS,
        SECURITY_BITS,
        MODULUS_BITS,
        width,
        opening_points,
    ] {
        hash.update((value as u64).to_le_bytes());
    }
    hash.update(Val::ORDER_U64.to_le_bytes());
    hash.finalize().into()
}

fn os_rng() -> Result<StdRng, Error> {
    StdRng::try_from_rng(&mut SysRng).map_err(|_| Error::Randomness)
}

fn hiding_mmcs() -> Result<Mmcs, Error> {
    let permutation = default_goldilocks_poseidon2_12();
    Ok(Mmcs::new(
        Hash::new(permutation.clone()),
        Compress::new(permutation),
        0,
        os_rng()?,
    ))
}

fn new_pcs(random_codewords: usize) -> Result<Pcs, Error> {
    // Separate unpredictable streams for input-tree salts, FRI-tree salts and
    // polynomial masks. SDK clones fork their RNG streams with fresh seeds.
    let input_mmcs = hiding_mmcs()?;
    let fri_mmcs = ChallengeMmcs::new(hiding_mmcs()?);
    let fri = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: QUERIES,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: fri_mmcs,
    };
    Ok(Pcs::new(
        Radix2DitParallel::default(),
        input_mmcs,
        fri,
        random_codewords,
        os_rng()?,
    ))
}

pub(crate) fn config() -> Result<Config, Error> {
    Ok(Config::new(
        new_pcs(RANDOM_CODEWORDS)?,
        Challenger::new(default_goldilocks_poseidon2_12()),
    ))
}

#[cfg(test)]
pub(crate) fn contract_pcs(random_codewords: usize) -> Result<Pcs, Error> {
    new_pcs(random_codewords)
}

pub(crate) fn analyze(air: &PrimitiveAir) -> Result<(StarkSecurityParams, SecurityReport), Error> {
    // No trace, LDE, Merkle tree or witness is allocated for this calculation.
    let fri = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: QUERIES,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: (),
    };
    // SDK 0.8 opens the complete width at both points whenever any next-row
    // column is read. The returned security report must count that full shape.
    let opening_points = 1 + usize::from(!air.main_next_row_columns().is_empty());
    if air.preprocessed_width() != 0
        || TRACE_HEIGHT < 2 * (QUERIES + EXTENSION_DEGREE * opening_points)
        || RANDOM_CODEWORDS < EXTENSION_DEGREE
    {
        return Err(Error::HidingBudget);
    }
    let parameters = StarkSecurityParams::from_air::<Val, Challenge, _>(
        fri.security_regime(),
        air,
        AirLayout::from_air::<Val>(air),
        TwoAdicMultiplicativeCoset::new(Val::ONE, TRACE_LOG_HEIGHT).unwrap(),
        MODULUS_BITS,
        SECURITY_BITS,
        opening_points,
        OpeningShape::hiding(RANDOM_CODEWORDS),
        fri.grinding_sites(),
    );
    let report = SecurityReport::from_parameters(&parameters);
    Ok((parameters, report))
}

/// One typed public statement owns this backend's analytical parameters.
/// Exact public values bind its lifetime; another statement requires a new
/// backend even when kind/width match (empty and nonempty degrees may differ).
pub(crate) struct Backend {
    pub(crate) config: Config,
    pub(crate) parameters: StarkSecurityParams,
    pub(crate) report: SecurityReport,
    kind: Kind,
    width: usize,
    next_row: bool,
    public_values: Vec<Val>,
}
impl Backend {
    pub(crate) fn new(statement: &impl PublicStatement) -> Result<Self, Error> {
        let air = statement.air();
        let (parameters, report) = analyze(&air)?;
        let report = report.require_target()?;
        let public_values = statement.public_values();
        if public_values.len() != air.num_public_values() {
            return Err(Error::Shape);
        }
        Ok(Self {
            config: config()?,
            parameters,
            report,
            kind: statement.kind(),
            width: air.width(),
            next_row: !air.main_next_row_columns().is_empty(),
            public_values,
        })
    }

    pub(crate) fn prove(
        &self,
        statement: &impl PrimitiveStatement,
    ) -> Result<Proof<Config>, Error> {
        self.prove_with_trace(statement, || Ok(statement.trace()))
    }

    /// A witness factory is invoked only after exact public-statement binding.
    /// It receives no owner key or key-export callback; this backend is experiment-private.
    pub(crate) fn prove_with_trace(
        &self,
        statement: &impl PublicStatement,
        trace: impl FnOnce() -> Result<p3_matrix::dense::RowMajorMatrix<Val>, Error>,
    ) -> Result<Proof<Config>, Error> {
        let public_values = statement.public_values();
        if statement.kind() != self.kind || public_values != self.public_values {
            return Err(Error::Shape);
        }
        let trace = trace()?;
        if trace.width != self.width || trace.values.len() != TRACE_HEIGHT * self.width {
            return Err(Error::Shape);
        }
        prove(&self.config, &statement.air(), trace, &public_values).map_err(|_| Error::Proving)
    }

    pub(crate) fn verify(
        &self,
        statement: &impl PublicStatement,
        proof: &Proof<Config>,
    ) -> Result<(), Error> {
        let public_values = statement.public_values();
        if statement.kind() != self.kind
            || public_values != self.public_values
            || proof.degree_bits != PROOF_DEGREE_BITS
            || proof.opened_values.trace_local.len() != self.width
            || proof.opened_values.trace_next.as_ref().map(Vec::len)
                != self.next_row.then_some(self.width)
            || proof.opened_values.preprocessed.is_some()
            || proof.commitments.random.is_none()
            || proof.opened_values.random.is_none()
        {
            return Err(Error::Shape);
        }
        let bound = proof.proven_security(&self.parameters);
        SecurityReport {
            unique_decoding_bits: bound.unique_decoding_bits,
            list_decoding_bits: bound.list_decoding_bits,
            ..self.report
        }
        .require_target()?;
        verify(&self.config, &statement.air(), proof, &public_values)
            .map_err(|_| Error::Verification)
    }
}
