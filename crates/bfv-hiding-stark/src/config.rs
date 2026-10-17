use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::Field;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, HidingFriPcs};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks, default_goldilocks_poseidon2_12};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;
use rand::SeedableRng;
use rand::rngs::{StdRng, SysRng};

pub type Val = Goldilocks;
pub type Perm = Poseidon2Goldilocks<12>;
pub type Hash = PaddingFreeSponge<Perm, 12, 8, 4>;
pub type Compress = TruncatedPermutation<Perm, 2, 4, 12>;
pub type Mmcs = MerkleTreeHidingMmcs<
    <Val as Field>::Packing,
    <Val as Field>::Packing,
    Hash,
    Compress,
    StdRng,
    2,
    4,
    SALT_ELEMENTS,
>;
pub type Challenge = BinomialExtensionField<Val, EXTENSION_DEGREE>;
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, Mmcs>;
pub type Challenger = DuplexChallenger<Val, Perm, 12, 8>;
pub type Pcs = HidingFriPcs<Val, Radix2DitParallel<Val>, Mmcs, ChallengeMmcs, StdRng>;
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;

pub const TRACE_LOG_HEIGHT: usize = 9;
pub const TRACE_HEIGHT: usize = 1 << TRACE_LOG_HEIGHT;
pub const PROOF_DEGREE_BITS: usize = TRACE_LOG_HEIGHT + 1;
pub const LOG_BLOWUP: usize = 3;
pub const QUERIES: usize = 192;
pub const EXTENSION_DEGREE: usize = 5;
pub const RANDOM_CODEWORDS: usize = 5;
pub const SALT_ELEMENTS: usize = 4;
pub const SECURITY_BITS: usize = 128;
pub const MODULUS_BITS: usize = 319;

const _: () = {
    assert!(TRACE_HEIGHT.is_power_of_two());
    assert!(RANDOM_CODEWORDS >= EXTENSION_DEGREE);
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
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
pub struct AllocationEstimate {
    pub trace_bytes: usize,
    pub masked_trace_bytes: usize,
    pub main_lde_bytes: usize,
}
impl AllocationEstimate {
    pub fn for_width(width: usize) -> Self {
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

pub fn config() -> Result<Config, Error> {
    Ok(Config::new(
        new_pcs(RANDOM_CODEWORDS)?,
        Challenger::new(default_goldilocks_poseidon2_12()),
    ))
}
