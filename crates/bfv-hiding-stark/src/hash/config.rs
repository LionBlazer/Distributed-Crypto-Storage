use super::challenger::Challenger;
use super::merkle::{LeafHash, NodeCompress};
use crate::{Challenge, Error, Val};
use crate::{LOG_BLOWUP, QUERIES, RANDOM_CODEWORDS, SALT_ELEMENTS};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_fri::{FriParameters, HidingFriPcs};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_uni_stark::StarkConfig;
use rand::SeedableRng;
use rand::rngs::{StdRng, SysRng};

const _: () = {
    assert!(LOG_BLOWUP == 3 && QUERIES == 192);
    assert!(RANDOM_CODEWORDS == 5 && SALT_ELEMENTS == 4);
    assert!(crate::EXTENSION_DEGREE == 5);
    assert!(crate::TRACE_HEIGHT == 512);
    assert!(crate::PROOF_DEGREE_BITS == 10);
};

pub type Mmcs = MerkleTreeHidingMmcs<Val, u8, LeafHash, NodeCompress, StdRng, 2, 32, SALT_ELEMENTS>;
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, Mmcs>;
pub type Pcs = HidingFriPcs<Val, Radix2DitParallel<Val>, Mmcs, ChallengeMmcs, StdRng>;
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;

fn os_rng() -> Result<StdRng, Error> {
    StdRng::try_from_rng(&mut SysRng).map_err(|_| Error::Randomness)
}
fn mmcs() -> Result<Mmcs, Error> {
    Ok(Mmcs::new(LeafHash, NodeCompress, 0, os_rng()?))
}
pub fn config() -> Result<Config, Error> {
    let fri = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: QUERIES,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: ChallengeMmcs::new(mmcs()?),
    };
    let pcs = Pcs::new(
        Radix2DitParallel::default(),
        mmcs()?,
        fri,
        RANDOM_CODEWORDS,
        os_rng()?,
    );
    Ok(Config::new(pcs, Challenger::new()))
}
