//! Shared native adapter inside the private owning program cfg(test) harness.
use super::ro::{Leaf, Node, Oracle, ResearchChallenger};
use bfv_hiding_stark::{Challenge, LOG_BLOWUP, QUERIES, RANDOM_CODEWORDS, SALT_ELEMENTS, Val};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_fri::{FriParameters, HidingFriPcs};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_uni_stark::StarkConfig;
use rand_public_pp::rngs::StdRng;

pub(in crate::gold::program) type Mmcs =
    MerkleTreeHidingMmcs<Val, u8, Leaf, Node, StdRng, 2, 32, SALT_ELEMENTS>;
pub(in crate::gold::program) type ChallengeMmcs = ExtensionMmcs<Val, Challenge, Mmcs>;
pub(in crate::gold::program) type Pcs =
    HidingFriPcs<Val, Radix2DitParallel<Val>, Mmcs, ChallengeMmcs, StdRng>;
pub(in crate::gold::program) type Config = StarkConfig<Pcs, Challenge, ResearchChallenger>;

pub(in crate::gold::program) fn mmcs(oracle: Oracle, rng: StdRng) -> Mmcs {
    Mmcs::new(Leaf(oracle.clone()), Node(oracle), 0, rng)
}
pub(in crate::gold::program) fn fri(oracle: Oracle, rng: StdRng) -> FriParameters<ChallengeMmcs> {
    FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: QUERIES,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: ChallengeMmcs::new(mmcs(oracle, rng)),
    }
}
pub(in crate::gold::program) fn config(
    oracle: Oracle,
    challenger: ResearchChallenger,
    input_salts: StdRng,
    fri_salts: StdRng,
    pcs_masks: StdRng,
) -> Config {
    assert_eq!(
        (LOG_BLOWUP, QUERIES, RANDOM_CODEWORDS, SALT_ELEMENTS),
        (3, 192, 5, 4)
    );
    Config::new(
        Pcs::new(
            Radix2DitParallel::default(),
            mmcs(oracle.clone(), input_salts),
            fri(oracle, fri_salts),
            RANDOM_CODEWORDS,
            pcs_masks,
        ),
        challenger,
    )
}
