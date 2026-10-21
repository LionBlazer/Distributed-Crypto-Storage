//! Sealed deterministic PUBLIC preprocessing. No seeded config can escape.
use super::{
    Error, Expected, Result,
    air::{DEGREE_BITS, FixedAir},
    profile,
};
use bfv_hiding_stark::{
    ChallengeMmcs, Challenger, Compress, Config, Hash, LOG_BLOWUP, Mmcs, Pcs, QUERIES,
    RANDOM_CODEWORDS,
};
use p3_batch_stark::ProverData;
use p3_dft::Radix2DitParallel;
use p3_fri::FriParameters;
use p3_goldilocks::default_goldilocks_poseidon2_12;
use rand::{SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha512};

fn stream(expected: &Expected, label: u8) -> StdRng {
    let mut hash = Sha512::new();
    hash.update(b"dcs/hiding-logup-wire/PUBLIC-PP-only/v1\0");
    hash.update(profile());
    hash.update(expected.context);
    hash.update(expected.output.to_le_bytes());
    hash.update([label]);
    let seed: [u8; 32] = hash.finalize()[..32]
        .try_into()
        .expect("fixed digest length");
    StdRng::from_seed(seed)
}
fn public_mmcs(expected: &Expected, label: u8) -> Mmcs {
    let permutation = default_goldilocks_poseidon2_12();
    Mmcs::new(
        Hash::new(permutation.clone()),
        Compress::new(permutation),
        0,
        stream(expected, label),
    )
}

/// The ONLY public helper output is data for public one-hot PP. Its local config
/// and all public-seeded RNG owners die here before any MAIN/AUX commit exists.
pub(super) fn public_data(air: &FixedAir, expected: &Expected) -> Result<ProverData<Config>> {
    air.preflight()?;
    let fri = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: QUERIES,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: ChallengeMmcs::new(public_mmcs(expected, 1)),
    };
    let pcs = Pcs::new(
        Radix2DitParallel::default(),
        public_mmcs(expected, 0),
        fri,
        RANDOM_CODEWORDS,
        stream(expected, 2),
    );
    let public_config = Config::new(pcs, Challenger::new(default_goldilocks_poseidon2_12()));
    let result = ProverData::from_airs_and_degrees(
        &public_config,
        std::slice::from_ref(air),
        &[DEGREE_BITS],
    )
    .map_err(|_| Error::Proving);
    drop(public_config);
    result
}
