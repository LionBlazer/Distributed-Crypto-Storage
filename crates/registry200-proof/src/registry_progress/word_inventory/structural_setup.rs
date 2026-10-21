//! Sealed ROLE+PROFILE-only PUBLIC preprocessing, no private proof config.
use super::{air::ProgramAir, assessment::Assessment, public_values};
use bfv_hiding_stark::{
    ChallengeMmcs, Challenger, Compress, Config, Hash, LOG_BLOWUP, Mmcs, Pcs, QUERIES,
    RANDOM_CODEWORDS,
};
use p3_air::BaseAir;
use p3_batch_stark::ProverData;
use p3_dft::Radix2DitParallel;
use p3_fri::FriParameters;
use p3_goldilocks::default_goldilocks_poseidon2_12;
use rand_public_pp::{SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha512};
fn stream(role: bool, label: u8) -> StdRng {
    let mut h = Sha512::new();
    h.update(b"DCS/research/word208/v2/STRUCTURAL-PUBLIC-PP-ONLY\0");
    h.update(super::profile());
    h.update([u8::from(role), label]);
    let mut seed = [0; 32];
    seed.copy_from_slice(&h.finalize()[..32]);
    StdRng::from_seed(seed)
}
fn mmcs(role: bool, label: u8) -> Mmcs {
    let p = default_goldilocks_poseidon2_12();
    Mmcs::new(
        Hash::new(p.clone()),
        Compress::new(p),
        0,
        stream(role, label),
    )
}
/// Only native PUBLIC ProverData escapes. There is no Metadata/private input,
/// accepting callback or reusable cryptographic verdict in this factory.
/// Native security/resources must be derived for this actual new AIR first.
pub(super) fn public_data(
    air: &ProgramAir,
    report: &Assessment,
) -> Result<ProverData<Config>, String> {
    report.require_resources()?;
    super::goldens::require_plan(&air.plan)?;
    if air.plan.height != 512 || air.num_public_values() != public_values::COUNT {
        return Err("structural-PP-shape".into());
    }
    let role = air.plan.pool.predicate;
    let fri = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: QUERIES,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: ChallengeMmcs::new(mmcs(role, 1)),
    };
    let pcs = Pcs::new(
        Radix2DitParallel::default(),
        mmcs(role, 0),
        fri,
        RANDOM_CODEWORDS,
        stream(role, 2),
    );
    let config = Config::new(pcs, Challenger::new(default_goldilocks_poseidon2_12()));
    let result = ProverData::from_airs_and_degrees(&config, core::slice::from_ref(air), &[10])
        .map_err(|_| "structural-public-PP-native".to_owned());
    drop(config);
    let data = result?;
    super::goldens::require_commitment(role, &data)?;
    Ok(data)
}
