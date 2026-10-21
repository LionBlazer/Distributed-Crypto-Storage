//! Closed PUBLIC-only preprocessing; seeded config dies before private proving.
use super::{
    air::QueryMaskAir,
    backend::{Error, Result},
    layout::*,
    security::Gate,
};
use bfv_hiding_stark::{
    ChallengeMmcs, Challenger, Compress, Config, Hash, LOG_BLOWUP, Mmcs, Pcs, QUERIES,
    RANDOM_CODEWORDS,
};
use p3_batch_stark::ProverData;
use p3_dft::Radix2DitParallel;
use p3_fri::FriParameters;
use p3_goldilocks::default_goldilocks_poseidon2_12;
use rand_public_pp::{SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha512};

fn stream(label: u8) -> StdRng {
    let mut h = Sha512::new();
    h.update(b"DCS/research/QueryMaskEncoding/STRUCTURAL-PUBLIC-PP-ONLY/v1\0");
    h.update(super::profile());
    h.update(super::QUERY_ROLE.to_le_bytes());
    h.update([label]);
    let mut seed = [0; 32];
    seed.copy_from_slice(&h.finalize()[..32]);
    StdRng::from_seed(seed)
}
fn mmcs(label: u8) -> Mmcs {
    let p = default_goldilocks_poseidon2_12();
    Mmcs::new(Hash::new(p.clone()), Compress::new(p), 0, stream(label))
}
pub(super) fn data(air: &QueryMaskAir, gate: &Gate) -> Result<ProverData<Config>> {
    gate.require_floor().map_err(|_| Error::Security)?;
    let fri = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: QUERIES,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: ChallengeMmcs::new(mmcs(1)),
    };
    let pcs = Pcs::new(
        Radix2DitParallel::default(),
        mmcs(0),
        fri,
        RANDOM_CODEWORDS,
        stream(2),
    );
    let config = Config::new(pcs, Challenger::new(default_goldilocks_poseidon2_12()));
    let result =
        ProverData::from_airs_and_degrees(&config, core::slice::from_ref(air), &[LOG_HEIGHT + 1]);
    drop(config);
    let data = result.map_err(|_| Error::Setup)?;
    let pp = data.common.preprocessed.as_ref().ok_or(Error::Shape)?;
    if pp.commitment.num_roots() != 1
        || pp.instances.len() != 1
        || pp.matrix_to_instance.as_slice() != [0]
        || data.common.lookups.len() != 1
        || !data.common.lookups[0].is_empty()
    {
        return Err(Error::Shape);
    }
    let meta = pp.instances[0].as_ref().ok_or(Error::Shape)?;
    if meta.matrix_index != 0 || meta.width != PP_WIDTH || meta.degree_bits != LOG_HEIGHT + 1 {
        return Err(Error::Shape);
    }
    Ok(data)
}
