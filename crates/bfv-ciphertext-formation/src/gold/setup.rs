//! Sealed deterministic PUBLIC-only preprocessing; no seeded configuration escapes.
use super::program::{Assessment, BUS, DEGREE_BITS, PP_WIDTH, ProgramAir};
use super::{Error, Result, relation::ExpectedRef, wire};
use bfv_hiding_stark::{
    ChallengeMmcs, Challenger, Compress, Config, Hash, LOG_BLOWUP, Mmcs, Pcs, QUERIES,
    RANDOM_CODEWORDS,
};
use p3_batch_stark::{CommonData, ProverData};
use p3_dft::Radix2DitParallel;
use p3_fri::FriParameters;
use p3_goldilocks::default_goldilocks_poseidon2_12;
use p3_lookup::Kind;
use rand_public_pp::{SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha512};

fn public_stream(expected: ExpectedRef<'_>, label: u8) -> StdRng {
    let mut hash = Sha512::new();
    hash.update(b"DCS/GOLD-FORMATION/PUBLIC-PP-ONLY/v1\0");
    hash.update(expected.kind().profile());
    hash.update(wire::profile_for(expected.kind()));
    hash.update(expected.binding());
    hash.update([label]);
    let digest = hash.finalize();
    let mut seed = [0; 32];
    seed.copy_from_slice(&digest[..32]);
    StdRng::from_seed(seed)
}
fn public_mmcs(expected: ExpectedRef<'_>, label: u8) -> Mmcs {
    let permutation = default_goldilocks_poseidon2_12();
    Mmcs::new(
        Hash::new(permutation.clone()),
        Compress::new(permutation),
        0,
        public_stream(expected, label),
    )
}

/// The config and all deterministically public-seeded RNG owners die before any
/// private MAIN/AUX/quotient/randomization commitment. Only PUBLIC ProverData
/// remains, with no config, RNG, private values or accepting result inside it.
/// The caller has already assessed the SAME immutable AIR before entering here.
pub(super) fn public_data(
    air: &ProgramAir,
    expected: ExpectedRef<'_>,
    assessment: &Assessment,
) -> Result<ProverData<Config>> {
    assessment.require_resources()?;
    wire::require_assessment(assessment)?;
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
        public_stream(expected, 2),
    );
    let public_config = Config::new(pcs, Challenger::new(default_goldilocks_poseidon2_12()));
    let result = ProverData::from_airs_and_degrees(
        &public_config,
        core::slice::from_ref(air),
        &[DEGREE_BITS],
    )
    .map_err(|_| Error::Backend);
    drop(public_config);
    let data = result?;
    require_common(&data.common, assessment)?;
    Ok(data)
}

/// Metadata consistency after the real fixed native factory, not a supplied
/// CommonData validator/adoption API. All callers use public_data above.
fn require_common(common: &CommonData<Config>, assessment: &Assessment) -> Result<()> {
    wire::require_assessment(assessment)?;
    let pp = common.preprocessed.as_ref().ok_or(Error::Shape)?;
    if pp.commitment.num_roots() != 1
        || pp.instances.len() != 1
        || pp.matrix_to_instance.as_slice() != [0]
        || common.lookups.len() != 1
    {
        return Err(Error::Shape);
    }
    let meta = pp.instances[0].as_ref().ok_or(Error::Shape)?;
    if meta.matrix_index != 0 || meta.width != PP_WIDTH || meta.degree_bits != DEGREE_BITS {
        return Err(Error::Shape);
    }
    let lookups = &common.lookups[0];
    if lookups.len() != assessment.packed_lookup_count() || lookups.total_count_weight() != 512 {
        return Err(Error::Shape);
    }
    let mut messages = 0usize;
    for (column, lookup) in lookups.iter().enumerate() {
        if lookup.kind != Kind::Global(BUS.to_owned())
            || lookup.column != column
            || lookup.flags.is_some()
            || lookup.elements.is_empty()
            || lookup.elements.len() != lookup.multiplicities.len()
            || lookup.elements.iter().any(|tuple| tuple.len() != 2)
        {
            return Err(Error::Shape);
        }
        messages = messages
            .checked_add(lookup.elements.len())
            .ok_or(Error::Resource)?;
    }
    if messages != 128 {
        return Err(Error::Shape);
    }
    Ok(())
}
