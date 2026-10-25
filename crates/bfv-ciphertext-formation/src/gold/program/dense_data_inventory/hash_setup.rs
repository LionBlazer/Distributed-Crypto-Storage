// Sealed SHA-suite PUBLIC PP reconstruction; its seeded config never proves.
use super::Expected;
use super::assessment::Assessment;
use super::hash_wire as wire;
use super::layout::{BUS, DOMAIN, LOG_H, PORTS, PP as PP_WIDTH};
use super::native::FullAir;
#[cfg(test)]
use crate::gold::public_hash_trace::Sha512;
use crate::gold::{Error, Result};
use bfv_hiding_stark::hash::{
    ChallengeMmcs, Challenger, Config, LeafHash, Mmcs, NodeCompress, Pcs,
};
use bfv_hiding_stark::{LOG_BLOWUP, QUERIES, RANDOM_CODEWORDS};
use p3_batch_stark::{CommonData, ProverData};
use p3_dft::Radix2DitParallel;
use p3_fri::FriParameters;
use p3_lookup::Kind;
use rand_public_pp::{SeedableRng, rngs::StdRng};
#[cfg(not(test))]
use sha2::{Digest, Sha512};

const DEGREE_BITS: usize = LOG_H + 1;

fn public_stream(expected: &Expected, label: u8) -> StdRng {
    let mut hash = Sha512::new();
    hash.update(b"DCS/hash-formation/PUBLIC-PP-ONLY/v1\0");
    hash.update((DOMAIN.len() as u64).to_le_bytes());
    hash.update(DOMAIN);
    hash.update(wire::profile());
    hash.update(expected.binding());
    hash.update([label]);
    let digest = hash.finalize();
    let mut seed = [0; 32];
    seed.copy_from_slice(&digest[..32]);
    StdRng::from_seed(seed)
}

#[cfg(test)]
#[allow(
    dead_code,
    reason = "shared DATA source; only the Query host owns the research test"
)]
pub(super) fn research_public_stream(expected: &Expected, label: u8) -> StdRng {
    assert!(label <= 2);
    public_stream(expected, label)
}

fn public_mmcs(expected: &Expected, label: u8) -> Mmcs {
    Mmcs::new(LeafHash, NodeCompress, 0, public_stream(expected, label))
}

/// Reuse the original full public matrix and automatic lookup packing. Only
/// PUBLIC material survives; the deterministically seeded config is dropped
/// before a caller can construct private MAIN/AUX/quotient/random commitments.
pub(super) fn public_data(
    air: &FullAir,
    expected: &Expected,
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
    let config = Config::new(pcs, Challenger::new());
    let result =
        ProverData::from_airs_and_degrees(&config, core::slice::from_ref(air), &[DEGREE_BITS])
            .map_err(|_| Error::Backend);
    drop(config);
    let public = result?;
    require_common(&public.common, assessment)?;
    Ok(public)
}

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
    if lookups.len() != assessment.packed_lookup_count()
        || lookups.total_count_weight() != (4 * PORTS) as u64
    {
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
    if messages != PORTS {
        return Err(Error::Shape);
    }
    Ok(())
}
