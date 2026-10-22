//! Deterministic PUBLIC-only SHA preprocessing for the original Predicate AIR.
//! No seeded config or RNG escapes into a private commitment operation.
use super::{
    air::ProgramAir,
    assessment::Assessment,
    goldens, hash_wire,
    plan::PP_WIDTH,
    probe::{DEGREE_BITS, Error, Result},
    public_values,
};
use bfv_hiding_stark::{Challenge, LOG_BLOWUP, QUERIES, RANDOM_CODEWORDS, hash};
use p3_air::BaseAir;
use p3_batch_stark::{CommonData, ProverData};
use p3_dft::Radix2DitParallel;
use p3_fri::FriParameters;
use p3_lookup::{Kind, Lookups};
use rand_public_pp::{SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha512};

fn stream(label: u8) -> StdRng {
    let mut digest = Sha512::new();
    digest.update(b"DCS/research/word208/hash-suite/PREDICATE-PUBLIC-PP-ONLY/v1\0");
    digest.update(super::profile());
    digest.update(hash_wire::profile());
    digest.update([1, label]);
    let mut seed = [0; 32];
    seed.copy_from_slice(&digest.finalize()[..32]);
    StdRng::from_seed(seed)
}

fn mmcs(label: u8) -> hash::Mmcs {
    hash::Mmcs::new(hash::LeafHash, hash::NodeCompress, 0, stream(label))
}

pub(super) fn public_data(
    air: &ProgramAir,
    report: &Assessment,
) -> Result<ProverData<hash::Config>> {
    report.require_resources().map_err(|_| Error::Resource)?;
    hash_wire::require_assessment(report)?;
    goldens::require_plan(&air.plan).map_err(|_| Error::Binding)?;
    if !air.plan.pool.predicate
        || air.plan.height != 512
        || air.num_public_values() != public_values::COUNT
    {
        return Err(Error::Shape);
    }
    let fri = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: QUERIES,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: hash::ChallengeMmcs::new(mmcs(1)),
    };
    let pcs = hash::Pcs::new(
        Radix2DitParallel::default(),
        mmcs(0),
        fri,
        RANDOM_CODEWORDS,
        stream(2),
    );
    let config = hash::Config::new(pcs, hash::Challenger::new());
    let result =
        ProverData::from_airs_and_degrees(&config, core::slice::from_ref(air), &[DEGREE_BITS]);
    drop(config);
    let data = result.map_err(|_| Error::Setup)?;
    require_common(&data.common, air, report)?;
    Ok(data)
}

/// Checked only after the genuine fixed factory above, never for adopting a
/// caller-supplied CommonData. The actual SDK retains default lookup packing.
fn require_common(
    common: &CommonData<hash::Config>,
    air: &ProgramAir,
    report: &Assessment,
) -> Result<()> {
    hash_wire::require_assessment(report)?;
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
    let original = Lookups::<bfv_hiding_stark::Val>::from_air::<Challenge, ProgramAir>(air);
    let packed = &common.lookups[0];
    if original.len() != 98
        || packed.len() != report.packed_lookup_count()
        || packed.total_count_weight() != original.total_count_weight()
    {
        return Err(Error::Shape);
    }
    let mut messages = 0usize;
    for (column, lookup) in packed.iter().enumerate() {
        let width = match &lookup.kind {
            Kind::Global(bus)
                if bus == "DCS/research/word208/v1/ssa"
                    || bus == "DCS/research/word208/v1/mask256" =>
            {
                2
            }
            Kind::Global(bus) if bus == "DCS/research/word208/v1/policy25" => 5,
            _ => return Err(Error::Shape),
        };
        if lookup.column != column
            || lookup.flags.is_some()
            || lookup.elements.is_empty()
            || lookup.elements.len() != lookup.multiplicities.len()
            || lookup.elements.iter().any(|tuple| tuple.len() != width)
        {
            return Err(Error::Shape);
        }
        messages = messages
            .checked_add(lookup.elements.len())
            .ok_or(Error::Resource)?;
    }
    if messages != original.len() {
        return Err(Error::Shape);
    }
    Ok(())
}
