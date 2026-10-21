//! Closed test-private hiding proof probe; no Source, head, SQL or state grant.
use super::probe_wire as wire;
use super::{
    Metadata,
    air::ProgramAir,
    assessment::{self, Assessment},
    complete,
    owner::PrimaryInputs,
    plan::{PP_WIDTH, Plan},
    witness,
};
use bfv_hiding_stark::{
    Challenge, ChallengeMmcs, Challenger, Compress, Config, Hash, LOG_BLOWUP, Mmcs, Pcs, QUERIES,
    RANDOM_CODEWORDS, Val,
};
use p3_batch_stark::{
    BatchProof, CommonData, ProverData, StarkInstance, prove_batch, verify_batch,
};
use p3_dft::Radix2DitParallel;
use p3_field::PrimeField64;
use p3_fri::FriParameters;
use p3_goldilocks::default_goldilocks_poseidon2_12;
use p3_lookup::{Kind, Lookups};
use rand_public_pp::{SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha512};
use std::panic::{AssertUnwindSafe, catch_unwind};

#[cfg(test)]
struct PhaseTiming {
    predicate: bool,
    operation: &'static str,
    phase: &'static str,
    began: std::time::Instant,
}
#[cfg(test)]
impl PhaseTiming {
    fn new(predicate: bool, operation: &'static str, phase: &'static str) -> Self {
        Self {
            predicate,
            operation,
            phase,
            began: std::time::Instant::now(),
        }
    }
}
#[cfg(test)]
impl Drop for PhaseTiming {
    fn drop(&mut self) {
        use std::io::Write as _;
        // Fixed public labels/numeric elapsed only. Diagnostic I/O failure must
        // never replace a native result or panic during another unwinding.
        let elapsed_us = self.began.elapsed().as_micros();
        let _ = writeln!(
            std::io::stderr().lock(),
            "word_probe_phase role={} operation={} phase={} elapsed_us={}",
            if self.predicate {
                "predicate"
            } else {
                "control"
            },
            self.operation,
            self.phase,
            elapsed_us,
        );
    }
}

pub(super) const DEGREE_BITS: usize = 10;
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Error {
    Shape,
    Resource,
    Security,
    Binding,
    Encoding,
    Setup,
    Proving,
    Backend,
    Verification,
}
pub(super) type Result<T> = core::result::Result<T, Error>;

/// All independently retained PUBLIC metadata, not a verdict or private opening.
/// Length framing and the full original images prevent a reduced-tag association.
pub(super) fn binding(m: &Metadata) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(b"DCS/research/word208/native-probe/complete-public-expectation/v1\0");
    h.update(super::profile());
    h.update(wire::profile());
    h.update([u8::from(m.predicate)]);
    let source = m.source.statement();
    h.update(crate::source::profile_digest(
        crate::source::Relation::StateCertificate,
    ));
    h.update(source.request);
    for (head, packet) in source.heads.iter().zip(&source.packets) {
        h.update((head.len() as u64).to_le_bytes());
        h.update(head);
        h.update((packet.len() as u64).to_le_bytes());
        h.update(packet);
    }
    let mut values = |v: &[Val]| {
        h.update((v.len() as u64).to_le_bytes());
        for x in v {
            h.update(x.as_canonical_u64().to_le_bytes());
        }
    };
    values(&source.key_commitment);
    values(&source.open_commitment);
    values(&m.registry_header);
    values(&m.enrollment_header);
    values(&m.context);
    values(&m.scope);
    values(&m.parent);
    values(&m.enrollment);
    values(&m.old);
    values(&m.command);
    values(&m.statement);
    values(&m.next);
    values(&m.result);
    values(&m.blind_sql);
    h.finalize().into()
}

/// The complete real security/resource assessment precedes PP and MAIN allocation.
pub(super) fn prescreen(m: &Metadata) -> Result<(ProgramAir, Assessment)> {
    m.source.statement().reaudit().map_err(|_| Error::Shape)?;
    let air = ProgramAir {
        plan: Plan::new(complete(m).map_err(|_| Error::Shape)?).map_err(|_| Error::Shape)?,
    };
    let report = assessment::assess(&air).map_err(|_| Error::Security)?;
    report.require_resources().map_err(|_| Error::Resource)?;
    wire::require_assessment(&report)?;
    Ok((air, report))
}
fn public_stream(m: &Metadata, label: u8) -> StdRng {
    let mut h = Sha512::new();
    h.update(b"DCS/research/word208/native-probe/PUBLIC-PP-ONLY/v1\0");
    h.update(binding(m));
    h.update([label]);
    let digest = h.finalize();
    let mut seed = [0; 32];
    seed.copy_from_slice(&digest[..32]);
    StdRng::from_seed(seed)
}
fn public_mmcs(m: &Metadata, label: u8) -> Mmcs {
    let p = default_goldilocks_poseidon2_12();
    Mmcs::new(
        Hash::new(p.clone()),
        Compress::new(p),
        0,
        public_stream(m, label),
    )
}
/// Sole PUBLIC PP factory. Only ProverData escapes; the seeded config/RNG dies
/// before any MAIN/AUX/quotient/randomization commitment. No caller PP is adopted.
pub(super) fn public_data(
    m: &Metadata,
    air: &ProgramAir,
    report: &Assessment,
) -> Result<ProverData<Config>> {
    report.require_resources().map_err(|_| Error::Resource)?;
    wire::require_assessment(report)?;
    let fri = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: QUERIES,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: ChallengeMmcs::new(public_mmcs(m, 1)),
    };
    let pcs = Pcs::new(
        Radix2DitParallel::default(),
        public_mmcs(m, 0),
        fri,
        RANDOM_CODEWORDS,
        public_stream(m, 2),
    );
    let config = Config::new(pcs, Challenger::new(default_goldilocks_poseidon2_12()));
    let result =
        ProverData::from_airs_and_degrees(&config, core::slice::from_ref(air), &[DEGREE_BITS])
            .map_err(|_| Error::Setup);
    drop(config);
    let data = result?;
    require_common(&data.common, air, report)?;
    Ok(data)
}
fn require_common(
    common: &CommonData<Config>,
    air: &ProgramAir,
    report: &Assessment,
) -> Result<()> {
    wire::require_assessment(report)?;
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
    let original = Lookups::<Val>::from_air::<Challenge, ProgramAir>(air);
    let lookups = &common.lookups[0];
    if original.len() != 98
        || lookups.len() != report.packed_lookup_count()
        || lookups.total_count_weight() != original.total_count_weight()
    {
        return Err(Error::Shape);
    }
    let mut messages = 0usize;
    for (column, lookup) in lookups.iter().enumerate() {
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
            || lookup.elements.iter().any(|x| x.len() != width)
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
pub(super) fn private_config() -> Result<Config> {
    bfv_hiding_stark::config().map_err(|_| Error::Backend)
}
pub(super) fn prove_trace(
    air: &ProgramAir,
    trace: &p3_matrix::dense::RowMajorMatrix<Val>,
    data: &ProverData<Config>,
) -> Result<BatchProof<Config>> {
    let config = private_config()?;
    let instances = [StarkInstance {
        air,
        trace,
        public_values: vec![],
    }];
    catch_unwind(AssertUnwindSafe(|| prove_batch(&config, &instances, data)))
        .map_err(|_| Error::Proving)?
        .map_err(|_| Error::Proving)
}

/// Returns only UNVERIFIED bytes. Same closed factory, resources first, ONE
/// guarded private SSA execution, and actual native proving; no self-verdict.
pub(super) fn produce(m: &Metadata, input: &PrimaryInputs) -> Result<Vec<u8>> {
    #[cfg(test)]
    let _total = PhaseTiming::new(m.predicate, "produce", "total");
    catch_unwind(AssertUnwindSafe(|| {
        let (public_air, report) = {
            #[cfg(test)]
            let _phase = PhaseTiming::new(m.predicate, "produce", "assessment");
            prescreen(m)?
        };
        let data = {
            #[cfg(test)]
            let _phase = PhaseTiming::new(m.predicate, "produce", "public_PP");
            public_data(m, &public_air, &report)?
        };
        let (air, trace) = {
            #[cfg(test)]
            let _phase = PhaseTiming::new(m.predicate, "produce", "MAIN_prepare");
            witness::prepare(m, input).map_err(|_| Error::Proving)?
        };
        // The writer must produce the SAME complete verifier-owned schedule.
        if air.plan.height != public_air.plan.height
            || air.plan.max_fanout != public_air.plan.max_fanout
            || air.plan.policy_queries != public_air.plan.policy_queries
            || (0..512).any(|r| air.plan.pp_row(r) != public_air.plan.pp_row(r))
        {
            return Err(Error::Binding);
        }
        drop(public_air);
        let proof = {
            #[cfg(test)]
            let _phase = PhaseTiming::new(m.predicate, "produce", "native_prove");
            prove_trace(&air, &trace.0, &data)?
        };
        drop(trace);
        drop(data);
        drop(air);
        {
            #[cfg(test)]
            let _phase = PhaseTiming::new(m.predicate, "produce", "canonical_encode");
            wire::encode(m, &proof, &report)
        }
    }))
    .map_err(|_| Error::Proving)?
}

/// Cold independent receiver: header before allocation, complete own expectation,
/// actual assessment/default factory, canonical decode and actual native verify.
/// Result<()> is diagnostic math only; no token can be persisted or installed.
pub(super) fn verify(m: &Metadata, frame: &[u8]) -> Result<()> {
    #[cfg(test)]
    let _total = PhaseTiming::new(m.predicate, "cold_verify", "total");
    let payload = wire::payload(m, frame)?;
    catch_unwind(AssertUnwindSafe(|| {
        let (air, report) = {
            #[cfg(test)]
            let _phase = PhaseTiming::new(m.predicate, "cold_verify", "assessment");
            prescreen(m)?
        };
        let proof = {
            #[cfg(test)]
            let _phase = PhaseTiming::new(m.predicate, "cold_verify", "decode");
            wire::decode(payload, &report)?
        };
        let data = {
            #[cfg(test)]
            let _phase = PhaseTiming::new(m.predicate, "cold_verify", "public_PP");
            public_data(m, &air, &report)?
        };
        let common = data.common;
        drop(data.prover_only);
        {
            #[cfg(test)]
            let _phase = PhaseTiming::new(m.predicate, "cold_verify", "native_verify");
            verify_batch(
                &private_config()?,
                core::slice::from_ref(&air),
                &proof,
                &[vec![]],
                &common,
            )
            .map_err(|_| Error::Verification)
        }
    }))
    .map_err(|_| Error::Backend)?
}
