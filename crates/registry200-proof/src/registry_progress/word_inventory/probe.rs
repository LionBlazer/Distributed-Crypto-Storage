//! Closed native mathematics with immutable ROLE-only public setup.
//! Setup retains no private input, RNG, trace or verification verdict.
use super::{
    Metadata,
    air::ProgramAir,
    assessment::{self, Assessment},
    complete_role,
    owner::PrimaryInputs,
    plan::{PP_WIDTH, Plan},
    probe_wire as wire,
    public_values::Expected,
    recipes::Origins,
    structural_setup, witness,
};
use bfv_hiding_stark::{Challenge, Config, Val};
use p3_batch_stark::{
    BatchProof, CommonData, ProverData, StarkInstance, prove_batch, verify_batch,
};
use p3_field::PrimeField64;
use p3_lookup::{Kind, Lookups};
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

#[cfg(not(test))]
struct PhaseTiming;
#[cfg(not(test))]
impl PhaseTiming {
    fn new(_predicate: bool, _operation: &'static str, _phase: &'static str) -> Self {
        Self
    }
}

pub(super) const DEGREE_BITS: usize = 10;
#[derive(Debug, PartialEq, Eq)]
pub(in crate::registry_progress) enum Error {
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
pub(in crate::registry_progress) type Result<T> = core::result::Result<T, Error>;

/// All independently retained PUBLIC metadata, not a verdict or private opening.
/// Length framing and the full original images prevent a reduced-tag association.
pub(in crate::registry_progress) fn binding(m: &Metadata) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(b"DCS/research/word208/native-probe/complete-public-expectation/v2\0");
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

/// No Metadata/sample fixture can choose the role AIR or preprocessing.
fn prescreen_role(predicate: bool) -> Result<(ProgramAir, Origins, Assessment)> {
    let built = complete_role(predicate).map_err(|_| Error::Shape)?;
    let air = ProgramAir {
        plan: Plan::new(built.pool).map_err(|_| Error::Shape)?,
    };
    super::goldens::require_plan(&air.plan).map_err(|_| Error::Binding)?;
    let report = assessment::assess(&air).map_err(|_| Error::Security)?;
    report.require_resources().map_err(|_| Error::Resource)?;
    wire::require_assessment(&report)?;
    Ok((air, built.origins, report))
}
#[cfg(test)]
pub(super) fn prescreen(m: &Metadata) -> Result<(ProgramAir, Assessment)> {
    let _ = Expected::checked(m).map_err(|_| Error::Shape)?;
    let (air, _origins, report) = prescreen_role(m.predicate)?;
    Ok((air, report))
}
/// Seeded public config dies in structural_setup; only independently derived
/// public ProverData escapes. No private commitment is made by that factory.
pub(super) fn public_data(air: &ProgramAir, report: &Assessment) -> Result<ProverData<Config>> {
    wire::require_assessment(report)?;
    let data = structural_setup::public_data(air, report).map_err(|_| Error::Setup)?;
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
/// Fresh OS randomness for EACH native proof; public values are independently
/// derived from the actual full current expectation, never from the frame.
pub(super) fn prove_trace(
    air: &ProgramAir,
    trace: &p3_matrix::dense::RowMajorMatrix<Val>,
    data: &ProverData<Config>,
    public: &Expected,
) -> Result<BatchProof<Config>> {
    let config = private_config()?;
    let instances = [StarkInstance {
        air,
        trace,
        public_values: public.values().to_vec(),
    }];
    catch_unwind(AssertUnwindSafe(|| prove_batch(&config, &instances, data)))
        .map_err(|_| Error::Proving)?
        .map_err(|_| Error::Proving)
}
/// Immutable producer preprocessing and recipe IDs. No private witness, RNG or
/// result status is retained. This is not Source/DATA/oldRoot/SQL authority.
pub(in crate::registry_progress) struct ProverSetup {
    air: ProgramAir,
    origins: Origins,
    report: Assessment,
    data: ProverData<Config>,
}
impl ProverSetup {
    pub(in crate::registry_progress) fn new(predicate: bool) -> Result<Self> {
        let _total = PhaseTiming::new(predicate, "prover_setup", "total");
        let (air, origins, report) = {
            let _phase = PhaseTiming::new(predicate, "prover_setup", "assessment");
            prescreen_role(predicate)?
        };
        let data = {
            let _phase = PhaseTiming::new(predicate, "prover_setup", "public_PP");
            public_data(&air, &report)?
        };
        Ok(Self {
            air,
            origins,
            report,
            data,
        })
    }
    /// UNVERIFIED bytes only; no self-verification or per-query accepted flag.
    pub(in crate::registry_progress) fn produce(
        &self,
        m: &Metadata,
        input: &PrimaryInputs,
    ) -> Result<Vec<u8>> {
        let _total = PhaseTiming::new(m.predicate, "produce", "total");
        if m.predicate != self.air.plan.pool.predicate {
            return Err(Error::Binding);
        }
        let public = Expected::checked(m).map_err(|_| Error::Shape)?;
        self.report
            .require_resources()
            .map_err(|_| Error::Resource)?;
        catch_unwind(AssertUnwindSafe(|| {
            let trace = {
                let _phase = PhaseTiming::new(m.predicate, "produce", "MAIN_prepare");
                witness::from_plan(&self.air, &self.origins, &public, input)
                    .map_err(|_| Error::Proving)?
            };
            let proof = {
                let _phase = PhaseTiming::new(m.predicate, "produce", "native_prove");
                prove_trace(&self.air, &trace.0, &self.data, &public)?
            };
            drop(trace);
            let _phase = PhaseTiming::new(m.predicate, "produce", "canonical_encode");
            wire::encode(m, &proof, &self.report)
        }))
        .map_err(|_| Error::Backend)?
    }
}
/// Receiver factory independently constructs its OWN role PP, then discards all
/// prover-only data/recipe storage. No producer-supplied CommonData is accepted.
pub(in crate::registry_progress) struct VerifierSetup {
    air: ProgramAir,
    report: Assessment,
    common: CommonData<Config>,
}
impl VerifierSetup {
    pub(in crate::registry_progress) fn new(predicate: bool) -> Result<Self> {
        let _total = PhaseTiming::new(predicate, "verifier_setup", "total");
        let (air, origins, report) = {
            let _phase = PhaseTiming::new(predicate, "verifier_setup", "assessment");
            prescreen_role(predicate)?
        };
        drop(origins);
        let data = {
            let _phase = PhaseTiming::new(predicate, "verifier_setup", "public_PP");
            public_data(&air, &report)?
        };
        let common = data.common;
        drop(data.prover_only);
        Ok(Self {
            air,
            report,
            common,
        })
    }
    /// Every invocation rechecks full original metadata/header, canonical bytes and
    /// actual native proof against fresh Expected309. Setup is not a proof cache.
    pub(in crate::registry_progress) fn verify(&self, m: &Metadata, frame: &[u8]) -> Result<()> {
        let _total = PhaseTiming::new(m.predicate, "verify", "total");
        let payload = wire::payload(m, frame)?;
        if m.predicate != self.air.plan.pool.predicate {
            return Err(Error::Binding);
        }
        let public = Expected::checked(m).map_err(|_| Error::Shape)?;
        self.report
            .require_resources()
            .map_err(|_| Error::Resource)?;
        catch_unwind(AssertUnwindSafe(|| {
            let proof = {
                let _phase = PhaseTiming::new(m.predicate, "verify", "decode");
                wire::decode(payload, &self.report)?
            };
            let _phase = PhaseTiming::new(m.predicate, "verify", "native_verify");
            verify_batch(
                &private_config()?,
                core::slice::from_ref(&self.air),
                &proof,
                &[public.values().to_vec()],
                &self.common,
            )
            .map_err(|_| Error::Verification)
        }))
        .map_err(|_| Error::Backend)?
    }
}
pub(in crate::registry_progress) fn require_frame(m: &Metadata, frame: &[u8]) -> Result<()> {
    wire::payload(m, frame)?;
    Expected::checked(m).map_err(|_| Error::Shape)?;
    Ok(())
}
/// Complete cold producer wrapper, with genuine new role-only PUBLIC setup.
#[cfg(test)]
pub(super) fn produce(m: &Metadata, input: &PrimaryInputs) -> Result<Vec<u8>> {
    let _total = PhaseTiming::new(m.predicate, "cold_produce", "total");
    let _ = Expected::checked(m).map_err(|_| Error::Shape)?;
    ProverSetup::new(m.predicate)?.produce(m, input)
}
/// Complete cold receiving wrapper: original header checked before PP allocation,
/// then fresh independent receiver PP and mandatory full native verification.
#[cfg(test)]
pub(super) fn verify(m: &Metadata, frame: &[u8]) -> Result<()> {
    let _total = PhaseTiming::new(m.predicate, "cold_verify", "total");
    let _ = wire::payload(m, frame)?;
    let _ = Expected::checked(m).map_err(|_| Error::Shape)?;
    VerifierSetup::new(m.predicate)?.verify(m, frame)
}
