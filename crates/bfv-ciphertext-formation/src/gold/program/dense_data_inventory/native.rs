// Fixed genuine dense proof backend; the facade owns mathematical result types.
use super::*;
use crate::gold::witness::PrivateTrace;
use bfv_hiding_stark::Config;
use p3_air::{Air, BaseAir};
use p3_batch_stark::{
    BatchProof, CommonData, ProverData, StarkInstance, prove_batch, verify_batch,
};
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Instant;

/// The SAME immutable AIR, with a separate PRIVATE full-PP factory only.
#[derive(Clone)]
pub(super) struct FullAir(pub(super) air::MetadataAir);
impl BaseAir<Val> for FullAir {
    fn width(&self) -> usize {
        self.0.width()
    }
    fn preprocessed_width(&self) -> usize {
        self.0.preprocessed_width()
    }
    fn num_public_values(&self) -> usize {
        self.0.num_public_values()
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        self.0.main_next_row_columns()
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        self.0.preprocessed_next_row_columns()
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        let mut words = Vec::with_capacity(H * PP);
        for row in 0..H {
            words.extend(self.0.plan.row(row).expect("same closed audited dense row"))
        }
        Some(RowMajorMatrix::new(words, PP))
    }
}
impl<AB: InteractionBuilder<F = Val>> Air<AB> for FullAir {
    fn eval(&self, b: &mut AB) {
        self.0.eval(b)
    }
}

pub(super) fn prescreen(e: &Expected) -> Result<(FullAir, assessment::Assessment)> {
    let air = air::MetadataAir::new(e)?;
    let report = assessment::assess(&air)?;
    report.require_resources()?;
    super::native_wire::require_assessment(&report)?;
    // The exact r30 modeled native stages are retained. Reserve an EXTRA16MiB
    // for bounded Graph/equation/opening banks beyond its already charged MAIN.
    // This remains an estimate, never a replacement for the whole-PID1792MiB fuse.
    let workspace = report
        .workspace_bytes()
        .checked_add(16 * 1024 * 1024)
        .ok_or(Error::Resource)?;
    if workspace > 1792 * 1024 * 1024 || graph::LOGICAL_VECTOR_CAP > 8 * 1024 * 1024 {
        return Err(Error::Resource);
    }
    Ok((FullAir(air), report))
}
pub(super) fn config() -> Result<Config> {
    bfv_hiding_stark::config().map_err(|_| Error::Backend)
}
pub(super) fn phase_start(phase: &str) -> Instant {
    #[cfg(test)]
    eprintln!("dense_data_native phase={phase} state=start");
    let _ = phase;
    Instant::now()
}
pub(super) fn phase_end(phase: &str, t: Instant) {
    #[cfg(test)]
    eprintln!(
        "dense_data_native phase={phase} state=end elapsed_ms={:.3}",
        t.elapsed().as_secs_f64() * 1000.
    );
    let _ = (phase, t);
}

pub(in crate::gold) fn produce(e: &Expected, prepared: Prepared) -> Result<Vec<u8>> {
    catch_unwind(AssertUnwindSafe(|| {
        prepared.require_dense_expected(e)?;
        let (air, report) = prescreen(e)?;
        let t = phase_start("public_pp_setup");
        let public = super::native_setup::public_data(&air, e, &report)?;
        phase_end("public_pp_setup", t);
        let t = phase_start("private_full_trace");
        let trace = prepared.dense_trace(e)?;
        phase_end("private_full_trace", t);
        let proof = prove_trace(e, &air, &trace, &public)?;
        drop(trace);
        drop(public);
        drop(air);
        let t = phase_start("canonical_encode");
        let bytes = super::native_wire::encode(e, &proof, &report)?;
        phase_end("canonical_encode", t);
        Ok(bytes)
    }))
    .map_err(|_| Error::Backend)?
}
pub(super) fn prove_trace(
    e: &Expected,
    air: &FullAir,
    trace: &PrivateTrace,
    public: &ProverData<Config>,
) -> Result<BatchProof<Config>> {
    let config = config()?;
    let instances = [StarkInstance {
        air,
        trace: &trace.0,
        public_values: e.values().to_vec(),
    }];
    let t = phase_start("prove_batch");
    let result = catch_unwind(AssertUnwindSafe(|| {
        prove_batch(&config, &instances, public)
    }))
    .map_err(|_| Error::Backend)?
    .map_err(|_| Error::Proving);
    phase_end("prove_batch", t);
    result
}
pub(in crate::gold) fn receive(e: &Expected, frame: &[u8]) -> Result<()> {
    let payload = super::native_wire::payload(e, frame)?;
    catch_unwind(AssertUnwindSafe(|| {
        let (air, report) = prescreen(e)?;
        let proof = super::native_wire::decode(payload, &report)?;
        let t = phase_start("cold_public_pp_setup");
        let public = super::native_setup::public_data(&air, e, &report)?;
        phase_end("cold_public_pp_setup", t);
        let common = public.common;
        drop(public.prover_only);
        verify(e, &air, &proof, &common)
    }))
    .map_err(|_| Error::Backend)?
}
pub(super) fn verify(
    e: &Expected,
    air: &FullAir,
    proof: &BatchProof<Config>,
    common: &CommonData<Config>,
) -> Result<()> {
    let config = config()?;
    let t = phase_start("cold_verify_batch");
    let result = catch_unwind(AssertUnwindSafe(|| {
        verify_batch(
            &config,
            core::slice::from_ref(air),
            proof,
            &[e.values().to_vec()],
            common,
        )
    }))
    .map_err(|_| Error::Backend)?
    .map_err(|_| Error::Verification);
    phase_end("cold_verify_batch", t);
    result
}
