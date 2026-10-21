//! Test-private genuine native proofs; no accepted SQL/Source/DATA/key capability.
use super::{
    Expected,
    air::QueryMaskAir,
    public_setup,
    security::{self, Gate},
    wire, writer,
};
use bfv_hiding_stark::Config;
use p3_batch_stark::{
    BatchProof, CommonData, ProverData, StarkInstance, prove_batch, verify_batch,
};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Instant;

struct Phase {
    label: &'static str,
    began: Instant,
}
impl Phase {
    fn new(label: &'static str) -> Self {
        Self {
            label,
            began: Instant::now(),
        }
    }
}
impl Drop for Phase {
    fn drop(&mut self) {
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr().lock(),
            "query_mask_phase phase={} elapsed_us={}",
            self.label,
            self.began.elapsed().as_micros()
        );
    }
}

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

fn closed() -> Result<(QueryMaskAir, Gate)> {
    let air = QueryMaskAir::closed().map_err(|_| Error::Shape)?;
    let gate = security::assess(&air).map_err(|_| Error::Security)?;
    wire::require_gate(&gate)?;
    Ok((air, gate))
}
fn native_prove(
    air: &QueryMaskAir,
    data: &ProverData<Config>,
    trace: &writer::PrivateTrace,
    expected: &Expected,
) -> Result<BatchProof<Config>> {
    // Unpredictable independent OS-seeded PCS/MMCS streams for EACH private proof.
    let config = bfv_hiding_stark::config().map_err(|_| Error::Backend)?;
    let instance = StarkInstance {
        air,
        trace: &trace.0,
        public_values: expected.values().to_vec(),
    };
    prove_batch(&config, &[instance], data).map_err(|_| Error::Proving)
}

/// Retains only fixed mathematical AIR, numeric gate and immutable PUBLIC PP.
pub(super) struct ProverSetup {
    air: QueryMaskAir,
    gate: Gate,
    data: ProverData<Config>,
}
impl ProverSetup {
    pub(super) fn new() -> Result<Self> {
        let _total = Phase::new("producer_setup_total");
        catch_unwind(AssertUnwindSafe(|| {
            let (air, gate) = closed()?;
            let data = {
                let _phase = Phase::new("producer_public_PP");
                public_setup::data(&air, &gate)?
            };
            Ok(Self { air, gate, data })
        }))
        .map_err(|_| Error::Backend)?
    }
    /// Returns UNVERIFIED bytes only. Opening and private trace die in this call.
    pub(super) fn produce(&self, expected: &Expected, opening: writer::Opening) -> Result<Vec<u8>> {
        let _total = Phase::new("produce_total");
        catch_unwind(AssertUnwindSafe(|| {
            wire::require_gate(&self.gate)?;
            let trace = {
                let _phase = Phase::new("private_MAIN_prepare");
                writer::prepare(&self.air, expected, &opening)?
            };
            let proof = {
                let _phase = Phase::new("native_prove");
                native_prove(&self.air, &self.data, &trace, expected)?
            };
            drop(trace);
            let _phase = Phase::new("canonical_encode");
            wire::encode(expected, &proof, &self.gate)
        }))
        .map_err(|_| Error::Backend)?
    }
    /// Deliberately bypasses honest writer validation ONLY for release-native
    /// rejection tests of an already constructed malicious MAIN. No callback/AIR
    /// selector exists, and the independent receiving factory stays unchanged.
    #[cfg(test)]
    pub(super) fn prove_negative_trace(
        &self,
        expected: &Expected,
        trace: &writer::PrivateTrace,
    ) -> Result<Vec<u8>> {
        let _total = Phase::new("negative_produce_total");
        catch_unwind(AssertUnwindSafe(|| {
            wire::require_gate(&self.gate)?;
            wire::encode(
                expected,
                &native_prove(&self.air, &self.data, trace, expected)?,
                &self.gate,
            )
        }))
        .map_err(|_| Error::Backend)?
    }
}

/// Independently reconstructs its OWN closed PUBLIC PP; accepts no producer data.
pub(super) struct VerifierSetup {
    air: QueryMaskAir,
    gate: Gate,
    common: CommonData<Config>,
}
impl VerifierSetup {
    pub(super) fn new() -> Result<Self> {
        let _total = Phase::new("verifier_setup_total");
        catch_unwind(AssertUnwindSafe(|| {
            let (air, gate) = closed()?;
            let data = {
                let _phase = Phase::new("verifier_public_PP");
                public_setup::data(&air, &gate)?
            };
            let common = data.common;
            drop(data.prover_only);
            Ok(Self { air, gate, common })
        }))
        .map_err(|_| Error::Backend)?
    }
    /// Every call binds full current Expected33, checks canonical bounded shape,
    /// then performs full native PCS/AIR verification. Returns no authority token.
    pub(super) fn verify(&self, expected: &Expected, frame: &[u8]) -> Result<()> {
        let _total = Phase::new("verify_total");
        let payload = wire::payload(expected, frame)?;
        wire::require_gate(&self.gate)?;
        catch_unwind(AssertUnwindSafe(|| {
            let proof = {
                let _phase = Phase::new("canonical_decode");
                wire::decode(payload, &self.gate)?
            };
            let _phase = Phase::new("native_verify");
            let config = bfv_hiding_stark::config().map_err(|_| Error::Backend)?;
            verify_batch(
                &config,
                core::slice::from_ref(&self.air),
                &proof,
                &[expected.values().to_vec()],
                &self.common,
            )
            .map_err(|_| Error::Verification)
        }))
        .map_err(|_| Error::Backend)?
    }
}
pub(super) fn verify(expected: &Expected, frame: &[u8]) -> Result<()> {
    let _ = wire::payload(expected, frame)?; // Fail malformed metadata before PP.
    VerifierSetup::new()?.verify(expected, frame)
}

#[cfg(test)]
pub(super) fn public_identity() -> Result<Vec<u8>> {
    let (air, gate) = closed()?;
    let data = public_setup::data(&air, &gate)?;
    postcard::to_allocvec(&data.common.preprocessed.ok_or(Error::Shape)?.commitment)
        .map_err(|_| Error::Encoding)
}

#[cfg(test)]
pub(super) fn check_trace(trace: &writer::PrivateTrace, expected: &Expected) -> Result<()> {
    writer::check(
        &QueryMaskAir::closed().map_err(|_| Error::Shape)?,
        trace,
        expected,
    )
}
