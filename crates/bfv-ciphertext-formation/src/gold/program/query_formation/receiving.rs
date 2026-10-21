//! Query-specific public receiving preparation, independently built before evidence.
use super::{Expected, assessment, native, native_setup, native_wire};
use crate::gold::{Error, Result};
use bfv_hiding_stark::Config;
use native::FullAir;
use p3_batch_stark::CommonData;
use std::panic::{AssertUnwindSafe, catch_unwind};
/// Locally derived immutable public setup for ONE complete captured expectation.
/// Contains no producer configuration, private randomness or verification verdict.
pub(in crate::gold) struct ReceivingSetup {
    expected: Expected,
    air: FullAir,
    report: assessment::Assessment,
    common: CommonData<Config>,
}
impl ReceivingSetup {
    pub(in crate::gold) fn new(e: &Expected) -> Result<Self> {
        catch_unwind(AssertUnwindSafe(|| {
            let (air, report) = native::prescreen(e)?;
            let t = native::phase_start("cold_public_pp_setup");
            let public = native_setup::public_data(&air, e, &report)?;
            native::phase_end("cold_public_pp_setup", t);
            let common = public.common;
            drop(public.prover_only);
            Ok(Self {
                expected: e.clone(),
                air,
                report,
                common,
            })
        }))
        .map_err(|_| Error::Backend)?
    }
    pub(in crate::gold) fn expected(&self) -> &Expected {
        &self.expected
    }
    pub(in crate::gold) fn receive(&self, frame: &[u8]) -> Result<()> {
        let payload = native_wire::payload(self.expected(), frame)?;
        catch_unwind(AssertUnwindSafe(|| {
            let proof = native_wire::decode(payload, &self.report)?;
            native::verify(&self.expected, &self.air, &proof, &self.common)
        }))
        .map_err(|_| Error::Backend)?
    }
}
