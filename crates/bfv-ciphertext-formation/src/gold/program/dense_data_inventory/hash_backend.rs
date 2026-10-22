// Closed SHA proof lifecycle over the SAME original FullAir and guarded writer.
use super::assessment::Assessment;
use super::native::FullAir;
use super::{Expected, Prepared, hash_setup, hash_wire, native};
use crate::gold::{Error, Result};
use bfv_hiding_stark::hash::Config;
use p3_batch_stark::{
    BatchProof, CommonData, ProverData, StarkInstance, prove_batch, verify_batch,
};
use std::panic::{AssertUnwindSafe, catch_unwind};

pub(in crate::gold) const MAX_FRAME_BYTES: usize = hash_wire::MAX_FRAME_BYTES;

pub(in crate::gold) fn profile_digest() -> [u8; 32] {
    hash_wire::profile()
}

/// Exact independently captured public expectation and locally derived PUBLIC PP.
/// Contains no private configuration, input, RNG or previous proof verdict.
pub(in crate::gold) struct ProverSetup {
    expected: Expected,
    air: FullAir,
    report: Assessment,
    public: ProverData<Config>,
}
impl ProverSetup {
    pub(in crate::gold) fn new(expected: &Expected) -> Result<Self> {
        catch_unwind(AssertUnwindSafe(|| {
            let (air, report) = native::prescreen(expected)?;
            hash_wire::require_assessment(&report)?;
            let public = hash_setup::public_data(&air, expected, &report)?;
            Ok(Self {
                expected: expected.clone(),
                air,
                report,
                public,
            })
        }))
        .map_err(|_| Error::Backend)?
    }

    pub(in crate::gold) fn expected(&self) -> &Expected {
        &self.expected
    }

    /// Every call consumes fresh protected inputs and creates fresh OS masks/salts.
    /// Reusing PUBLIC PP permits no private commitment or proof-verdict reuse.
    pub(in crate::gold) fn produce(&self, prepared: Prepared) -> Result<Vec<u8>> {
        catch_unwind(AssertUnwindSafe(|| {
            prepared.require_dense_expected(&self.expected)?;
            let trace = prepared.dense_trace(&self.expected)?;
            let config = bfv_hiding_stark::hash::config().map_err(|_| Error::Backend)?;
            let proof = {
                let instances = [StarkInstance {
                    air: &self.air,
                    trace: &trace.0,
                    public_values: self.expected.values().to_vec(),
                }];
                prove_batch(&config, &instances, &self.public).map_err(|_| Error::Proving)?
            };
            drop(trace);
            drop(config);
            hash_wire::encode(&self.expected, &proof, &self.report)
        }))
        .map_err(|_| Error::Backend)?
    }
}

/// Receiving setup retains independently derived CommonData, never producer PP
/// storage, private configuration, a supplied SDK object or any checked receipt.
pub(in crate::gold) struct ReceivingSetup {
    expected: Expected,
    air: FullAir,
    report: Assessment,
    common: CommonData<Config>,
}
impl ReceivingSetup {
    pub(in crate::gold) fn new(expected: &Expected) -> Result<Self> {
        catch_unwind(AssertUnwindSafe(|| {
            let (air, report) = native::prescreen(expected)?;
            hash_wire::require_assessment(&report)?;
            let public = hash_setup::public_data(&air, expected, &report)?;
            let common = public.common;
            drop(public.prover_only);
            Ok(Self {
                expected: expected.clone(),
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
        let payload = hash_wire::payload(&self.expected, frame)?;
        catch_unwind(AssertUnwindSafe(|| {
            let proof = hash_wire::decode(payload, &self.report)?;
            verify(&self.expected, &self.air, &proof, &self.common)
        }))
        .map_err(|_| Error::Backend)?
    }
}

pub(in crate::gold) fn produce(expected: &Expected, prepared: Prepared) -> Result<Vec<u8>> {
    prepared.require_dense_expected(expected)?;
    ProverSetup::new(expected)?.produce(prepared)
}

/// Cold receiving rejects the header and bounded payload BEFORE constructing PP.
/// Both cold and prepared receiving always execute the actual native verifier.
pub(in crate::gold) fn receive(expected: &Expected, frame: &[u8]) -> Result<()> {
    let payload = hash_wire::payload(expected, frame)?;
    catch_unwind(AssertUnwindSafe(|| {
        let (air, report) = native::prescreen(expected)?;
        hash_wire::require_assessment(&report)?;
        let proof = hash_wire::decode(payload, &report)?;
        let public = hash_setup::public_data(&air, expected, &report)?;
        let common = public.common;
        drop(public.prover_only);
        verify(expected, &air, &proof, &common)
    }))
    .map_err(|_| Error::Backend)?
}

fn verify(
    expected: &Expected,
    air: &FullAir,
    proof: &BatchProof<Config>,
    common: &CommonData<Config>,
) -> Result<()> {
    let config = bfv_hiding_stark::hash::config().map_err(|_| Error::Backend)?;
    verify_batch(
        &config,
        core::slice::from_ref(air),
        proof,
        &[expected.values().to_vec()],
        common,
    )
    .map_err(|_| Error::Verification)
}
