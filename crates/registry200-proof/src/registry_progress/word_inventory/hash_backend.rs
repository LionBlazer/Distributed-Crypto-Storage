//! Closed Predicate backend for the separate fixed SHA hiding suite.
//! The original AIR, recipe/trace writer and all public words remain unchanged.
use super::{
    Metadata,
    air::ProgramAir,
    assessment::{self, Assessment},
    complete_role, goldens, hash_setup, hash_wire,
    owner::PrimaryInputs,
    plan::Plan,
    probe::{DEGREE_BITS, Error, Result},
    public_values::Expected,
    recipes::Origins,
    witness,
};
use bfv_hiding_stark::{Challenge, hash};
use p3_batch_stark::{CommonData, ProverData, StarkInstance, prove_batch, verify_batch};
use p3_commit::UnivariateStarkPcs;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn prescreen() -> Result<(ProgramAir, Origins, Assessment)> {
    let built = complete_role(true).map_err(|_| Error::Shape)?;
    let air = ProgramAir {
        plan: Plan::new(built.pool).map_err(|_| Error::Shape)?,
    };
    goldens::require_plan(&air.plan).map_err(|_| Error::Binding)?;
    let report = assessment::assess(&air).map_err(|_| Error::Security)?;
    report.require_resources().map_err(|_| Error::Resource)?;
    hash_wire::require_assessment(&report)?;
    if !<hash::Pcs as UnivariateStarkPcs<Challenge, hash::Challenger>>::ZK {
        return Err(Error::Security);
    }
    Ok((air, built.origins, report))
}

/// Public role-only preprocessing; no private input, RNG or verdict is retained.
pub(in crate::registry_progress) struct ProverSetup {
    air: ProgramAir,
    origins: Origins,
    report: Assessment,
    data: ProverData<hash::Config>,
}

impl ProverSetup {
    pub(in crate::registry_progress) fn new() -> Result<Self> {
        let (air, origins, report) = prescreen()?;
        let data = hash_setup::public_data(&air, &report)?;
        Ok(Self {
            air,
            origins,
            report,
            data,
        })
    }

    pub(in crate::registry_progress) fn produce(
        &self,
        metadata: &Metadata,
        input: &PrimaryInputs,
    ) -> Result<Vec<u8>> {
        if !metadata.predicate {
            return Err(Error::Binding);
        }
        let public = Expected::checked(metadata).map_err(|_| Error::Shape)?;
        self.report
            .require_resources()
            .map_err(|_| Error::Resource)?;
        catch_unwind(AssertUnwindSafe(|| {
            let trace = witness::from_plan(&self.air, &self.origins, &public, input)
                .map_err(|_| Error::Proving)?;
            // The public deterministic config has already died in hash_setup.
            // This separate config obtains fresh OS entropy for private commits.
            let config = hash::config().map_err(|_| Error::Backend)?;
            let instances = [StarkInstance {
                air: &self.air,
                trace: &trace.0,
                public_values: public.values().to_vec(),
            }];
            let proof = prove_batch(&config, &instances, &self.data).map_err(|_| Error::Proving)?;
            drop(trace);
            hash_wire::encode(metadata, &proof, &self.report)
        }))
        .map_err(|_| Error::Backend)?
    }
}

/// The receiver constructs its own public PP and drops all prover-only storage.
pub(in crate::registry_progress) struct VerifierSetup {
    air: ProgramAir,
    report: Assessment,
    common: CommonData<hash::Config>,
}

impl VerifierSetup {
    pub(in crate::registry_progress) fn new() -> Result<Self> {
        let (air, origins, report) = prescreen()?;
        drop(origins);
        let data = hash_setup::public_data(&air, &report)?;
        let common = data.common;
        drop(data.prover_only);
        Ok(Self {
            air,
            report,
            common,
        })
    }

    pub(in crate::registry_progress) fn verify(
        &self,
        metadata: &Metadata,
        frame: &[u8],
    ) -> Result<()> {
        let payload = hash_wire::payload(metadata, frame)?;
        let public = Expected::checked(metadata).map_err(|_| Error::Shape)?;
        self.report
            .require_resources()
            .map_err(|_| Error::Resource)?;
        catch_unwind(AssertUnwindSafe(|| {
            let proof = hash_wire::decode(payload, &self.report)?;
            let config = hash::config().map_err(|_| Error::Backend)?;
            verify_batch(
                &config,
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

#[cfg(test)]
pub(super) fn assessed() -> Assessment {
    prescreen().expect("original fixed Predicate assessment").2
}

const _: () = assert!(DEGREE_BITS == 10);
