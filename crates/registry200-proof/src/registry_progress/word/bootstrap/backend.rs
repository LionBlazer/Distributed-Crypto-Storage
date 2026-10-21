//! Closed assessed hiding-FRI configuration; no caller-supplied AIR or topology.
use super::{Error, Expected, PUBLIC_VALUES, Result};
use crate::{Val, registry_progress::bootstrap_air::EmptyRegistryAir, source};
use bfv_hiding_stark::{self as engine, Config, SecurityReport, codec};
use p3_air::BaseAir;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{Proof, StarkSecurityParams};
pub(super) const WIDTH: usize = crate::registry_progress::bootstrap_air::WIDTH;
type Air = EmptyRegistryAir<PUBLIC_VALUES>;
pub(super) fn air(e: &Expected) -> Air {
    EmptyRegistryAir::from_fields(
        e.values(),
        source::commitment::prefix(e.source().statement(), [Val::ZERO; 4]),
        e.enrollment_header().to_vec(),
        e.registry_header().to_vec(),
        e.enrollment(),
        e.source().statement().open_commitment,
        e.root(),
    )
}
pub(super) struct Backend {
    pub(super) air: Air,
    pub(super) shape: codec::Topology,
    values: [Val; PUBLIC_VALUES],
    config: Config,
    parameters: StarkSecurityParams,
    report: SecurityReport,
}
impl Backend {
    pub(super) fn new(e: &Expected) -> Result<Self> {
        let air = air(e);
        let (parameters, report) = engine::analyze(&air)?;
        let report = report.require_target()?;
        if air.width() != WIDTH
            || air.num_public_values() != PUBLIC_VALUES
            || air.preprocessed_width() != 0
            || air.main_next_row_columns().is_empty()
            || report.degree > 5
            || !(2..=16).contains(&report.quotient_chunks)
        {
            return Err(Error::Shape);
        }
        Ok(Self {
            shape: codec::Topology::checked(WIDTH, report.quotient_chunks)?,
            air,
            values: e.values(),
            config: engine::config()?,
            parameters,
            report,
        })
    }
    pub(super) fn prove(&self, trace: RowMajorMatrix<Val>) -> Result<Proof<Config>> {
        Ok(engine::prove_with_config(
            &self.config,
            &self.air,
            trace,
            &self.values,
        )?)
    }
    pub(super) fn verify(&self, proof: &Proof<Config>) -> Result<()> {
        Ok(engine::verify_with_assessment(
            &self.config,
            &self.air,
            &self.parameters,
            self.report,
            proof,
            &self.values,
        )?)
    }
}
