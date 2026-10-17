//! Exact emitter topology for the existing linked hiding FRI profile.
use super::Error;
use crate::backend::analyze;
use crate::opening::proof_codec::Topology;
use crate::primitive::{Kind, PublicStatement};
use p3_air::BaseAir;

pub(in crate::opening) struct Shape {
    pub(super) topology: Topology,
}
impl Shape {
    pub(in crate::opening) fn new(statement: &impl PublicStatement) -> Result<Self, Error> {
        let wanted = match statement.kind() {
            Kind::CanonicalIndexOpening => (11521, 691),
            Kind::RegistryBootstrap => (1082, 104),
            Kind::LockingSelection => (1948, 116),
            _ => return Err(Error::Profile),
        };
        let air = statement.air();
        let (_, report) = analyze(&air)?;
        let report = report.require_target()?;
        if (air.width(), air.num_public_values()) != wanted
            || air.preprocessed_width() != 0
            || air.main_next_row_columns().is_empty()
            || report.degree > 5
            || report.quotient_chunks <= 1
            || report.quotient_chunks > 16
        {
            return Err(Error::Shape);
        }
        Ok(Self {
            topology: Topology::checked(wanted.0, report.quotient_chunks).map_err(Error::from)?,
        })
    }
    /// Existing owning-test seam; production checks once through the shared codec.
    #[cfg(test)]
    pub(in crate::opening) fn check(
        &self,
        p: &p3_uni_stark::Proof<crate::backend::Config>,
    ) -> Result<(), Error> {
        self.topology.check(p).map_err(Error::from)
    }
}
