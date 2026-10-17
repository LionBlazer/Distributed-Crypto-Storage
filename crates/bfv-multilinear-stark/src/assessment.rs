//! Full SDK union assessment of actual verifier instances, with fixed floor 144.
use crate::{AirSpec, Config, Error, MultiStarkSecurityReport, POLICY_BITS, VerifierAir};
use p3_multi_stark::{VerifierInstances, security_report};

/// The caller supplies its independently built verifying key and exact instances.
/// No key, prepared-token, trace or proof ownership moves into this library.
/// Rechecks supported metadata and dimensions BEFORE the SDK can access a missing
/// preprocessed PCS. Actual constraints/lookups are assessed anew, never taken
/// from config_for's earlier symbolic pass or from proof-supplied counts.
pub fn assess<A: VerifierAir<crate::Val, crate::Challenge>>(
    config: &Config,
    instances: &VerifierInstances<'_, Config, A>,
) -> Result<MultiStarkSecurityReport, Error> {
    let specs: Vec<_> = instances
        .iter()
        .map(|i| AirSpec::new(i.air(), i.num_variables()))
        .collect();
    let (tables, main, public) = crate::config::dimensions(&specs)?;
    let expected = config.plan();
    if tables != expected.tables
        || main != expected.main_cells
        || public != expected.preprocessed_cells
        || instances
            .iter()
            .any(|i| i.public_values().len() != i.air().num_public_values())
    {
        return Err(Error::InvalidShape);
    }
    crate::config::validate_airs(&specs, &tables)?;
    let report = security_report(config, instances).map_err(|_| Error::Security)?;
    report
        .require_security(POLICY_BITS)
        .map_err(|_| Error::Security)?;
    if report.security_bits().is_none_or(|bits| !bits.is_finite())
        || !report.unassessed_components().is_empty()
    {
        return Err(Error::Security);
    }
    Ok(report)
}
