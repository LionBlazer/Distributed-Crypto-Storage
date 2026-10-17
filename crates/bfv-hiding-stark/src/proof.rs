//! SDK calls plus fixed hiding shape checks; semantic statement lifetime belongs to the consumer.
use crate::*;
use p3_air::{Air, DebugConstraintBuilder};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{Proof, QuotientAir, StarkSecurityParams, VerifierConstraintFolder};

/// Low-level SDK proof under a TRUSTED caller-owned matching fixed configuration.
/// This function does not certify configuration identity or analytical policy.
/// Callers retain the same immutable AIR/public values used for assessment.
pub fn prove_with_config<A>(
    config: &Config,
    air: &A,
    trace: RowMajorMatrix<Val>,
    public_values: &[Val],
) -> Result<Proof<Config>, Error>
where
    A: QuotientAir<Config> + for<'a> Air<DebugConstraintBuilder<'a, Val>>,
{
    if public_values.len() != air.num_public_values()
        || trace.width != air.width()
        || air.width().checked_mul(TRACE_HEIGHT) != Some(trace.values.len())
    {
        return Err(Error::Shape);
    }
    p3_uni_stark::prove(config, air, trace, public_values).map_err(|_| Error::Proving)
}

/// Low-level shape and SDK verification under TRUSTED matching configuration/assessment.
/// This function does not authenticate their association with this actual AIR.
/// Parameters are trusted local analytical data, never a submitted receipt.
pub fn verify_with_assessment<A>(
    config: &Config,
    air: &A,
    parameters: &StarkSecurityParams,
    report: SecurityReport,
    proof: &Proof<Config>,
    public_values: &[Val],
) -> Result<(), Error>
where
    A: Air<p3_air::symbolic::SymbolicAirBuilder<Val>>
        + for<'a> Air<VerifierConstraintFolder<'a, Config>>,
{
    let width = air.width();
    let next_row = !air.main_next_row_columns().is_empty();
    if public_values.len() != air.num_public_values()
        || proof.degree_bits != PROOF_DEGREE_BITS
        || proof.opened_values.trace_local.len() != width
        || proof.opened_values.trace_next.as_ref().map(Vec::len) != next_row.then_some(width)
        || proof.opened_values.preprocessed.is_some()
        || proof.commitments.random.is_none()
        || proof.opened_values.random.is_none()
    {
        return Err(Error::Shape);
    }
    let bound = proof.proven_security(parameters);
    SecurityReport {
        unique_decoding_bits: bound.unique_decoding_bits,
        list_decoding_bits: bound.list_decoding_bits,
        ..report
    }
    .require_target()?;
    p3_uni_stark::verify(config, air, proof, public_values).map_err(|_| Error::Verification)
}
