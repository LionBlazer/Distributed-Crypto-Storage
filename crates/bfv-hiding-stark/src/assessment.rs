use crate::{
    Challenge, EXTENSION_DEGREE, Error, LOG_BLOWUP, MODULUS_BITS, PROOF_DEGREE_BITS, QUERIES,
    RANDOM_CODEWORDS, SECURITY_BITS, TRACE_HEIGHT, TRACE_LOG_HEIGHT, Val,
};
use p3_field::{PrimeCharacteristicRing, coset::TwoAdicMultiplicativeCoset};
use p3_fri::FriParameters;
use p3_uni_stark::{AirLayout, OpeningShape, ProvenSecurity, StarkSecurityParams};
/// The report describes this exact fixed suite and actual AIR, not composed protocol security.
#[derive(Debug, Clone, Copy)]
pub struct SecurityReport {
    pub unique_decoding_bits: usize,
    pub list_decoding_bits: usize,
    pub constraints: usize,
    pub degree: usize,
    pub quotient_chunks: usize,
    pub batched_functions: usize,
}
impl SecurityReport {
    fn from_parameters(parameters: &StarkSecurityParams) -> Self {
        // Hiding doubles the committed polynomial degree. An analysis at the
        // original TRACE_LOG_HEIGHT would analyze the wrong proof domain.
        let bound = ProvenSecurity::compute_from_proof(PROOF_DEGREE_BITS, parameters);
        Self {
            unique_decoding_bits: bound.unique_decoding_bits,
            list_decoding_bits: bound.list_decoding_bits,
            constraints: parameters.num_constraints,
            degree: parameters.air_max_constraint_degree,
            quotient_chunks: parameters.num_quotient_chunks,
            batched_functions: parameters.num_batched_functions,
        }
    }

    pub fn require_target(self) -> Result<Self, Error> {
        if self.unique_decoding_bits < SECURITY_BITS || self.list_decoding_bits < SECURITY_BITS {
            return Err(Error::SecurityProfile);
        }
        Ok(self)
    }
}

pub fn analyze<A>(air: &A) -> Result<(StarkSecurityParams, SecurityReport), Error>
where
    A: p3_air::Air<p3_air::symbolic::SymbolicAirBuilder<Val, Challenge>>,
{
    // Public generic metadata must be representable before symbolic vectors allocate.
    for length in [
        air.width(),
        air.width().checked_mul(2).ok_or(Error::Shape)?,
        air.num_public_values(),
        air.num_periodic_columns(),
    ] {
        if std::alloc::Layout::array::<p3_air::symbolic::SymbolicVariable<Val>>(length).is_err() {
            return Err(Error::Shape);
        }
    }
    if air.width() == 0
        || air
            .width()
            .checked_mul(TRACE_HEIGHT)
            .and_then(|n| n.checked_mul(core::mem::size_of::<Val>()))
            .is_none()
        || air.assumes_boolean_trace()
        || !air.public_boundary_io().is_empty()
    {
        return Err(Error::Shape);
    }
    // No trace, LDE, Merkle tree or witness is allocated for this calculation.
    let fri = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: QUERIES,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: (),
    };
    // SDK 0.8 opens the complete width at both points whenever any next-row
    // column is read. The returned security report must count that full shape.
    let opening_points = 1 + usize::from(!air.main_next_row_columns().is_empty());
    if air.preprocessed_width() != 0
        || TRACE_HEIGHT < 2 * (QUERIES + EXTENSION_DEGREE * opening_points)
        || RANDOM_CODEWORDS < EXTENSION_DEGREE
    {
        return Err(Error::HidingBudget);
    }
    let parameters = StarkSecurityParams::from_air::<Val, Challenge, _>(
        fri.security_regime(),
        air,
        AirLayout::from_air::<Val>(air),
        TwoAdicMultiplicativeCoset::new(Val::ONE, TRACE_LOG_HEIGHT).unwrap(),
        MODULUS_BITS,
        SECURITY_BITS,
        opening_points,
        OpeningShape::hiding(RANDOM_CODEWORDS),
        fri.grinding_sites(),
    );
    let report = SecurityReport::from_parameters(&parameters);
    Ok((parameters, report))
}
