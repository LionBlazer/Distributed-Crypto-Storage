use crate::{
    Challenge, EXTENSION_DEGREE, Error, LOG_BLOWUP, MODULUS_BITS, PROOF_DEGREE_BITS, QUERIES,
    RANDOM_CODEWORDS, SECURITY_BITS, TRACE_HEIGHT, TRACE_LOG_HEIGHT, Val,
};
use p3_air::symbolic::{
    SymbolicAirBuilder, SymbolicExpression, SymbolicExpressionExt, get_all_symbolic_constraints,
};
use p3_air::{Air, AirBuilder, BaseAir, BoundaryPublic, ExtensionBuilder};
use p3_field::{PrimeCharacteristicRing, coset::TwoAdicMultiplicativeCoset};
use p3_fri::FriParameters;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{AirLayout, OpeningShape, ProvenSecurity, StarkSecurityParams};
use std::borrow::Cow;

/// A single assessment's actual expressions, never a proof or an analyzed-shape claim.
/// SDK 0.8 separately asks for constraint count and periodic-weighted degree. Reusing
/// the collected expressions avoids rebuilding their DAG for the second request.
/// This view is deliberately symbolic-only: grouping base/extension constraints
/// would change the alpha-fold order if it were used in a prover or verifier.
struct CollectedAir<'a, A> {
    air: &'a A,
    base: Vec<SymbolicExpression<Val>>,
    extension: Vec<SymbolicExpressionExt<Val, Challenge>>,
}
impl<'a, A: Air<SymbolicAirBuilder<Val, Challenge>>> CollectedAir<'a, A> {
    fn new(air: &'a A, layout: AirLayout) -> Self {
        let (base, extension) = get_all_symbolic_constraints(air, layout);
        Self {
            air,
            base,
            extension,
        }
    }
}
impl<A: BaseAir<Val>> BaseAir<Val> for CollectedAir<'_, A> {
    fn width(&self) -> usize {
        self.air.width()
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        self.air.preprocessed_trace()
    }
    fn preprocessed_width(&self) -> usize {
        self.air.preprocessed_width()
    }
    fn num_periodic_columns(&self) -> usize {
        self.air.num_periodic_columns()
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        self.air.periodic_columns()
    }
    fn periodic_values(&self, row_index: usize) -> Vec<Val> {
        self.air.periodic_values(row_index)
    }
    fn periodic_columns_matrix(&self) -> Option<RowMajorMatrix<Val>> {
        self.air.periodic_columns_matrix()
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        self.air.main_next_row_columns()
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        self.air.preprocessed_next_row_columns()
    }
    fn num_constraints(&self) -> Option<usize> {
        self.air.num_constraints()
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        self.air.max_constraint_degree()
    }
    fn num_public_values(&self) -> usize {
        self.air.num_public_values()
    }
    fn public_boundary_io(&self) -> &[BoundaryPublic] {
        self.air.public_boundary_io()
    }
    fn assumes_boolean_trace(&self) -> bool {
        self.air.assumes_boolean_trace()
    }
}
impl<A: BaseAir<Val>> Air<SymbolicAirBuilder<Val, Challenge>> for CollectedAir<'_, A> {
    fn eval(&self, builder: &mut SymbolicAirBuilder<Val, Challenge>) {
        for constraint in &self.base {
            builder.assert_zero(constraint.clone());
        }
        for constraint in &self.extension {
            builder.assert_zero_ext(constraint.clone());
        }
    }
}
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
    let layout = AirLayout::from_air::<Val>(air);
    let collected = CollectedAir::new(air, layout);
    let parameters = StarkSecurityParams::from_air::<Val, Challenge, _>(
        fri.security_regime(),
        &collected,
        layout,
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
