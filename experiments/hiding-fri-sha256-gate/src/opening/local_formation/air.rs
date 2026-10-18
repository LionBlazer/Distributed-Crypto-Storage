//! Legacy producer policy over the shared exact seven-stream integer circuit.
use super::statement::Statement;
use crate::backend::Val;
use crate::primitive::PublicStatement;
#[cfg(test)]
pub(crate) use bfv_ciphertext_formation::circuit::PERIODICS;
pub(crate) use bfv_ciphertext_formation::circuit::WIDTH;
#[cfg(test)]
pub(in crate::opening) use bfv_ciphertext_formation::circuit::{
    CARRY, COEFFICIENTS, CP, LANE_BITS, SALTS, value,
};
use bfv_ciphertext_formation::circuit::{CircuitStatement, FormationAir};
use p3_air::{Air, AirBuilder, BaseAir};
use std::borrow::Cow;
pub(crate) struct LocalAir(FormationAir);
impl LocalAir {
    pub(super) fn new(s: &Statement) -> Self {
        Self(FormationAir::new(
            CircuitStatement::new(
                s.public_values().try_into().unwrap(),
                s.contexts(),
                core::array::from_fn(|i| {
                    s.expected.bases[i]
                        .expected
                        .ciphertext()
                        .b_coefficients()
                        .to_vec()
                }),
            )
            .unwrap(),
        ))
    }
    pub(in crate::opening) fn returned(
        s: &crate::opening::locking::formation::statement::Statement,
    ) -> Self {
        Self(FormationAir::new(
            CircuitStatement::new(
                s.public_values().try_into().unwrap(),
                s.contexts(),
                core::array::from_fn(|i| {
                    s.expected.bases[i]
                        .expected
                        .ciphertext()
                        .b_coefficients()
                        .to_vec()
                }),
            )
            .unwrap(),
        ))
    }
}
impl BaseAir<Val> for LocalAir {
    fn width(&self) -> usize {
        self.0.width()
    }
    fn num_public_values(&self) -> usize {
        self.0.num_public_values()
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        self.0.main_next_row_columns()
    }
    fn num_periodic_columns(&self) -> usize {
        self.0.num_periodic_columns()
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        self.0.max_constraint_degree()
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        self.0.periodic_columns()
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for LocalAir {
    fn eval(&self, b: &mut AB) {
        self.0.eval(b);
    }
}
