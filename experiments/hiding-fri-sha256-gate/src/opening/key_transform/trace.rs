//! PUBLIC fixture/rebuilt-test adapter around the single shared mathematical circuit.
use super::statement::{Expected, SetupDescriptor, Statement};
use crate::backend::{Error, Val};
#[cfg(test)]
pub(in crate::opening) use bfv_key_transform::circuit::{advance, write_row};
pub(in crate::opening) use bfv_key_transform::circuit::{digest, oracle};
use p3_matrix::dense::RowMajorMatrix;
pub(in crate::opening) struct Witness {
    pub(in crate::opening) coefficients: Vec<i8>,
    pub(in crate::opening) salts: [[Val; 4]; 2],
}
impl Witness {
    pub(in crate::opening) fn new(
        coefficients: Vec<i8>,
        input: [Val; 4],
        output: [Val; 4],
    ) -> Result<Self, Error> {
        if coefficients.len() != super::N || coefficients.iter().any(|s| !(-20..=20).contains(s)) {
            return Err(Error::Shape);
        }
        Ok(Self {
            coefficients,
            salts: [input, output],
        })
    }
    pub(in crate::opening) fn statement(&self, descriptor: SetupDescriptor) -> Statement {
        let value = bfv_key_transform::circuit::statement(
            &self.coefficients,
            self.salts,
            descriptor.shared(),
        );
        Statement {
            expected: Expected {
                descriptor,
                coefficients: value.expected.coefficients,
            },
            transformed: value.transformed,
        }
    }
    pub(in crate::opening) fn trace(
        &self,
        statement: &Statement,
    ) -> Result<RowMajorMatrix<Val>, Error> {
        bfv_key_transform::circuit::trace(&self.coefficients, self.salts, &statement.shared())
    }
}
