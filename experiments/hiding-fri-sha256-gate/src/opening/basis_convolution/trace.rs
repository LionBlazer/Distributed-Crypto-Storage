//! Private natural-order Shat witness, one bank and genuine unconditional P2 rows.
use super::statement::{Expected, Statement};
use crate::backend::{Error, Val};
use crate::opening::key_transform::{self, trace::Witness as KeyWitness};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

pub(in crate::opening) struct Witness {
    pub(in crate::opening) evaluations: Vec<Val>,
    pub(in crate::opening) salts: [[Val; 4]; 2],
}
pub(in crate::opening) use bfv_basis_convolution::circuit::oracle;
#[cfg(test)]
pub(in crate::opening) use bfv_basis_convolution::circuit::{advance, write_row};
impl Witness {
    pub(in crate::opening) fn new(key: &KeyWitness, output_salt: [Val; 4]) -> Self {
        Self {
            evaluations: key_transform::trace::oracle(
                &key.coefficients
                    .iter()
                    .copied()
                    .map(key_transform::signed)
                    .collect::<Vec<_>>(),
            ),
            salts: [key.salts[1], output_salt],
        }
    }
    pub(in crate::opening) fn statement(&self, expected: Expected) -> Statement {
        let public = Statement {
            expected,
            result: [Val::ZERO; 4],
        };
        let shared = bfv_basis_convolution::circuit::statement(
            &self.evaluations,
            self.salts,
            public.shared().expected,
        );
        Statement {
            expected: public.expected,
            result: shared.result,
        }
    }
    pub(in crate::opening) fn trace(&self, s: &Statement) -> Result<RowMajorMatrix<Val>, Error> {
        bfv_basis_convolution::circuit::trace(&self.evaluations, self.salts, &s.shared())
    }
}
