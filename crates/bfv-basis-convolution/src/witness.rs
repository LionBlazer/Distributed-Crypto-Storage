//! Borrowed explicit mathematical input; the enclosing Owner job owns guarded storage.
use crate::{Expected, N, Statement, circuit};
use bfv_hiding_stark::{Error, Val};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use zeroize::Zeroizing;

pub struct ProverWitness<'input> {
    evaluations: &'input [u64],
    salts: Zeroizing<[[u64; 4]; 2]>,
}
impl<'input> ProverWitness<'input> {
    pub fn new(
        evaluations: &'input [u64],
        input_salt: [u64; 4],
        result_salt: [u64; 4],
    ) -> Result<Self, Error> {
        if evaluations.len() != N
            || evaluations
                .iter()
                .chain(&input_salt)
                .chain(&result_salt)
                .any(|v| *v >= Val::ORDER_U64)
        {
            return Err(Error::Shape);
        }
        Ok(Self {
            evaluations,
            salts: Zeroizing::new([input_salt, result_salt]),
        })
    }
    pub fn statement(&self, expected: Expected) -> Statement {
        let values: Vec<_> = self
            .evaluations
            .iter()
            .copied()
            .map(Val::from_u64)
            .collect();
        circuit::statement(&values, self.field_salts(), expected)
    }
    pub(crate) fn trace(
        &self,
        statement: &Statement,
    ) -> Result<p3_matrix::dense::RowMajorMatrix<Val>, Error> {
        let values: Vec<_> = self
            .evaluations
            .iter()
            .copied()
            .map(Val::from_u64)
            .collect();
        circuit::trace(&values, self.field_salts(), statement)
    }
    fn field_salts(&self) -> [[Val; 4]; 2] {
        (*self.salts).map(|s| s.map(Val::from_u64))
    }
}
