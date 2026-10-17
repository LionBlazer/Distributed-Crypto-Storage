//! Owned explicit witness. This type has no Debug, Clone, serialization or private-data getters.
use crate::{Expected, N, SetupDescriptor, Statement, circuit};
use bfv_hiding_stark::{Error, Val};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use rand::{
    RngExt, SeedableRng,
    rngs::{StdRng, SysRng},
};
use zeroize::Zeroizing;

pub struct ProverWitness {
    coefficients: Zeroizing<Vec<i8>>,
    salts: Zeroizing<[[u64; 4]; 2]>,
}
impl ProverWitness {
    pub fn new(
        coefficients: Zeroizing<Vec<i8>>,
        input: [u64; 4],
        output: [u64; 4],
    ) -> Result<Self, Error> {
        if coefficients.len() != N
            || coefficients.iter().any(|s| !(-20..=20).contains(s))
            || input.iter().chain(&output).any(|v| *v >= Val::ORDER_U64)
        {
            return Err(Error::Shape);
        }
        Ok(Self {
            coefficients,
            salts: Zeroizing::new([input, output]),
        })
    }
    pub fn statement(&self, descriptor: SetupDescriptor) -> Statement {
        circuit::statement(&self.coefficients, self.field_salts(), descriptor)
    }
    pub(crate) fn trace(
        &self,
        statement: &Statement,
    ) -> Result<p3_matrix::dense::RowMajorMatrix<Val>, Error> {
        circuit::trace(&self.coefficients, self.field_salts(), statement)
    }
    fn field_salts(&self) -> [[Val; 4]; 2] {
        (*self.salts).map(|salt| salt.map(Val::from_u64))
    }
}
/// Full fixed input root, computed from caller-owned coefficients without a transform.
pub fn input_commitment(
    descriptor: &SetupDescriptor,
    coefficients: &[i8],
    input_salt: [u64; 4],
) -> Result<[u64; 4], Error> {
    if coefficients.len() != N
        || coefficients.iter().any(|s| !(-20..=20).contains(s))
        || input_salt.iter().any(|v| *v >= Val::ORDER_U64)
    {
        return Err(Error::Shape);
    }
    let statement = Statement {
        expected: Expected {
            descriptor: descriptor.clone(),
            coefficients: [Val::ZERO; 4],
        },
        transformed: [Val::ZERO; 4],
    };
    let shifted: Vec<_> = coefficients
        .iter()
        .map(|v| Val::from_u8((*v + 20) as u8))
        .collect();
    Ok(circuit::digest(
        statement.contexts()[0],
        input_salt.map(Val::from_u64),
        &shifted,
    )
    .map(|v| v.as_canonical_u64()))
}
/// Independent OS-derived salt; never a fixture seed.
pub fn random_salt() -> Result<[u64; 4], Error> {
    let mut rng = StdRng::try_from_rng(&mut SysRng).map_err(|_| Error::Randomness)?;
    Ok(core::array::from_fn(|_| {
        rng.random::<Val>().as_canonical_u64()
    }))
}
