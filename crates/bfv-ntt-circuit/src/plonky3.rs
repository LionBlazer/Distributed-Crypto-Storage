//! Optional full-vector public-preprocessing AIR; verifier does not run butterflies.
use crate::{
    Aux, Basis, DEGREE, Direction, Error, Output, Request, Result, codec, parameters::lane,
    profile_digest,
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks as Val;
use p3_matrix::dense::RowMajorMatrix;
pub struct NttAir {
    direction: Direction,
    basis: Basis,
    public: Option<RowMajorMatrix<Val>>,
}
impl NttAir {
    /// Metadata only. Consumers must reject proof setup without actual preprocessing.
    pub fn shape(direction: Direction, basis: Basis) -> Self {
        Self {
            direction,
            basis,
            public: None,
        }
    }
    pub fn direction(&self) -> Direction {
        self.direction
    }
    pub fn basis(&self) -> Basis {
        self.basis
    }
    pub fn is_prepared(&self) -> bool {
        self.public.is_some()
    }
}
impl BaseAir<Val> for NttAir {
    fn width(&self) -> usize {
        1
    }
    fn preprocessed_width(&self) -> usize {
        self.direction.preprocessed_width()
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        self.public.clone()
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn num_public_values(&self) -> usize {
        32
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for NttAir {
    fn eval(&self, builder: &mut AB) {
        let main = {
            let m = builder.main();
            m.current(0).unwrap()
        };
        builder.assert_zero(main);
        let public: Vec<AB::Expr> = {
            let p = builder.preprocessed();
            (0..self.preprocessed_width())
                .map(|i| p.current(i).unwrap().into())
                .collect()
        };
        let modulus_digits = crate::air_equation::modulus_digits::<AB>(self.basis);
        for s in 0..self.direction.stages() {
            crate::air_equation::enforce(builder, &modulus_digits, &public[s * 32..(s + 1) * 32]);
        }
    }
}
/// Public range/binding preparation, never a cryptographic verification result.
pub struct Prepared {
    air: NttAir,
    values: Vec<Val>,
}
impl Prepared {
    pub fn into_parts(self) -> (NttAir, Vec<Val>) {
        (self.air, self.values)
    }
    pub fn coefficient_row(&self, index: usize) -> Option<&[Val]> {
        self.air
            .public
            .as_ref()?
            .values
            .chunks_exact(self.air.direction.preprocessed_width())
            .nth(index)
    }
}
fn append(out: &mut Vec<Val>, value: u128, n: usize) {
    out.extend(crate::math::digits(value, n).map(Val::from_u16));
}
/// Only canonical codecs/ranges/hashes, full final-output equality, fixed gathers and
/// fixed public weights. No butterfly, quotient, modular product or NTT evaluation.
pub fn prepare(r: &Request, o: &Output, aux: &Aux) -> Result<Prepared> {
    codec::check_binding(r, o, aux)?;
    let width = r.direction.preprocessed_width();
    let mut public = Vec::with_capacity(DEGREE * width);
    for j in 0..DEGREE {
        for s in 0..r.direction.stages() {
            let previous = if s == 0 {
                &r.input
            } else {
                &aux.stages[s - 1].coefficients
            };
            let l = lane(r.direction, r.basis, s, j);
            let stage = &aux.stages[s];
            let row = &stage.rows[j];
            append(&mut public, previous[l.x] as u128, 4);
            append(
                &mut public,
                if l.b == 0 { 0 } else { previous[l.y] as u128 },
                4,
            );
            append(&mut public, stage.coefficients[j] as u128, 4);
            append(&mut public, l.a as u128, 4);
            append(&mut public, l.b as u128, 4);
            append(&mut public, row.biased_quotient, 5);
            public.extend(row.carries.iter().map(|&v| Val::from_u32(v)));
        }
    }
    if public.len() != DEGREE * width {
        return Err(Error::Shape);
    }
    let mut values = Vec::with_capacity(32);
    for h in [
        profile_digest(r.direction, r.basis),
        codec::digest(&r.encode()),
        codec::digest(&o.encode()),
        codec::digest(&aux.encode()),
    ] {
        values.extend(
            h.as_chunks::<4>()
                .0
                .iter()
                .map(|b| Val::from_u32(u32::from_le_bytes(*b))),
        );
    }
    Ok(Prepared {
        air: NttAir {
            direction: r.direction,
            basis: r.basis,
            public: Some(RowMajorMatrix::new(public, width)),
        },
        values,
    })
}
