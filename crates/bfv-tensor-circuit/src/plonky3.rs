//! Optional public-preprocessed full tensor relation; preparation never multiplies inputs.
use crate::{
    Aux, BASE, Basis, CARRY_OFFSET, DEGREE, Error, Output, PREPROCESSED_WIDTH, Request, Result,
    TERMS, codec, profile_digest,
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks as Val;
use p3_matrix::dense::RowMajorMatrix;
pub struct TensorAir {
    basis: Basis,
    public: Option<RowMajorMatrix<Val>>,
}
impl TensorAir {
    /// Analysis only. Consumers must require actual prepared public data for proof setup.
    pub fn shape(basis: Basis) -> Self {
        Self {
            basis,
            public: None,
        }
    }
    pub fn basis(&self) -> Basis {
        self.basis
    }
    pub fn is_prepared(&self) -> bool {
        self.public.is_some()
    }
}
impl BaseAir<Val> for TensorAir {
    fn width(&self) -> usize {
        1
    }
    fn preprocessed_width(&self) -> usize {
        PREPROCESSED_WIDTH
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
fn product<AB: AirBuilder<F = Val>>(out: &mut [AB::Expr; 8], x: &[AB::Expr], y: &[AB::Expr]) {
    for (i, x) in x.iter().enumerate() {
        for (j, y) in y.iter().enumerate() {
            out[i + j] += x.clone() * y.clone();
        }
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for TensorAir {
    fn eval(&self, builder: &mut AB) {
        let main = {
            let m = builder.main();
            m.current(0).unwrap()
        };
        builder.assert_zero(main);
        let p: Vec<AB::Expr> = {
            let p = builder.preprocessed();
            (0..PREPROCESSED_WIDTH)
                .map(|i| p.current(i).unwrap().into())
                .collect()
        };
        let modulus: Vec<_> = crate::math::digits(self.basis.modulus())
            .map(|d| AB::Expr::from(Val::from_u16(d)))
            .collect();
        for (component, terms) in TERMS.iter().enumerate() {
            let mut a = core::array::from_fn(|_| AB::Expr::ZERO);
            let mut d = core::array::from_fn(|_| AB::Expr::ZERO);
            for &(x, y) in *terms {
                product::<AB>(&mut a, &p[4 * x..4 * x + 4], &p[4 * y..4 * y + 4]);
            }
            for (i, v) in p[16 + 4 * component..20 + 4 * component].iter().enumerate() {
                d[i] += v.clone();
            }
            product::<AB>(&mut d, &p[28 + 4 * component..32 + 4 * component], &modulus);
            let carry = &p[40 + 7 * component..47 + 7 * component];
            for (i, (a, d)) in a.into_iter().zip(d).enumerate() {
                let here = if i == 0 {
                    AB::Expr::from(Val::from_u64(CARRY_OFFSET as u64))
                } else {
                    carry[i - 1].clone()
                };
                let next = if i == 7 {
                    AB::Expr::from(Val::from_u64(CARRY_OFFSET as u64))
                } else {
                    carry[i].clone()
                };
                builder.assert_zero(
                    a + here + Val::from_u64((CARRY_OFFSET * (BASE - 1)) as u64)
                        - d
                        - next * Val::from_u64(BASE as u64),
                );
            }
        }
    }
}
pub struct Prepared {
    air: TensorAir,
    values: Vec<Val>,
}
impl Prepared {
    pub fn into_parts(self) -> (TensorAir, Vec<Val>) {
        (self.air, self.values)
    }
    pub fn coefficient_row(&self, index: usize) -> Option<&[Val]> {
        self.air
            .public
            .as_ref()?
            .values
            .as_chunks::<PREPROCESSED_WIDTH>()
            .0
            .get(index)
            .map(|row| row.as_slice())
    }
}
fn append(out: &mut Vec<Val>, v: u64) {
    out.extend(crate::math::digits(v).map(Val::from_u16));
}
/// Only codecs/ranges/digests and limb splitting. No scalar tensor or quotient evaluation.
pub fn prepare(r: &Request, o: &Output, a: &Aux) -> Result<Prepared> {
    codec::check_binding(r, o, a)?;
    let mut public = Vec::with_capacity(DEGREE * PREPROCESSED_WIDTH);
    for (j, row) in a.rows.iter().enumerate() {
        for i in 0..4 {
            append(&mut public, r.input[i * DEGREE + j]);
        }
        for i in 0..3 {
            append(&mut public, o.coefficients[i * DEGREE + j]);
        }
        for &q in &row.quotients {
            append(&mut public, q);
        }
        for chain in &row.carries {
            public.extend(chain.iter().map(|&d| Val::from_u32(d)));
        }
    }
    if public.len() != DEGREE * PREPROCESSED_WIDTH {
        return Err(Error::Shape);
    }
    let mut values = Vec::with_capacity(32);
    for h in [
        profile_digest(r.basis),
        codec::digest(&r.encode()),
        codec::digest(&o.encode()),
        codec::digest(&a.encode()),
    ] {
        values.extend(
            h.as_chunks::<4>()
                .0
                .iter()
                .map(|b| Val::from_u32(u32::from_le_bytes(*b))),
        );
    }
    Ok(Prepared {
        air: TensorAir {
            basis: r.basis,
            public: Some(RowMajorMatrix::new(public, PREPROCESSED_WIDTH)),
        },
        values,
    })
}
