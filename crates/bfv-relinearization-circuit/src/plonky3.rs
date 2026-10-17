//! Optional public-preprocessed arithmetic AIR, never a complete relinearization verifier.
use crate::{
    Aux, BASE, CARRY_OFFSET, DEGREE, Error, MODULI, Output, Request, Result, Role,
    codec::{self, Rows},
    profile_digest,
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks as Val;
use p3_matrix::dense::RowMajorMatrix;
pub struct ArithmeticAir {
    role: Role,
    public: Option<RowMajorMatrix<Val>>,
}
impl ArithmeticAir {
    /// Metadata only. Consumers must reject setup lacking actual public preprocessing.
    pub fn shape(role: Role) -> Self {
        Self { role, public: None }
    }
    pub fn role(&self) -> Role {
        self.role
    }
    pub fn is_prepared(&self) -> bool {
        self.public.is_some()
    }
}
impl BaseAir<Val> for ArithmeticAir {
    fn width(&self) -> usize {
        1
    }
    fn preprocessed_width(&self) -> usize {
        self.role.preprocessed_width()
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
        Some(match self.role {
            Role::Embed => 1,
            Role::AccumulateAndAdd => 2,
        })
    }
}
fn product<AB: AirBuilder<F = Val>>(out: &mut [AB::Expr; 6], x: &[AB::Expr], y: &[AB::Expr]) {
    for (i, x) in x.iter().enumerate() {
        for (j, y) in y.iter().enumerate() {
            out[i + j] += x.clone() * y.clone();
        }
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for ArithmeticAir {
    fn eval(&self, builder: &mut AB) {
        let main = {
            let m = builder.main();
            m.current(0).unwrap()
        };
        builder.assert_zero(main);
        let p: Vec<AB::Expr> = {
            let p = builder.preprocessed();
            (0..self.preprocessed_width())
                .map(|i| p.current(i).unwrap().into())
                .collect()
        };
        match self.role {
            Role::Embed => {
                for source in 0..5 {
                    for (target, &modulus) in MODULI.iter().enumerate() {
                        let poly = 5 * source + target; // All canonical residues <2^44 and t<=2: residual <2^46<Gold.
                        builder.assert_zero(
                            p[source].clone()
                                - p[5 + poly].clone()
                                - p[30 + poly].clone() * Val::from_u64(modulus),
                        );
                    }
                }
            }
            Role::AccumulateAndAdd => {
                for (target, &modulus) in MODULI.iter().enumerate() {
                    let input = target * 51;
                    let modulus: Vec<_> = crate::math::limbs(modulus)
                        .map(|v| AB::Expr::from(Val::from_u16(v)))
                        .collect();
                    for component in 0..2 {
                        let poly = 2 * target + component;
                        let mut a = core::array::from_fn(|_| AB::Expr::ZERO);
                        let mut d = core::array::from_fn(|_| AB::Expr::ZERO);
                        for (i, v) in p[input + 3 * component..input + 3 * component + 3]
                            .iter()
                            .enumerate()
                        {
                            a[i] += v.clone();
                        }
                        for source in 0..5 {
                            product::<AB>(
                                &mut a,
                                &p[input + 3 * (2 + source)..input + 3 * (3 + source)],
                                &p[input + 3 * (7 + 5 * component + source)
                                    ..input + 3 * (8 + 5 * component + source)],
                            );
                        }
                        for (i, v) in p[255 + 3 * poly..258 + 3 * poly].iter().enumerate() {
                            d[i] += v.clone();
                        }
                        product::<AB>(&mut d, &p[285 + 3 * poly..288 + 3 * poly], &modulus);
                        let carry = &p[315 + 5 * poly..320 + 5 * poly];
                        for (i, (a, d)) in a.into_iter().zip(d).enumerate() {
                            let here = if i == 0 {
                                AB::Expr::from(Val::from_u64(CARRY_OFFSET as u64))
                            } else {
                                carry[i - 1].clone()
                            };
                            let next = if i == 5 {
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
        }
    }
}
pub struct Prepared {
    air: ArithmeticAir,
    values: Vec<Val>,
}
impl Prepared {
    pub fn into_parts(self) -> (ArithmeticAir, Vec<Val>) {
        (self.air, self.values)
    }
    pub fn coefficient_row(&self, index: usize) -> Option<&[Val]> {
        self.air
            .public
            .as_ref()?
            .values
            .chunks_exact(self.air.role.preprocessed_width())
            .nth(index)
    }
}
fn append(out: &mut Vec<Val>, v: u64) {
    out.extend(crate::math::limbs(v).map(Val::from_u16));
}
/// Canonical decoding/binding/ranges and exact public layout only. No modular
/// reduction, quotient, tensor, MAC or NTT evaluation of caller coefficients.
pub fn prepare(r: &Request, o: &Output, a: &Aux) -> Result<Prepared> {
    codec::check_binding(r, o, a)?;
    let width = r.role.preprocessed_width();
    let mut public = Vec::with_capacity(DEGREE * width);
    match &a.rows {
        Rows::Embed(rows) => {
            for (coefficient, row) in rows.iter().enumerate() {
                for source in 0..5 {
                    public.push(Val::from_u64(r.input[source * DEGREE + coefficient]));
                }
                for poly in 0..25 {
                    public.push(Val::from_u64(o.coefficients[poly * DEGREE + coefficient]));
                }
                public.extend(row.iter().map(|&t| Val::from_u8(t)));
            }
        }
        Rows::Accumulate(rows) => {
            for (coefficient, row) in rows.iter().enumerate() {
                for poly in 0..85 {
                    append(&mut public, r.input[poly * DEGREE + coefficient]);
                }
                for poly in 0..10 {
                    append(&mut public, o.coefficients[poly * DEGREE + coefficient]);
                }
                for &q in &row.quotients {
                    append(&mut public, q);
                }
                for chain in &row.carries {
                    public.extend(chain.iter().map(|&d| Val::from_u32(d)));
                }
            }
        }
    };
    if public.len() != DEGREE * width {
        return Err(Error::Shape);
    }
    let mut values = Vec::with_capacity(32);
    for h in [
        profile_digest(r.role),
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
        air: ArithmeticAir {
            role: r.role,
            public: Some(RowMajorMatrix::new(public, width)),
        },
        values,
    })
}
