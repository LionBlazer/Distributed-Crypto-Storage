//! Optional public/preprocessed limb AIR. No scaler arithmetic on verifier inputs.
use crate::{Aux, DEGREE, Error, Output, Request, Result, Role, codec, profile_digest};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks as Val;
use p3_matrix::dense::RowMajorMatrix;

pub struct ScaleAir {
    role: Role,
    public: Option<RowMajorMatrix<Val>>,
}
impl ScaleAir {
    /// Metadata/symbolic analysis ONLY. No coefficient evaluation/auxiliary construction.
    /// Proof consumers must require is_prepared() and Some(preprocessed_trace()).
    pub fn shape(role: Role) -> Self {
        Self { role, public: None }
    }
    pub fn is_prepared(&self) -> bool {
        self.public.is_some()
    }
    pub fn role(&self) -> Role {
        self.role
    }
}
impl BaseAir<Val> for ScaleAir {
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
        Some(1)
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for ScaleAir {
    fn eval(&self, builder: &mut AB) {
        let zero = {
            let main = builder.main();
            main.current(0).unwrap()
        };
        builder.assert_zero(zero);
        let p: Vec<AB::Expr> = {
            let public = builder.preprocessed();
            (0..self.preprocessed_width())
                .map(|i| public.current(i).unwrap().into())
                .collect()
        };
        crate::air_equation::enforce(builder, self.role, &p);
    }
}
/// Range-checked public preprocessing and exact statement values, not verified proof.
pub struct Prepared {
    air: ScaleAir,
    values: Vec<Val>,
}
impl Prepared {
    pub fn into_parts(self) -> (ScaleAir, Vec<Val>) {
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
fn append_limbs(out: &mut Vec<Val>, v: u128, n: usize) {
    for limb in crate::math::unsigned_limbs(v, n) {
        out.push(Val::from_u16(limb));
    }
}
/// NO evaluation of S,v,W,quotients or a scalar scaler. Only codec/ranges, exact
/// digests, simple copied-prefix equality and splitting canonical public integers.
pub fn prepare(request: &Request, output: &Output, aux: &Aux) -> Result<Prepared> {
    codec::check_binding(request, output, aux)?;
    let role = request.role;
    let n = role.input_moduli().len();
    let width = role.preprocessed_width();
    let offset = if role == Role::Extend5To10 {
        5 * DEGREE
    } else {
        0
    };
    let mut public = Vec::with_capacity(DEGREE * width);
    for (row, a) in aux.rows.iter().enumerate() {
        for i in 0..n {
            append_limbs(&mut public, request.input[i * DEGREE + row] as u128, 4);
        }
        for i in 0..5 {
            append_limbs(
                &mut public,
                output.coefficients[offset + i * DEGREE + row] as u128,
                4,
            );
        }
        append_limbs(&mut public, a.v as u128, 4);
        append_limbs(&mut public, a.remainder_v, 8);
        append_limbs(&mut public, a.biased_w as u128, 3);
        append_limbs(&mut public, a.remainder_e, 8);
        for &u in &a.biased_quotients {
            append_limbs(&mut public, u, 5);
        }
        public.extend(a.carries.iter().map(|&d| Val::from_u32(d)));
    }
    if public.len() != DEGREE * width {
        return Err(Error::Shape);
    }
    let mut values = Vec::with_capacity(32);
    for h in [
        profile_digest(role),
        codec::digest(&request.encode()),
        codec::digest(&output.encode()),
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
        air: ScaleAir {
            role,
            public: Some(RowMajorMatrix::new(public, width)),
        },
        values,
    })
}
