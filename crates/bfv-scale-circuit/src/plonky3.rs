//! Optional public/preprocessed limb AIR. No scaler arithmetic on verifier inputs.
use crate::{
    Aux, BASE, CARRY_OFFSET, DEGREE, Error, Output, Request, Result, Role, W_OFFSET, codec,
    constants, profile_digest,
};
use ethnum::U256;
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
fn number<AB: AirBuilder<F = Val>>(out: &mut [AB::Expr], number: U256) {
    for (i, v) in out.iter_mut().enumerate() {
        *v += Val::from_u16(((number >> (16 * i)).as_u128() & 65535) as u16);
    }
}
fn product<AB: AirBuilder<F = Val>>(out: &mut [AB::Expr], a: &[AB::Expr], constant: &[u16]) {
    for (i, x) in a.iter().enumerate() {
        for (j, &y) in constant.iter().enumerate() {
            if i + j < out.len() {
                out[i + j] += x.clone() * Val::from_u16(y);
            }
        }
    }
}
fn digits(v: u128, n: usize) -> Vec<u16> {
    crate::math::unsigned_limbs(v, n)
}
fn equation<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    a: Vec<AB::Expr>,
    d: Vec<AB::Expr>,
    carry: &[AB::Expr],
) {
    for (i, (a, d)) in a.into_iter().zip(d).enumerate() {
        let here = if i == 0 {
            AB::Expr::from(Val::from_u64(CARRY_OFFSET as u64))
        } else {
            carry[i - 1].clone()
        };
        let next = if i == carry.len() {
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
impl<AB: AirBuilder<F = Val>> Air<AB> for ScaleAir {
    fn eval(&self, builder: &mut AB) {
        let c = constants(self.role);
        let n = self.role.input_moduli().len();
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
        let y = 4 * n;
        let v = y + 20;
        let rv = v + 4;
        let wb = rv + 8;
        let re = wb + 3;
        let u = re + 8;
        let carry = u + 25;
        let mut a = vec![AB::Expr::ZERO; 12];
        let mut d = vec![AB::Expr::ZERO; 12];
        for (i, &t) in c.t.iter().enumerate() {
            product::<AB>(&mut a, &p[4 * i..4 * i + 4], &digits(t, 8));
        }
        number::<AB>(&mut a, U256::ONE << (c.shift - 1));
        product::<AB>(&mut d, &p[v..v + 4], &digits(1u128 << c.shift, 8));
        for (i, x) in p[rv..rv + 8].iter().enumerate() {
            d[i] += x.clone();
        }
        equation(builder, a, d, &p[carry..carry + 11]);
        let mut a = vec![AB::Expr::ZERO; 11];
        let mut d = vec![AB::Expr::ZERO; 11];
        for (i, t) in c.theta.iter().enumerate() {
            product::<AB>(
                if t.negative { &mut d } else { &mut a },
                &p[4 * i..4 * i + 4],
                &digits(t.magnitude, 8),
            );
        }
        number::<AB>(&mut a, (U256::ONE << 126) + (U256::ONE << 172));
        product::<AB>(&mut d, &p[wb..wb + 3], &digits(1u128 << 127, 8));
        for (i, x) in p[re..re + 8].iter().enumerate() {
            d[i] += x.clone();
        }
        equation(builder, a, d, &p[carry + 11..carry + 21]);
        for j in 0..5 {
            let modulus = self.role.computed_moduli()[j];
            let mut a = vec![AB::Expr::ZERO; 8];
            let mut d = vec![AB::Expr::ZERO; 8];
            for i in 0..n {
                product::<AB>(
                    &mut a,
                    &p[4 * i..4 * i + 4],
                    &digits(c.omega[j][i] as u128, 4),
                );
            }
            for (i, x) in p[wb..wb + 3].iter().enumerate() {
                a[i] += x.clone();
            }
            number::<AB>(&mut a, U256::from(modulus) << 64);
            product::<AB>(&mut d, &p[v..v + 4], &digits(c.gamma[j] as u128, 4));
            for (i, x) in p[y + 4 * j..y + 4 * j + 4].iter().enumerate() {
                d[i] += x.clone();
            }
            product::<AB>(
                &mut d,
                &p[u + 5 * j..u + 5 * j + 5],
                &digits(modulus as u128, 4),
            );
            number::<AB>(&mut d, U256::from(W_OFFSET));
            equation(builder, a, d, &p[carry + 21 + 7 * j..carry + 28 + 7 * j]);
        }
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
    for limb in digits(v, n) {
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
