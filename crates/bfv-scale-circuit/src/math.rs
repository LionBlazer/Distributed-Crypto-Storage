//! Prover-side exact public arithmetic and auxiliary generation. Never verifier work.
use crate::{
    Aux, AuxiliaryRow, BASE, CARRY_OFFSET, DEGREE, Error, Evaluation, K_OFFSET, Output, Request,
    Result, Role, W_OFFSET, codec, constants,
};
use ethnum::{I256, U256};

pub(crate) fn rounded_w(e: I256) -> I256 {
    (e + I256::from(1u128 << 126)).div_euclid(I256::from(1u128 << 127))
}
pub(crate) fn unsigned_limbs(value: u128, n: usize) -> Vec<u16> {
    (0..n)
        .map(|i| ((value >> (16 * i)) & 65535) as u16)
        .collect()
}
struct Equation {
    a: Vec<i128>,
    d: Vec<i128>,
}
impl Equation {
    fn new(n: usize) -> Self {
        Self {
            a: vec![0; n],
            d: vec![0; n],
        }
    }
    fn number(target: &mut [i128], x: U256) {
        for (i, d) in target.iter_mut().enumerate() {
            *d += ((x >> (16 * i)).as_u128() & 65535) as i128;
        }
    }
    fn product(target: &mut [i128], a: &[u16], b: &[u16]) {
        for (i, &x) in a.iter().enumerate() {
            for (j, &y) in b.iter().enumerate() {
                if i + j < target.len() {
                    target[i + j] += i128::from(x) * i128::from(y);
                } else {
                    assert_eq!(u32::from(x) * u32::from(y), 0, "fixed full digit width");
                }
            }
        }
    }
    fn carry(&self, out: &mut Vec<u32>) -> Result<()> {
        let mut c = 0i128;
        for i in 0..self.a.len() {
            let diff = self.a[i] + c - self.d[i];
            if diff % BASE != 0 {
                return Err(Error::Arithmetic);
            }
            c = diff / BASE;
            if i + 1 == self.a.len() {
                if c != 0 {
                    return Err(Error::Arithmetic);
                }
            } else {
                let d = c + CARRY_OFFSET;
                if !(0..1 << 25).contains(&d) {
                    return Err(Error::Arithmetic);
                }
                out.push(d as u32);
            }
        }
        Ok(())
    }
}
fn carries(role: Role, r: &[u64], y: &[u64; 5], row: &AuxiliaryRow) -> Result<[u32; 56]> {
    let c = constants(role);
    let rr: Vec<_> = r.iter().map(|&v| unsigned_limbs(v as u128, 4)).collect();
    let mut first = Equation::new(12);
    for (ri, &t) in rr.iter().zip(&c.t) {
        Equation::product(&mut first.a, ri, &unsigned_limbs(t, 8));
    }
    Equation::number(&mut first.a, U256::ONE << (c.shift - 1));
    let shift: Vec<_> = (0..8)
        .map(|i| ((1u128 << c.shift) >> (16 * i)) as u16)
        .collect();
    Equation::product(&mut first.d, &unsigned_limbs(row.v as u128, 4), &shift);
    Equation::number(&mut first.d, U256::from(row.remainder_v));
    let mut second = Equation::new(11);
    for (ri, t) in rr.iter().zip(&c.theta) {
        Equation::product(
            if t.negative {
                &mut second.d
            } else {
                &mut second.a
            },
            ri,
            &unsigned_limbs(t.magnitude, 8),
        );
    }
    Equation::number(&mut second.a, (U256::ONE << 126) + (U256::ONE << 172));
    Equation::product(
        &mut second.d,
        &unsigned_limbs(row.biased_w as u128, 3),
        &unsigned_limbs(1u128 << 127, 8),
    );
    Equation::number(&mut second.d, U256::from(row.remainder_e));
    let mut out = Vec::with_capacity(56);
    first.carry(&mut out)?;
    second.carry(&mut out)?;
    for (j, &value) in y.iter().enumerate() {
        let p = role.computed_moduli()[j];
        let mut eq = Equation::new(8);
        for (ri, &omega) in rr.iter().zip(&c.omega[j]) {
            Equation::product(&mut eq.a, ri, &unsigned_limbs(omega as u128, 4));
        }
        Equation::number(&mut eq.a, U256::from(row.biased_w));
        Equation::number(&mut eq.a, U256::from(p) << 64);
        Equation::product(
            &mut eq.d,
            &unsigned_limbs(row.v as u128, 4),
            &unsigned_limbs(c.gamma[j] as u128, 4),
        );
        Equation::number(&mut eq.d, U256::from(value));
        Equation::product(
            &mut eq.d,
            &unsigned_limbs(row.biased_quotients[j], 5),
            &unsigned_limbs(p as u128, 4),
        );
        Equation::number(&mut eq.d, U256::from(W_OFFSET));
        eq.carry(&mut out)?;
    }
    out.try_into().map_err(|_| Error::Arithmetic)
}
/// Executes exact pinned RnsScaler arithmetic for EVERY one of8192 coefficients.
/// Public certificate is an input to a separate proof, never accepted evidence.
pub fn evaluate_with_certificate(request: &Request) -> Result<Evaluation> {
    let role = request.role;
    let c = constants(role);
    let n = role.input_moduli().len();
    let mut output = Output {
        role,
        binding: request.binding,
        input_digest: codec::digest(&request.encode()),
        coefficients: vec![0; role.output_coefficients()],
    };
    let offset = if role == Role::Extend5To10 {
        output.coefficients[..5 * DEGREE].copy_from_slice(&request.input);
        5 * DEGREE
    } else {
        0
    };
    let mut rows = Vec::with_capacity(DEGREE);
    for index in 0..DEGREE {
        let r: [u64; 10] = core::array::from_fn(|i| {
            if i < n {
                request.input[i * DEGREE + index]
            } else {
                0
            }
        });
        let r = &r[..n];
        let mut s = U256::ZERO;
        let mut e = I256::ZERO;
        for ((ri, t), theta) in r.iter().zip(&c.t).zip(&c.theta) {
            s += U256::from(*ri) * U256::from(*t);
            let z = I256::from(*ri) * I256::from(theta.magnitude);
            if theta.negative {
                e -= z;
            } else {
                e += z;
            }
        }
        let rounded = s + (U256::ONE << (c.shift - 1));
        let v = u64::try_from((rounded >> c.shift).as_u128()).map_err(|_| Error::Arithmetic)?;
        let rv = (rounded - (U256::from(v) << c.shift)).as_u128();
        let w = rounded_w(e);
        let wb = w + I256::from(W_OFFSET);
        if wb < I256::ZERO || wb >= I256::from(1u64 << 46) {
            return Err(Error::Arithmetic);
        }
        let re = (e + I256::from(1u128 << 126))
            .rem_euclid(I256::from(1u128 << 127))
            .as_u128();
        let mut y = [0u64; 5];
        let mut u = [0u128; 5];
        for j in 0..5 {
            let p = I256::from(role.computed_moduli()[j]);
            let mut a = w - I256::from(v) * I256::from(c.gamma[j]);
            for (&ri, &omega) in r.iter().zip(&c.omega[j]) {
                a += I256::from(ri) * I256::from(omega);
            }
            y[j] = a.rem_euclid(p).as_u64();
            let k = (a - I256::from(y[j])) / p;
            let biased = k + I256::from(K_OFFSET);
            if biased < I256::ZERO || biased >= I256::from(1u128 << 66) {
                return Err(Error::Arithmetic);
            }
            u[j] = biased.as_u128();
            output.coefficients[offset + j * DEGREE + index] = y[j];
        }
        let mut row = AuxiliaryRow {
            v,
            remainder_v: rv,
            biased_w: wb.as_u64(),
            remainder_e: re,
            biased_quotients: u,
            carries: [0; 56],
        };
        row.validate(role)?;
        row.carries = carries(role, r, &y, &row)?;
        rows.push(row);
    }
    let aux = Aux {
        role,
        binding: request.binding,
        input_digest: output.input_digest,
        output_digest: codec::digest(&output.encode()),
        rows,
    };
    codec::check_binding(request, &output, &aux)?;
    Ok(Evaluation { output, aux })
}
