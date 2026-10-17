//! Prover-side public arithmetic stages, not key switching or transform verification.
use crate::{
    AccumulationRow, Aux, BASE, CARRY_OFFSET, DEGREE, Error, Evaluation, MODULI, Output, Request,
    Result, Role,
    codec::{self, Rows},
};
pub(crate) fn limbs(value: u64) -> impl Iterator<Item = u16> {
    (0..3).map(move |i| ((value >> (16 * i)) & 65535) as u16)
}
struct Equation {
    a: [i128; 6],
    d: [i128; 6],
}
impl Equation {
    fn number(out: &mut [i128; 6], value: u64) {
        for (i, v) in limbs(value).enumerate() {
            out[i] += i128::from(v);
        }
    }
    fn product(out: &mut [i128; 6], x: u64, y: u64) {
        for (i, x) in limbs(x).enumerate() {
            for (j, y) in limbs(y).enumerate() {
                out[i + j] += i128::from(x) * i128::from(y);
            }
        }
    }
    fn carries(&self) -> Result<[u32; 5]> {
        let mut out = [0; 5];
        let mut carry = 0;
        for (i, (&a, &d)) in self.a.iter().zip(&self.d).enumerate() {
            let residual = a + carry - d;
            if residual % BASE != 0 {
                return Err(Error::Arithmetic);
            }
            carry = residual / BASE;
            if i == 5 {
                if carry != 0 {
                    return Err(Error::Arithmetic);
                }
            } else {
                let shifted = carry + CARRY_OFFSET;
                if !(0..1 << 25).contains(&shifted) {
                    return Err(Error::Arithmetic);
                }
                out[i] = shifted as u32;
            }
        }
        Ok(out)
    }
}
fn carry_chain(
    original: u64,
    digits: &[u64; 5],
    keys: &[u64; 5],
    output: u64,
    quotient: u64,
    p: u64,
) -> Result<[u32; 5]> {
    let mut e = Equation {
        a: [0; 6],
        d: [0; 6],
    };
    Equation::number(&mut e.a, original);
    for (&d, &k) in digits.iter().zip(keys) {
        Equation::product(&mut e.a, d, k);
    }
    Equation::number(&mut e.d, output);
    Equation::product(&mut e.d, p, quotient);
    e.carries()
}
/// Only public coefficients. Embed computes all 25 reductions; AccumulateAndAdd
/// computes all 10 full five-term sums plus original c0/c1. It performs no NTT/key import.
pub fn evaluate_with_certificate(r: &Request) -> Result<Evaluation> {
    let mut coefficients = vec![0; r.role.output_coefficients()];
    let rows = match r.role {
        Role::Embed => {
            let mut rows = Vec::with_capacity(DEGREE);
            for coefficient in 0..DEGREE {
                let mut quotients = [0; 25];
                for (source, &source_modulus) in MODULI.iter().enumerate() {
                    let residue = r.input[source * DEGREE + coefficient];
                    debug_assert!(residue < source_modulus);
                    for (target, &p) in MODULI.iter().enumerate() {
                        let poly = 5 * source + target;
                        coefficients[poly * DEGREE + coefficient] = residue % p;
                        quotients[poly] = (residue / p) as u8;
                    }
                }
                rows.push(quotients);
            }
            Rows::Embed(rows)
        }
        Role::AccumulateAndAdd => {
            let mut rows = Vec::with_capacity(DEGREE);
            for coefficient in 0..DEGREE {
                let mut quotients = [0; 10];
                let mut carries = [[0; 5]; 10];
                for (target, &p) in MODULI.iter().enumerate() {
                    let block = 17 * target;
                    let digits: [u64; 5] =
                        core::array::from_fn(|i| r.input[(block + 2 + i) * DEGREE + coefficient]);
                    for component in 0..2 {
                        let original = r.input[(block + component) * DEGREE + coefficient];
                        let keys: [u64; 5] = core::array::from_fn(|i| {
                            r.input[(block + 7 + 5 * component + i) * DEGREE + coefficient]
                        });
                        let numerator = digits
                            .iter()
                            .zip(&keys)
                            .fold(original as u128, |sum, (&d, &k)| {
                                sum + d as u128 * k as u128
                            });
                        let output = (numerator % p as u128) as u64;
                        let quotient = (numerator / p as u128) as u64;
                        let poly = 2 * target + component;
                        coefficients[poly * DEGREE + coefficient] = output;
                        quotients[poly] = quotient;
                        carries[poly] = carry_chain(original, &digits, &keys, output, quotient, p)?;
                    }
                }
                let row = AccumulationRow { quotients, carries };
                row.validate()?;
                rows.push(row);
            }
            Rows::Accumulate(rows)
        }
    };
    let output = Output {
        role: r.role,
        binding: r.binding,
        keyset: r.keyset,
        input_digest: codec::digest(&r.encode()),
        coefficients,
    };
    let aux = Aux {
        role: r.role,
        binding: r.binding,
        keyset: r.keyset,
        input_digest: output.input_digest,
        output_digest: codec::digest(&output.encode()),
        rows,
    };
    codec::check_binding(r, &output, &aux)?;
    Ok(Evaluation { output, aux })
}
