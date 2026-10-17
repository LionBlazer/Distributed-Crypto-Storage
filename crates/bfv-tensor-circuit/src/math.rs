//! Exact full-vector public prover arithmetic; not a verifier implementation.
use crate::{
    Aux, AuxiliaryRow, BASE, CARRY_OFFSET, DEGREE, Error, Evaluation, Output, Request, Result,
    TERMS, codec,
};
pub(crate) fn digits(v: u64) -> impl Iterator<Item = u16> {
    (0..4).map(move |i| ((v >> (16 * i)) & 65535) as u16)
}
struct Equation {
    a: [i128; 8],
    d: [i128; 8],
}
impl Equation {
    fn product(out: &mut [i128; 8], x: u64, y: u64) {
        for (i, x) in digits(x).enumerate() {
            for (j, y) in digits(y).enumerate() {
                out[i + j] += i128::from(x) * i128::from(y);
            }
        }
    }
    fn carry(&self) -> Result<[u32; 7]> {
        let mut result = [0; 7];
        let mut c = 0;
        for (i, (&a, &d)) in self.a.iter().zip(&self.d).enumerate() {
            let residual = a + c - d;
            if residual % BASE != 0 {
                return Err(Error::Arithmetic);
            }
            c = residual / BASE;
            if i == 7 {
                if c != 0 {
                    return Err(Error::Arithmetic);
                }
            } else {
                let shifted = c + CARRY_OFFSET;
                if !(0..1 << 25).contains(&shifted) {
                    return Err(Error::Arithmetic);
                }
                result[i] = shifted as u32;
            }
        }
        Ok(result)
    }
}
fn carry_chain(
    inputs: &[u64; 4],
    component: usize,
    output: u64,
    quotient: u64,
    p: u64,
) -> Result<[u32; 7]> {
    let mut e = Equation {
        a: [0; 8],
        d: [0; 8],
    };
    for &(x, y) in TERMS[component] {
        Equation::product(&mut e.a, inputs[x], inputs[y]);
    }
    for (i, d) in digits(output).enumerate() {
        e.d[i] += i128::from(d);
    }
    Equation::product(&mut e.d, quotient, p);
    e.carry()
}
/// All four complete operands produce all three complete components. Each product
/// is <2^124 and the middle sum <2^125, so fixed u128 arithmetic is exact.
pub fn evaluate_with_certificate(r: &Request) -> Result<Evaluation> {
    let p = r.basis.modulus();
    let mut coefficients = vec![0; 3 * DEGREE];
    let mut rows = Vec::with_capacity(DEGREE);
    for j in 0..DEGREE {
        let inputs: [u64; 4] = core::array::from_fn(|i| r.input[i * DEGREE + j]);
        let numerators = [
            inputs[0] as u128 * inputs[2] as u128,
            inputs[0] as u128 * inputs[3] as u128 + inputs[1] as u128 * inputs[2] as u128,
            inputs[1] as u128 * inputs[3] as u128,
        ];
        let mut quotients = [0; 3];
        let mut carries = [[0; 7]; 3];
        for (component, numerator) in numerators.into_iter().enumerate() {
            let output = (numerator % p as u128) as u64;
            let quotient = (numerator / p as u128) as u64;
            coefficients[component * DEGREE + j] = output;
            quotients[component] = quotient;
            carries[component] = carry_chain(&inputs, component, output, quotient, p)?;
        }
        let row = AuxiliaryRow { quotients, carries };
        row.validate(r.basis)?;
        rows.push(row);
    }
    let output = Output {
        basis: r.basis,
        binding: r.binding,
        input_digest: codec::digest(&r.encode()),
        coefficients,
    };
    let aux = Aux {
        basis: r.basis,
        binding: r.binding,
        input_digest: output.input_digest,
        output_digest: codec::digest(&output.encode()),
        rows,
    };
    codec::check_binding(r, &output, &aux)?;
    Ok(Evaluation { output, aux })
}
