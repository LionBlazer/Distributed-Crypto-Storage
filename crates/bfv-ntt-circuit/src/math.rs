//! Prover-side evaluation of public residues and bounded auxiliary generation.
use crate::{
    Aux, AuxiliaryRow, BASE, CARRY_OFFSET, DEGREE, Error, Evaluation, Output, QUOTIENT_OFFSET,
    Request, Result, Stage, codec, parameters::lane,
};
pub(crate) fn digits(v: u128, n: usize) -> impl Iterator<Item = u16> {
    (0..n).map(move |i| ((v >> (16 * i)) & 65535) as u16)
}
pub(crate) struct Equation {
    pub a: [i128; 8],
    pub d: [i128; 8],
}
impl Equation {
    fn new() -> Self {
        Self {
            a: [0; 8],
            d: [0; 8],
        }
    }
    fn number(out: &mut [i128; 8], v: u128) {
        for (i, x) in out.iter_mut().enumerate() {
            *x += ((v >> (16 * i)) & 65535) as i128;
        }
    }
    fn product(out: &mut [i128; 8], x: u128, y: u128, nx: usize, ny: usize) {
        for (i, x) in digits(x, nx).enumerate() {
            for (j, y) in digits(y, ny).enumerate() {
                if i + j < 8 {
                    out[i + j] += i128::from(x) * i128::from(y);
                } else {
                    assert_eq!(u32::from(x) * u32::from(y), 0, "fixed full product width");
                }
            }
        }
    }
    fn carries(&self) -> Result<[u32; 7]> {
        let mut out = [0; 7];
        let mut c = 0;
        for (i, (&a, &d)) in self.a.iter().zip(&self.d).enumerate() {
            let diff = a + c - d;
            if diff % BASE != 0 {
                return Err(Error::Arithmetic);
            }
            c = diff / BASE;
            if i == 7 {
                if c != 0 {
                    return Err(Error::Arithmetic);
                }
            } else {
                let d = c + CARRY_OFFSET;
                if !(0..1 << 25).contains(&d) {
                    return Err(Error::Arithmetic);
                }
                out[i] = d as u32;
            }
        }
        Ok(out)
    }
}
pub(crate) fn equation(p: u64, x: u64, y: u64, a: u64, b: u64, out: u64, u: u128) -> Equation {
    let mut e = Equation::new();
    Equation::number(&mut e.a, (p as u128) << 64);
    Equation::product(&mut e.a, a as u128, x as u128, 4, 4);
    Equation::product(&mut e.a, b as u128, y as u128, 4, 4);
    Equation::number(&mut e.d, out as u128);
    Equation::product(&mut e.d, u, p as u128, 5, 4);
    e
}
/// Fixed positive weights bound the numerator below 2^125 and U below 2^65.
/// All 8192 coefficients of all 13 layers, plus inverse normalization. Public only.
pub fn evaluate_with_certificate(r: &Request) -> Result<Evaluation> {
    let p = r.basis.modulus();
    let modulus = p as u128;
    let mut stages: Vec<Stage> = Vec::with_capacity(r.direction.stages());
    for s in 0..r.direction.stages() {
        let previous = stages
            .last()
            .map_or(r.input.as_slice(), |stage| stage.coefficients.as_slice());
        let mut coefficients = Vec::with_capacity(DEGREE);
        let mut rows = Vec::with_capacity(DEGREE);
        for j in 0..DEGREE {
            let l = lane(r.direction, r.basis, s, j);
            let x = previous[l.x];
            let y = if l.b == 0 { 0 } else { previous[l.y] };
            // All four canonical factors are <p<2^62, so this is <2^125.
            let numerator = l.a as u128 * x as u128 + l.b as u128 * y as u128;
            let output = (numerator % modulus) as u64;
            let k = numerator / modulus;
            let u = k + QUOTIENT_OFFSET;
            if u >= 1u128 << 66 {
                return Err(Error::Arithmetic);
            }
            let biased_quotient = u;
            let carries = equation(p, x, y, l.a, l.b, output, biased_quotient).carries()?;
            coefficients.push(output);
            rows.push(AuxiliaryRow {
                biased_quotient,
                carries,
            });
        }
        stages.push(Stage { coefficients, rows });
    }
    let output = Output {
        direction: r.direction,
        basis: r.basis,
        binding: r.binding,
        input_digest: codec::digest(&r.encode()),
        coefficients: stages.last().unwrap().coefficients.clone(),
    };
    let aux = Aux {
        direction: r.direction,
        basis: r.basis,
        binding: r.binding,
        input_digest: output.input_digest,
        output_digest: codec::digest(&output.encode()),
        stages,
    };
    codec::check_binding(r, &output, &aux)?;
    Ok(Evaluation { output, aux })
}
