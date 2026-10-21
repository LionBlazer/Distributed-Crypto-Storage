//! Exact prover arithmetic and a separate checked-integer quotient verifier.
use super::{
    Evaluation, K_OFFSET, Output, PublicCertificate, Quotients, Request, Result, W_OFFSET,
    check_bindings,
    constants::{CoefficientConstants, constants},
    output_digest, request_digest,
};
use crate::{Error, geometry::N};
use ethnum::I256;
fn add(a: I256, b: I256) -> Result<I256> {
    a.checked_add(b).ok_or(Error::Arithmetic)
}
fn sub(a: I256, b: I256) -> Result<I256> {
    a.checked_sub(b).ok_or(Error::Arithmetic)
}
fn mul(a: I256, b: I256) -> Result<I256> {
    a.checked_mul(b).ok_or(Error::Arithmetic)
}
/// Linear dot products only; this function has no division, reduction, rounding, or SDK call.
fn dot_products(c: &CoefficientConstants, r: &[u64]) -> Result<(I256, I256)> {
    let mut s = I256::ZERO;
    let mut e = I256::ZERO;
    for ((&ri, &t), theta) in r.iter().zip(&c.t).zip(&c.theta) {
        s = add(s, mul(I256::from(ri), I256::from(t))?)?;
        let term = mul(I256::from(ri), I256::from(theta.magnitude))?;
        e = if theta.negative {
            sub(e, term)?
        } else {
            add(e, term)?
        };
    }
    Ok((s, e))
}
fn reduction_numerator(
    c: &CoefficientConstants,
    r: &[u64],
    v: u64,
    w: I256,
    j: usize,
) -> Result<I256> {
    let mut a = sub(w, mul(I256::from(v), I256::from(c.gamma[j]))?)?;
    for (&ri, &omega) in r.iter().zip(&c.omega[j]) {
        a = add(a, mul(I256::from(ri), I256::from(omega))?)?;
    }
    Ok(a)
}
/// Prover ONLY: performs the SDK-equivalent divisions and supplies their quotient witnesses.
pub(crate) fn evaluate(request: &Request) -> Result<Evaluation> {
    let role = request.role;
    let c = constants(role);
    let mut coefficients = vec![vec![0; N]; role.output_moduli().len()];
    if role == super::Role::Extend2To4 {
        coefficients[..2].clone_from_slice(&request.input);
    }
    let mut rows = Vec::with_capacity(N);
    let unit = I256::from(1u128 << c.shift);
    let half = I256::from(1u128 << (c.shift - 1));
    for index in 0..N {
        let r: [u64; 4] =
            core::array::from_fn(|i| request.input.get(i).map_or(0, |row| row[index]));
        let r = &r[..role.input_moduli().len()];
        let (s, e) = dot_products(c, r)?;
        let v256 = add(s, half)? / unit;
        if v256 < I256::ZERO || v256 > I256::from(u64::MAX) {
            return Err(Error::Arithmetic);
        }
        let v = v256.as_u64();
        let w = add(e, I256::from(1u128 << 126))?.div_euclid(I256::from(1u128 << 127));
        let wb = add(w, I256::from(W_OFFSET))?;
        if wb < I256::ZERO || wb >= I256::from(1u64 << 46) {
            return Err(Error::Arithmetic);
        }
        let mut biased_k = [0; 2];
        for (j, &p) in role.computed_moduli().iter().enumerate() {
            let a = reduction_numerator(c, r, v, w, j)?;
            let value = a.rem_euclid(I256::from(p)).as_u64();
            let k = sub(a, I256::from(value))? / I256::from(p);
            let u = add(k, I256::from(K_OFFSET))?;
            if u < I256::ZERO || u >= I256::from(1u128 << 66) {
                return Err(Error::Arithmetic);
            }
            biased_k[j] = u.as_u128();
            coefficients[role.computed_offset() + j][index] = value;
        }
        rows.push(Quotients {
            v,
            biased_w: wb.as_u64(),
            biased_k,
        });
    }
    let output = Output::new(request, coefficients)?;
    let certificate = PublicCertificate {
        role,
        binding: request.binding,
        input_digest: request_digest(request),
        output_digest: output_digest(&output),
        rows,
    };
    Ok(Evaluation {
        output,
        certificate,
    })
}
/// Deterministic PUBLIC scalar relation checking, with no SDK Scaler, quotient division,
/// remainder operation, NTT, ciphertext multiplication, plaintext, or secret-key access.
/// Every equation is signed256-bit checked integer arithmetic, never a finite-field alias.
/// This does not verify the Source/encoding, multiplication, SQL completeness, or consensus.
pub(crate) fn verify_certificate(
    request: &Request,
    output: &Output,
    certificate: &PublicCertificate,
) -> Result<()> {
    check_bindings(request, output, certificate)?;
    let role = request.role;
    let c = constants(role);
    let unit = I256::from(1u128 << c.shift);
    let half = I256::from(1u128 << (c.shift - 1));
    let w_unit = I256::from(1u128 << 127);
    let w_half = I256::from(1u128 << 126);
    for index in 0..N {
        let row = &certificate.rows[index];
        row.validate()?;
        let r: [u64; 4] =
            core::array::from_fn(|i| request.input.get(i).map_or(0, |values| values[index]));
        let r = &r[..role.input_moduli().len()];
        let (s, e) = dot_products(c, r)?;
        // The supplied v is unique: this interval characterizes floor((S+half)/unit).
        let rv = sub(add(s, half)?, mul(I256::from(row.v), unit)?)?;
        if rv < I256::ZERO || rv >= unit {
            return Err(Error::Arithmetic);
        }
        let w = sub(I256::from(row.biased_w), I256::from(W_OFFSET))?;
        // Includes negative and exact-half SDK ties: floor((E+2^126)/2^127).
        let re = sub(add(e, w_half)?, mul(w, w_unit)?)?;
        if re < I256::ZERO || re >= w_unit {
            return Err(Error::Arithmetic);
        }
        for (j, &p) in role.computed_moduli().iter().enumerate() {
            let a = reduction_numerator(c, r, row.v, w, j)?;
            let value = output.coefficients[role.computed_offset() + j][index];
            let k = sub(I256::from(row.biased_k[j]), I256::from(K_OFFSET))?;
            if sub(a, I256::from(value))? != mul(I256::from(p), k)? {
                return Err(Error::Arithmetic);
            }
        }
    }
    Ok(())
}
