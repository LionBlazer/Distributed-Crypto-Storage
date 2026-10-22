//! Public polynomial identity experiment. No SQL or assessed FS/security authority.
use crate::{
    Error, Polynomial, Result,
    geometry::{N, QP},
    modular::Modulus,
};
use p3_maybe_rayon::prelude::*;
use sha2::{Digest, Sha512};

pub(crate) const POINTS: usize = 18;
pub(crate) struct ProductCertificate {
    pub(crate) products: [Polynomial; 3],
    pub(crate) quotients: [Polynomial; 3],
}
fn mul(a: u64, b: u64, p: u64) -> u64 {
    ((u128::from(a) * u128::from(b)) % u128::from(p)) as u64
}
fn add(a: u64, b: u64, p: u64) -> u64 {
    (a + b) % p
}
fn sub(a: u64, b: u64, p: u64) -> u64 {
    (a + p - b) % p
}
fn pow(mut a: u64, mut e: u64, p: u64) -> u64 {
    let mut out = 1;
    while e != 0 {
        if e & 1 != 0 {
            out = mul(out, a, p);
        }
        a = mul(a, a, p);
        e >>= 1;
    }
    out
}
fn canonical(poly: &Polynomial, length: usize) -> Result<()> {
    if poly.len() != QP.len()
        || poly
            .iter()
            .zip(QP)
            .any(|(row, p)| row.len() != length || row.iter().any(|&v| v >= p))
    {
        return Err(Error::Shape);
    }
    Ok(())
}
fn primitive_root(p: u64) -> Result<u64> {
    // Any root of exact order2N yields the same ordinary polynomial convolution.
    let order = 2 * N as u64;
    if !(p - 1).is_multiple_of(order) {
        return Err(Error::Shape);
    }
    for candidate in 2..1024 {
        let root = pow(candidate, (p - 1) / order, p);
        if pow(root, order, p) == 1 && pow(root, order / 2, p) == p - 1 {
            return Ok(root);
        }
    }
    Err(Error::Arithmetic)
}
pub(crate) fn produce(inputs: &[Polynomial; 4]) -> Result<ProductCertificate> {
    for input in inputs {
        canonical(input, N)?;
    }
    let mut products: [Polynomial; 3] = std::array::from_fn(|_| Vec::with_capacity(4));
    let mut quotients: [Polynomial; 3] = std::array::from_fn(|_| Vec::with_capacity(4));
    for (basis, p) in QP.into_iter().enumerate() {
        let root = primitive_root(p)?;
        let field = Modulus::new(p)?;
        let mut transformed: [Vec<u64>; 4] = std::array::from_fn(|i| {
            let mut values = vec![0; 2 * N];
            values[..N].copy_from_slice(&inputs[i][basis]);
            field.transform(&mut values, root, false);
            values
        });
        for component in 0..3 {
            let mut product = vec![0; 2 * N];
            for i in 0..2 * N {
                product[i] = match component {
                    0 => mul(transformed[0][i], transformed[2][i], p),
                    1 => add(
                        mul(transformed[0][i], transformed[3][i], p),
                        mul(transformed[1][i], transformed[2][i], p),
                        p,
                    ),
                    _ => mul(transformed[1][i], transformed[3][i], p),
                };
            }
            field.transform(&mut product, root, true);
            if product[2 * N - 1] != 0 {
                return Err(Error::Arithmetic);
            }
            let high = product[N..2 * N - 1].to_vec();
            let low = (0..N).map(|i| sub(product[i], product[N + i], p)).collect();
            quotients[component].push(high);
            products[component].push(low);
        }
        // Explicitly release large public intermediates before the next basis.
        for values in &mut transformed {
            values.clear();
        }
    }
    Ok(ProductCertificate {
        products,
        quotients,
    })
}

pub(crate) fn transcript_prefix(
    statement: &crate::statement::Expected,
    complete_frame: &[u8],
) -> Sha512 {
    let mut h = Sha512::new();
    h.update(b"DCS/UNREL-PIT-EXPERIMENT/v1/full-canonical-transcript/");
    for bytes in [
        statement.request_wire(),
        statement.output_wire(),
        complete_frame,
    ] {
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(bytes);
    }
    h
}
fn points(prefix: &Sha512, basis: usize, p: u64) -> [u64; POINTS] {
    std::array::from_fn(|index| {
        let mut h = prefix.clone();
        h.update(b"/field-point/v1/");
        h.update((basis as u32).to_le_bytes());
        h.update((index as u32).to_le_bytes());
        // Full512 bits are reduced. No finalized512-bit seed is expanded into
        // supposedly independent challenges; every message includes all bytes.
        h.finalize().iter().fold(0u64, |value, &byte| {
            ((u128::from(value) * 256 + u128::from(byte)) % u128::from(p)) as u64
        })
    })
}
pub(crate) fn check(
    inputs: &[Polynomial; 4],
    certificate: &ProductCertificate,
    prefix: &Sha512,
) -> Result<()> {
    for input in inputs {
        canonical(input, N)?;
    }
    for product in &certificate.products {
        canonical(product, N)?;
    }
    for quotient in &certificate.quotients {
        canonical(quotient, N - 1)?;
    }
    // Exactly four read-only field jobs share the host's existing Rayon pool.
    // No polynomial copy, new pool, challenge change or detached worker exists.
    QP.into_par_iter().enumerate().try_for_each(|(basis, p)| {
        let field = Modulus::new(p)?;
        for point in points(prefix, basis, p) {
            let a: [u64; 4] = std::array::from_fn(|i| field.evaluate(&inputs[i][basis], point));
            let lhs = [
                field.multiply(a[0], a[2]),
                field.add(field.multiply(a[0], a[3]), field.multiply(a[1], a[2])),
                field.multiply(a[1], a[3]),
            ];
            let xn1 = field.add(field.power(point, N as u64), 1);
            for (component, lhs) in lhs.into_iter().enumerate() {
                let y = field.evaluate(&certificate.products[component][basis], point);
                let h = field.evaluate(&certificate.quotients[component][basis], point);
                if lhs != field.add(y, field.multiply(xn1, h)) {
                    return Err(Error::Arithmetic);
                }
            }
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dense_public_convolution_retains_every_product_and_quotient_coefficient() -> Result<()> {
        // Fixed PUBLIC NONSECRET coefficients, including every basis boundary.
        let inputs = std::array::from_fn(|operand| {
            QP.iter()
                .map(|&p| {
                    (0..N)
                        .map(|at| match (at + operand) % 5 {
                            0 => p - 1,
                            1 => p / 2,
                            2 => operand as u64 + 1,
                            3 => (at as u64 * 7919 + 17 + operand as u64) % p,
                            _ => 0,
                        })
                        .collect()
                })
                .collect()
        });
        let certificate = produce(&inputs)?;
        let mut digest = Sha512::new();
        for polynomial in certificate.products.iter().chain(&certificate.quotients) {
            for row in polynomial {
                for value in row {
                    digest.update(value.to_le_bytes());
                }
            }
        }
        let digest: String = digest
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            digest,
            "94120219463f2115c811c87e1cc6ff83c533f6ec15b8bf94dbc7dcee48be38bd5158f7a93534781576068593641888aefd5fa36f003abc6ecf43c4a10d672b51"
        );
        check(&inputs, &certificate, &prefix(&certificate))?;
        Ok(())
    }
    fn inputs() -> [Polynomial; 4] {
        std::array::from_fn(|i| {
            QP.iter()
                .map(|&p| {
                    let mut values = vec![0; N];
                    values[0] = i as u64 + 1;
                    values[N - 1] = p - (i as u64 + 2);
                    values[N / 2] = 17 + i as u64;
                    values
                })
                .collect()
        })
    }
    fn prefix(c: &ProductCertificate) -> Sha512 {
        let mut h = Sha512::new();
        h.update(b"PUBLIC TEST ONLY full polynomial certificate");
        for polynomial in c.products.iter().chain(c.quotients.iter()) {
            for row in polynomial {
                for value in row {
                    h.update(value.to_le_bytes());
                }
            }
        }
        h
    }
    #[test]
    fn complete_convolution_certificate_checks_and_repaired_false_last_word_is_rejected()
    -> Result<()> {
        let inputs = inputs();
        let mut c = produce(&inputs)?;
        check(&inputs, &c, &prefix(&c))?;
        for component in 0..3 {
            for (basis, p) in QP.into_iter().enumerate() {
                c.products[component][basis][N - 1] = (c.products[component][basis][N - 1] + 1) % p;
                assert!(
                    check(&inputs, &c, &prefix(&c)).is_err(),
                    "Fresh hash must not authorize false component {component} in basis {basis}"
                );
                c.products[component][basis][N - 1] =
                    (c.products[component][basis][N - 1] + p - 1) % p;
            }
        }
        c.quotients[1][3][N - 2] = (c.quotients[1][3][N - 2] + 1) % QP[3];
        assert!(check(&inputs, &c, &prefix(&c)).is_err());
        Ok(())
    }
    #[test]
    fn degree_and_residue_caps_precede_challenge_checks() -> Result<()> {
        let inputs = inputs();
        let mut c = produce(&inputs)?;
        c.quotients[0][0].push(0);
        assert!(check(&inputs, &c, &prefix(&c)).is_err());
        c.quotients[0][0].pop();
        c.products[0][0][0] = QP[0];
        assert!(check(&inputs, &c, &prefix(&c)).is_err());
        Ok(())
    }
    #[test]
    fn public_sparse_ring_convolution_oracle_matches_all_coefficients() -> Result<()> {
        let inputs = inputs();
        let c = produce(&inputs)?;
        for (basis, p) in QP.into_iter().enumerate() {
            for component in 0..3 {
                let terms: &[(usize, usize)] = match component {
                    0 => &[(0, 2)],
                    1 => &[(0, 3), (1, 2)],
                    _ => &[(1, 3)],
                };
                let mut expected = vec![0; N];
                for &(a, b) in terms {
                    for (i, &x) in inputs[a][basis]
                        .iter()
                        .enumerate()
                        .filter(|(_, x)| **x != 0)
                    {
                        for (j, &y) in inputs[b][basis]
                            .iter()
                            .enumerate()
                            .filter(|(_, y)| **y != 0)
                        {
                            let at = (i + j) % N;
                            let term = mul(x, y, p);
                            expected[at] = if i + j < N {
                                add(expected[at], term, p)
                            } else {
                                sub(expected[at], term, p)
                            };
                        }
                    }
                }
                assert_eq!(c.products[component][basis], expected);
            }
        }
        Ok(())
    }
}
