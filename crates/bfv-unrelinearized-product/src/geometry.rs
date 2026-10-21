//! Closed public N4096/Q2/P2 geometry for an experimental un-relinearized product.
use crate::{Error, Result};
pub const N: usize = 4096;
pub const Q: [u64; 2] = [1073692673, 1073668097];
pub const P: [u64; 2] = [4611686018427322369, 4611686018427289601];
pub const QP: [u64; 4] = [Q[0], Q[1], P[0], P[1]];
pub const T: u64 = 65537;

/// Checks every natural PowerBasis coefficient; no omitted high or final coefficient.
pub(crate) fn validate_polynomials(values: &[Vec<u64>], moduli: &[u64]) -> Result<()> {
    if values.len() != moduli.len() {
        return Err(Error::Shape);
    }
    for (row, &q) in values.iter().zip(moduli) {
        if row.len() != N {
            return Err(Error::Shape);
        }
        if row.iter().any(|&value| value >= q) {
            return Err(Error::Arithmetic);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn geometry_matches_pinned_sdk_prime_generator_and_context() {
        use fhe::bfv::BfvParametersBuilder;
        use fhe_math::zq::primes::generate_prime;
        let parameters = BfvParametersBuilder::new()
            .set_degree(N)
            .set_plaintext_modulus(T)
            .set_moduli_sizes(&[30, 30])
            .set_variance(10)
            .build_arc()
            .unwrap();
        assert_eq!(parameters.moduli(), Q);
        let first = generate_prime(62, 2 * N as u64, 1 << 62).unwrap();
        let second = generate_prime(62, 2 * N as u64, first).unwrap();
        assert_eq!([first, second], P);
        assert_eq!(
            (parameters.moduli_sizes().iter().sum::<usize>() + 60).div_ceil(62),
            2
        );
    }
    #[test]
    fn noncanonical_last_coefficients_and_inexact_shapes_reject() {
        let mut values = QP.iter().map(|&p| vec![p - 1; N]).collect::<Vec<_>>();
        validate_polynomials(&values, &QP).unwrap();
        for basis in 0..QP.len() {
            values[basis][N - 1] = QP[basis];
            assert!(validate_polynomials(&values, &QP).is_err());
            values[basis][N - 1] = QP[basis] - 1;
        }
        values[3].pop();
        assert!(validate_polynomials(&values, &QP).is_err());
    }
}
