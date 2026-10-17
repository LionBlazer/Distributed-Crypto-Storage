//! The exact linear BFV ciphertext-addition circuit, on canonical level-zero NTT residues.
//! This is arithmetic to be proved by a separate proof system, never a proof by itself.
#![forbid(unsafe_code)]

pub use bfv_fixed_geometry::{DEGREE, MODULI};
/// Two ciphertext components, then modulus-major and coefficient-major order.
pub const COEFFICIENTS: usize = 2 * MODULI.len() * DEGREE;
const HEADER_BYTES: usize = 8 + 32;
pub const REQUEST_BYTES: usize = HEADER_BYTES + 2 * COEFFICIENTS * 8;
pub const OUTPUT_BYTES: usize = HEADER_BYTES + COEFFICIENTS * 8;
const REQUEST_MAGIC: &[u8; 8] = b"BFVLADQ1";
const OUTPUT_MAGIC: &[u8; 8] = b"BFVLADR1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Shape,
    NonCanonicalResidue,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BFV linear circuit rejected {self:?}")
    }
}
impl std::error::Error for Error {}

/// Creates the complete public circuit input from two genuine BFV ciphertexts.
/// The caller must independently bind its digest, not trust a prover-supplied input.
pub fn encode_request(binding: [u8; 32], left: &[u64], right: &[u64]) -> Result<Vec<u8>, Error> {
    if left.len() != COEFFICIENTS || right.len() != COEFFICIENTS {
        return Err(Error::Shape);
    }
    let mut wire = Vec::with_capacity(REQUEST_BYTES);
    wire.extend_from_slice(REQUEST_MAGIC);
    wire.extend_from_slice(&binding);
    for coefficients in [left, right] {
        for (index, value) in coefficients.iter().enumerate() {
            if *value >= modulus(index) {
                return Err(Error::NonCanonicalResidue);
            }
            wire.extend_from_slice(&value.to_le_bytes());
        }
    }
    Ok(wire)
}

/// Adds every residue of both components, modulo its original coefficient modulus.
/// NTT is linear, so this is precisely BFV ciphertext addition in NTT representation.
/// No slot plaintext, secret key, reduced security parameters, or answer fixture is used.
pub fn evaluate(request: &[u8]) -> Result<Vec<u8>, Error> {
    if request.len() != REQUEST_BYTES || &request[..8] != REQUEST_MAGIC {
        return Err(Error::Shape);
    }
    let mut output = Vec::with_capacity(OUTPUT_BYTES);
    output.extend_from_slice(OUTPUT_MAGIC);
    output.extend_from_slice(&request[8..HEADER_BYTES]);
    let (left, right) = request[HEADER_BYTES..].split_at(COEFFICIENTS * 8);
    for (index, (a, b)) in left
        .as_chunks::<8>()
        .0
        .iter()
        .zip(right.as_chunks::<8>().0.iter())
        .enumerate()
    {
        let a = residue(a);
        let b = residue(b);
        let q = modulus(index);
        if a >= q || b >= q {
            return Err(Error::NonCanonicalResidue);
        }
        // Both operands are < q < 2^44: no u64 overflow and at most one subtraction.
        let sum = a + b;
        let reduced = if sum >= q { sum - q } else { sum };
        output.extend_from_slice(&reduced.to_le_bytes());
    }
    Ok(output)
}

/// Fully validates the output representation; it does not prove the addition.
/// Returned residues can be reconstructed as a ciphertext only after proof verification.
pub fn decode_output(output: &[u8]) -> Result<([u8; 32], Vec<u64>), Error> {
    if output.len() != OUTPUT_BYTES || &output[..8] != OUTPUT_MAGIC {
        return Err(Error::Shape);
    }
    let binding = output[8..HEADER_BYTES]
        .try_into()
        .map_err(|_| Error::Shape)?;
    let mut coefficients = Vec::with_capacity(COEFFICIENTS);
    for (index, chunk) in output[HEADER_BYTES..].as_chunks::<8>().0.iter().enumerate() {
        let value = residue(chunk);
        if value >= modulus(index) {
            return Err(Error::NonCanonicalResidue);
        }
        coefficients.push(value);
    }
    Ok((binding, coefficients))
}

fn residue(bytes: &[u8; 8]) -> u64 {
    u64::from_le_bytes(*bytes)
}
fn modulus(index: usize) -> u64 {
    MODULI[(index / DEGREE) % MODULI.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn additions_wrap_in_each_modulus_and_preserve_the_bound_request_identity() {
        let left: Vec<_> = (0..COEFFICIENTS).map(|i| modulus(i) - 1).collect();
        let right = vec![1; COEFFICIENTS];
        let request = encode_request([3; 32], &left, &right).unwrap();

        let output = evaluate(&request).unwrap();

        let (binding, values) = decode_output(&output).unwrap();
        assert_eq!(binding, [3; 32]);
        assert_eq!(values, vec![0; COEFFICIENTS]);
    }

    #[test]
    fn malformed_lengths_magic_and_noncanonical_residues_never_produce_a_result() {
        let zeros = vec![0; COEFFICIENTS];
        let valid = encode_request([4; 32], &zeros, &zeros).unwrap();
        assert_eq!(evaluate(&[]), Err(Error::Shape));
        assert_eq!(evaluate(&valid[..valid.len() - 1]), Err(Error::Shape));
        let mut extra = valid.clone();
        extra.push(0);
        assert_eq!(evaluate(&extra), Err(Error::Shape));
        let mut bad_magic = valid.clone();
        bad_magic[0] ^= 1;
        assert_eq!(evaluate(&bad_magic), Err(Error::Shape));
        for offset in [HEADER_BYTES, HEADER_BYTES + COEFFICIENTS * 8] {
            let mut noncanonical = valid.clone();
            noncanonical[offset..offset + 8].copy_from_slice(&MODULI[0].to_le_bytes());
            assert_eq!(evaluate(&noncanonical), Err(Error::NonCanonicalResidue));
        }
        assert_eq!(encode_request([0; 32], &[], &zeros), Err(Error::Shape));
    }

    #[test]
    fn output_decoding_rejects_noncanonical_values_and_trailing_bytes() {
        let zeros = vec![0; COEFFICIENTS];
        let mut output = evaluate(&encode_request([1; 32], &zeros, &zeros).unwrap()).unwrap();
        output[HEADER_BYTES..HEADER_BYTES + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(decode_output(&output), Err(Error::NonCanonicalResidue));
        output.push(0);
        assert_eq!(decode_output(&output), Err(Error::Shape));
    }
}
