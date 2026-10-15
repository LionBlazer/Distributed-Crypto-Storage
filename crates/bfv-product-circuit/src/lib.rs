//! Exact BFV ciphertext-by-public-plaintext multiplication on canonical NTT residues.
//! This arithmetic is an input to a separate proof system, never a proof by itself.
#![forbid(unsafe_code)]

pub use bfv_linear_circuit::{COEFFICIENTS, DEGREE, MODULI};
const HEADER_BYTES: usize = 8 + 32;
pub const REQUEST_BYTES: usize = HEADER_BYTES + 2 * COEFFICIENTS * 8;
pub const OUTPUT_BYTES: usize = HEADER_BYTES + COEFFICIENTS * 8;
const REQUEST_MAGIC: &[u8; 8] = b"BFVPMUQ1";
const OUTPUT_MAGIC: &[u8; 8] = b"BFVPMUR1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Shape,
    NonCanonicalResidue,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BFV product circuit rejected {self:?}")
    }
}
impl std::error::Error for Error {}

/// Encodes both complete public operands, ordered component/modulus/coefficient.
/// For ct-by-pt operations the plaintext NTT polynomial is repeated for both components.
/// The trusted verifier must independently derive both operands and bind their digest.
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

/// Multiplies every component coefficient by its public plaintext NTT residue.
/// The full product is below 2^88 and is reduced with u128 arithmetic, without
/// field-wrap assumptions, secret keys, plaintext row data, or reduced parameters.
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
        .zip(right.as_chunks::<8>().0)
        .enumerate()
    {
        let a = u64::from_le_bytes(*a);
        let b = u64::from_le_bytes(*b);
        let q = modulus(index);
        if a >= q || b >= q {
            return Err(Error::NonCanonicalResidue);
        }
        let result = ((a as u128 * b as u128) % q as u128) as u64;
        output.extend_from_slice(&result.to_le_bytes());
    }
    Ok(output)
}

/// Validates only the fixed output representation, never its arithmetic correctness.
pub fn decode_output(output: &[u8]) -> Result<([u8; 32], Vec<u64>), Error> {
    if output.len() != OUTPUT_BYTES || &output[..8] != OUTPUT_MAGIC {
        return Err(Error::Shape);
    }
    let binding = output[8..HEADER_BYTES]
        .try_into()
        .map_err(|_| Error::Shape)?;
    let mut coefficients = Vec::with_capacity(COEFFICIENTS);
    for (index, bytes) in output[HEADER_BYTES..].as_chunks::<8>().0.iter().enumerate() {
        let value = u64::from_le_bytes(*bytes);
        if value >= modulus(index) {
            return Err(Error::NonCanonicalResidue);
        }
        coefficients.push(value);
    }
    Ok((binding, coefficients))
}

fn modulus(index: usize) -> u64 {
    MODULI[(index / DEGREE) % MODULI.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_moduli_and_components_reduce_products_beyond_u64_without_losing_binding() {
        let left: Vec<_> = (0..COEFFICIENTS).map(|i| modulus(i) - 1).collect();
        let request = encode_request([9; 32], &left, &left).unwrap();

        let (binding, actual) = decode_output(&evaluate(&request).unwrap()).unwrap();

        assert_eq!(binding, [9; 32]);
        assert_eq!(actual, vec![1; COEFFICIENTS]);
    }

    #[test]
    fn malformed_and_noncanonical_inputs_are_rejected_for_both_complete_operands() {
        let zeros = vec![0; COEFFICIENTS];
        let valid = encode_request([2; 32], &zeros, &zeros).unwrap();
        assert_eq!(evaluate(&[]), Err(Error::Shape));
        assert_eq!(evaluate(&valid[..valid.len() - 1]), Err(Error::Shape));
        let mut trailing = valid.clone();
        trailing.push(0);
        assert_eq!(evaluate(&trailing), Err(Error::Shape));
        let mut magic = valid.clone();
        magic[0] ^= 1;
        assert_eq!(evaluate(&magic), Err(Error::Shape));
        for operand in 0..2 {
            for index in [0, COEFFICIENTS - 1] {
                let mut changed = valid.clone();
                let offset = HEADER_BYTES + (operand * COEFFICIENTS + index) * 8;
                changed[offset..offset + 8].copy_from_slice(&modulus(index).to_le_bytes());
                assert_eq!(evaluate(&changed), Err(Error::NonCanonicalResidue));
            }
        }
        assert_eq!(
            encode_request([0; 32], &zeros[..1], &zeros),
            Err(Error::Shape)
        );
    }

    #[test]
    fn output_codec_rejects_wrong_domains_trailing_bytes_and_last_residue_overflow() {
        let zeros = vec![0; COEFFICIENTS];
        let valid = evaluate(&encode_request([2; 32], &zeros, &zeros).unwrap()).unwrap();
        let mut changed = valid.clone();
        changed[0] ^= 1;
        assert_eq!(decode_output(&changed), Err(Error::Shape));
        let mut changed = valid.clone();
        changed.push(0);
        assert_eq!(decode_output(&changed), Err(Error::Shape));
        let mut changed = valid;
        let offset = HEADER_BYTES + (COEFFICIENTS - 1) * 8;
        changed[offset..offset + 8].copy_from_slice(&modulus(COEFFICIENTS - 1).to_le_bytes());
        assert_eq!(decode_output(&changed), Err(Error::NonCanonicalResidue));
    }
}
