//! Complete public-vector routing for level0/0 relinearization, without arithmetic
//! evaluation, representation conversion or proof/admission authority.
use crate::{DEGREE, Error, MODULI, Request, Result, Role, decode_request, encode_request};

const BASES: usize = MODULI.len();

/// Assemble the five natural-order PowerBasis c2 rows for the existing Embed role.
/// The caller supplies the independent binding and keyset labels; the canonical
/// codec checks all dimensions and residues without evaluating the relation.
pub fn embed_request(
    binding: [u8; 32],
    keyset_context: [u8; 32],
    inverse_c2: &[u64],
) -> Result<Request> {
    decode_request(&encode_request(
        Role::Embed,
        binding,
        keyset_context,
        inverse_c2,
    )?)
}

/// Borrow Embed row 5*source+target, still PowerBasis. Exact 25N geometry and
/// bounded indices are checked before slicing, then every selected-row residue
/// is checked against q_target. Other rows are not read or certified here.
pub fn digit_row(embedded: &[u64], source: usize, target: usize) -> Result<&[u64]> {
    if embedded.len() != Role::Embed.output_coefficients() || source >= BASES || target >= BASES {
        return Err(Error::Shape);
    }
    let start = (BASES * source + target) * DEGREE;
    let row = &embedded[start..start + DEGREE];
    if row.iter().any(|&value| value >= MODULI[target]) {
        return Err(Error::NonCanonicalResidue);
    }
    Ok(row)
}

/// Assemble the existing MAC request in target-major blocks of 17 complete NTT
/// rows: O0,O1,D0..D4,K00..K04,K10..K14. Digits are source-major25N; each key
/// component/decomposition slice and each original contains five ordered Q rows.
/// No NTT, multiplication, key derivation or edge-proof verification runs here.
pub fn mac_request(
    binding: [u8; 32],
    keyset_context: [u8; 32],
    originals: [&[u64]; 2],
    digits: &[u64],
    key_rows: [[&[u64]; 5]; 2],
) -> Result<Request> {
    let component_length = Role::Embed.input_coefficients();
    if originals.iter().any(|row| row.len() != component_length)
        || digits.len() != Role::Embed.output_coefficients()
        || key_rows
            .iter()
            .flatten()
            .any(|row| row.len() != component_length)
    {
        return Err(Error::Shape);
    }
    let mut values = Vec::with_capacity(Role::AccumulateAndAdd.input_coefficients());
    for target in 0..BASES {
        let range = target * DEGREE..(target + 1) * DEGREE;
        for original in originals {
            values.extend_from_slice(&original[range.clone()]);
        }
        for source in 0..BASES {
            let row = BASES * source + target;
            values.extend_from_slice(&digits[row * DEGREE..(row + 1) * DEGREE]);
        }
        for component in key_rows {
            for decomposition in component {
                values.extend_from_slice(&decomposition[range.clone()]);
            }
        }
    }
    decode_request(&encode_request(
        Role::AccumulateAndAdd,
        binding,
        keyset_context,
        &values,
    )?)
}

/// Validate all 10 target-major canonical NTT rows and copy row2*target+component
/// into two component-major Q5 arrays (equivalently row5*component+target).
/// The result remains native NTT, never a PowerBasis ciphertext-wire encoding.
pub fn component_outputs(accumulated: &[u64]) -> Result<[Vec<u64>; 2]> {
    if accumulated.len() != Role::AccumulateAndAdd.output_coefficients() {
        return Err(Error::Shape);
    }
    for (row, &modulus) in accumulated
        .as_chunks::<DEGREE>()
        .0
        .iter()
        .zip(Role::AccumulateAndAdd.output_moduli())
    {
        if row.iter().any(|&value| value >= modulus) {
            return Err(Error::NonCanonicalResidue);
        }
    }
    let mut output: [Vec<u64>; 2] = core::array::from_fn(|_| Vec::with_capacity(BASES * DEGREE));
    for (component, values) in output.iter_mut().enumerate() {
        for target in 0..BASES {
            let row = 2 * target + component;
            values.extend_from_slice(&accumulated[row * DEGREE..(row + 1) * DEGREE]);
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests;
