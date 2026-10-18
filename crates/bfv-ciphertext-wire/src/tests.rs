//! Public, non-secret byte fixtures; no SDK or encrypted computation is used here.
use super::*;
use bfv_fixed_geometry::{DEGREE, MODULI};

fn varint(mut value: usize, output: &mut Vec<u8>) {
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        output.push(byte | if value == 0 { 0 } else { 128 });
        if value == 0 {
            break;
        }
    }
}
fn polynomial(degree: usize, representation: u8, variable_time: bool) -> Vec<u8> {
    let mut bytes = vec![8, representation, 16];
    varint(degree, &mut bytes);
    bytes.push(26);
    let packed = degree * (43 + 43 + 44 + 44 + 44) / 8;
    varint(packed, &mut bytes);
    bytes.resize(bytes.len() + packed, 0);
    if variable_time {
        bytes.extend([32, 1]);
    }
    bytes
}
fn envelope(polynomials: &[Vec<u8>], seed: Option<&[u8]>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for polynomial in polynomials {
        bytes.push(10);
        varint(polynomial.len(), &mut bytes);
        bytes.extend(polynomial);
    }
    if let Some(seed) = seed {
        bytes.push(18);
        varint(seed.len(), &mut bytes);
        bytes.extend(seed);
    }
    bytes
}
fn set_residue(polynomial: &mut [u8], modulus_index: usize, index: usize, value: u64) {
    let packed_start = polynomial.len() - PACKED_POLYNOMIAL_BYTES;
    let preceding_bits: usize = MODULI[..modulus_index]
        .iter()
        .map(|q| (u64::BITS - (q - 1).leading_zeros()) as usize * DEGREE)
        .sum();
    let width = (u64::BITS - (MODULI[modulus_index] - 1).leading_zeros()) as usize;
    for bit in 0..width {
        let at = preceding_bits + index * width + bit;
        let mask = 1 << (at % 8);
        let byte = &mut polynomial[packed_start + at / 8];
        *byte &= !mask;
        if value & (1 << bit) != 0 {
            *byte |= mask;
        }
    }
}

#[test]
fn fixed_seeded_and_unseeded_forms_preserve_both_variable_time_policies() {
    for first in [false, true] {
        let p = polynomial(DEGREE, 2, first);
        assert_eq!(
            validate(&envelope(std::slice::from_ref(&p), Some(&[0; 32]))),
            Ok(())
        );
        for second in [false, true] {
            let wire = envelope(&[p.clone(), polynomial(DEGREE, 2, second)], None);
            assert_eq!(validate(&wire), Ok(()));
            assert!(wire.len() <= MAX_CANONICAL_UNSEEDED_BYTES);
        }
    }
    assert_eq!(PACKED_POLYNOMIAL_BYTES, 223232);
    assert_eq!(MAX_CANONICAL_UNSEEDED_BYTES, 446494);
}

#[test]
fn first_and_final_residues_of_every_modulus_have_exact_canonical_bounds() {
    let zero = polynomial(DEGREE, 2, false);
    let mut boundary = zero.clone();
    for (lane, q) in MODULI.into_iter().enumerate() {
        for index in [0, DEGREE - 1] {
            set_residue(&mut boundary, lane, index, q - 1);
        }
    }
    assert_eq!(
        validate(&envelope(std::slice::from_ref(&boundary), Some(&[7; 32]))),
        Ok(())
    );
    assert_eq!(validate(&envelope(&[zero.clone(), boundary], None)), Ok(()));
    for (lane, q) in MODULI.into_iter().enumerate() {
        for index in [0, DEGREE - 1] {
            let mut bad = zero.clone();
            set_residue(&mut bad, lane, index, q);
            for seeded in [true, false] {
                let wire = if seeded {
                    envelope(std::slice::from_ref(&bad), Some(&[7; 32]))
                } else {
                    envelope(&[zero.clone(), bad.clone()], None)
                };
                assert_eq!(
                    validate(&wire),
                    Err(WireError::InvalidEncoding),
                    "lane {lane}, index {index}, seeded {seeded}"
                );
            }
        }
    }
}

#[test]
fn many_tiny_polynomials_are_rejected_without_any_sdk_dependency() {
    // The actual historical amplification input fits the byte cap. An SDK decoder
    // would expand these degree8/NttShoup records against its N8192 context.
    let tiny = polynomial(8, 3, false);
    let wire = envelope(&vec![tiny; 2299], None);
    assert_eq!(wire.len(), 524172);
    assert!(wire.len() < MAX_CIPHERTEXT_BYTES);
    assert_eq!(validate(&wire), Err(WireError::InvalidEncoding));
}

#[test]
fn count_seed_degree_representation_and_noncanonical_fields_reject() {
    let p = polynomial(DEGREE, 2, false);
    assert!(validate(&envelope(&[], None)).is_err());
    assert!(validate(&envelope(std::slice::from_ref(&p), None)).is_err());
    assert!(validate(&envelope(&[p.clone(), p.clone()], Some(&[0; 32]))).is_err());
    for length in [0, 1, 31, 33] {
        assert!(validate(&envelope(std::slice::from_ref(&p), Some(&vec![0; length]))).is_err());
    }
    for degree in [0, 8, 8191, 16384] {
        let wire = envelope(&[polynomial(degree, 2, false)], Some(&[0; 32]));
        assert!(validate(&wire).is_err());
    }
    for representation in [0, 1, 3, 255] {
        let wire = envelope(&[polynomial(DEGREE, representation, false)], Some(&[0; 32]));
        assert!(validate(&wire).is_err());
    }
    for suffix in [[32, 0], [32, 2], [40, 1], [8, 2]] {
        let mut bad = p.clone();
        bad.extend(suffix);
        assert!(validate(&envelope(&[bad], Some(&[0; 32]))).is_err());
    }
    let valid = envelope(std::slice::from_ref(&p), Some(&[0; 32]));
    for suffix in [
        vec![24, 0],
        vec![24, 1],
        vec![18, 0],
        vec![32, 1],
        vec![128],
    ] {
        let mut bad = valid.clone();
        bad.extend(suffix);
        assert!(validate(&bad).is_err());
    }
}

#[test]
fn nonminimal_overflowing_truncated_and_oversized_lengths_reject() {
    let p = polynomial(DEGREE, 2, false);
    let mut overlong = p.clone();
    overlong.splice(3..5, [128, 192, 0]);
    assert!(validate(&envelope(&[overlong], Some(&[0; 32]))).is_err());
    let mut overflow = vec![10];
    overflow.extend([255; 9]);
    overflow.push(1);
    assert_eq!(validate(&overflow), Err(WireError::InvalidEncoding));
    let mut invalid_u64 = vec![10];
    invalid_u64.extend([255; 9]);
    invalid_u64.push(2);
    assert_eq!(validate(&invalid_u64), Err(WireError::InvalidEncoding));
    let valid = envelope(std::slice::from_ref(&p), Some(&[0; 32]));
    for length in [0, 1, 2, 3, 4, 10, p.len(), valid.len() - 1] {
        assert!(validate(&valid[..length]).is_err());
    }
    assert_eq!(
        validate(&vec![0; MAX_CIPHERTEXT_BYTES + 1]),
        Err(WireError::ResourceLimit)
    );
}
