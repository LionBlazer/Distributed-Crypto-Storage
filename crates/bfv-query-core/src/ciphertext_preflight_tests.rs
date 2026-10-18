//! Public, non-secret ciphertext fixtures at the Core SDK-decoding boundary.
use super::*;

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
fn variable_time(mut polynomial: Vec<u8>, enabled: bool) -> Vec<u8> {
    let without_flag = bfv_ciphertext_wire::PACKED_POLYNOMIAL_BYTES + 9;
    if polynomial.len() == without_flag + 2 {
        assert!(polynomial.ends_with(&[32, 1]));
        polynomial.truncate(without_flag);
    } else {
        assert_eq!(polynomial.len(), without_flag);
    }
    if enabled {
        polynomial.extend([32, 1]);
    }
    polynomial
}

#[test]
fn actual_sdk_seeded_unseeded_and_both_variable_time_policies_keep_full_plaintext() {
    let parameters = official_parameters().unwrap();
    let key = SecretKey::random(&parameters, &mut rand::rng());
    let plaintext =
        Plaintext::try_encode(&[1u64, 114688, 73][..], Encoding::simd(), &parameters).unwrap();
    let seeded: Ciphertext = key.try_encrypt(&plaintext, &mut rand::rng()).unwrap();
    let unseeded = Ciphertext::new(seeded.iter().cloned().collect(), &parameters).unwrap();
    let seeded_proto = fhe::proto::bfv::Ciphertext::from(&seeded);
    let unseeded_proto = fhe::proto::bfv::Ciphertext::from(&unseeded);
    assert_eq!(seeded_proto.c.len(), 1);
    assert_eq!(seeded_proto.seed.len(), 32);
    assert_eq!(unseeded_proto.c.len(), 2);
    let mut expected = vec![0u64; DEGREE];
    expected[..3].copy_from_slice(&[1, 114688, 73]);
    let check = |wire: &[u8]| {
        let decoded = checked_ciphertext(wire, &parameters).unwrap();
        assert_eq!(decoded.to_bytes(), wire);
        let plaintext = key.try_decrypt(&decoded).unwrap();
        let actual = Vec::<u64>::try_decode(&plaintext, Encoding::simd()).unwrap();
        assert_eq!(actual, expected); // ALL8192 values, including the zero tail.
    };
    for first in [false, true] {
        let p = variable_time(seeded_proto.c[0].clone(), first);
        check(&envelope(
            std::slice::from_ref(&p),
            Some(&seeded_proto.seed),
        ));
        for second in [false, true] {
            check(&envelope(
                &[
                    variable_time(unseeded_proto.c[0].clone(), first),
                    variable_time(unseeded_proto.c[1].clone(), second),
                ],
                None,
            ));
        }
    }
}

#[test]
fn public_projection_rejects_tiny_polynomial_amplification_under_valid_metadata() {
    // Exact historical bomb: each tiny NttShoup record is valid for degree8, but
    // must never reach an SDK decoder that would expand it against the N8192 context.
    let tiny = vec![8, 3, 16, 8, 26, 218, 1];
    let mut polynomial = tiny;
    polynomial.resize(polynomial.len() + 218, 0);
    let bomb = envelope(&vec![polynomial; 2299], None);
    assert_eq!(bomb.len(), 524172);
    assert!(bomb.len() < bfv_ciphertext_wire::MAX_CIPHERTEXT_BYTES);
    let parameters = official_parameters().unwrap();
    assert!(matches!(
        checked_ciphertext(&bomb, &parameters),
        Err(Error::InvalidShape)
    ));

    // Public setup and query metadata are independently valid; malformed CT is
    // the failing boundary, not an absent parameter/setup/context shortcut.
    let setup =
        PublicSetup::from_public_material(Geometry::Rows16, &parameters.to_bytes(), &[], &[])
            .unwrap();
    let evaluator =
        PublicUpdateEvaluator::from_parameters(&setup.update_parameters().unwrap()).unwrap();
    let context = QueryContext::new([29; 16], [31; HEAD_BYTES], [37; HEAD_BYTES]);
    assert!(matches!(
        evaluator.encode_public_select(context, RowProjection::AgeAmount, &bomb),
        Err(Error::InvalidShape)
    ));
}
