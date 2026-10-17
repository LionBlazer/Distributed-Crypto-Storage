//! Owning public codec/range controls. Full upstream SDK parity belongs to the proof consumer.
use super::*;
fn zero(role: Role) -> Request {
    decode_request(&encode_request(role, [0x31; 32], &vec![0; role.input_coefficients()]).unwrap())
        .unwrap()
}
#[test]
fn fixed_request_codec_preserves_every_residue_and_rejects_headers_lengths_and_modulus_aliases() {
    for role in [Role::Extend5To10, Role::Scale10To5] {
        let mut input = vec![0; role.input_coefficients()];
        for (i, &p) in role.input_moduli().iter().enumerate() {
            input[i * DEGREE] = p - 1;
            input[(i + 1) * DEGREE - 1] = 1;
        }
        let wire = encode_request(role, [7; 32], &input).unwrap();
        let request = decode_request(&wire).unwrap();
        assert_eq!(request.input(), input);
        assert_eq!(request.binding(), [7; 32]);
        assert_eq!(request.encode(), wire);
        for pos in [0, 8, 72, 73, 74] {
            let mut bad = wire.clone();
            bad[pos] ^= 128;
            assert!(decode_request(&bad).is_err());
        }
        assert!(decode_request(&wire[..wire.len() - 1]).is_err());
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(decode_request(&trailing).is_err());
        for (i, &p) in role.input_moduli().iter().enumerate() {
            let mut bad = wire.clone();
            let at = 80 + ((i + 1) * DEGREE - 1) * 8;
            bad[at..at + 8].copy_from_slice(&p.to_le_bytes());
            assert!(matches!(
                decode_request(&bad),
                Err(Error::NonCanonicalResidue)
            ));
        }
    }
}
#[test]
fn zero_evaluation_has_full_role_shape_and_canonical_public_auxiliary_roundtrip() {
    for role in [Role::Extend5To10, Role::Scale10To5] {
        let r = zero(role);
        let e = evaluate_with_certificate(&r).unwrap();
        assert_eq!(e.output.coefficients(), vec![0; role.output_coefficients()]);
        let output = e.output.encode();
        let aux = e.aux.encode();
        assert_eq!(output.len(), role.output_bytes());
        assert_eq!(aux.len(), role.aux_bytes());
        assert_eq!(decode_output(&output).unwrap().encode(), output);
        assert_eq!(decode_aux(&aux).unwrap().encode(), aux);
        assert_eq!(e.aux.rows().len(), DEGREE);
        codec::check_binding(&r, &e.output, &e.aux).unwrap();
        assert!(decode_output(&output[..output.len() - 1]).is_err());
        assert!(decode_aux(&aux[..aux.len() - 1]).is_err());
        let mut tail = aux.clone();
        tail.push(0);
        assert!(decode_aux(&tail).is_err());
    }
}
#[test]
fn extension_copies_all_original_rows_and_scales_the_last_negative_one_into_every_new_modulus() {
    let role = Role::Extend5To10;
    let mut input = vec![0; role.input_coefficients()];
    for (i, &p) in MODULI.iter().enumerate() {
        input[(i + 1) * DEGREE - 1] = p - 1;
    }
    let r = decode_request(&encode_request(role, [1; 32], &input).unwrap()).unwrap();
    let e = evaluate_with_certificate(&r).unwrap();
    assert_eq!(&e.output.coefficients()[..input.len()], input);
    for (i, &p) in AUXILIARY_MODULI.iter().enumerate() {
        let row = &e.output.coefficients()[(5 + i) * DEGREE..(6 + i) * DEGREE];
        assert!(row[..DEGREE - 1].iter().all(|&x| x == 0));
        assert_eq!(row[DEGREE - 1], p - 1);
    }
}
#[test]
fn exact_sdk_approximate_garner_rounding_is_not_replaced_by_an_ideal_centered_crt_quotient() {
    let role = Role::Extend5To10;
    let rests = [
        4398046429184,
        4398046396416,
        8796093014016,
        8796092719104,
        8796092358656,
    ];
    let mut input = vec![0; role.input_coefficients()];
    for (i, &v) in rests.iter().enumerate() {
        input[i * DEGREE + DEGREE - 1] = v;
    }
    let r = decode_request(&encode_request(role, [2; 32], &input).unwrap()).unwrap();
    let e = evaluate_with_certificate(&r).unwrap();
    // Analytical fixed vector x=floor(Q/2). This is the pinned SDK algorithm's
    // approximate quotient, not an assertion that the SDK has a native defect.
    assert_eq!(e.aux.rows()[DEGREE - 1].v, 22491303157761);
    assert_ne!(e.aux.rows()[DEGREE - 1].v, 22491303157760);
    assert_eq!(constants(role).garner_shift(), 127);
    assert_eq!(constants(Role::Scale10To5).garner_shift(), 125);
    assert!(constants(role).theta().iter().all(|t| t.magnitude == 0));
}
#[test]
fn signed_theta_rounding_ties_go_to_positive_infinity_on_both_sides_of_zero() {
    use ethnum::I256;
    let h = I256::from(1u128 << 126);
    for (input, expected) in [
        (-h - I256::ONE, -1),
        (-h, 0),
        (-h + I256::ONE, 0),
        (h - I256::ONE, 0),
        (h, 1),
        (h + I256::ONE, 1),
    ] {
        assert_eq!(math::rounded_w(input), I256::from(expected));
    }
}
#[test]
fn canonical_auxiliary_high_bits_and_inexact_frame_sizes_reject_before_gold_conversion() {
    for role in [Role::Extend5To10, Role::Scale10To5] {
        let e = evaluate_with_certificate(&zero(role)).unwrap();
        let wire = e.aux.encode();
        let h = constants(role).garner_shift();
        for (offset, mask) in [
            (8 + h / 8, 1u8 << (h % 8)),
            (29, 64),
            (45, 128),
            (54, 4),
            (94, 2),
        ] {
            let mut bad = wire.clone();
            bad[144 + offset] |= mask;
            assert!(
                matches!(decode_aux(&bad), Err(Error::AuxiliaryRange)),
                "role{role:?} field{offset}"
            );
        }
        let mut wrong = wire.clone();
        wrong[73] = 2;
        assert!(decode_aux(&wrong).is_err());
    }
}
#[test]
fn changed_binding_output_and_copied_prefix_cannot_be_relabelled_as_another_request() {
    let r = zero(Role::Extend5To10);
    let mut e = evaluate_with_certificate(&r).unwrap();
    let other = decode_request(&encode_request(r.role(), [9; 32], r.input()).unwrap()).unwrap();
    assert_eq!(
        codec::check_binding(&other, &e.output, &e.aux),
        Err(Error::Binding)
    );
    // Even coherent public digest rebinding cannot alter a copied Q row.
    e.output.coefficients[DEGREE - 1] = 1;
    e.aux.output_digest = codec::digest(&e.output.encode());
    assert_eq!(
        codec::check_binding(&r, &e.output, &e.aux),
        Err(Error::Binding)
    );
}
#[cfg(feature = "plonky3")]
#[test]
fn shape_only_air_has_no_preprocessed_authority_and_rebuilt_last_word_forgery_fails_the_limb_relation()
 {
    use p3_air::{BaseAir, check_all_constraints};
    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks as F;
    use p3_matrix::dense::RowMajorMatrix;
    let r = zero(Role::Scale10To5);
    let mut e = evaluate_with_certificate(&r).unwrap();
    let shape = plonky3::ScaleAir::shape(r.role());
    assert!(!shape.is_prepared());
    assert!(shape.preprocessed_trace().is_none());
    assert_eq!(shape.preprocessed_width(), 164);
    let (air, pv) = plonky3::prepare(&r, &e.output, &e.aux)
        .unwrap()
        .into_parts();
    let trace = RowMajorMatrix::new(vec![F::ZERO; DEGREE], 1);
    assert!(air.is_prepared());
    assert!(check_all_constraints(&air, &trace, &pv, Some(1)).is_ok());
    drop(air);
    e.output.coefficients[5 * DEGREE - 1] = 1;
    e.aux.output_digest = codec::digest(&e.output.encode());
    let (wrong, pv) = plonky3::prepare(&r, &e.output, &e.aux)
        .unwrap()
        .into_parts();
    assert!(!check_all_constraints(&wrong, &trace, &pv, Some(1)).is_ok());
}
