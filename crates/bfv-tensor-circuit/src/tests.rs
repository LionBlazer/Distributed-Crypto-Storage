//! Owning examples of fixed public tensor framing and arithmetic. No participant secrets.
use super::*;
fn request(index: u8, input: &[u64]) -> Request {
    decode_request(&encode_request(Basis::new(index).unwrap(), [0x61; 32], input).unwrap()).unwrap()
}
fn zero(index: u8) -> Request {
    request(index, &vec![0; 4 * DEGREE])
}
fn golden(index: u8) -> Request {
    let p = Basis::new(index).unwrap().modulus();
    let mut input = vec![0; 4 * DEGREE];
    for (i, v) in [2, 3, 5, 7].into_iter().enumerate() {
        input[i * DEGREE] = v;
        input[(i + 1) * DEGREE - 1] = p - 1;
    }
    // Separate both cross terms with asymmetric operand support.
    input[DEGREE - 2] = p - 1;
    input[3 * DEGREE + DEGREE - 2] = p - 1;
    input[DEGREE + DEGREE - 3] = p - 1;
    input[2 * DEGREE + DEGREE - 3] = p - 1;
    request(index, &input)
}
#[test]
fn canonical_request_preserves_all_four_vectors_and_rejects_unknown_tags_lengths_and_modulus_aliases()
 {
    assert!(Basis::new(10).is_err());
    let mut profiles = std::collections::HashSet::new();
    for index in 0..10 {
        let r = golden(index);
        let wire = r.encode();
        assert!(profiles.insert(profile_digest(r.basis())));
        let decoded = decode_request(&wire).unwrap();
        assert_eq!(decoded.input(), r.input());
        assert_eq!(decoded.binding(), [0x61; 32]);
        assert_eq!(decoded.encode(), wire);
        assert_eq!(wire.len(), r.basis().request_bytes());
        for at in [0, 8, 72, 73, 74, 75, 76] {
            let mut bad = wire.clone();
            bad[at] ^= 128;
            assert!(decode_request(&bad).is_err());
        }
        assert!(decode_request(&wire[..wire.len() - 1]).is_err());
        let mut tail = wire.clone();
        tail.push(0);
        assert!(decode_request(&tail).is_err());
        for component in 0..4 {
            let mut alias = wire.clone();
            let at = 80 + ((component + 1) * DEGREE - 1) * 8;
            alias[at..at + 8].copy_from_slice(&r.basis().modulus().to_le_bytes());
            assert!(matches!(
                decode_request(&alias),
                Err(Error::NonCanonicalResidue)
            ));
        }
    }
}
#[test]
fn complete_tensor_golden_has_both_middle_terms_distinct_outer_components_and_all_other_words_zero()
{
    let r = golden(0);
    let e = evaluate_with_certificate(&r).unwrap();
    let output = e.output.coefficients();
    assert_eq!(output.len(), 3 * DEGREE);
    for (component, small) in [10, 29, 21].into_iter().enumerate() {
        let row = &output[component * DEGREE..(component + 1) * DEGREE];
        assert_eq!(row[0], small);
        assert!(row[1..DEGREE - 3].iter().all(|&v| v == 0));
        assert_eq!(row[DEGREE - 3], u64::from(component == 1));
        assert_eq!(row[DEGREE - 2], u64::from(component == 1));
        assert_eq!(row[DEGREE - 1], if component == 1 { 2 } else { 1 });
    }
}
#[test]
fn largest_canonical_inputs_use_exact_high_limbs_and_full_middle_quotient_on_all_ten_moduli() {
    for index in 0..10 {
        let r = golden(index);
        let p = r.basis().modulus();
        let e = evaluate_with_certificate(&r).unwrap();
        assert_eq!(
            e.aux.rows()[DEGREE - 1].quotients(),
            &[p - 2, 2 * p - 4, p - 2]
        );
        for component in 0..3 {
            assert_eq!(
                e.output.coefficients()[(component + 1) * DEGREE - 1],
                if component == 1 { 2 } else { 1 }
            );
        }
    }
}
#[test]
fn complete_zero_output_and_public_auxiliary_roundtrip_have_fixed_canonical_sizes() {
    let r = zero(9);
    let e = evaluate_with_certificate(&r).unwrap();
    let output = e.output.encode();
    let aux = e.aux.encode();
    assert_eq!(output.len(), r.basis().output_bytes());
    assert_eq!(aux.len(), r.basis().aux_bytes());
    assert_eq!(e.aux.rows().len(), DEGREE);
    assert!(e.output.coefficients().iter().all(|&v| v == 0));
    assert!(e.aux.rows().iter().all(|row| *row.quotients() == [0; 3]));
    assert_eq!(decode_output(&output).unwrap().encode(), output);
    assert_eq!(decode_aux(&aux).unwrap().encode(), aux);
    assert!(decode_output(&output[..output.len() - 1]).is_err());
    assert!(decode_aux(&aux[..aux.len() - 1]).is_err());
    let mut tail = aux;
    tail.push(0);
    assert!(decode_aux(&tail).is_err());
}
#[test]
fn every_output_component_rejects_a_modulus_alias_in_its_last_coefficient() {
    let r = zero(9);
    let e = evaluate_with_certificate(&r).unwrap();
    let wire = e.output.encode();
    for component in 0..3 {
        let mut bad = wire.clone();
        let at = 112 + ((component + 1) * DEGREE - 1) * 8;
        bad[at..at + 8].copy_from_slice(&r.basis().modulus().to_le_bytes());
        assert!(matches!(
            decode_output(&bad),
            Err(Error::NonCanonicalResidue)
        ));
    }
    let mut wrong = wire;
    wrong[73] = 1;
    assert!(decode_output(&wrong).is_err());
}
#[test]
fn public_auxiliary_quotient_bounds_and_each_shifted_carry_chain_reject_aliases() {
    let r = zero(9);
    let e = evaluate_with_certificate(&r).unwrap();
    let wire = e.aux.encode();
    let p = r.basis().modulus();
    let base = 144 + (DEGREE - 1) * AUXILIARY_ROW_BYTES;
    for (component, bound) in [p, 2 * p, p].into_iter().enumerate() {
        let mut bad = wire.clone();
        bad[base + 8 * component..base + 8 * component + 8].copy_from_slice(&bound.to_le_bytes());
        assert!(matches!(decode_aux(&bad), Err(Error::AuxiliaryRange)));
    }
    for component in 0..3 {
        let mut bad = wire.clone();
        bad[base + 24 + 28 * component + 3] |= 2;
        assert!(matches!(decode_aux(&bad), Err(Error::AuxiliaryRange)));
    }
}
#[test]
fn another_request_or_changed_complete_operand_cannot_reuse_public_output_and_auxiliary_binding() {
    let r = golden(9);
    let e = evaluate_with_certificate(&r).unwrap();
    let other = decode_request(&encode_request(r.basis(), [0x62; 32], r.input()).unwrap()).unwrap();
    assert_eq!(
        codec::check_binding(&other, &e.output, &e.aux),
        Err(Error::Binding)
    );
    for component in 0..4 {
        let mut input = r.input().to_vec();
        input[(component + 1) * DEGREE - 1] -= 1;
        let changed = request(9, &input);
        assert_eq!(
            codec::check_binding(&changed, &e.output, &e.aux),
            Err(Error::Binding)
        );
    }
}
#[cfg(feature = "plonky3")]
#[test]
fn prepared_full_rows_preserve_every_high_limb_and_shape_alone_cannot_supply_public_preprocessing()
{
    use p3_air::BaseAir;
    use p3_field::{PrimeCharacteristicRing, PrimeField64};
    let r = golden(9);
    let e = evaluate_with_certificate(&r).unwrap();
    let shape = plonky3::TensorAir::shape(r.basis());
    assert!(!shape.is_prepared());
    assert!(shape.preprocessed_trace().is_none());
    assert_eq!(shape.preprocessed_width(), 61);
    let prepared = plonky3::prepare(&r, &e.output, &e.aux).unwrap();
    let row = prepared.coefficient_row(DEGREE - 1).unwrap();
    let integer = |at: usize| {
        row[at..at + 4]
            .iter()
            .enumerate()
            .map(|(i, v)| v.as_canonical_u64() << (16 * i))
            .sum::<u64>()
    };
    let p = r.basis().modulus();
    for component in 0..4 {
        assert_eq!(integer(4 * component), p - 1);
    }
    for (component, expected) in [1, 2, 1].into_iter().enumerate() {
        assert_eq!(integer(16 + 4 * component), expected);
    }
    for (component, expected) in [p - 2, 2 * p - 4, p - 2].into_iter().enumerate() {
        assert_eq!(integer(28 + 4 * component), expected);
    }
    let (air, pv) = prepared.into_parts();
    let trace =
        p3_matrix::dense::RowMajorMatrix::new(vec![p3_goldilocks::Goldilocks::ZERO; DEGREE], 1);
    assert!(p3_air::check_all_constraints(&air, &trace, &pv, Some(1)).is_ok());
}
#[cfg(feature = "plonky3")]
#[test]
fn coherent_canonical_output_quotient_and_carry_forgeries_reach_each_tensor_equation_and_reject() {
    use p3_field::PrimeCharacteristicRing;
    let r = golden(9);
    let original = evaluate_with_certificate(&r).unwrap();
    let trace =
        p3_matrix::dense::RowMajorMatrix::new(vec![p3_goldilocks::Goldilocks::ZERO; DEGREE], 1);
    for component in 0..3 {
        for attack in 0..3 {
            let mut output = original.output.clone();
            let mut aux = original.aux.clone();
            match attack {
                0 => {
                    output.coefficients[(component + 1) * DEGREE - 1] ^= 1;
                    aux.output_digest = codec::digest(&output.encode());
                }
                1 => aux.rows[DEGREE - 1].quotients[component] ^= 1,
                _ => aux.rows[DEGREE - 1].carries[component][6] ^= 1,
            }
            let aux = decode_aux(&aux.encode()).unwrap();
            let (air, pv) = plonky3::prepare(&r, &output, &aux).unwrap().into_parts();
            assert!(
                !p3_air::check_all_constraints(&air, &trace, &pv, Some(1)).is_ok(),
                "component {component}, attack {attack}"
            );
        }
    }
    // Coherent first-cross-term-only output must fail the mandatory second term.
    let mut output = original.output.clone();
    output.coefficients[DEGREE] = 14;
    let mut aux = original.aux.clone();
    aux.output_digest = codec::digest(&output.encode());
    let (air, pv) = plonky3::prepare(&r, &output, &aux).unwrap().into_parts();
    assert!(!p3_air::check_all_constraints(&air, &trace, &pv, Some(1)).is_ok());
}
