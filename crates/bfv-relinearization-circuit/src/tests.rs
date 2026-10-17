//! Public non-secret owning examples. These are arithmetic stages, not a relinearization proof.
use super::*;
fn request(role: Role, input: &[u64]) -> Request {
    decode_request(&encode_request(role, [0x71; 32], [0x72; 32], input).unwrap()).unwrap()
}
fn zero(role: Role) -> Request {
    request(role, &vec![0; role.input_coefficients()])
}
fn embedded() -> Request {
    let mut input = vec![0; 5 * DEGREE];
    for source in 0..5 {
        input[source * DEGREE] = source as u64 + 1;
    }
    input[2 * DEGREE + DEGREE - 1] = 2 * MODULI[0];
    request(Role::Embed, &input)
}
fn accumulated() -> Request {
    let mut input = vec![0; 85 * DEGREE];
    for (target, &p) in MODULI.iter().enumerate() {
        let block = 17 * target;
        input[block * DEGREE] = 7;
        input[(block + 1) * DEGREE] = 11;
        for (source, ((d, k0), k1)) in [1, 2, 3, 4, 5]
            .into_iter()
            .zip([2, 3, 5, 7, 11])
            .zip([13, 17, 19, 23, 29])
            .enumerate()
        {
            input[(block + 2 + source) * DEGREE] = d;
            input[(block + 7 + source) * DEGREE] = k0;
            input[(block + 12 + source) * DEGREE] = k1;
            let coefficient = 1 + source;
            input[(block + 2 + source) * DEGREE + coefficient] = 1;
            input[(block + 7 + source) * DEGREE + coefficient] = source as u64 + 2;
            input[(block + 12 + source) * DEGREE + coefficient] = source as u64 + 7;
        }
        for poly in block..block + 17 {
            input[(poly + 1) * DEGREE - 1] = p - 1;
        }
    }
    request(Role::AccumulateAndAdd, &input)
}
#[test]
fn fixed_role_codecs_preserve_all_vectors_and_reject_unknown_headers_lengths_and_input_aliases() {
    for role in [Role::Embed, Role::AccumulateAndAdd] {
        let mut input = vec![0; role.input_coefficients()];
        for (poly, &p) in role.input_moduli().iter().enumerate() {
            input[(poly + 1) * DEGREE - 1] = p - 1;
        }
        let r = request(role, &input);
        let wire = r.encode();
        assert_eq!(decode_request(&wire).unwrap().input(), input);
        assert_eq!(r.keyset_context(), [0x72; 32]);
        assert_eq!(r.binding(), [0x71; 32]);
        assert_eq!(wire.len(), role.request_bytes());
        for at in [0, 8, 104, 105, 106, 107, 108] {
            let mut bad = wire.clone();
            bad[at] ^= 128;
            assert!(decode_request(&bad).is_err());
        }
        assert!(decode_request(&wire[..wire.len() - 1]).is_err());
        let mut tail = wire.clone();
        tail.push(0);
        assert!(decode_request(&tail).is_err());
        let mut alias = wire;
        let last = role.input_moduli().len() - 1;
        alias[112 + ((last + 1) * DEGREE - 1) * 8..]
            .copy_from_slice(&role.input_moduli()[last].to_le_bytes());
        assert!(matches!(
            decode_request(&alias),
            Err(Error::NonCanonicalResidue)
        ));
    }
}
#[test]
fn complete_embedding_keeps_source_target_order_and_requires_quotient_two_instead_of_a_boolean() {
    assert_eq!(
        EMBEDDING_QUOTIENT_BOUNDS,
        [
            [0, 1, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [2, 2, 0, 1, 1],
            [1, 1, 0, 0, 1],
            [1, 1, 0, 0, 0]
        ]
    );
    let r = embedded();
    let e = evaluate_with_certificate(&r).unwrap();
    let rows = e.aux.embedding_rows().unwrap();
    assert_eq!(rows[DEGREE - 1][10], 2);
    assert_eq!(rows[DEGREE - 1][11], 2);
    let last_expected = [0, 131072, 17592185716738, 278529, 999425];
    for source in 0..5 {
        for (target, &expected) in last_expected.iter().enumerate() {
            let poly = 5 * source + target;
            let row = &e.output.coefficients()[poly * DEGREE..(poly + 1) * DEGREE];
            assert_eq!(row[0], source as u64 + 1);
            assert!(row[1..DEGREE - 1].iter().all(|&x| x == 0));
            assert_eq!(row[DEGREE - 1], if source == 2 { expected } else { 0 });
        }
    }
}
#[test]
fn all_five_target_bases_keep_both_originals_and_every_ordered_mac_term() {
    let e = evaluate_with_certificate(&accumulated()).unwrap();
    for target in 0..5 {
        for (component, first) in [113, 352].into_iter().enumerate() {
            let poly = 2 * target + component;
            let row = &e.output.coefficients()[poly * DEGREE..(poly + 1) * DEGREE];
            assert_eq!(row[0], first);
            for source in 0..5 {
                assert_eq!(
                    row[1 + source],
                    source as u64 + if component == 0 { 2 } else { 7 }
                );
            }
            assert!(row[6..DEGREE - 1].iter().all(|&v| v == 0));
            assert_eq!(row[DEGREE - 1], 4);
        }
    }
}
#[test]
fn maximum_canonical_mac_terms_use_all_six_digits_and_a_forty_seven_bit_quotient() {
    let e = evaluate_with_certificate(&accumulated()).unwrap();
    let row = &e.aux.accumulation_rows().unwrap()[DEGREE - 1];
    for (target, &p) in MODULI.iter().enumerate() {
        for component in 0..2 {
            assert_eq!(row.quotients()[2 * target + component], 5 * p - 9);
            assert_eq!(
                e.output.coefficients()[(2 * target + component + 1) * DEGREE - 1],
                4
            );
        }
    }
}
#[test]
fn fixed_outputs_and_both_auxiliary_forms_roundtrip_every_byte_without_trailing_data() {
    for role in [Role::Embed, Role::AccumulateAndAdd] {
        let r = zero(role);
        let e = evaluate_with_certificate(&r).unwrap();
        assert!(e.output.coefficients().iter().all(|&x| x == 0));
        let output = e.output.encode();
        let aux = e.aux.encode();
        assert_eq!(output.len(), role.output_bytes());
        assert_eq!(aux.len(), role.aux_bytes());
        assert_eq!(decode_output(&output).unwrap().encode(), output);
        assert_eq!(decode_aux(&aux).unwrap().encode(), aux);
        assert!(decode_output(&output[..output.len() - 1]).is_err());
        assert!(decode_aux(&aux[..aux.len() - 1]).is_err());
        let mut tail = aux;
        tail.push(0);
        assert!(decode_aux(&tail).is_err());
    }
}
#[test]
fn canonical_remainders_embedding_bounds_and_all_mac_carry_ranges_are_mandatory() {
    let r = embedded();
    let e = evaluate_with_certificate(&r).unwrap();
    let mut bad = e.aux.encode();
    bad[176 + (DEGREE - 1) * 25 + 10] = 3;
    assert!(matches!(decode_aux(&bad), Err(Error::AuxiliaryRange)));
    let mut diagonal = e.aux.encode();
    diagonal[176] = 1;
    assert!(matches!(decode_aux(&diagonal), Err(Error::AuxiliaryRange)));
    let r = accumulated();
    let e = evaluate_with_certificate(&r).unwrap();
    let wire = e.aux.encode();
    for (target, &p) in MODULI.iter().enumerate() {
        for component in 0..2 {
            let poly = 2 * target + component;
            let mut bad = wire.clone();
            let at = 176 + (DEGREE - 1) * 260 + 6 * poly;
            bad[at..at + 6].copy_from_slice(&(5 * p).to_le_bytes()[..6]);
            assert!(matches!(decode_aux(&bad), Err(Error::AuxiliaryRange)));
            let mut carry = wire.clone();
            carry[176 + (DEGREE - 1) * 260 + 60 + 20 * poly + 3] |= 2;
            assert!(matches!(decode_aux(&carry), Err(Error::AuxiliaryRange)));
        }
    }
    for (role, e) in [
        (Role::Embed, evaluate_with_certificate(&embedded()).unwrap()),
        (Role::AccumulateAndAdd, e),
    ] {
        let mut wire = e.output.encode();
        let poly = role.output_moduli().len() - 1;
        wire[144 + ((poly + 1) * DEGREE - 1) * 8..]
            .copy_from_slice(&role.output_moduli()[poly].to_le_bytes());
        assert!(matches!(
            decode_output(&wire),
            Err(Error::NonCanonicalResidue)
        ));
    }
}
#[test]
fn independent_binding_and_keyset_context_and_last_operand_cannot_be_relabelled() {
    for role in [Role::Embed, Role::AccumulateAndAdd] {
        let r = zero(role);
        let e = evaluate_with_certificate(&r).unwrap();
        for (binding, keyset) in [([0x73; 32], r.keyset_context()), (r.binding(), [0x74; 32])] {
            let other =
                decode_request(&encode_request(role, binding, keyset, r.input()).unwrap()).unwrap();
            assert_eq!(
                codec::check_binding(&other, &e.output, &e.aux),
                Err(Error::Binding)
            );
        }
        let mut input = r.input().to_vec();
        *input.last_mut().unwrap() = 1;
        assert_eq!(
            codec::check_binding(&request(role, &input), &e.output, &e.aux),
            Err(Error::Binding)
        );
    }
}
#[cfg(feature = "plonky3")]
#[test]
fn full_public_preprocessing_checks_both_roles_and_shape_metadata_has_no_authority() {
    use p3_air::BaseAir;
    use p3_field::PrimeCharacteristicRing;
    for r in [embedded(), accumulated()] {
        let e = evaluate_with_certificate(&r).unwrap();
        let shape = plonky3::ArithmeticAir::shape(r.role());
        assert!(!shape.is_prepared());
        assert!(shape.preprocessed_trace().is_none());
        assert_eq!(shape.preprocessed_width(), r.role().preprocessed_width());
        let prepared = plonky3::prepare(&r, &e.output, &e.aux).unwrap();
        assert_eq!(
            prepared.coefficient_row(DEGREE - 1).unwrap().len(),
            r.role().preprocessed_width()
        );
        let (air, pv) = prepared.into_parts();
        let trace =
            p3_matrix::dense::RowMajorMatrix::new(vec![p3_goldilocks::Goldilocks::ZERO; DEGREE], 1);
        assert!(p3_air::check_all_constraints(&air, &trace, &pv, Some(1)).is_ok());
    }
}
#[cfg(feature = "plonky3")]
#[test]
fn coherent_embedding_output_and_quotient_forgeries_reach_the_scalar_relation_and_reject() {
    use p3_field::PrimeCharacteristicRing;
    let r = embedded();
    let original = evaluate_with_certificate(&r).unwrap();
    let trace =
        p3_matrix::dense::RowMajorMatrix::new(vec![p3_goldilocks::Goldilocks::ZERO; DEGREE], 1);
    for attack in 0..2 {
        let mut output = original.output.clone();
        let mut aux = original.aux.clone();
        if attack == 0 {
            output.coefficients[11 * DEGREE - 1] = 1;
            aux.output_digest = codec::digest(&output.encode());
        } else {
            let codec::Rows::Embed(rows) = &mut aux.rows else {
                unreachable!()
            };
            rows[DEGREE - 1][10] = 1;
        }
        let aux = decode_aux(&aux.encode()).unwrap();
        let (air, pv) = plonky3::prepare(&r, &output, &aux).unwrap().into_parts();
        assert!(!p3_air::check_all_constraints(&air, &trace, &pv, Some(1)).is_ok());
    }
}
#[cfg(feature = "plonky3")]
#[test]
fn coherent_mac_output_quotient_carry_and_omitted_last_term_forgeries_reach_air_and_reject() {
    use p3_field::PrimeCharacteristicRing;
    let r = accumulated();
    let original = evaluate_with_certificate(&r).unwrap();
    let trace =
        p3_matrix::dense::RowMajorMatrix::new(vec![p3_goldilocks::Goldilocks::ZERO; DEGREE], 1);
    for poly in 0..10 {
        for attack in 0..3 {
            let mut output = original.output.clone();
            let mut aux = original.aux.clone();
            let codec::Rows::Accumulate(rows) = &mut aux.rows else {
                unreachable!()
            };
            match attack {
                0 => {
                    output.coefficients[(poly + 1) * DEGREE - 1] ^= 1;
                    aux.output_digest = codec::digest(&output.encode());
                }
                1 => rows[DEGREE - 1].quotients[poly] ^= 1,
                _ => rows[DEGREE - 1].carries[poly][4] ^= 1,
            }
            let aux = decode_aux(&aux.encode()).unwrap();
            let (air, pv) = plonky3::prepare(&r, &output, &aux).unwrap().into_parts();
            assert!(
                !p3_air::check_all_constraints(&air, &trace, &pv, Some(1)).is_ok(),
                "poly {poly}, attack {attack}"
            );
        }
    }
    let mut output = original.output.clone();
    output.coefficients[5] = 0;
    let mut aux = original.aux.clone();
    aux.output_digest = codec::digest(&output.encode());
    let (air, pv) = plonky3::prepare(&r, &output, &aux).unwrap().into_parts();
    assert!(!p3_air::check_all_constraints(&air, &trace, &pv, Some(1)).is_ok());
}
