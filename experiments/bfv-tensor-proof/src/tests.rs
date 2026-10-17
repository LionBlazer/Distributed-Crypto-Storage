use super::*;
use bfv_tensor_circuit::{
    Aux, Basis, DEGREE, Output, Request, decode_aux, decode_output, decode_request, encode_request,
    evaluate_with_certificate,
};
use std::sync::OnceLock;
struct Genuine {
    request: Request,
    generated: Generated,
}
fn representative(index: u8) -> &'static Genuine {
    static Q: OnceLock<Genuine> = OnceLock::new();
    static P: OnceLock<Genuine> = OnceLock::new();
    let cell = match index {
        0 => &Q,
        9 => &P,
        _ => panic!("only two public negative fixtures retained"),
    };
    cell.get_or_init(|| {
        let request = fixture::request(Basis::new(index).unwrap(), [0x19; 32]).unwrap();
        let generated = prove(&request).unwrap();
        assert!(
            verify(&request, &generated.output, &generated.proof)
                .unwrap()
                .matches(&request, &generated.output)
        );
        Genuine { request, generated }
    })
}

#[test]
fn all8192_three_components_match_actual_sdk_poly_tensor_for_all_ten_bases() {
    use fhe_math::rq::{Context, Poly, Representation, traits::TryConvertFrom};
    use std::sync::Arc;
    for index in 0..10 {
        let basis = Basis::new(index).unwrap();
        let input = fixture::request(basis, [7; 32]).unwrap();
        let context = Arc::new(Context::new(&[basis.modulus()], DEGREE).unwrap());
        let polys: Vec<Poly> = input
            .input()
            .as_chunks::<DEGREE>()
            .0
            .iter()
            .map(|row| {
                Poly::try_convert_from(row.to_vec(), &context, false, Representation::Ntt).unwrap()
            })
            .collect();
        // Call the upstream polynomial multiplication/addition implementation;
        // do not reproduce tensor modular arithmetic as the oracle.
        let d0 = &polys[0] * &polys[2];
        let mut d1 = &polys[0] * &polys[3];
        d1 += &(&polys[1] * &polys[2]);
        let d2 = &polys[1] * &polys[3];
        let expected: Vec<u64> = [d0, d1, d2].iter().flat_map(Vec::<u64>::from).collect();
        let evaluated = evaluate_with_certificate(&input).unwrap();
        assert_eq!(evaluated.output.coefficients(), expected, "basis{index}");
    }
}

#[test]
fn all_ten_genuine_serialized_full_tensor_proofs_verify_and_drop_sequentially() {
    for index in 0..10 {
        let basis = Basis::new(index).unwrap();
        let input = fixture::request(basis, [0x71; 32]).unwrap();
        let generated = prove(&input).unwrap();
        let checked = verify(&input, &generated.output, &generated.proof).unwrap();
        assert!(checked.matches(&input, &generated.output));
        assert_eq!(checked.basis(), basis);
        assert_eq!(generated.output.coefficients().len(), 3 * DEGREE);
        assert!(generated.proof.len() <= MAX_PROOF_BYTES);
        // No all-basis proof bank: this genuine serialized proof drops here.
    }
}

#[test]
fn genuine_foreign_basis_profile_context_and_representation_cannot_replace_trusted_tensor() {
    for index in [0, 9] {
        let valid = representative(index);
        for offset in [0, 8, 39, 40, 71, 72, 73, 74, 75, 79] {
            let mut frame = valid.generated.proof.clone();
            frame[offset] ^= 1;
            assert_eq!(
                verify(&valid.request, &valid.generated.output, &frame).unwrap_err(),
                Error::Frame
            );
        }
        let foreign = representative(if index == 0 { 9 } else { 0 });
        assert!(
            verify(
                &valid.request,
                &foreign.generated.output,
                &foreign.generated.proof
            )
            .is_err()
        );
        let changed = decode_request(
            &encode_request(valid.request.basis(), [0x99; 32], valid.request.input()).unwrap(),
        )
        .unwrap();
        assert!(verify(&changed, &valid.generated.output, &valid.generated.proof).is_err());
    }
}

#[test]
fn all_four_inputs_and_three_outputs_bind_the_last_coefficient_and_original_order() {
    for index in [0, 9] {
        let valid = representative(index);
        let basis = valid.request.basis();
        for component in 0..4 {
            let mut input = valid.request.input().to_vec();
            let at = (component + 1) * DEGREE - 1;
            input[at] = (input[at] + 1) % basis.modulus();
            let changed =
                decode_request(&encode_request(basis, valid.request.binding(), &input).unwrap())
                    .unwrap();
            assert!(verify(&changed, &valid.generated.output, &valid.generated.proof).is_err());
        }
        for component in 0..3 {
            let mut out = valid.generated.output.encode();
            let at = 112 + ((component + 1) * DEGREE - 1) * 8;
            let old = u64::from_le_bytes(out[at..at + 8].try_into().unwrap());
            out[at..at + 8].copy_from_slice(&((old + 1) % basis.modulus()).to_le_bytes());
            assert!(
                verify(
                    &valid.request,
                    &decode_output(&out).unwrap(),
                    &valid.generated.proof
                )
                .is_err()
            );
        }
    }
}
fn changed_output(evaluated: bfv_tensor_circuit::Evaluation, values: &[u64]) -> (Output, Aux) {
    use sha2::{Digest, Sha256};
    assert_eq!(values.len(), 3 * DEGREE);
    let mut out = evaluated.output.encode();
    for (i, value) in values.iter().enumerate() {
        out[112 + 8 * i..120 + 8 * i].copy_from_slice(&value.to_le_bytes());
    }
    let mut aux = evaluated.aux.encode();
    aux[112..144].copy_from_slice(&Sha256::digest(&out));
    (decode_output(&out).unwrap(), decode_aux(&aux).unwrap())
}
fn integer_rejects(input: &Request, output: &Output, aux: &Aux) {
    use p3_air::BaseAir;
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;
    let (air, values) = proof::statement(input, output, aux).unwrap();
    let main = RowMajorMatrix::new(vec![backend::Val::ZERO; DEGREE * air.width()], air.width());
    assert!(!p3_air::check_all_constraints(&air, &main, &values, Some(1)).is_ok());
}

#[test]
fn canonical_rebuilt_last_output_forgeries_reach_every_component_on_all_ten_bases() {
    for index in 0..10 {
        let input = fixture::request(Basis::new(index).unwrap(), [0x53; 32]).unwrap();
        for component in 0..3 {
            let evaluated = evaluate_with_certificate(&input).unwrap();
            let mut values = evaluated.output.coefficients().to_vec();
            let at = (component + 1) * DEGREE - 1;
            values[at] = (values[at] + 1) % input.basis().modulus();
            let (out, aux) = changed_output(evaluated, &values);
            integer_rejects(&input, &out, &aux);
        }
    }
}

#[test]
fn canonical_quotient_and_every_shifted_carry_are_checked_at_the_last_full_row() {
    for index in [0, 9] {
        let input = fixture::request(Basis::new(index).unwrap(), [0x39; 32]).unwrap();
        let evaluated = evaluate_with_certificate(&input).unwrap();
        let original = evaluated.aux.encode();
        let row = 144 + (DEGREE - 1) * 108;
        for component in 0..3 {
            let mut forged = original.clone();
            let at = row + 8 * component;
            let old = u64::from_le_bytes(forged[at..at + 8].try_into().unwrap());
            forged[at..at + 8].copy_from_slice(&(if old == 0 { 1 } else { old - 1 }).to_le_bytes());
            integer_rejects(&input, &evaluated.output, &decode_aux(&forged).unwrap());
            for carry in 0..7 {
                let mut forged = original.clone();
                forged[row + 24 + 28 * component + 4 * carry] ^= 1;
                integer_rejects(&input, &evaluated.output, &decode_aux(&forged).unwrap());
            }
        }
    }
}

#[test]
fn dropping_either_real_sdk_cross_product_cannot_replace_the_middle_component() {
    use fhe_math::rq::{Context, Poly, Representation, traits::TryConvertFrom};
    use std::sync::Arc;
    for index in [0, 9] {
        let input = fixture::request(Basis::new(index).unwrap(), [0x29; 32]).unwrap();
        let ctx = Arc::new(Context::new(&[input.basis().modulus()], DEGREE).unwrap());
        let polys: Vec<Poly> = input
            .input()
            .as_chunks::<DEGREE>()
            .0
            .iter()
            .map(|x| Poly::try_convert_from(x.to_vec(), &ctx, false, Representation::Ntt).unwrap())
            .collect();
        for term in [&polys[0] * &polys[3], &polys[1] * &polys[2]] {
            let evaluated = evaluate_with_certificate(&input).unwrap();
            let mut values = evaluated.output.coefficients().to_vec();
            let wrong = Vec::<u64>::from(&term);
            assert_ne!(&values[DEGREE..2 * DEGREE], wrong);
            values[DEGREE..2 * DEGREE].copy_from_slice(&wrong);
            let (out, aux) = changed_output(evaluated, &values);
            integer_rejects(&input, &out, &aux);
        }
    }
}

#[test]
fn canonical_component_order_swap_with_rebound_auxiliary_cannot_swap_outer_products() {
    use sha2::{Digest, Sha256};
    for index in [0, 9] {
        let input = fixture::request(Basis::new(index).unwrap(), [0x62; 32]).unwrap();
        let evaluated = evaluate_with_certificate(&input).unwrap();
        let mut values = evaluated.output.coefficients().to_vec();
        for i in 0..DEGREE {
            values.swap(i, 2 * DEGREE + i);
        }
        assert_ne!(values, evaluated.output.coefficients());
        let (out, aux) = changed_output(evaluated, &values);
        let mut wire = aux.encode();
        for row in wire[144..].as_chunks_mut::<108>().0 {
            for i in 0..8 {
                row.swap(i, 16 + i);
            }
            for i in 0..28 {
                row.swap(24 + i, 80 + i);
            }
        }
        wire[112..144].copy_from_slice(&Sha256::digest(out.encode()));
        integer_rejects(&input, &out, &decode_aux(&wire).unwrap());
    }
}

#[test]
fn modulus_aliases_and_out_of_range_quotients_carries_reject_before_field_conversion() {
    for index in 0..10 {
        let input = fixture::request(Basis::new(index).unwrap(), [0x46; 32]).unwrap();
        let evaluated = evaluate_with_certificate(&input).unwrap();
        let mut bad = input.input().to_vec();
        bad[4 * DEGREE - 1] = input.basis().modulus();
        assert!(encode_request(input.basis(), input.binding(), &bad).is_err());
        for component in 0..3 {
            let mut out = evaluated.output.encode();
            let at = 112 + ((component + 1) * DEGREE - 1) * 8;
            out[at..at + 8].copy_from_slice(&input.basis().modulus().to_le_bytes());
            assert!(decode_output(&out).is_err());
            let row = 144 + (DEGREE - 1) * 108;
            let mut aux = evaluated.aux.encode();
            let bound = if component == 1 {
                2 * input.basis().modulus()
            } else {
                input.basis().modulus()
            };
            aux[row + 8 * component..row + 8 * component + 8].copy_from_slice(&bound.to_le_bytes());
            assert!(decode_aux(&aux).is_err());
            let mut aux = evaluated.aux.encode();
            let at = row + 24 + 28 * component + 24;
            aux[at..at + 4].copy_from_slice(&(1u32 << 25).to_le_bytes());
            assert!(decode_aux(&aux).is_err());
        }
    }
}

#[test]
fn raw_sdk_proof_with_prover_selected_equations_cannot_replace_the_tensor_relation() {
    use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;
    struct ProverSelected {
        base: backend::BoundAir,
        constraints: usize,
    }
    impl BaseAir<backend::Val> for ProverSelected {
        fn width(&self) -> usize {
            self.base.width()
        }
        fn preprocessed_width(&self) -> usize {
            self.base.preprocessed_width()
        }
        fn preprocessed_trace(&self) -> Option<RowMajorMatrix<backend::Val>> {
            self.base.preprocessed_trace()
        }
        fn num_public_values(&self) -> usize {
            self.base.num_public_values()
        }
        fn max_constraint_degree(&self) -> Option<usize> {
            self.base.max_constraint_degree()
        }
        fn main_next_row_columns(&self) -> Vec<usize> {
            vec![]
        }
        fn preprocessed_next_row_columns(&self) -> Vec<usize> {
            vec![]
        }
    }
    impl<AB: AirBuilder<F = backend::Val>> Air<AB> for ProverSelected {
        fn eval(&self, b: &mut AB) {
            let zero = b.main().current(0).unwrap();
            for _ in 0..self.constraints {
                b.assert_zero(zero);
            }
        }
    }
    for index in [0, 9] {
        let input = fixture::request(Basis::new(index).unwrap(), [0x58; 32]).unwrap();
        let evaluated = evaluate_with_certificate(&input).unwrap();
        let mut v = evaluated.output.coefficients().to_vec();
        v[2 * DEGREE - 1] = (v[2 * DEGREE - 1] + 1) % input.basis().modulus();
        let (out, aux) = changed_output(evaluated, &v);
        let (air, values) = proof::statement(&input, &out, &aux).unwrap();
        let (cfg, report) = backend::config(&air, input.basis()).unwrap();
        let attacker = ProverSelected {
            base: air,
            constraints: report.constraints,
        };
        let (pre, _) = p3_uni_stark::setup_preprocessed(&cfg, &attacker, 13)
            .unwrap()
            .unwrap();
        let main = RowMajorMatrix::new(vec![backend::Val::ZERO; DEGREE], 1);
        let forged =
            p3_uni_stark::prove_with_preprocessed(&cfg, &attacker, main, &values, Some(&pre))
                .unwrap();
        let frame = proof::encode_frame(&input, &aux, &forged).unwrap();
        assert_eq!(
            verify(&input, &out, &frame).unwrap_err(),
            Error::Verification
        );
    }
}

#[test]
fn a_genuine_proof_under_foreign_public_preprocessing_cannot_choose_the_verifier_key() {
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;
    for index in [0, 9] {
        let input = fixture::request(Basis::new(index).unwrap(), [0x83; 32]).unwrap();
        let evaluated = evaluate_with_certificate(&input).unwrap();
        let (air, values) = proof::statement(&input, &evaluated.output, &evaluated.aux).unwrap();
        let (cfg, _) = backend::config(&air, input.basis()).unwrap();
        let mut wrong = input.input().to_vec();
        wrong[DEGREE - 1] = (wrong[DEGREE - 1] + 1) % input.basis().modulus();
        let foreign =
            decode_request(&encode_request(input.basis(), input.binding(), &wrong).unwrap())
                .unwrap();
        let foreign_result = evaluate_with_certificate(&foreign).unwrap();
        let (attacker, _) =
            proof::statement(&foreign, &foreign_result.output, &foreign_result.aux).unwrap();
        let (pre, key) = p3_uni_stark::setup_preprocessed(&cfg, &attacker, 13)
            .unwrap()
            .unwrap();
        let main = RowMajorMatrix::new(vec![backend::Val::ZERO; DEGREE], 1);
        let forged =
            p3_uni_stark::prove_with_preprocessed(&cfg, &attacker, main, &values, Some(&pre))
                .unwrap();
        p3_uni_stark::verify_with_preprocessed(&cfg, &attacker, &forged, &values, Some(&key))
            .unwrap();
        let frame = proof::encode_frame(&input, &evaluated.aux, &forged).unwrap();
        assert_eq!(
            verify(&input, &evaluated.output, &frame).unwrap_err(),
            Error::Verification
        );
    }
}

#[test]
fn bounded_canonical_sdk_decoder_and_new_frame_cap_reject_before_acceptance() {
    let bytes = postcard::to_allocvec(&usize::MAX).unwrap();
    assert_eq!(
        codec::take_from_bytes::<Vec<u64>>(&bytes).unwrap_err(),
        Error::ProofResourceLimit
    );
    let bytes = postcard::to_allocvec(&vec![vec![0u8; 4097]]).unwrap();
    assert_eq!(
        codec::take_from_bytes::<Vec<Vec<u8>>>(&bytes).unwrap_err(),
        Error::ProofResourceLimit
    );
    let bytes = postcard::to_allocvec(&vec![vec![[0u8; 8]; 4096]; 65]).unwrap();
    assert_eq!(
        codec::take_from_bytes::<Vec<Vec<[u8; 8]>>>(&bytes).unwrap_err(),
        Error::ProofResourceLimit
    );
    let valid = representative(0);
    assert_eq!(
        verify(&valid.request, &valid.generated.output, &[]).unwrap_err(),
        Error::ProofLength
    );
    assert_eq!(
        verify(
            &valid.request,
            &valid.generated.output,
            &vec![0; MAX_PROOF_BYTES + 1]
        )
        .unwrap_err(),
        Error::ProofLength
    );
    let mut trailing = valid.generated.proof.clone();
    trailing.push(0);
    assert_eq!(
        verify(&valid.request, &valid.generated.output, &trailing).unwrap_err(),
        Error::TrailingProofBytes
    );
    let mut truncated = valid.generated.proof.clone();
    truncated.pop();
    assert!(verify(&valid.request, &valid.generated.output, &truncated).is_err());
}

#[test]
fn binary_goldilocks_openings_charge_all_eight_byte_slots_before_acceptance() {
    use p3_field::PrimeCharacteristicRing;
    let row = vec![backend::Val::from_u64(7); 61];
    let bytes = postcard::to_allocvec(&row).unwrap();
    let limits = bounded_postcard::Limits {
        max_sequence_elements: 4096,
        max_total_elements: 9 * row.len(),
    };
    assert_eq!(
        bounded_postcard::take_from_bytes::<Vec<backend::Val>>(
            &bytes,
            bounded_postcard::Limits {
                max_total_elements: limits.max_total_elements - 1,
                ..limits
            }
        )
        .unwrap_err(),
        bounded_postcard::Error::ResourceLimit
    );
    let (decoded, trailing) =
        bounded_postcard::take_from_bytes::<Vec<backend::Val>>(&bytes, limits).unwrap();
    assert_eq!(decoded, row);
    assert!(trailing.is_empty());
}

#[test]
fn tracefree_analysis_uses_each_real_fixed_air_and_shared_security_configuration() {
    use bfv_tensor_circuit::plonky3::TensorAir;
    for index in 0..10 {
        let basis = Basis::new(index).unwrap();
        assert!(!TensorAir::shape(basis).is_prepared());
        let r = backend::analyze(basis).unwrap();
        assert_eq!(
            (
                r.trace_height,
                r.main_width,
                r.public_width,
                r.public_values
            ),
            (8192, 1, 61, 40)
        );
        assert_eq!((r.basis_index, r.modulus), (index, basis.modulus()));
        assert_eq!((r.extension_degree, r.queries, r.blowup), (5, 192, 8));
        assert!(r.constraints > 0 && r.degree <= 2 && r.quotient_chunks <= 8);
        assert!(r.unique_decoding_bits >= 128 && r.list_decoding_bits >= 128);
    }
}
