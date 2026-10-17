use super::*;
use bfv_ntt_circuit::{
    Aux, Basis, Direction, Output, Request, decode_aux, decode_output, decode_request,
    encode_request, evaluate_with_certificate,
};
use std::sync::OnceLock;
fn directions() -> [Direction; 2] {
    [Direction::Forward, Direction::Inverse]
}
fn representatives() -> [(Direction, Basis); 4] {
    [
        (Direction::Forward, Basis::new(0).unwrap()),
        (Direction::Inverse, Basis::new(0).unwrap()),
        (Direction::Forward, Basis::new(9).unwrap()),
        (Direction::Inverse, Basis::new(9).unwrap()),
    ]
}
struct Genuine {
    request: Request,
    generated: Generated,
}
fn representative(direction: Direction, basis: Basis) -> &'static Genuine {
    static FQ: OnceLock<Genuine> = OnceLock::new();
    static IQ: OnceLock<Genuine> = OnceLock::new();
    static FP: OnceLock<Genuine> = OnceLock::new();
    static IP: OnceLock<Genuine> = OnceLock::new();
    let cell = match (direction, basis.index()) {
        (Direction::Forward, 0) => &FQ,
        (Direction::Inverse, 0) => &IQ,
        (Direction::Forward, 9) => &FP,
        (Direction::Inverse, 9) => &IP,
        _ => panic!("only four public representative fixtures are retained"),
    };
    cell.get_or_init(|| {
        let request = fixture::request(direction, basis, [0x19; 32]).unwrap();
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
fn all8192_coefficients_match_the_actual_native_sdk_in_both_directions_and_all_ten_bases() {
    use fhe_math::{ntt::NttOperator, zq::Modulus};
    // This pins the actual feature-selected type, not the mere presence of a
    // transitive tfhe-ntt package in Cargo.lock. ROOT also checks metadata.
    assert_eq!(
        std::any::type_name::<NttOperator>(),
        "fhe_math::ntt::native::NttOperator"
    );
    for index in 0..10 {
        let basis = Basis::new(index).unwrap();
        let modulus = Modulus::new(basis.modulus()).unwrap();
        let native = NttOperator::new(&modulus, 8192).unwrap();
        for direction in directions() {
            let input = fixture::request(direction, basis, [7; 32]).unwrap();
            let evaluated = evaluate_with_certificate(&input).unwrap();
            let mut expected = input.input().to_vec();
            match direction {
                Direction::Forward => native.forward(&mut expected),
                Direction::Inverse => native.backward(&mut expected),
            }
            assert_eq!(
                evaluated.output.coefficients(),
                expected.as_slice(),
                "{} basis{}",
                backend::direction_name(direction),
                index
            );
        }
    }
}

#[test]
fn native_sdk_impulse_opens_the_exact_deterministic_root_and_inverse_normalization() {
    use fhe_math::{ntt::NttOperator, zq::Modulus};
    for index in 0..10 {
        let basis = Basis::new(index).unwrap();
        let modulus = Modulus::new(basis.modulus()).unwrap();
        let native = NttOperator::new(&modulus, 8192).unwrap();
        let mut impulse = vec![0; 8192];
        impulse[1] = 1;
        native.forward(&mut impulse);
        let parameters = bfv_ntt_circuit::parameters(basis);
        assert_eq!(parameters.primitive_root(), impulse[0]);
        assert_eq!(
            modulus.pow(parameters.primitive_root(), 8192),
            basis.modulus() - 1
        );
        assert_eq!(parameters.inverse_size(), modulus.inv(8192).unwrap());
        native.backward(&mut impulse);
        let mut monomial = vec![0; 8192];
        monomial[1] = 1;
        assert_eq!(impulse, monomial);
    }
}

#[test]
fn all_twenty_full_profile_genuine_stages_verify_and_release_each_proof_sequentially() {
    // All 20 cases are mandatory and unignored. Do not retain a proof bank or
    // infer other bases from four representatives. ROOT gates actual security
    // and the complete SDK oracle before invoking this owning example.
    for index in 0..10 {
        let basis = Basis::new(index).unwrap();
        for direction in directions() {
            let input = fixture::request(direction, basis, [0x71; 32]).unwrap();
            let generated = prove(&input).unwrap();
            let checked = verify(&input, &generated.output, &generated.proof).unwrap();
            assert!(checked.matches(&input, &generated.output));
            assert_eq!(checked.direction(), direction);
            assert_eq!(checked.basis().index(), index);
            assert_eq!(generated.output.coefficients().len(), 8192);
            assert!(generated.proof.len() <= MAX_PROOF_BYTES);
            // generated/checked are dropped at this iteration boundary.
        }
    }
}

#[test]
fn genuine_foreign_direction_basis_profile_and_order_cannot_replace_trusted_stage() {
    for (direction, basis) in representatives() {
        let valid = representative(direction, basis);
        for offset in [0, 8, 39, 40, 71, 72, 73, 74, 75, 79] {
            let mut changed = valid.generated.proof.clone();
            changed[offset] ^= 1;
            assert_eq!(
                verify(&valid.request, &valid.generated.output, &changed).unwrap_err(),
                Error::Frame,
                "header{offset}"
            );
        }
        let other_direction = match direction {
            Direction::Forward => Direction::Inverse,
            Direction::Inverse => Direction::Forward,
        };
        let foreign = representative(other_direction, basis);
        assert!(
            verify(
                &valid.request,
                &foreign.generated.output,
                &foreign.generated.proof
            )
            .is_err()
        );
        let other_basis = Basis::new(if basis.index() == 0 { 9 } else { 0 }).unwrap();
        let foreign = representative(direction, other_basis);
        assert!(
            verify(
                &valid.request,
                &foreign.generated.output,
                &foreign.generated.proof
            )
            .is_err()
        );
    }
}

#[test]
fn complete_input_output_and_last_coefficient_are_bound_with_the_same_opaque_request() {
    for (direction, basis) in representatives() {
        let valid = representative(direction, basis);
        let q = basis.modulus();
        for index in [0, 4095, 8191] {
            let mut values = valid.request.input().to_vec();
            values[index] = (values[index] + 1) % q;
            let other = decode_request(
                &encode_request(direction, basis, valid.request.binding(), &values).unwrap(),
            )
            .unwrap();
            assert!(verify(&other, &valid.generated.output, &valid.generated.proof).is_err());
            let mut wire = valid.generated.output.encode();
            let offset = 112 + index * 8;
            let current = u64::from_le_bytes(wire[offset..offset + 8].try_into().unwrap());
            wire[offset..offset + 8].copy_from_slice(&((current + 1) % q).to_le_bytes());
            assert!(
                verify(
                    &valid.request,
                    &decode_output(&wire).unwrap(),
                    &valid.generated.proof
                )
                .is_err()
            );
        }
        let mut reversed = valid.request.input().to_vec();
        reversed.reverse();
        let reordered = decode_request(
            &encode_request(direction, basis, valid.request.binding(), &reversed).unwrap(),
        )
        .unwrap();
        assert!(verify(&reordered, &valid.generated.output, &valid.generated.proof).is_err());
    }
}

fn replace_final_outputs(
    input: &Request,
    evaluated: bfv_ntt_circuit::Evaluation,
    values: &[u64],
) -> (Output, Aux) {
    use sha2::{Digest, Sha256};
    assert_eq!(values.len(), 8192);
    let mut output = evaluated.output.encode();
    let mut auxiliary = evaluated.aux.encode();
    let last = 144 + (input.direction().stages() - 1) * 8192 * 45;
    for (index, &value) in values.iter().enumerate() {
        output[112 + 8 * index..120 + 8 * index].copy_from_slice(&value.to_le_bytes());
        auxiliary[last + 45 * index..last + 45 * index + 8].copy_from_slice(&value.to_le_bytes());
    }
    auxiliary[112..144].copy_from_slice(&Sha256::digest(&output));
    // Hashes, last-stage equality, representation and all public ranges agree;
    // this is not just an old transcript or a malformed codec rejection.
    (
        decode_output(&output).unwrap(),
        decode_aux(&auxiliary).unwrap(),
    )
}
fn replace_final_output(
    input: &Request,
    evaluated: bfv_ntt_circuit::Evaluation,
    index: usize,
    value: u64,
) -> (Output, Aux) {
    let mut values = evaluated.output.coefficients().to_vec();
    values[index] = value;
    replace_final_outputs(input, evaluated, &values)
}
fn integer_rejects(input: &Request, output: &Output, auxiliary: &Aux) {
    use p3_air::BaseAir;
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;
    let (air, values) = proof::statement(input, output, auxiliary).unwrap();
    let main = RowMajorMatrix::new(vec![backend::Val::ZERO; 8192 * air.width()], air.width());
    assert!(!p3_air::check_all_constraints(&air, &main, &values, Some(1)).is_ok());
}

#[test]
fn rebuilt_canonical_last_butterfly_forgery_fails_for_every_direction_and_basis() {
    for index in 0..10 {
        let basis = Basis::new(index).unwrap();
        for direction in directions() {
            let input = fixture::request(direction, basis, [0x53; 32]).unwrap();
            let evaluated = evaluate_with_certificate(&input).unwrap();
            let value = (evaluated.output.coefficients()[8191] + 1) % basis.modulus();
            let (output, auxiliary) = replace_final_output(&input, evaluated, 8191, value);
            integer_rejects(&input, &output, &auxiliary);
        }
    }
}

#[test]
fn a_wrong_primitive_root_or_bit_reversed_output_cannot_satisfy_the_fixed_routing() {
    use fhe_math::zq::Modulus;
    for index in [0, 9] {
        let basis = Basis::new(index).unwrap();
        let mut input = vec![0; 8192];
        input[1] = 1;
        let request =
            decode_request(&encode_request(Direction::Forward, basis, [0x29; 32], &input).unwrap())
                .unwrap();
        let evaluated = evaluate_with_certificate(&request).unwrap();
        let modulus = Modulus::new(basis.modulus()).unwrap();
        let wrong = modulus.pow(bfv_ntt_circuit::parameters(basis).primitive_root(), 3);
        assert_ne!(wrong, evaluated.output.coefficients()[0]);
        let (output, auxiliary) = replace_final_output(&request, evaluated, 0, wrong);
        integer_rejects(&request, &output, &auxiliary);
        let evaluated = evaluate_with_certificate(&request).unwrap();
        let reordered = (0usize..8192)
            .map(|i| {
                let reversed = i.reverse_bits() >> (usize::BITS - 13);
                evaluated.output.coefficients()[reversed]
            })
            .collect::<Vec<_>>();
        assert_ne!(reordered, evaluated.output.coefficients());
        let (output, auxiliary) = replace_final_outputs(&request, evaluated, &reordered);
        integer_rejects(&request, &output, &auxiliary);
    }
}

#[test]
fn skipping_the_inverse_n_inverse_normalization_fails_after_all_public_hashes_are_rebuilt() {
    for index in [0, 9] {
        let basis = Basis::new(index).unwrap();
        let input = fixture::request(Direction::Inverse, basis, [0x83; 32]).unwrap();
        let evaluated = evaluate_with_certificate(&input).unwrap();
        let encoded = evaluated.aux.encode();
        let previous = 144 + (Direction::Inverse.stages() - 2) * 8192 * 45;
        let (index, unscaled) = (0..8192)
            .map(|i| {
                (
                    i,
                    u64::from_le_bytes(
                        encoded[previous + i * 45..previous + i * 45 + 8]
                            .try_into()
                            .unwrap(),
                    ),
                )
            })
            .find(|(i, value)| *value != evaluated.output.coefficients()[*i])
            .unwrap();
        let (output, auxiliary) = replace_final_output(&input, evaluated, index, unscaled);
        integer_rejects(&input, &output, &auxiliary);
    }
}

#[test]
fn canonical_intermediate_residue_quotient_and_carry_forgeries_rebuild_but_fail_integer_air() {
    for (direction, basis) in representatives() {
        let input = fixture::request(direction, basis, [0x39; 32]).unwrap();
        let evaluated = evaluate_with_certificate(&input).unwrap();
        let original = evaluated.aux.encode();
        for stage in [0, direction.stages() - 1] {
            let row = 144 + (stage * 8192 + 8191) * 45;
            for offset in [8, 17, 17 + 6 * 4] {
                let mut forged = original.clone();
                forged[row + offset] ^= 1;
                let aux = decode_aux(&forged).unwrap();
                integer_rejects(&input, &evaluated.output, &aux);
            }
        }
        // Alter an early canonical intermediate result; the next layer must
        // consume this exact routed value rather than an independently trusted copy.
        let row = 144 + 8191 * 45;
        let old = u64::from_le_bytes(original[row..row + 8].try_into().unwrap());
        let mut forged = original.clone();
        forged[row..row + 8].copy_from_slice(&((old + 1) % basis.modulus()).to_le_bytes());
        integer_rejects(&input, &evaluated.output, &decode_aux(&forged).unwrap());
    }
}

#[test]
fn noncanonical_residue_unused_quotient_bits_and_carry_bits_reject_before_field_conversion() {
    for index in 0..10 {
        let basis = Basis::new(index).unwrap();
        for direction in directions() {
            let input = fixture::request(direction, basis, [0x46; 32]).unwrap();
            let evaluated = evaluate_with_certificate(&input).unwrap();
            let original = evaluated.aux.encode();
            let row = 144 + (direction.stages() * 8192 - 1) * 45;
            let mut residue = original.clone();
            residue[row..row + 8].copy_from_slice(&basis.modulus().to_le_bytes());
            assert!(decode_aux(&residue).is_err());
            for (offset, bit) in [(8 + 8, 0x04u8), (17 + 6 * 4 + 3, 0x02)] {
                let mut forged = original.clone();
                forged[row + offset] |= bit;
                assert!(decode_aux(&forged).is_err());
            }
            let mut values = input.input().to_vec();
            values[8191] = basis.modulus();
            assert!(encode_request(direction, basis, input.binding(), &values).is_err());
            assert!(encode_request(direction, basis, input.binding(), &values[..8191]).is_err());
        }
    }
}

#[test]
fn raw_sdk_proof_with_prover_selected_constraints_cannot_replace_the_fixed_ntt() {
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
            self.base.main_next_row_columns()
        }
        fn preprocessed_next_row_columns(&self) -> Vec<usize> {
            self.base.preprocessed_next_row_columns()
        }
    }
    impl<AB: AirBuilder<F = backend::Val>> Air<AB> for ProverSelected {
        fn eval(&self, builder: &mut AB) {
            let zero = builder.main().current(0).unwrap();
            for _ in 0..self.constraints {
                builder.assert_zero(zero);
            }
        }
    }
    for (direction, basis) in representatives() {
        let input = fixture::request(direction, basis, [0x58; 32]).unwrap();
        let evaluated = evaluate_with_certificate(&input).unwrap();
        let value = (evaluated.output.coefficients()[8191] + 1) % basis.modulus();
        let (output, aux) = replace_final_output(&input, evaluated, 8191, value);
        let (air, values) = proof::statement(&input, &output, &aux).unwrap();
        let (cfg, report) = backend::config(&air, direction, basis).unwrap();
        let attacker = ProverSelected {
            base: air,
            constraints: report.constraints,
        };
        let (preprocessed, _) = p3_uni_stark::setup_preprocessed(&cfg, &attacker, 13)
            .unwrap()
            .unwrap();
        let main = RowMajorMatrix::new(
            vec![backend::Val::ZERO; 8192 * attacker.width()],
            attacker.width(),
        );
        let forged = p3_uni_stark::prove_with_preprocessed(
            &cfg,
            &attacker,
            main,
            &values,
            Some(&preprocessed),
        )
        .unwrap();
        let frame = proof::encode_frame(&input, &aux, &forged).unwrap();
        assert_eq!(
            verify(&input, &output, &frame).unwrap_err(),
            Error::Verification
        );
    }
}

#[test]
fn bounded_sdk_decoder_caps_and_frame_length_cannot_be_bypassed() {
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
    let valid = representative(Direction::Forward, Basis::new(0).unwrap());
    assert_eq!(
        verify(&valid.request, &valid.generated.output, &[]).unwrap_err(),
        Error::ProofLength
    );
    let oversized = vec![0; MAX_PROOF_BYTES + 1];
    assert_eq!(
        verify(&valid.request, &valid.generated.output, &oversized).unwrap_err(),
        Error::ProofLength
    );
    let mut trailing = valid.generated.proof.clone();
    trailing.push(0);
    assert_eq!(
        verify(&valid.request, &valid.generated.output, &trailing).unwrap_err(),
        Error::TrailingProofBytes
    );
}

#[test]
fn tracefree_shape_analysis_uses_each_real_fixed_air_and_preserves_security_targets() {
    use bfv_ntt_circuit::plonky3::NttAir;
    for index in 0..10 {
        let basis = Basis::new(index).unwrap();
        for direction in directions() {
            assert!(!NttAir::shape(direction, basis).is_prepared());
            let report = backend::analyze(direction, basis).unwrap();
            assert_eq!(report.trace_height, 8192);
            assert_eq!(report.basis_index, index);
            assert_eq!(report.modulus, basis.modulus());
            assert_eq!(report.public_values, 40);
            assert_eq!(report.queries, 192);
            assert_eq!(report.extension_degree, 5);
            assert_eq!(report.blowup, 8);
            assert!(report.constraints > 0 && report.degree <= 5);
            assert!(report.unique_decoding_bits >= 128 && report.list_decoding_bits >= 128);
        }
    }
}

#[test]
fn canonical_stage_order_swaps_cannot_replace_the_fixed_transform_schedule() {
    for (direction, basis) in representatives() {
        let input = fixture::request(direction, basis, [0x62; 32]).unwrap();
        let evaluated = evaluate_with_certificate(&input).unwrap();
        let mut encoded = evaluated.aux.encode();
        let stage_bytes = 8192 * 45;
        let (first, second) = encoded[144..144 + 2 * stage_bytes].split_at_mut(stage_bytes);
        assert_ne!(first, second);
        first.swap_with_slice(second);
        // The complete tuples and public hashes are rebuilt for their new
        // positions; the final output still agrees with the untouched last layer.
        let auxiliary = decode_aux(&encoded).unwrap();
        integer_rejects(&input, &evaluated.output, &auxiliary);
    }
}

#[test]
fn binary_goldilocks_rows_charge_all_eight_byte_slots_before_acceptance() {
    use p3_field::PrimeCharacteristicRing;
    let row = vec![backend::Val::from_u64(7); 448];
    let bytes = postcard::to_allocvec(&row).unwrap();
    let limits = bounded_postcard::Limits {
        max_sequence_elements: MAX_PROOF_SEQUENCE_ELEMENTS,
        // One vector slot plus eight binary byte-array slots per field.
        max_total_elements: 9 * row.len(),
    };
    assert_eq!(
        bounded_postcard::take_from_bytes::<Vec<backend::Val>>(
            &bytes,
            bounded_postcard::Limits {
                max_total_elements: limits.max_total_elements - 1,
                ..limits
            },
        )
        .unwrap_err(),
        bounded_postcard::Error::ResourceLimit
    );
    let (decoded, trailing) =
        bounded_postcard::take_from_bytes::<Vec<backend::Val>>(&bytes, limits).unwrap();
    assert_eq!(decoded, row);
    assert!(trailing.is_empty());
}
