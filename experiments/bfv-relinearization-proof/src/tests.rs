use super::*;
use bfv_relinearization_circuit::{
    Aux, DEGREE, MODULI, Output, Request, Role, decode_aux, decode_output, decode_request,
    encode_request, evaluate_with_certificate,
};
use std::sync::OnceLock;
fn roles() -> [Role; 2] {
    [Role::Embed, Role::AccumulateAndAdd]
}
struct Genuine {
    request: Request,
    generated: Generated,
}
fn representative(role: Role) -> &'static Genuine {
    static E: OnceLock<Genuine> = OnceLock::new();
    static A: OnceLock<Genuine> = OnceLock::new();
    let cell = match role {
        Role::Embed => &E,
        Role::AccumulateAndAdd => &A,
    };
    cell.get_or_init(|| {
        let request = fixture::request(role, [0x19; 32], [0x31; 32]).unwrap();
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
fn both_full8192_roles_have_genuine_serialized_proofs_verified_and_dropped_sequentially() {
    for role in roles() {
        let input = fixture::request(role, [0x71; 32], [0x75; 32]).unwrap();
        let generated = prove(&input).unwrap();
        let checked = verify(&input, &generated.output, &generated.proof).unwrap();
        assert!(checked.matches(&input, &generated.output));
        assert_eq!(checked.role(), role);
        assert_eq!(checked.keyset_context(), input.keyset_context());
        assert_eq!(
            generated.output.coefficients().len(),
            role.output_coefficients()
        );
        assert!(generated.proof.len() <= max_proof_bytes(role));
        // Each full proof drops at this boundary; no private state or proof bank.
    }
}
#[test]
fn genuine_foreign_roles_profiles_bindings_and_keyset_contexts_cannot_replace_expected_stage() {
    for role in roles() {
        let valid = representative(role);
        for offset in [0, 8, 39, 40, 71, 72, 103, 104, 105, 106, 107, 111] {
            let mut frame = valid.generated.proof.clone();
            frame[offset] ^= 1;
            assert_eq!(
                verify(&valid.request, &valid.generated.output, &frame).unwrap_err(),
                Error::Frame
            );
        }
        for (binding, keyset) in [
            ([0x99; 32], valid.request.keyset_context()),
            (valid.request.binding(), [0x99; 32]),
        ] {
            let changed = decode_request(
                &encode_request(role, binding, keyset, valid.request.input()).unwrap(),
            )
            .unwrap();
            assert!(verify(&changed, &valid.generated.output, &valid.generated.proof).is_err());
        }
        let other = representative(match role {
            Role::Embed => Role::AccumulateAndAdd,
            Role::AccumulateAndAdd => Role::Embed,
        });
        assert!(
            verify(
                &valid.request,
                &other.generated.output,
                &other.generated.proof
            )
            .is_err()
        );
    }
}
#[test]
fn complete_last_input_and_output_polynomials_are_bound_on_both_roles() {
    for role in roles() {
        let valid = representative(role);
        // Every public input polynomial is covered, including all85 MAC inputs.
        for (poly, &p) in role.input_moduli().iter().enumerate() {
            let mut values = valid.request.input().to_vec();
            let at = (poly + 1) * DEGREE - 1;
            values[at] = (values[at] + 1) % p;
            let changed = decode_request(
                &encode_request(
                    role,
                    valid.request.binding(),
                    valid.request.keyset_context(),
                    &values,
                )
                .unwrap(),
            )
            .unwrap();
            assert!(verify(&changed, &valid.generated.output, &valid.generated.proof).is_err());
        }
        for (poly, &p) in role.output_moduli().iter().enumerate() {
            let mut wire = valid.generated.output.encode();
            let at = 144 + ((poly + 1) * DEGREE - 1) * 8;
            let old = u64::from_le_bytes(wire[at..at + 8].try_into().unwrap());
            wire[at..at + 8].copy_from_slice(&((old + 1) % p).to_le_bytes());
            assert!(
                verify(
                    &valid.request,
                    &decode_output(&wire).unwrap(),
                    &valid.generated.proof
                )
                .is_err()
            );
        }
    }
}
fn replace_outputs(
    evaluated: bfv_relinearization_circuit::Evaluation,
    values: &[u64],
) -> (Output, Aux) {
    use sha2::{Digest, Sha256};
    let mut out = evaluated.output.encode();
    assert_eq!(values.len(), evaluated.output.role().output_coefficients());
    for (i, value) in values.iter().enumerate() {
        out[144 + 8 * i..152 + 8 * i].copy_from_slice(&value.to_le_bytes());
    }
    let mut aux = evaluated.aux.encode();
    aux[144..176].copy_from_slice(&Sha256::digest(&out));
    (decode_output(&out).unwrap(), decode_aux(&aux).unwrap())
}
fn rebind_altered_job(
    original: &Request,
    evaluated: bfv_relinearization_circuit::Evaluation,
) -> (Output, Aux) {
    use sha2::{Digest, Sha256};
    let input = Sha256::digest(original.encode());
    let mut out = evaluated.output.encode();
    out[112..144].copy_from_slice(&input);
    let mut aux = evaluated.aux.encode();
    aux[112..144].copy_from_slice(&input);
    aux[144..176].copy_from_slice(&Sha256::digest(&out));
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
fn canonical_rebuilt_last_word_forgery_reaches_every_embedding_and_accumulation_output() {
    for role in roles() {
        let input = fixture::request(role, [0x53; 32], [0x54; 32]).unwrap();
        for (poly, &p) in role.output_moduli().iter().enumerate() {
            let evaluated = evaluate_with_certificate(&input).unwrap();
            let mut values = evaluated.output.coefficients().to_vec();
            let at = (poly + 1) * DEGREE - 1;
            values[at] = (values[at] + 1) % p;
            let (out, aux) = replace_outputs(evaluated, &values);
            integer_rejects(&input, &out, &aux);
        }
    }
}
#[test]
fn canonical_embedding_quotient_two_is_checked_in_the_last_row_and_not_assumed_boolean() {
    let input = fixture::request(Role::Embed, [0x61; 32], [0x62; 32]).unwrap();
    let e = evaluate_with_certificate(&input).unwrap();
    let original = e.aux.encode();
    let at = 176 + (DEGREE - 1) * 25 + 2 * 5;
    assert_eq!(original[at], 2);
    let mut forged = original;
    forged[at] = 1;
    integer_rejects(&input, &e.output, &decode_aux(&forged).unwrap());
}
#[test]
fn all_ten_mac_quotients_and_every_final_chain_carry_are_checked_on_full_last_row() {
    let input = fixture::request(Role::AccumulateAndAdd, [0x39; 32], [0x40; 32]).unwrap();
    let e = evaluate_with_certificate(&input).unwrap();
    let original = e.aux.encode();
    let row = 176 + (DEGREE - 1) * 260;
    for poly in 0..10 {
        let mut forged = original.clone();
        let at = row + 6 * poly;
        let mut q = [0u8; 8];
        q[..6].copy_from_slice(&forged[at..at + 6]);
        let old = u64::from_le_bytes(q);
        let new = if old == 0 { 1 } else { old - 1 };
        forged[at..at + 6].copy_from_slice(&new.to_le_bytes()[..6]);
        integer_rejects(&input, &e.output, &decode_aux(&forged).unwrap());
    }
    for carry in 0..5 {
        let mut forged = original.clone();
        forged[row + 60 + 20 * 9 + 4 * carry] ^= 1;
        integer_rejects(&input, &e.output, &decode_aux(&forged).unwrap());
    }
}
#[test]
fn omitting_any_of_five_complete_digit_terms_cannot_rebuild_a_valid_original_job() {
    let input = fixture::request(Role::AccumulateAndAdd, [0x29; 32], [0x30; 32]).unwrap();
    let original = evaluate_with_certificate(&input).unwrap();
    for source in 0..5 {
        let mut values = input.input().to_vec();
        for target in 0..5 {
            values[(17 * target + 2 + source) * DEGREE..(17 * target + 3 + source) * DEGREE]
                .fill(0);
        }
        let altered = decode_request(
            &encode_request(
                input.role(),
                input.binding(),
                input.keyset_context(),
                &values,
            )
            .unwrap(),
        )
        .unwrap();
        let evaluated = evaluate_with_certificate(&altered).unwrap();
        assert_ne!(
            original.output.coefficients(),
            evaluated.output.coefficients()
        );
        let (out, aux) = rebind_altered_job(&input, evaluated);
        integer_rejects(&input, &out, &aux);
    }
}
#[test]
fn swapping_key_source_order_or_outer_components_cannot_rebind_to_the_original_input() {
    let input = fixture::request(Role::AccumulateAndAdd, [0x43; 32], [0x44; 32]).unwrap();
    let original = evaluate_with_certificate(&input).unwrap();
    let mut values = input.input().to_vec();
    for target in 0..5 {
        let base = 17 * target;
        for i in 0..DEGREE {
            values.swap((base + 7) * DEGREE + i, (base + 8) * DEGREE + i);
        }
    }
    let altered = decode_request(
        &encode_request(
            input.role(),
            input.binding(),
            input.keyset_context(),
            &values,
        )
        .unwrap(),
    )
    .unwrap();
    let evaluated = evaluate_with_certificate(&altered).unwrap();
    assert_ne!(
        original.output.coefficients(),
        evaluated.output.coefficients()
    );
    let (out, aux) = rebind_altered_job(&input, evaluated);
    integer_rejects(&input, &out, &aux);
    // Swap complete outputs plus their valid quotient/carry chains, preserving ranges/hashes.
    let mut values = original.output.coefficients().to_vec();
    for target in 0..5 {
        for i in 0..DEGREE {
            values.swap(2 * target * DEGREE + i, (2 * target + 1) * DEGREE + i);
        }
    }
    assert_ne!(values, original.output.coefficients());
    let (out, aux) = replace_outputs(original, &values);
    let mut wire = aux.encode();
    for row in wire[176..].as_chunks_mut::<260>().0 {
        for target in 0..5 {
            for i in 0..6 {
                row.swap(12 * target + i, 12 * target + 6 + i);
            }
            for i in 0..20 {
                row.swap(60 + 40 * target + i, 80 + 40 * target + i);
            }
        }
    }
    integer_rejects(&input, &out, &decode_aux(&wire).unwrap());
}
#[test]
fn noncanonical_residue_quotient_and_carry_aliases_reject_before_field_conversion() {
    for role in roles() {
        let input = fixture::request(role, [0x46; 32], [0x47; 32]).unwrap();
        let e = evaluate_with_certificate(&input).unwrap();
        let mut values = input.input().to_vec();
        let at = values.len() - 1;
        values[at] = *role.input_moduli().last().unwrap();
        assert!(encode_request(role, input.binding(), input.keyset_context(), &values).is_err());
        for (poly, &p) in role.output_moduli().iter().enumerate() {
            let mut out = e.output.encode();
            let at = 144 + ((poly + 1) * DEGREE - 1) * 8;
            out[at..at + 8].copy_from_slice(&p.to_le_bytes());
            assert!(decode_output(&out).is_err());
        }
        let mut aux = e.aux.encode();
        match role {
            Role::Embed => {
                aux[176 + (DEGREE - 1) * 25] = 1;
                assert!(decode_aux(&aux).is_err());
            }
            Role::AccumulateAndAdd => {
                let row = 176 + (DEGREE - 1) * 260;
                let bound = 5 * MODULI[4];
                aux[row + 54..row + 60].copy_from_slice(&bound.to_le_bytes()[..6]);
                assert!(decode_aux(&aux).is_err());
                let mut aux = e.aux.encode();
                let at = row + 60 + 20 * 9 + 4 * 4;
                aux[at..at + 4].copy_from_slice(&(1u32 << 25).to_le_bytes());
                assert!(decode_aux(&aux).is_err());
            }
        }
    }
}
#[test]
fn raw_sdk_prover_selected_equations_cannot_replace_either_fixed_arithmetic_role() {
    use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;
    struct Chosen {
        base: backend::BoundAir,
        constraints: usize,
    }
    impl BaseAir<backend::Val> for Chosen {
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
    impl<AB: AirBuilder<F = backend::Val>> Air<AB> for Chosen {
        fn eval(&self, b: &mut AB) {
            let zero = b.main().current(0).unwrap();
            for _ in 0..self.constraints {
                b.assert_zero(zero);
            }
        }
    }
    for role in roles() {
        let input = fixture::request(role, [0x58; 32], [0x59; 32]).unwrap();
        let e = evaluate_with_certificate(&input).unwrap();
        let mut values = e.output.coefficients().to_vec();
        let at = values.len() - 1;
        let p = *role.output_moduli().last().unwrap();
        values[at] = (values[at] + 1) % p;
        let (out, aux) = replace_outputs(e, &values);
        let (air, values) = proof::statement(&input, &out, &aux).unwrap();
        let (cfg, report) = backend::config(&air, role).unwrap();
        let attacker = Chosen {
            base: air,
            constraints: report.constraints,
        };
        let (pre, _) = p3_uni_stark::setup_preprocessed(&cfg, &attacker, 13)
            .unwrap()
            .unwrap();
        let forged = p3_uni_stark::prove_with_preprocessed(
            &cfg,
            &attacker,
            RowMajorMatrix::new(vec![backend::Val::ZERO; DEGREE], 1),
            &values,
            Some(&pre),
        )
        .unwrap();
        let frame = proof::encode_frame(&input, &aux, &forged).unwrap();
        assert_eq!(
            verify(&input, &out, &frame).unwrap_err(),
            Error::Verification
        );
    }
}
#[test]
fn genuine_foreign_public_preprocessing_does_not_supply_the_verifier_key() {
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;
    for role in roles() {
        let input = fixture::request(role, [0x83; 32], [0x84; 32]).unwrap();
        let e = evaluate_with_certificate(&input).unwrap();
        let (air, values) = proof::statement(&input, &e.output, &e.aux).unwrap();
        let (cfg, _) = backend::config(&air, role).unwrap();
        let mut wrong = input.input().to_vec();
        wrong[DEGREE - 1] = (wrong[DEGREE - 1] + 1) % MODULI[0];
        let foreign = decode_request(
            &encode_request(role, input.binding(), input.keyset_context(), &wrong).unwrap(),
        )
        .unwrap();
        let result = evaluate_with_certificate(&foreign).unwrap();
        let (attacker, _) = proof::statement(&foreign, &result.output, &result.aux).unwrap();
        let (pre, key) = p3_uni_stark::setup_preprocessed(&cfg, &attacker, 13)
            .unwrap()
            .unwrap();
        let forged = p3_uni_stark::prove_with_preprocessed(
            &cfg,
            &attacker,
            RowMajorMatrix::new(vec![backend::Val::ZERO; DEGREE], 1),
            &values,
            Some(&pre),
        )
        .unwrap();
        p3_uni_stark::verify_with_preprocessed(&cfg, &attacker, &forged, &values, Some(&key))
            .unwrap();
        let frame = proof::encode_frame(&input, &e.aux, &forged).unwrap();
        assert_eq!(
            verify(&input, &e.output, &frame).unwrap_err(),
            Error::Verification
        );
    }
}
#[test]
fn bounded_canonical_decoder_and_independent_role_caps_reject_malformed_proofs() {
    for role in roles() {
        let huge = postcard::to_allocvec(&usize::MAX).unwrap();
        assert_eq!(
            codec::take_from_bytes::<Vec<u64>>(role, &huge).unwrap_err(),
            Error::ProofResourceLimit
        );
        let nested = postcard::to_allocvec(&vec![vec![0u8; 4097]]).unwrap();
        assert_eq!(
            codec::take_from_bytes::<Vec<Vec<u8>>>(role, &nested).unwrap_err(),
            Error::ProofResourceLimit
        );
        let total = postcard::to_allocvec(&vec![vec![[0u8; 8]; 4096]; 65]).unwrap();
        assert_eq!(
            codec::take_from_bytes::<Vec<Vec<[u8; 8]>>>(role, &total).unwrap_err(),
            Error::ProofResourceLimit
        );
        let valid = representative(role);
        assert_eq!(
            verify(&valid.request, &valid.generated.output, &[]).unwrap_err(),
            Error::ProofLength
        );
        assert_eq!(
            verify(
                &valid.request,
                &valid.generated.output,
                &vec![0; max_proof_bytes(role) + 1]
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
}
#[test]
fn binary_goldilocks_public_rows_charge_each_byte_slot_in_both_role_budgets() {
    use p3_field::PrimeCharacteristicRing;
    for role in roles() {
        let row = vec![backend::Val::from_u64(7); role.preprocessed_width()];
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
}
#[test]
fn tracefree_analysis_uses_both_actual_fixed_roles_with_the_shared_profile_wrapper() {
    use bfv_relinearization_circuit::plonky3::ArithmeticAir;
    for role in roles() {
        assert!(!ArithmeticAir::shape(role).is_prepared());
        let r = backend::analyze(role).unwrap();
        assert_eq!(
            (
                r.trace_height,
                r.main_width,
                r.public_width,
                r.public_values
            ),
            (8192, 1, role.preprocessed_width(), 40)
        );
        assert_eq!((r.extension_degree, r.queries, r.blowup), (5, 192, 8));
        assert!(r.constraints > 0 && r.quotient_chunks <= 8);
        assert!(
            r.degree
                <= match role {
                    Role::Embed => 1,
                    Role::AccumulateAndAdd => 2,
                }
        );
        assert!(r.unique_decoding_bits >= 128 && r.list_decoding_bits >= 128);
    }
}
