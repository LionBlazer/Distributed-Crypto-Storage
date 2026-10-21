//! Public arithmetic conformance and rejection examples; no proof/SQL acceptance fixtures.
use super::*;
use crate::geometry::{N, Q, T};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
fn request(role: Role, variant: usize) -> Request {
    let product: BigUint = role
        .input_moduli()
        .iter()
        .map(|&p| BigUint::from(p))
        .product();
    let half = product >> 1usize;
    let input = role
        .input_moduli()
        .iter()
        .enumerate()
        .map(|(basis, &p)| {
            (0..N)
                .map(|index| match variant {
                    0 => 0,
                    1 => p - 1,
                    2 => match (index + 3 * basis) % 7 {
                        0 => 0,
                        1 => 1,
                        2 => p - 1,
                        3 => p / 2,
                        _ => {
                            ((index as u128 * 987654321 + basis as u128 * 123456789 + 17)
                                % p as u128) as u64
                        }
                    },
                    3 => {
                        let x = if index % 3 == 0 {
                            half.clone() - 1u64
                        } else if index % 3 == 1 {
                            half.clone()
                        } else {
                            half.clone() + 1u64
                        };
                        (x % p).to_u64().unwrap()
                    }
                    _ => unreachable!(),
                })
                .collect::<Vec<_>>()
        })
        .collect();
    Request::new(role, [0x39; 32], input).unwrap()
}
fn sdk_scaler(role: Role) -> fhe_math::rq::scaler::Scaler {
    use fhe_math::{
        rns::ScalingFactor,
        rq::{Context, scaler::Scaler},
    };
    let from = Context::new_arc(role.input_moduli(), N).unwrap();
    let to = Context::new_arc(role.output_moduli(), N).unwrap();
    let factor = if role == Role::Extend2To4 {
        ScalingFactor::one()
    } else {
        ScalingFactor::new(
            &BigUint::from(T),
            &Q.iter().map(|&p| BigUint::from(p)).product(),
        )
    };
    Scaler::new(&from, &to, factor).unwrap()
}
fn sdk_output(request: &Request, scaler: &fhe_math::rq::scaler::Scaler) -> Vec<Vec<u64>> {
    use fhe_math::rq::{Context, Poly, Representation, traits::TryConvertFrom};
    let context = Context::new_arc(request.role.input_moduli(), N).unwrap();
    let coefficients = ndarray::Array2::from_shape_vec(
        (request.role.input_moduli().len(), N),
        request.input.iter().flatten().copied().collect(),
    )
    .unwrap();
    let input =
        Poly::try_convert_from(coefficients, &context, false, Representation::PowerBasis).unwrap();
    let output = input.scale(scaler).unwrap();
    output
        .coefficients()
        .outer_iter()
        .map(|row| row.to_vec())
        .collect()
}
#[test]
fn both_complete_scalers_match_actual_sdk_on_all4096_coefficients_including_centered_crt_boundaries()
 {
    for role in [Role::Extend2To4, Role::Scale4To2] {
        let scaler = sdk_scaler(role);
        for variant in 0..4 {
            let r = request(role, variant);
            let e = evaluate(&r).unwrap();
            let native = sdk_output(&r, &scaler);
            assert!(
                e.output.rows() == native,
                "complete public SDK coefficient oracle mismatch"
            );
            verify_certificate(&r, &e.output, &e.certificate).unwrap();
            let wire = e.certificate.encode().unwrap();
            assert_eq!(wire.len(), 131216);
            let decoded = PublicCertificate::decode(&wire).unwrap();
            assert!(decoded.encode().unwrap() == wire);
            verify_certificate(&r, &e.output, &decoded).unwrap();
        }
    }
}
#[test]
fn sdk_scaler_certificate_does_not_claim_ideal_rounding_for_arbitrary_qp_midpoints() {
    let r = request(Role::Scale4To2, 3);
    let native = sdk_output(&r, &sdk_scaler(Role::Scale4To2));
    let evaluated = evaluate(&r).unwrap();
    assert_eq!(evaluated.output.rows(), native);
    verify_certificate(&r, &evaluated.output, &evaluated.certificate).unwrap();

    // Index1 is x=(QP-1)/2. The directed fixed-precision SDK algorithm is
    // faithfully certified, but this arbitrary QP midpoint is outside the
    // centered depth-one tensor bound supplied by the complete product relation.
    let modulus: BigUint = crate::QP.iter().map(|&p| BigUint::from(p)).product();
    let q: BigUint = Q.iter().map(|&p| BigUint::from(p)).product();
    let half = modulus >> 1usize;
    for (row, &p) in r.rows().iter().zip(&crate::QP) {
        assert_eq!(row[1], (&half % p).to_u64().unwrap());
    }
    let ideal = (BigUint::from(T) * half + (&q >> 1usize)) / q;
    let ideal_residues = Q.map(|p| (&ideal % p).to_u64().unwrap());
    let actual = [native[0][1], native[1][1]];
    assert_eq!(actual, [1_072_594_946, 513_385_678]);
    assert_eq!(ideal_residues, [1_097_726, 560_282_418]);
    assert_ne!(actual, ideal_residues);
}
#[test]
fn full_frame_decoder_rejects_profile_role_reserved_highbits_short_and_trailing_bytes() {
    for role in [Role::Extend2To4, Role::Scale4To2] {
        let e = evaluate(&request(role, 0)).unwrap();
        let wire = e.certificate.encode().unwrap();
        for (offset, bit) in [
            (0, 1),
            (8, 128),
            (9, 1),
            (48, 1),
            (HEADER_BYTES + 13, 64),
            (HEADER_BYTES + 22, 4),
            (CERTIFICATE_BYTES - 1, 4),
        ] {
            let mut changed = wire.clone();
            changed[offset] ^= bit;
            assert!(PublicCertificate::decode(&changed).is_err());
        }
        assert!(PublicCertificate::decode(&wire[..wire.len() - 1]).is_err());
        let mut changed = wire.clone();
        changed.push(0);
        assert!(PublicCertificate::decode(&changed).is_err());
    }
}
#[test]
fn repaired_last_output_binding_still_fails_and_every_quotient_is_checked_without_rerunning_sdk() {
    for role in [Role::Extend2To4, Role::Scale4To2] {
        let r = request(role, 2);
        let e = evaluate(&r).unwrap();
        for component in 0..2 {
            let mut forged = e.output.clone();
            let at = role.computed_offset() + component;
            forged.coefficients[at][N - 1] =
                (forged.coefficients[at][N - 1] + 1) % role.computed_moduli()[component];
            let mut certificate = e.certificate.clone();
            certificate.output_digest = output_digest(&forged);
            assert!(matches!(
                verify_certificate(&r, &forged, &certificate),
                Err(Error::Arithmetic)
            ));
        }
        for field in 0..4 {
            let mut certificate = e.certificate.clone();
            let row = &mut certificate.rows[N - 1];
            match field {
                0 => row.v ^= 1,
                1 => row.biased_w ^= 1,
                2 => row.biased_k[0] ^= 1,
                _ => row.biased_k[1] ^= 1,
            }
            assert!(matches!(
                verify_certificate(&r, &e.output, &certificate),
                Err(Error::Arithmetic)
            ));
        }
        let mut forged_input = r.clone();
        forged_input.input[0][N - 1] ^= 1;
        assert!(matches!(
            verify_certificate(&forged_input, &e.output, &e.certificate),
            Err(Error::Binding)
        ));
        let changed_binding = Request::new(role, [0x41; 32], r.input.clone()).unwrap();
        assert!(matches!(
            verify_certificate(&changed_binding, &e.output, &e.certificate),
            Err(Error::Binding)
        ));
        let mut range = e.certificate.clone();
        range.rows[N - 1].biased_w = 1 << 46;
        assert!(matches!(
            verify_certificate(&r, &e.output, &range),
            Err(Error::Arithmetic)
        ));
        for j in 0..2 {
            let mut range = e.certificate.clone();
            range.rows[N - 1].biased_k[j] = 1 << 66;
            assert!(matches!(
                verify_certificate(&r, &e.output, &range),
                Err(Error::Arithmetic)
            ));
        }
    }
}
#[test]
fn copied_q_prefix_and_last_input_residue_cannot_be_repaired_into_an_accepted_extension() {
    let r = request(Role::Extend2To4, 1);
    let e = evaluate(&r).unwrap();
    for q in 0..2 {
        let mut forged = e.output.clone();
        forged.coefficients[q][N - 1] = 0;
        let mut certificate = e.certificate.clone();
        certificate.output_digest = output_digest(&forged);
        assert!(matches!(
            verify_certificate(&r, &forged, &certificate),
            Err(Error::Arithmetic)
        ));
    }
    for role in [Role::Extend2To4, Role::Scale4To2] {
        let r = request(role, 0);
        let e = evaluate(&r).unwrap();
        let mut changed = r.clone();
        let basis = role.input_moduli().len() - 1;
        changed.input[basis][N - 1] = role.input_moduli()[basis];
        assert!(matches!(
            verify_certificate(&changed, &e.output, &e.certificate),
            Err(Error::Arithmetic)
        ));
        let mut out = e.output.clone();
        let basis = role.output_moduli().len() - 1;
        out.coefficients[basis][N - 1] = role.output_moduli()[basis];
        assert!(matches!(
            verify_certificate(&r, &out, &e.certificate),
            Err(Error::Arithmetic)
        ));
    }
}
#[test]
fn fixed_constructor_theta_bounds_justify_all_signed256_dot_products_and_compact_quotient_ranges() {
    use ethnum::I256;
    for role in [Role::Extend2To4, Role::Scale4To2] {
        let c = constants::constants(role);
        assert_eq!(c.shift, 127);
        assert!(c.t.iter().all(|&t| t < (1u128 << 127)));
        let max_r: u128 = role.input_moduli().iter().map(|&p| u128::from(p - 1)).sum();
        assert!(max_r < (1u128 << 63) + (1u128 << 31));
        // Hence v<2^64, S<2^191 and every signed dot product is far below2^255.
        let mut max_e = I256::ZERO;
        for (&p, theta) in role.input_moduli().iter().zip(&c.theta) {
            max_e += I256::from(p - 1) * I256::from(theta.magnitude);
        }
        assert!(max_e < (I256::ONE << 157));
        // Thus |w|<=2^30+1. For either output modulus p>=2^29:
        // -v-|w|/p < k < sum(r)+|w|/p. Both biased bounds fit66bits.
        let bound_w =
            (max_e + I256::from(1u128 << 126)).div_euclid(I256::from(1u128 << 127)) + I256::ONE;
        assert!(bound_w < I256::from(1u64 << 32));
        for &p in role.computed_moduli() {
            let extra = bound_w.div_euclid(I256::from(p)) + I256::ONE;
            assert!(I256::from(max_r) + extra < I256::from(K_OFFSET));
        }
        if role == Role::Extend2To4 {
            assert!(c.theta.iter().all(|t| t.magnitude == 0));
        } else {
            assert!(c.theta[2..].iter().all(|t| t.magnitude == 0));
        }
    }
}
