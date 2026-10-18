//! Explicit PUBLIC NONSECRET SDK mathematical fixtures. Owner policy is tested in Core.
use super::*;
use bfv_hiding_stark::Val;
use fhe::bfv::{Ciphertext, Encoding, Plaintext, SecretKey};
use fhe_math::rq::{Poly, Representation, traits::TryConvertFrom};
use fhe_traits::{DeserializeParametrized, FheEncoder, FheEncrypter, Serialize};
use p3_air::{BaseAir, check_all_constraints, check_constraints};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use zeroize::Zeroizing;
struct Fixture {
    expected: Expected,
    opening: EncodedOpening,
    shat: Zeroizing<Vec<u64>>,
    salts: [[u64; 4]; 6],
}
fn fixture() -> Fixture {
    let parameters = bfv_basis_convolution::parameters();
    let secret = SecretKey::random(&parameters, &mut rand::rng());
    let wide = Zeroizing::new(fhe::proto::bfv::SecretKey::from(&secret).coeffs);
    let coefficients = Zeroizing::new(
        wide.iter()
            .map(|v| i8::try_from(*v).unwrap())
            .collect::<Vec<_>>(),
    );
    let shat: Zeroizing<Vec<u64>> = Zeroizing::new(
        bfv_key_transform::circuit::oracle(
            &coefficients
                .iter()
                .copied()
                .map(bfv_key_transform::signed)
                .collect::<Vec<_>>(),
        )
        .iter()
        .map(|v| v.as_canonical_u64())
        .collect(),
    );
    let key = bfv_key_transform::ProverWitness::new(coefficients, [1; 4], [2; 4])
        .unwrap()
        .statement(bfv_key_transform::SetupDescriptor {
            database: [3; 16],
            key_domain: [4; 16],
            public_setup_digest: bfv_basis_convolution::setup_digest(),
            key_epoch: 1,
        });
    let unscaled: Vec<_> = (0..N).map(|j| (j as u64 * 71) % 114689).collect();
    let plaintext = Plaintext::try_encode(&unscaled, Encoding::poly(), &parameters).unwrap();
    let ciphertext: Ciphertext = secret.try_encrypt(&plaintext, &mut rand::rng()).unwrap();
    let bytes = Ciphertext::new(ciphertext.iter().cloned().collect(), &parameters)
        .unwrap()
        .to_bytes();
    let salts = core::array::from_fn(|i| [i as u64 + 11; 4]);
    let bases = core::array::from_fn(|i| {
        let expected = bfv_basis_convolution::Expected::new(
            key.clone(),
            &parameters.to_bytes(),
            &bytes,
            [5; 32],
            i,
        )
        .unwrap();
        bfv_basis_convolution::ProverWitness::new(&shat, [2; 4], salts[i])
            .unwrap()
            .statement(expected)
    });
    let w = Zeroizing::new(
        unscaled
            .iter()
            .map(|m| m * 78307 % 114689)
            .collect::<Vec<_>>(),
    );
    let context = [7u64; 8];
    let salt = [8u64; 4];
    let root = bfv_key_transform::circuit::digest(
        context.map(Val::from_u64),
        salt.map(Val::from_u64),
        &w.iter().copied().map(Val::from_u64).collect::<Vec<_>>(),
    )
    .map(|v| v.as_canonical_u64());
    let commitment = EncodedCommitment::new([9; 32], context, root).unwrap();
    let opening = EncodedOpening::new(w, salt, commitment.clone()).unwrap();
    Fixture {
        expected: Expected::new(commitment, bases).unwrap(),
        opening,
        shat,
        salts,
    }
}
fn witness(f: &Fixture) -> ProverWitness<'_> {
    ProverWitness::new(
        &f.opening,
        &f.shat,
        core::array::from_fn(|i| f.salts[i]),
        f.salts[5],
    )
    .unwrap()
}
fn changed_b(f: &Fixture, amount: i64, only: Option<usize>) -> Expected {
    let parameters = bfv_basis_convolution::parameters();
    let ciphertext = Ciphertext::from_bytes(f.expected.ciphertext().bytes(), &parameters).unwrap();
    let mut polynomials = ciphertext.iter().cloned().collect::<Vec<_>>();
    polynomials[0].change_representation(Representation::PowerBasis);
    let mut coefficients = polynomials[0]
        .coefficients()
        .iter()
        .copied()
        .collect::<Vec<_>>();
    for (i, q) in Q.into_iter().enumerate() {
        if only.is_none() || only == Some(i) {
            let at = i * N + N - 1;
            coefficients[at] = (i128::from(coefficients[at]) + i128::from(amount))
                .rem_euclid(i128::from(q)) as u64;
        }
    }
    polynomials[0] = Poly::try_convert_from(
        coefficients,
        parameters.context_at_level(0).unwrap(),
        false,
        Representation::PowerBasis,
    )
    .unwrap();
    polynomials[0].change_representation(Representation::Ntt);
    let bytes = Ciphertext::new(polynomials, &parameters)
        .unwrap()
        .to_bytes();
    assert_ne!(bytes, f.expected.ciphertext().bytes());
    let bases = core::array::from_fn(|i| {
        let expected = bfv_basis_convolution::Expected::new(
            f.expected.key().clone(),
            &parameters.to_bytes(),
            &bytes,
            f.expected.request(),
            i,
        )
        .unwrap();
        bfv_basis_convolution::ProverWitness::new(&f.shat, [2; 4], f.salts[i])
            .unwrap()
            .statement(expected)
    });
    Expected::new(f.expected.encoding().clone(), bases).unwrap()
}
#[test]
fn caller_owned_scaled_opening_checks_all8192_words_salt_context_and_exact_root() {
    let f = fixture();
    for length in [N - 1, N + 1] {
        assert!(
            EncodedOpening::new(
                Zeroizing::new(vec![0; length]),
                [8; 4],
                f.expected.encoding().clone()
            )
            .is_err()
        );
    }
    let mut words = f.opening.w.to_vec();
    words[N - 1] = 114689;
    assert!(
        EncodedOpening::new(Zeroizing::new(words), [8; 4], f.expected.encoding().clone()).is_err()
    );
    for part in 0..3 {
        let mut words = f.opening.w.to_vec();
        let mut salt = [8; 4];
        let mut c = f.expected.encoding().clone();
        match part {
            0 => words[N - 1] = (words[N - 1] + 1) % 114689,
            1 => salt[3] += 1,
            _ => {
                let mut context = c.context();
                context[7] += 1;
                c = EncodedCommitment::new(c.producer_identity(), context, c.root()).unwrap();
            }
        }
        assert!(EncodedOpening::new(Zeroizing::new(words), salt, c).is_err());
    }
}
#[test]
fn actual_sdk_unknown_rng_recovers_one_common_bounded_noise_and_all40960_integer_equations() {
    let f = fixture();
    let w = witness(&f);
    let prepared = w.prepare(&f.expected, [6; 32]).unwrap();
    for i in 0..5 {
        for j in 0..N {
            assert!((-20..=20).contains(&prepared.error[j]));
            assert_eq!(
                i128::from(f.expected.bases()[i].expected.ciphertext().b_coefficients()[j])
                    + prepared.r[i][j]
                    - i128::from(prepared.error[j])
                    - i128::from(DELTA[i]) * i128::from(prepared.w[j]),
                i128::from(Q[i]) * prepared.k[i][j]
            );
        }
    }
    let air = prepared.statement.air().unwrap();
    assert_eq!(
        (
            air.width(),
            air.num_public_values(),
            air.num_periodic_columns()
        ),
        (12752, 44, 592)
    );
    let trace = prepared.trace().unwrap();
    check_constraints(&air, &trace, &prepared.statement.public_values());
}
#[test]
fn canonical_b_changes_with_valid_basis_claims_cannot_hide_differing_or_out_of_support_noise() {
    let f = fixture();
    let w = witness(&f);
    let honest = w.prepare(&f.expected, [6; 32]).unwrap();
    let last = i64::from(honest.error[N - 1]);
    let inconsistent = changed_b(&f, if last == 20 { -1 } else { 1 }, Some(4));
    assert!(w.prepare(&inconsistent, [6; 32]).is_err());
    for target in [-21, 21] {
        let excessive = changed_b(&f, i64::from(target) - last, None);
        assert!(w.prepare(&excessive, [6; 32]).is_err());
    }
    // A coherent +1 residual within support is a valid repaired mathematical control.
    let delta = if last == 20 { -1 } else { 1 };
    let repaired = changed_b(&f, delta, None);
    let repaired = w.prepare(&repaired, [6; 32]).unwrap();
    assert_eq!(i64::from(repaired.error[N - 1]), last + delta);
    check_constraints(
        &repaired.statement.air().unwrap(),
        &repaired.trace().unwrap(),
        &repaired.statement.public_values(),
    );
}
#[test]
fn missing_key_or_basis_never_reaches_formation_claim_factory() {
    let f = fixture();
    let p = Prerequisites {
        key: &[],
        bases: [&[]; 5],
    };
    let entered = std::cell::Cell::new(false);
    let result = evidence::prove_with_factory([6; 32], &f.expected, &p, || {
        entered.set(true);
        panic!("must reject before private witness factory")
    });
    assert!(result.is_err());
    assert!(!entered.get());
}
#[test]
fn last_biased_quotient_bit_forgery_fails_the_actual_shared_integer_air() {
    let f = fixture();
    let w = witness(&f);
    let prepared = w.prepare(&f.expected, [6; 32]).unwrap();
    let mut trace = prepared.trace().unwrap();
    let at = 511 * circuit::WIDTH + circuit::COEFFICIENTS + 15 * circuit::LANE_BITS;
    trace.values[at + 315] = Val::ONE - trace.values[at + 315];
    let _ = circuit::refresh_contexts(prepared.statement.contexts(), &mut trace);
    assert!(
        !check_all_constraints(
            &prepared.statement.air().unwrap(),
            &trace,
            &prepared.statement.public_values(),
            Some(1)
        )
        .is_ok()
    );
    let config = bfv_hiding_stark::config().unwrap();
    let air = prepared.statement.air().unwrap();
    if let Ok(proof) =
        p3_uni_stark::prove(&config, &air, trace, &prepared.statement.public_values())
    {
        assert!(
            p3_uni_stark::verify(&config, &air, &proof, &prepared.statement.public_values())
                .is_err()
        );
    }
}
