//! Explicit test data; actual random SDK key stays private and guarded.
use super::*;
use fhe::bfv::{BfvParametersBuilder, Ciphertext, Encoding, Plaintext, SecretKey};
use fhe_math::rq::{Poly, Representation, traits::TryConvertFrom};
use fhe_traits::{FheEncoder, FheEncrypter, Serialize};

fn naive(a: &[u64], s: &[i64]) -> Vec<i64> {
    let mut out = vec![0_i128; N];
    for (i, &x) in a.iter().enumerate() {
        for (j, &y) in s.iter().enumerate() {
            let term = i128::from(x) * i128::from(y);
            if i + j < N {
                out[i + j] += term;
            } else {
                out[i + j - N] -= term;
            }
        }
    }
    out.into_iter().map(|x| i64::try_from(x).unwrap()).collect()
}
#[test]
fn gold_dense_and_sparse_negacyclic_products_match_all4096_integer_coefficients() {
    let plan = fft::Plan::new().unwrap();
    let dense = (0..N)
        .map(|i| (i as u64 * 7919 + Q[0] - 2) % Q[0])
        .collect::<Vec<_>>();
    let s = (0..N).map(|i| (i % 41) as i64 - 20).collect::<Vec<_>>();
    let sf = plan.secret_frequency(&s).unwrap();
    assert_eq!(*plan.product(&dense, &sf, Q[0]).unwrap(), naive(&dense, &s));
    let mut a = vec![0; N];
    a[0] = Q[1] - 1;
    a[N - 1] = Q[1] - 2;
    let mut s = vec![0; N];
    s[0] = -20;
    s[1] = 20;
    s[N - 1] = 1;
    let sf = plan.secret_frequency(&s).unwrap();
    assert_eq!(*plan.product(&a, &sf, Q[1]).unwrap(), naive(&a, &s));
    assert!(plan.product(&a[..N - 1], &sf, Q[1]).is_err());
    a[N - 1] = Q[1];
    assert!(plan.product(&a, &sf, Q[1]).is_err());
}
#[test]
fn exact_sdk_ciphertexts_match_gold_witness_and_all4096_independent_sdk_poly_products() {
    // ONE genuine SDK key/input fixture serves the positive and hostile cases.
    let parameters = BfvParametersBuilder::new()
        .set_degree(N)
        .set_plaintext_modulus(T)
        .set_moduli(&Q)
        .set_variance(10)
        .build_arc()
        .unwrap();
    let key = SecretKey::random(&parameters, &mut rand::rng());
    let raw = [
        Zeroizing::new(
            (0..N)
                .map(|i| (i as u64 * 17 + 65535) % T)
                .collect::<Vec<_>>(),
        ),
        Zeroizing::new(
            (0..N)
                .map(|i| u64::from(i < 256 && i % 3 != 0))
                .collect::<Vec<_>>(),
        ),
    ];
    let mut ciphertexts = Vec::new();
    for values in &raw {
        let pt = Zeroizing::new(
            Plaintext::try_encode(values.as_slice(), Encoding::poly(), &parameters).unwrap(),
        );
        let ct: Ciphertext = key.try_encrypt(&*pt, &mut rand::rng()).unwrap();
        ciphertexts.push(Ciphertext::new(ct.iter().cloned().collect(), &parameters).unwrap());
    }
    let output = &ciphertexts[0] * &ciphertexts[1];
    let statement = Statement::new(
        [0x71; 32],
        [ciphertexts[0].to_bytes(), ciphertexts[1].to_bytes()],
        output.to_bytes(),
    )
    .unwrap();
    let key_wire = Zeroizing::new(key.to_bytes());
    let refs = [raw[0].as_slice(), raw[1].as_slice()];
    let mut witness =
        Witness::from_sdk_key(&statement, refs, Zeroizing::new(key_wire.to_vec())).unwrap();
    witness.check(&statement, refs).unwrap();
    assert_eq!(
        (u128::from(Q[0]) * u128::from(Q[1]) % u128::from(T)) as u64,
        SCALE
    );
    for basis in 0..2 {
        assert_eq!(
            (u128::from(DELTA[basis]) * u128::from(Q[basis] - T) % u128::from(Q[basis])) as u64,
            1
        );
    }
    let ctx = parameters.context_at_level(0).unwrap();
    let mut sdk_s = Zeroizing::new(
        Poly::try_convert_from(
            witness.secret.as_slice(),
            ctx,
            false,
            Representation::PowerBasis,
        )
        .unwrap(),
    );
    sdk_s.change_representation(Representation::Ntt);
    let plan = fft::Plan::new().unwrap();
    let sf = plan.secret_frequency(&witness.secret).unwrap();
    for (operand, ct) in ciphertexts.iter().enumerate() {
        let mut sdk_as = Zeroizing::new(&ct[1] * &*sdk_s);
        sdk_as.change_representation(Representation::PowerBasis);
        for (basis, &q) in Q.iter().enumerate() {
            let gold = plan
                .product(&statement.input(2 * operand + 1)[basis], &sf, q)
                .unwrap();
            for at in 0..N {
                assert!(
                    i128::from(gold[at]).rem_euclid(i128::from(q)) as u64
                        == sdk_as.coefficients()[[basis, at]],
                    "private SDK polynomial oracle mismatch"
                );
            }
        }
    }
    // Wrong, still CBD-range-valid S: a public A coefficient away from +-40
    // prevents its constant shift from being absorbed by ANY allowed error.
    let inputs = Inputs::new(&statement).unwrap();
    assert!(
        inputs.components[1][0]
            .iter()
            .any(|&a| a > 40 && a < Q[0] - 40)
    );
    let s0 = witness.secret[0];
    let changed = if s0 == 20 { s0 - 1 } else { s0 + 1 };
    let mut wrong_key = Zeroizing::new(key_wire.to_vec());
    wrong_key[3] = ((changed << 1) ^ (changed >> 63)) as u8;
    assert!(Witness::from_sdk_key(&statement, refs, wrong_key).is_err());
    witness.secret[0] = changed;
    assert!(witness.check(&statement, refs).is_err());
    witness.secret[0] = s0;

    // A basis-local c0 error is individually small in BOTH bases, but there
    // is no shared E. Derivation must reject even if it may choose fresh K.
    let at = N - 1;
    let delta = if witness.errors[0][at] == 20 { -1 } else { 1 };
    let mut c0 = inputs.components[0][1].to_vec();
    c0[at] = (i128::from(c0[at]) + delta).rem_euclid(i128::from(Q[1])) as u64;
    let mut attacked = inputs;
    attacked.components[0][1] = &c0;
    assert!(Witness::derive_inputs(attacked, refs, Zeroizing::new(key_wire.to_vec())).is_err());
    assert!(witness.check_inputs(attacked, refs).is_err());

    // Swapped Q-basis data is re-canonicalized: failure is not a range oracle.
    let wrong_basis = inputs.components[1][0]
        .iter()
        .map(|&v| v % Q[1])
        .collect::<Vec<_>>();
    let mut attacked = inputs;
    attacked.components[1][1] = &wrong_basis;
    assert!(witness.check_inputs(attacked, refs).is_err());
    let mut a = inputs.components[1][0].to_vec();
    a[at] = (a[at] + 1) % Q[0];
    let mut attacked = inputs;
    attacked.components[1][0] = &a;
    assert!(witness.secret.iter().any(|&s| s != 0));
    assert!(witness.check_inputs(attacked, refs).is_err());
    let mut high_word = Zeroizing::new(raw[0].to_vec());
    high_word[at] = (high_word[at] + 1) % T;
    assert!(
        witness
            .check(&statement, [high_word.as_slice(), raw[1].as_slice()])
            .is_err()
    );
    let k = witness.quotients[1][1][at];
    witness.quotients[1][1][at] = k + 1;
    assert!(witness.check(&statement, refs).is_err());
    witness.quotients[1][1][at] = k;
    witness.quotients[1][1][at] = MAX_K + 1;
    assert!(witness.check(&statement, refs).is_err());
    witness.quotients[1][1][at] = k;
    // The full original request identity, not merely nonce, is independently pinned.
    let replacement = Statement::new(
        [0x72; 32],
        [ciphertexts[0].to_bytes(), ciphertexts[1].to_bytes()],
        output.to_bytes(),
    )
    .unwrap();
    assert!(matches!(
        witness.check(&replacement, refs),
        Err(Error::Binding)
    ));
    let replacement = Statement::new(
        statement.binding(),
        [ciphertexts[1].to_bytes(), ciphertexts[0].to_bytes()],
        output.to_bytes(),
    )
    .unwrap();
    assert!(matches!(
        witness.check(&replacement, refs),
        Err(Error::Binding)
    ));
    witness.check(&statement, refs).unwrap();
}
#[test]
fn fixed_sdk_secret_codec_rejects_unknown_trailing_noncanonical_and_oversized_values() {
    let mut bytes = vec![0x0a, 0x80, 0x20];
    bytes.resize(N + 3, 0);
    assert!(decode_sdk_secret(Zeroizing::new(bytes.clone())).is_ok());
    for at in [0, 1, 2, 3, N + 2] {
        let mut altered = Zeroizing::new(bytes.clone());
        altered[at] = 0xff;
        assert!(decode_sdk_secret(altered).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(decode_sdk_secret(Zeroizing::new(extra)).is_err());
    bytes.pop();
    assert!(decode_sdk_secret(Zeroizing::new(bytes)).is_err());
}
