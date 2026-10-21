//! Explicit public test inputs; random SDK key bytes stay guarded and are never printed.
use super::witness::{hash_fields, pack_secret};
use super::*;
use fhe::bfv::{BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, Plaintext, SecretKey};
use fhe_traits::{FheEncoder, FheEncrypter, Serialize};
use p3_field::PrimeCharacteristicRing;
use std::sync::{Arc, OnceLock};
use zeroize::Zeroizing;

pub(super) fn fixture() -> (Expected, Prepared) {
    static PARAMETERS: OnceLock<Arc<BfvParameters>> = OnceLock::new();
    let parameters = PARAMETERS.get_or_init(|| {
        BfvParametersBuilder::new()
            .set_degree(N)
            .set_plaintext_modulus(T)
            .set_moduli(&Q)
            .set_variance(10)
            .build_arc()
            .unwrap()
    });
    let key = SecretKey::random(parameters, &mut rand::rng());
    let mut source = Zeroizing::new(vec![0u64; N]);
    let mut mask = Zeroizing::new(vec![0u64; N]);
    for (i, (age, amount)) in [(0usize, 65535u64), (1, 0), (128, 255), (255, 65534)]
        .into_iter()
        .enumerate()
    {
        source[2 * i * 512 + age] = 256 + age as u64;
        source[(2 * i + 1) * 512 + age] = amount;
    }
    for age in 128..256 {
        mask[255 - age] = 1;
    }
    let mut ciphertexts = Vec::with_capacity(2);
    for raw in [&source, &mask] {
        let plaintext = Zeroizing::new(
            Plaintext::try_encode(raw.as_slice(), Encoding::poly(), parameters).unwrap(),
        );
        let ct: Ciphertext = key.try_encrypt(&*plaintext, &mut rand::rng()).unwrap();
        ciphertexts.push(
            Ciphertext::new(ct.iter().cloned().collect(), parameters)
                .unwrap()
                .to_bytes(),
        );
    }
    let request = Request::checked([0x61; 32], ciphertexts.try_into().unwrap()).unwrap();
    let contexts =
        core::array::from_fn(|role| core::array::from_fn(|i| Val::from_usize(101 + role * 16 + i)));
    let salts: [[u64; 4]; 3] = [[7, 8, 9, 10], [11, 12, 13, 14], [15, 16, 17, 18]];
    let words = [
        Zeroizing::new(source.iter().map(|&v| v * SCALE % T).collect::<Vec<_>>()),
        Zeroizing::new(mask.iter().map(|&v| v * SCALE % T).collect::<Vec<_>>()),
    ];
    let key_bytes = Zeroizing::new(key.to_bytes());
    let secret = Zeroizing::new(fhe::proto::bfv::SecretKey::from(&key).coeffs);
    let packed = pack_secret(&secret).unwrap();
    let roots = [
        hash_fields(contexts[0], &salts[0], &words[0]).unwrap(),
        hash_fields(contexts[1], &salts[1], &words[1]).unwrap(),
        hash_fields(contexts[2], &salts[2], &packed).unwrap(),
    ];
    let expected = Expected::checked(request, [0x71; 64], contexts, roots).unwrap();
    let [source, mask] = words;
    let prepared = Prepared::new(
        &expected,
        [
            ScaledOpening::checked(contexts[0], roots[0], source, Zeroizing::new(salts[0]))
                .unwrap(),
            ScaledOpening::checked(contexts[1], roots[1], mask, Zeroizing::new(salts[1])).unwrap(),
        ],
        SecretOpening::checked(contexts[2], roots[2], key_bytes, Zeroizing::new(salts[2])).unwrap(),
    )
    .unwrap();
    (expected, prepared)
}

#[test]
fn canonical_request_and_foreign_prepared_reject_before_main() {
    let (expected, prepared) = fixture();
    assert_eq!(
        Request::decode(expected.request().bytes()).unwrap().bytes(),
        expected.request().bytes()
    );
    let mut appended = expected.request().bytes().to_vec();
    appended.push(0);
    assert!(Request::decode(&appended).is_err());
    let mut foreign = expected.request().bytes().to_vec();
    foreign[8] ^= 1;
    assert!(matches!(Request::decode(&foreign), Err(Error::Encoding)));
    let mut nonce = expected.request().nonce();
    nonce[0] ^= 1;
    let bytes = expected.request().bytes();
    let a = u32::from_le_bytes(bytes[72..76].try_into().unwrap()) as usize;
    let changed = Request::checked(
        nonce,
        [bytes[80..80 + a].to_vec(), bytes[80 + a..].to_vec()],
    )
    .unwrap();
    assert_ne!(changed.q(), expected.request().q());
    let foreign =
        Expected::checked(changed, [0x71; 64], expected.contexts(), expected.roots()).unwrap();
    assert!(matches!(
        prepared.require_expected(&foreign),
        Err(Error::Binding)
    ));
    assert!(matches!(
        Request::checked([0; 32], [vec![], vec![]]),
        Err(Error::Binding)
    ));
}

#[test]
fn openings_reject_wrong_full_word_tail_salt_secret_and_bounds() {
    let context = [Val::ONE; 8];
    let salt = [1u64; 4];
    let words = Zeroizing::new(vec![0u64; N]);
    let root = hash_fields(context, &salt, &words).unwrap();
    let mut changed = words.clone();
    changed[N - 1] = 1;
    assert!(matches!(
        ScaledOpening::checked(context, root, changed, Zeroizing::new(salt)),
        Err(Error::Binding)
    ));
    let mut invalid = words.clone();
    invalid[N - 1] = T;
    assert!(matches!(
        ScaledOpening::checked(context, root, invalid, Zeroizing::new(salt)),
        Err(Error::Shape)
    ));
    assert!(matches!(
        ScaledOpening::checked(context, root, words, Zeroizing::new([2; 4])),
        Err(Error::Binding)
    ));
    let mut secret = Zeroizing::new(vec![0u8; N + 3]);
    secret[..3].copy_from_slice(&[0x0a, 0x80, 0x20]);
    let packed = pack_secret(&vec![0; N]).unwrap();
    let root = hash_fields(context, &salt, &packed).unwrap();
    let mut bad = secret.clone();
    bad[N + 2] = 42;
    assert!(matches!(
        SecretOpening::checked(context, root, bad, Zeroizing::new(salt)),
        Err(Error::Arithmetic)
    ));
    secret[N + 2] = 2;
    assert!(matches!(
        SecretOpening::checked(context, root, secret, Zeroizing::new(salt)),
        Err(Error::Binding)
    ));
}

#[test]
fn graph_fft_matches_independent_full_negacyclic_integer_oracle() {
    let fft = fft::Plan::new().unwrap();
    let a = (0..N)
        .map(|i| (i as u64 * 7919 + Q[0] - 2) % Q[0])
        .collect::<Vec<_>>();
    let s = Zeroizing::new((0..N).map(|i| (i % 41) as i64 - 20).collect::<Vec<_>>());
    let frequency = fft.secret_frequency(&s).unwrap();
    let actual = fft.product(&a, &frequency, Q[0]).unwrap();
    let mut expected = Zeroizing::new(vec![0i128; N]);
    for (i, &x) in a.iter().enumerate() {
        for (j, &y) in s.iter().enumerate() {
            let term = i128::from(x) * i128::from(y);
            if i + j < N {
                expected[i + j] += term
            } else {
                expected[i + j - N] -= term
            }
        }
    }
    for (a, e) in actual.iter().zip(expected.iter()) {
        assert_eq!(i128::from(*a), *e);
    }
}
