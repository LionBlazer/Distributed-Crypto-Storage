//! PUBLIC NONSECRET fixtures. No Source/Formation proof or admitted DATA token.
use super::*;
use fhe::bfv::{BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, Plaintext, SecretKey};
use fhe_traits::{FheEncoder, FheEncrypter, Serialize};
use std::sync::{Arc, OnceLock};
struct Fixture {
    key: KeyExpected,
    sdk: Zeroizing<Vec<u8>>,
    salt: Zeroizing<[u64; 4]>,
    data: lower::data::Expected,
    plain: Zeroizing<Vec<u64>>,
}
pub(super) fn scope() -> InputScope {
    InputScope {
        database: [1; 16],
        transaction: 7,
        call: 3,
        principal: 1,
        application: [2; 32],
        genesis: [3; 32],
        rules: [4; 32],
        context: [5; 32],
        parent: [6; 32],
        client: [7; 32],
        controller: [8; 32],
        source_version: [9; 32],
        data_admission: [10; 32],
        snapshot: [11; 32],
        statement: [12; 32],
        command: [13; 32],
        attempt: [14; 32],
        nonce: [15; 32],
    }
}
fn bits() -> [u8; 32] {
    let mut out = [0; 32];
    for age in 128..256 {
        out[age / 8] |= 1 << (age % 8);
    }
    out
}
impl Fixture {
    fn new() -> Self {
        static PARAMETERS: OnceLock<Arc<BfvParameters>> = OnceLock::new();
        let p = PARAMETERS.get_or_init(|| {
            BfvParametersBuilder::new()
                .set_degree(N)
                .set_plaintext_modulus(T)
                .set_moduli(&Q)
                .set_variance(10)
                .build_arc()
                .unwrap()
        });
        let key = SecretKey::random(p, &mut rand::rng());
        let sdk = Zeroizing::new(key.to_bytes());
        let secret = Zeroizing::new(fhe::proto::bfv::SecretKey::from(&key).coeffs);
        let salt = Zeroizing::new([11, 12, 13, 14]);
        let key_context = core::array::from_fn(|i| Val::from_usize(31 + i));
        let packed = Zeroizing::new(
            secret
                .as_chunks::<8>()
                .0
                .iter()
                .map(|r| {
                    r.iter()
                        .enumerate()
                        .fold(0, |word, (i, v)| word | (((*v + 20) as u64) << (6 * i)))
                })
                .collect::<Vec<_>>(),
        );
        let cs = owner::commit_words(key_context, &salt, &packed).unwrap();
        let expected = KeyExpected::checked(
            [0x71; 32],
            Parameters::fixed(),
            key_context.map(|v| v.as_canonical_u64()),
            cs.map(|v| v.as_canonical_u64()),
        )
        .unwrap();
        let mut raw = Zeroizing::new(vec![0; N]);
        for (i, (age, amount)) in [(0usize, 65535u64), (1, 0), (128, 255), (255, 65534)]
            .into_iter()
            .enumerate()
        {
            raw[2 * i * 512 + age] = 256 + age as u64;
            raw[(2 * i + 1) * 512 + age] = amount;
        }
        let plaintext =
            Zeroizing::new(Plaintext::try_encode(raw.as_slice(), Encoding::poly(), p).unwrap());
        let ct: Ciphertext = key.try_encrypt(&*plaintext, &mut rand::rng()).unwrap();
        let ct = Ciphertext::new(ct.iter().cloned().collect(), p).unwrap();
        let request = lower::data::Request::checked([0x72; 32], ct.to_bytes()).unwrap();
        let context = core::array::from_fn(|i| Val::from_usize(51 + i));
        let words = Zeroizing::new(raw.iter().map(|v| v * SCALE % T).collect::<Vec<_>>());
        let cw = owner::commit_words(context, &[4; 4], &words).unwrap();
        let data =
            lower::data::Expected::checked(request, [0x73; 64], [context, key_context], [cw, cs])
                .unwrap();
        Self {
            key: expected,
            sdk,
            salt,
            data,
            plain: raw,
        }
    }
    fn owner(&self) -> Owner {
        Owner::from_sdk(self.key.clone(), self.sdk.clone(), self.salt.clone()).unwrap()
    }
}
pub(super) fn oracle(data: &[u64], mask: &Mask256) -> Zeroizing<Vec<u64>> {
    let mask = mask.raw_words();
    let mut out = Zeroizing::new(vec![0; N]);
    for (i, &a) in data.iter().enumerate().filter(|(_, v)| **v != 0) {
        for (j, &b) in mask.iter().enumerate().filter(|(_, v)| **v != 0) {
            let n = (i + j) % N;
            let term = (u128::from(a) * u128::from(b) % u128::from(T)) as u64;
            out[n] = if i + j < N {
                (out[n] + term) % T
            } else {
                (out[n] + T - term) % T
            };
        }
    }
    out
}
#[test]
fn actual_ciphertext_worker_and_complete_checker_precede_full_plaintext_oracle() {
    let f = Fixture::new();
    let owner = f.owner();
    let binding = InputBinding::checked(scope()).unwrap();
    let started = std::time::Instant::now();
    let query = owner
        .originate(Mask256::new(bits()), binding.clone(), &f.data)
        .unwrap();
    let encrypted_ms = started.elapsed().as_secs_f64() * 1000.0;
    let request = PublicRequest::decode(query.public_request().as_bytes()).unwrap();
    assert_eq!(request.data_ciphertext(), f.data.request().ciphertext());
    let worker_started = std::time::Instant::now();
    let worker = Evaluator::new().unwrap();
    let response = worker.evaluate(&request).unwrap();
    let worker_ms = worker_started.elapsed().as_secs_f64() * 1000.0;
    let receive_started = std::time::Instant::now();
    let actual = owner.complete(&query, &response).unwrap();
    let receive_ms = receive_started.elapsed().as_secs_f64() * 1000.0;
    let complete_ms = started.elapsed().as_secs_f64() * 1000.0;
    eprintln!(
        "gold_owner complete_math complete_ms={complete_ms:.3} encryption_ms={encrypted_ms:.3} worker_ms={worker_ms:.3} receive_ms={receive_ms:.3} request_bytes={} certificate_bytes={}",
        request.as_bytes().len(),
        response.certificate().len()
    );
    let mut damaged = response.certificate().to_vec();
    damaged[0] ^= 1;
    let bad = UnverifiedProduct::from_parts(response.output().to_vec(), damaged).unwrap();
    assert!(owner.complete(&query, &bad).is_err());
    assert_eq!(
        owner.complete(&query, &response).unwrap().coefficients(),
        actual.coefficients()
    );
    assert!(actual.binding() == &binding);
    let expected = oracle(&f.plain, &Mask256::new(bits()));
    assert_eq!(actual.coefficients(), expected.as_slice());
    assert_eq!(actual.coefficients().len(), N);
    let mut foreign = scope();
    foreign.call += 1;
    let other = owner
        .originate(
            Mask256::new(bits()),
            InputBinding::checked(foreign).unwrap(),
            &f.data,
        )
        .unwrap();
    assert!(owner.complete(&other, &response).is_err());
}
#[test]
fn protected_cold_origin_reopens_original_bytes_and_rejects_tampering() {
    let f = Fixture::new();
    let owner = f.owner();
    let binding = InputBinding::checked(scope()).unwrap();
    let query = owner
        .originate(Mask256::new(bits()), binding.clone(), &f.data)
        .unwrap();
    let original = query.public_request().clone();
    let identity = CustodyIdentity::checked([0x81; 32]).unwrap();
    let key = CustodyKey::new(Zeroizing::new([0x82; 32]));
    let record = owner.seal_origin(&query, &identity, &key).unwrap();
    drop(query);
    drop(owner);
    let restore_started = std::time::Instant::now();
    let owner = f.owner();
    let mask = Mask256::new(bits());
    let expectation = RestoreExpected::checked(&binding, &mask, &f.data, &original).unwrap();
    let restored = owner
        .restore_origin(expectation, &identity, &key, &record)
        .unwrap();
    let restore_ms = restore_started.elapsed().as_secs_f64() * 1000.0;
    eprintln!(
        "gold_owner cold_import_restore complete_ms={restore_ms:.3} record_bytes={}",
        record.as_bytes().len()
    );
    assert_eq!(restored.public_request().as_bytes(), original.as_bytes());
    let response = Evaluator::new()
        .unwrap()
        .evaluate(restored.public_request())
        .unwrap();
    let result = owner.complete(&restored, &response).unwrap();
    assert_eq!(result.coefficients(), oracle(&f.plain, &mask).as_slice());
    let mut corrupt = record.as_bytes().to_vec();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    let corrupt = EncryptedOrigin::from_bytes(&corrupt).unwrap();
    assert!(matches!(
        owner.restore_origin(
            RestoreExpected::checked(&binding, &mask, &f.data, &original).unwrap(),
            &identity,
            &key,
            &corrupt
        ),
        Err(Error::Authentication)
    ));
    let foreign = CustodyIdentity::checked([0x83; 32]).unwrap();
    assert!(matches!(
        owner.restore_origin(
            RestoreExpected::checked(&binding, &mask, &f.data, &original).unwrap(),
            &foreign,
            &key,
            &record
        ),
        Err(Error::Binding)
    ));
    let mut changed = bits();
    changed[0] ^= 1;
    let changed = Mask256::new(changed);
    assert!(matches!(
        owner.restore_origin(
            RestoreExpected::checked(&binding, &changed, &f.data, &original).unwrap(),
            &identity,
            &key,
            &record
        ),
        Err(Error::Binding)
    ));
    assert!(EncryptedOrigin::from_bytes(&vec![0; MAX_ORIGIN_BYTES + 1]).is_err());
}
fn varint(mut n: usize, out: &mut Vec<u8>) {
    while n >= 128 {
        out.push((n as u8 & 127) | 128);
        n >>= 7;
    }
    out.push(n as u8);
}
// Negative-only PUBLIC canonical encoder, never a product or proof acceptance source.
fn encoded_ct(c0: &[Vec<u64>], a: &[Vec<u64>]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in [c0, a] {
        let mut packed = vec![0; N * 60 / 8];
        for (basis, row) in p.iter().enumerate() {
            for (i, &v) in row.iter().enumerate() {
                assert!(v < Q[basis]);
                for bit in 0..30 {
                    let at = basis * N * 30 + i * 30 + bit;
                    packed[at / 8] |= (((v >> bit) & 1) as u8) << (at % 8);
                }
            }
        }
        let mut poly = vec![8, 2, 16];
        varint(N, &mut poly);
        poly.push(26);
        varint(packed.len(), &mut poly);
        poly.extend(packed);
        poly.extend([32, 1]);
        out.push(10);
        varint(poly.len(), &mut out);
        out.extend(poly);
    }
    out
}
#[test]
fn repaired_authenticated_records_still_require_all_original_private_equations() {
    let f = Fixture::new();
    let owner = f.owner();
    let binding = InputBinding::checked(scope()).unwrap();
    let query = owner
        .originate(Mask256::new(bits()), binding.clone(), &f.data)
        .unwrap();
    let identity = CustodyIdentity::checked([0x91; 32]).unwrap();
    let key = CustodyKey::new(Zeroizing::new([0x92; 32]));
    let mask = Mask256::new(bits());
    let original = query.public_request();
    let input =
        lower::data::Request::checked([1; 32], original.query_ciphertext().to_vec()).unwrap();
    let mut c0 = input.input(0).to_vec();
    c0[1][N - 1] = (c0[1][N - 1] + 1) % Q[1];
    let altered = encoded_ct(&c0, input.input(1));
    // Canonical SDK parse succeeds: rejection must be shared-E arithmetic, not shape.
    {
        use fhe_traits::DeserializeParametrized;
        Ciphertext::from_bytes(&altered, &owner::parameters().unwrap()).unwrap();
    }
    let altered = PublicRequest::checked(binding.clone(), &f.data, altered).unwrap();
    let repaired = custody::seal_payload(
        &owner,
        &f.data,
        &altered,
        &identity,
        &key,
        custody::payload(&mask, &altered),
    )
    .unwrap();
    assert!(matches!(
        owner.restore_origin(
            RestoreExpected::checked(&binding, &mask, &f.data, &altered).unwrap(),
            &identity,
            &key,
            &repaired
        ),
        Err(Error::Arithmetic)
    ));
    let mut wrong = bits();
    wrong[0] ^= 1;
    let wrong = Mask256::new(wrong);
    let repaired = custody::seal_payload(
        &owner,
        &f.data,
        original,
        &identity,
        &key,
        custody::payload(&wrong, original),
    )
    .unwrap();
    assert!(matches!(
        owner.restore_origin(
            RestoreExpected::checked(&binding, &wrong, &f.data, original).unwrap(),
            &identity,
            &key,
            &repaired
        ),
        Err(Error::Arithmetic)
    ));
}
#[test]
fn actual_sdk_key_is_checked_against_complete_independent_key_and_data_scope() {
    let f = Fixture::new();
    let mut salt = f.salt.clone();
    salt[0] += 1;
    assert!(matches!(
        Owner::from_sdk(f.key.clone(), f.sdk.clone(), salt),
        Err(Error::Binding)
    ));
    let mut secret = f.sdk.clone();
    secret[3] = if secret[3] <= 38 {
        secret[3] + 2
    } else {
        secret[3] - 2
    };
    assert!(matches!(
        Owner::from_sdk(f.key.clone(), secret, f.salt.clone()),
        Err(Error::Binding)
    ));
    let mut p = Parameters::fixed();
    p.plaintext += 1;
    assert!(matches!(
        KeyExpected::checked(f.key.scope(), p, f.key.context_words(), f.key.root_words()),
        Err(Error::Binding)
    ));
    let owner = f.owner();
    let binding = InputBinding::checked(scope()).unwrap();
    let mut roots = f.data.roots();
    roots[1][0] += Val::ONE;
    let other = lower::data::Expected::checked(
        f.data.request().clone(),
        [0x73; 64],
        f.data.contexts(),
        roots,
    )
    .unwrap();
    assert!(matches!(
        owner.originate(Mask256::new(bits()), binding.clone(), &other),
        Err(Error::Binding)
    ));
    let query = owner
        .originate(Mask256::new(bits()), binding, &f.data)
        .unwrap();
    let mut trailing = query.public_request().as_bytes().to_vec();
    trailing.push(0);
    assert!(PublicRequest::decode(&trailing).is_err());
    assert!(PublicRequest::decode(&vec![0; MAX_REQUEST_BYTES + 1]).is_err());
}
