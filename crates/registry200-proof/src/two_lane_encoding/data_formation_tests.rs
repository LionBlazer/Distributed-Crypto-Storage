//! One PUBLIC NONSECRET State/Role3/DATA Formation collection. No SQL/network admission.
use super::*;
use crate::{Val, source};
use bfv_hiding_stark::{Challenge, Config, codec};
use bfv_unrelinearized_product as arithmetic;
use compact_store::{Layout, Owner};
use fhe::bfv::{BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, Plaintext, SecretKey};
use fhe_math::zq::Modulus;
use fhe_traits::{
    DeserializeParametrized, FheDecoder, FheDecrypter, FheEncoder, FheEncrypter, Serialize,
};
use p3_goldilocks::default_goldilocks_poseidon2_12;
use p3_symmetric::Permutation;
use std::{sync::Arc, time::Instant};

const AEAD_KEY: [u8; 32] = [0x71; 32];
const ROWS: [u8; 12] = [0, 255, 255, 1, 0, 0, 128, 255, 0, 255, 254, 255];
fn key_binding(cs: [Val; 4]) -> statement::KeyBinding {
    statement::KeyBinding::new(
        [0x42; 16],
        [0x91; 16],
        7,
        [0x95; 32],
        source::statement::encode_digest(cs),
    )
    .unwrap()
}
fn cs_root(context: [Val; 8], key: &[u8], salt: [u64; 4]) -> [Val; 4] {
    assert!(key.len() == super::super::N + 3 && key[..3] == [0x0a, 0x80, 0x20]);
    let mut fields = Zeroizing::new(Vec::with_capacity(528));
    fields.extend(context.iter().map(|value| value.as_canonical_u64()));
    fields.extend(salt);
    fields.extend([0; 4]);
    for group in key[3..].as_chunks::<8>().0 {
        let mut word = 0;
        for (i, &byte) in group.iter().enumerate() {
            assert!(byte <= 40);
            let signed = i64::from(byte >> 1) ^ -i64::from(byte & 1);
            word |= ((signed + 20) as u64) << (6 * i);
        }
        fields.push(word);
    }
    assert_eq!(fields.len(), 528);
    let mut state = [Val::ZERO; 12];
    let permutation = default_goldilocks_poseidon2_12();
    for block in fields.as_chunks::<8>().0 {
        for (cell, &value) in state[..8].iter_mut().zip(block) {
            *cell = Val::from_u64(value);
        }
        permutation.permute_mut(&mut state);
    }
    state[..4].try_into().unwrap()
}
fn state_source() -> (source::version::SourceVersionExpected, Zeroizing<Vec<u8>>) {
    let owner = Owner::from_key([0x42; 16], [0x73; 16], Zeroizing::new(AEAD_KEY));
    let stored = owner
        .seal(
            Layout {
                schema: source::DATA_SCHEMA,
                row_width: 3,
                rows_per_page: 256,
                row_count: 4,
            },
            &ROWS,
            source::statement::limits(),
        )
        .unwrap();
    let mut index = Zeroizing::new(vec![0; 2336]);
    index[..112].copy_from_slice(&stored.commitment().encode());
    index[112..144].fill(0x31);
    let ages = [0u8, 1, 128, 255];
    let mut count = 0u32;
    for age in 0..256 {
        let present = ages.contains(&(age as u8));
        index[144 + 4 * age..148 + 4 * age].copy_from_slice(&u32::from(present).to_le_bytes());
        index[1168 + 4 * age..1172 + 4 * age].copy_from_slice(&count.to_le_bytes());
        if present {
            index[2196 + count as usize] = ages
                .iter()
                .position(|value| usize::from(*value) == age)
                .unwrap() as u8;
            count += 1;
        }
    }
    index[2192..2196].copy_from_slice(&count.to_le_bytes());
    for i in 0..4 {
        index[2208 + 32 * i] = i as u8 + 1;
    }
    let indexed = owner
        .seal(
            Layout {
                schema: source::INDEX_SCHEMA,
                row_width: 1,
                rows_per_page: 4096,
                row_count: 2336,
            },
            &index,
            source::statement::limits(),
        )
        .unwrap();
    let images = [stored.encode(), indexed.encode()];
    let heads = [stored.commitment(), indexed.commitment()];
    let key = source::commitment::digest(&source::commitment::key_fields(
        &heads[0].encode(),
        AEAD_KEY,
        [Val::ONE; 4],
    ));
    let draft = source::version::SourceVersionExpected::checked(
        [&images[0], &images[1]],
        heads,
        source::statement::encode_digest(key),
        [0; 32],
    )
    .unwrap();
    let mut plain = Zeroizing::new(ROWS.to_vec());
    plain.extend_from_slice(&index);
    let state = source::commitment::digest(&source::commitment::opening_fields(
        draft.statement(),
        [Val::TWO; 4],
        &plain,
    ));
    let expected = source::version::SourceVersionExpected::checked(
        [&images[0], &images[1]],
        heads,
        source::statement::encode_digest(key),
        source::statement::encode_digest(state),
    )
    .unwrap();
    assert_eq!(expected.version_id(), draft.version_id());
    (expected, plain)
}
/// Owner-only fixture state. No producer/checker/evaluator receives these fields.
struct ClientCompletion {
    key: SecretKey,
    parameters: Arc<BfvParameters>,
    data_plain: Zeroizing<Vec<u64>>,
}
impl ClientCompletion {
    fn encrypt_domain_mask(&self, run: usize) -> (Vec<u8>, Zeroizing<Vec<u64>>) {
        let mut mask = [0u8; 32];
        for age in 0..256 {
            let matches = if run == 0 { age >= 128 } else { age == 0 };
            if matches {
                mask[age / 8] |= 1 << (age % 8);
            }
        }
        let mut words = super::super::circuit::compile_mask(&mask);
        let modulus = Modulus::new(super::super::T).unwrap();
        modulus.scalar_mul_vec(&mut words, modulus.inv(super::super::SCALE).unwrap());
        let plaintext = Zeroizing::new(
            Plaintext::try_encode(words.as_slice(), Encoding::poly(), &self.parameters).unwrap(),
        );
        let encrypted: Ciphertext = self.key.try_encrypt(&*plaintext, &mut rand::rng()).unwrap();
        let full = Ciphertext::new(encrypted.iter().cloned().collect(), &self.parameters).unwrap();
        (full.to_bytes(), words)
    }
    fn complete_checked_product(
        &self,
        checked: &arithmetic::ArithmeticCheckedProduct,
        mask: &[u64],
    ) {
        let encrypted =
            Ciphertext::from_bytes(checked.expected().output_wire(), &self.parameters).unwrap();
        let decrypted: Plaintext = self.key.try_decrypt(&encrypted).unwrap();
        let decrypted = Zeroizing::new(decrypted);
        let actual = Zeroizing::new(Vec::<u64>::try_decode(&*decrypted, Encoding::poly()).unwrap());
        // Independent PUBLIC full-ring oracle, computed only AFTER actual checking.
        let expected = ring_oracle(&self.data_plain, mask);
        assert!(*actual == *expected);
    }
}
fn ring_oracle(left: &[u64], right: &[u64]) -> Zeroizing<Vec<u64>> {
    let mut output = Zeroizing::new(vec![0; super::super::N]);
    for (i, &x) in left.iter().enumerate().filter(|(_, value)| **value != 0) {
        for (j, &y) in right.iter().enumerate().filter(|(_, value)| **value != 0) {
            let term = (u128::from(x) * u128::from(y) % u128::from(super::super::T)) as u64;
            let at = (i + j) % super::super::N;
            output[at] = if i + j < super::super::N {
                (output[at] + term) % super::super::T
            } else {
                (output[at] + super::super::T - term) % super::super::T
            };
        }
    }
    output
}
/// Actual public encrypted evaluator. No key/plaintext/mask/oracle is supplied.
fn public_product(ciphertexts: [&[u8]; 2], parameters: &Arc<BfvParameters>) -> Vec<u8> {
    let [left, right] = ciphertexts.map(|bytes| Ciphertext::from_bytes(bytes, parameters).unwrap());
    let output = &left * &right;
    assert_eq!(output.len(), 3);
    output.to_bytes()
}
struct Fixture {
    state: source::version::SourceVersionExpected,
    plain: Zeroizing<Vec<u8>>,
    request: data::Request,
    expected: Expected,
    witness: Witness,
    key: Zeroizing<Vec<u8>>,
    cs_salt: Zeroizing<[u64; 4]>,
    completion: ClientCompletion,
}
fn fixture() -> Fixture {
    let parameters = BfvParametersBuilder::new()
        .set_degree(super::super::N)
        .set_plaintext_modulus(super::super::T)
        .set_moduli(&super::super::Q)
        .set_variance(10)
        .build_arc()
        .unwrap();
    let key = SecretKey::random(&parameters, &mut rand::rng());
    let key_bytes = Zeroizing::new(key.to_bytes());
    let cs_salt = Zeroizing::new([7; 4]);
    let context = secret_context(&key_binding([Val::ZERO; 4]));
    let binding = key_binding(cs_root(context, &key_bytes, *cs_salt));
    assert!(secret_context(&binding) == context);
    let (state, plain) = state_source();
    let encoding = statement::Expected::source_version(&state, binding).unwrap();
    let witness =
        Witness::source_version(&encoding, Zeroizing::new(plain.to_vec()), [2; 4], [5; 4]).unwrap();
    let mut raw = witness.coefficients();
    let modulus = Modulus::new(super::super::T).unwrap();
    modulus.scalar_mul_vec(&mut raw, modulus.inv(super::super::SCALE).unwrap());
    let plaintext = Zeroizing::new(
        Plaintext::try_encode(raw.as_slice(), Encoding::poly(), &parameters).unwrap(),
    );
    let began = Instant::now();
    let encrypted: Ciphertext = key.try_encrypt(&*plaintext, &mut rand::rng()).unwrap();
    let full = Ciphertext::new(encrypted.iter().cloned().collect(), &parameters).unwrap();
    let request = data::Request::checked([0x61; 32], full.to_bytes()).unwrap();
    eprintln!(
        "two_lane_data_formation phase=sdk_data_encrypt ms={:.3} bytes={}",
        began.elapsed().as_secs_f64() * 1000.,
        request.ciphertext().len()
    );
    let expected = Expected::checked(&request, &witness.statement()).unwrap();
    let completion = ClientCompletion {
        key,
        parameters,
        data_plain: raw,
    };
    Fixture {
        state,
        plain,
        request,
        expected,
        witness,
        key: key_bytes,
        cs_salt,
        completion,
    }
}
struct Evidence {
    state: Vec<u8>,
    child: Vec<u8>,
}
impl Evidence {
    fn borrowed(&self) -> Prerequisites<'_> {
        Prerequisites::checked(&self.state, &self.child).unwrap()
    }
}
fn prerequisites(f: &Fixture) -> Evidence {
    let began = Instant::now();
    let state = source::version::prove(
        &f.state,
        &source::circuit::Witness::new(AEAD_KEY, [Val::ONE; 4], [Val::TWO; 4], [0, 1, 128, 255]),
    )
    .unwrap()
    .into_bytes();
    eprintln!(
        "two_lane_data_formation phase=state_prove ms={:.3} bytes={}",
        began.elapsed().as_secs_f64() * 1000.,
        state.len()
    );
    let began = Instant::now();
    let child = super::super::prove(&f.expected.source.expected, &f.witness, &state)
        .unwrap()
        .into_parts()
        .1;
    eprintln!(
        "two_lane_data_formation phase=unverified_child_prove ms={:.3} bytes={}",
        began.elapsed().as_secs_f64() * 1000.,
        child.len()
    );
    Evidence { state, child }
}
fn early_rejections(f: &Fixture) {
    assert!(Prerequisites::checked(&[], &[1]).is_err());
    assert!(Prerequisites::checked(&[1], &[]).is_err());
    for bytes in [&[][..], &vec![0; data::MAX_EVIDENCE_BYTES + 1]] {
        assert!(matches!(
            verify(
                &f.expected,
                &f.request,
                Prerequisites::checked(&[1], &[1]).unwrap(),
                bytes
            ),
            Err(Error::Formation(gold::Error::Resource))
        ));
    }
    let mut nonce = f.request.nonce();
    nonce[0] ^= 1;
    let foreign = data::Request::checked(nonce, f.request.ciphertext().to_vec()).unwrap();
    assert!(matches!(
        f.expected.require_request(&foreign),
        Err(Error::Binding)
    ));
    let mut tail = f.witness.coefficients();
    tail[super::super::N - 1] = super::super::T;
    assert!(
        gold::ScaledOpening::checked(
            f.expected.core.contexts()[0],
            f.expected.core.roots()[0],
            tail,
            Zeroizing::new([5; 4])
        )
        .is_err()
    );
    let mut bad = f.key.to_vec();
    *bad.last_mut().unwrap() = 41;
    let w = Witness::source_version(
        &f.expected.source.expected,
        Zeroizing::new(f.plain.to_vec()),
        [2; 4],
        [5; 4],
    )
    .unwrap();
    assert!(matches!(
        PrivateInputs::checked(w, Zeroizing::new(bad), Zeroizing::new([7; 4])),
        Err(Error::Binding)
    ));
    let mut claim = f.state.statement().clone();
    claim.relation = source::Relation::CanonicalIndex;
    let canonical = crate::admission::CanonicalSource::checked_claim(&claim).unwrap();
    let old = statement::Statement {
        expected: statement::Expected::source(
            &canonical,
            f.expected.source.expected.key_binding().clone(),
        )
        .unwrap(),
        encoded: f.expected.source.encoded,
    };
    assert!(matches!(
        Expected::checked(&f.request, &old),
        Err(Error::Binding)
    ));
}
fn repaired_data_ood(frame: &[u8]) -> Vec<u8> {
    assert!(frame.len() > 128 && &frame[..8] == b"DCSGFD01");
    let (mut proof, trailing) =
        bounded_postcard::take_from_bytes::<p3_batch_stark::BatchProof<Config>>(
            &frame[128..],
            bounded_postcard::Limits {
                max_sequence_elements: 4096,
                max_total_elements: 8 * 1024 * 1024,
            },
        )
        .unwrap();
    assert!(trailing.is_empty());
    proof.opened_values.instances[0]
        .base_opened_values
        .trace_local[0] += Challenge::ONE;
    let payload = postcard::to_allocvec(&proof).unwrap();
    drop(proof);
    let mut repaired = frame[..128].to_vec();
    repaired[104..108].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    repaired.extend(payload);
    repaired
}
fn repaired_state_ood(f: &Fixture, evidence: &Evidence) -> Vec<u8> {
    let backend = crate::fixed::Backend::source_version(&f.state).unwrap();
    let mut proof: p3_uni_stark::Proof<Config> = codec::decode(
        &evidence.state,
        &backend.shape,
        crate::wire::MAX_SEQUENCE_ELEMENTS,
        crate::wire::SOURCE_SLOTS,
    )
    .unwrap();
    proof.opened_values.trace_local[0] += Challenge::ONE;
    codec::serialize(&proof, &backend.shape, wire::MAX_SOURCE).unwrap()
}
fn two_checked_products(verified: &VerifiedDataFormation, completion: ClientCompletion) {
    let data_bytes = verified.expected().request().ciphertext();
    for run in 0..2 {
        let (query, raw_mask) = completion.encrypt_domain_mask(run);
        let began = Instant::now();
        let output = public_product([data_bytes, &query], &completion.parameters);
        let claim = arithmetic::Expected::checked(
            [run as u8 + 1; 32],
            [data_bytes.to_vec(), query],
            output,
        )
        .unwrap();
        let bytes = arithmetic::produce(&claim).unwrap().into_bytes();
        let checked = arithmetic::check_arithmetic(&claim, &bytes).unwrap();
        completion.complete_checked_product(&checked, &raw_mask);
        eprintln!(
            "two_lane_data_formation phase=fixture_checked_query run={} ms={:.3} certificate_bytes={}",
            run,
            began.elapsed().as_secs_f64() * 1000.,
            bytes.len()
        );
    }
}
#[test]
fn one_actual_state_data_formation_is_freshly_checked_before_two_fixture_query_products() {
    let started = Instant::now();
    let f = fixture();
    early_rejections(&f);
    let evidence = prerequisites(&f);
    // Fresh State verification is mandatory at BOTH upper producer and receiver.
    let bad_state = repaired_state_ood(&f, &evidence);
    let false_witness = Witness::source_version(
        &f.expected.source.expected,
        Zeroizing::new(f.plain.to_vec()),
        [2; 4],
        [5; 4],
    )
    .unwrap();
    let private = PrivateInputs::checked(
        false_witness,
        Zeroizing::new(f.key.to_vec()),
        Zeroizing::new(*f.cs_salt),
    )
    .unwrap();
    assert!(matches!(
        prove(
            &f.expected,
            &f.request,
            Prerequisites::checked(&bad_state, &evidence.child).unwrap(),
            private
        ),
        Err(Error::Prerequisite(wire::Error::SourceVersionProof(
            crate::BackendError::Verification
        )))
    ));
    let Fixture {
        state,
        plain,
        request,
        expected,
        witness,
        key,
        cs_salt,
        completion,
    } = f;
    drop(state);
    drop(plain);
    let began = Instant::now();
    let bytes = prove(
        &expected,
        &request,
        evidence.borrowed(),
        PrivateInputs::checked(witness, key, cs_salt).unwrap(),
    )
    .unwrap()
    .into_bytes();
    eprintln!(
        "two_lane_data_formation phase=consuming_data_prove ms={:.3} bytes={}",
        began.elapsed().as_secs_f64() * 1000.,
        bytes.len()
    );
    let began = Instant::now();
    let verified = verify(&expected, &request, evidence.borrowed(), &bytes).unwrap();
    assert!(verified.expected().request().bytes() == request.bytes());
    assert!(verified.expected().source().values() == expected.source.values());
    eprintln!(
        "two_lane_data_formation phase=fresh_receive ms={:.3}",
        began.elapsed().as_secs_f64() * 1000.
    );
    assert!(matches!(
        verify(
            &expected,
            &request,
            Prerequisites::checked(&bad_state, &evidence.child).unwrap(),
            &bytes
        ),
        Err(Error::Prerequisite(wire::Error::SourceVersionProof(
            crate::BackendError::Verification
        )))
    ));
    assert!(
        verify(
            &expected,
            &request,
            Prerequisites::checked(&evidence.child, &evidence.child).unwrap(),
            &bytes
        )
        .is_err()
    );
    let mut foreign = expected.source.clone();
    foreign.encoded[3] += Val::ONE;
    let foreign = Expected::checked(&request, &foreign).unwrap();
    assert!(matches!(
        verify(&foreign, &request, evidence.borrowed(), &bytes),
        Err(Error::Binding)
    ));
    let mut nonce = request.nonce();
    nonce[0] ^= 1;
    let foreign_request = data::Request::checked(nonce, request.ciphertext().to_vec()).unwrap();
    assert!(matches!(
        verify(
            &expected,
            &foreign_request,
            Prerequisites::checked(&[1], &[1]).unwrap(),
            &bytes
        ),
        Err(Error::Binding)
    ));
    let mut bad_header = bytes.clone();
    bad_header[40] ^= 1;
    assert!(matches!(
        verify(&expected, &request, evidence.borrowed(), &bad_header),
        Err(Error::Formation(gold::Error::Binding))
    ));
    let repaired = repaired_data_ood(&bytes);
    assert!(matches!(
        verify(&expected, &request, evidence.borrowed(), &repaired),
        Err(Error::Formation(gold::Error::Verification))
    ));
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(verify(&expected, &request, evidence.borrowed(), &trailing).is_err());
    // Fixture-only owner-generated query inputs: no production OriginatingQuery,
    // query/Cmd proof, registry transition, freshness, weighted QC or SQL claim.
    two_checked_products(&verified, completion);
    eprintln!(
        "two_lane_data_formation phase=whole ms={:.3}",
        started.elapsed().as_secs_f64() * 1000.
    );
}
