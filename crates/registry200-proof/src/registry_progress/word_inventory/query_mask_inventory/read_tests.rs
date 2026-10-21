//! Bounded PUBLIC example. Actual encrypted arithmetic precedes owner-only assertions.
use super::*;
use crate::{
    Val,
    registry_progress::word_inventory::owner_cases::{self, Kind},
    source,
    two_lane_encoding::{self as encoding, circuit::Witness, statement::KeyBinding},
};
use bfv_hiding_stark::{Challenge, Config, codec};
use fhe::bfv::{BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, Plaintext, SecretKey};
use fhe_math::zq::Modulus;
use fhe_traits::{
    DeserializeParametrized, FheDecoder, FheDecrypter, FheEncoder, FheEncrypter, Serialize,
};
use p3_batch_stark::BatchProof;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::default_goldilocks_poseidon2_12;
use p3_symmetric::Permutation;
use std::{sync::Arc, time::Instant};
use zeroize::Zeroizing;

fn root(context: [Val; 8], salt: [Val; 4], words: &[u64]) -> [Val; 4] {
    let mut fields = context
        .into_iter()
        .chain(salt)
        .chain([Val::ZERO; 4])
        .chain(words.iter().copied().map(Val::from_u64))
        .collect::<Vec<_>>();
    assert!(matches!(fields.len(), 528 | 4112));
    let mut state = [Val::ZERO; 12];
    let p = default_goldilocks_poseidon2_12();
    for block in fields.as_chunks::<8>().0 {
        state[..8].copy_from_slice(block);
        p.permute_mut(&mut state);
    }
    let result = state[..4].try_into().unwrap();
    fields.fill(Val::ZERO);
    state.fill(Val::ZERO);
    result
}
fn encrypt(key: &SecretKey, p: &Arc<BfvParameters>, words: &[u64]) -> Vec<u8> {
    let plain = Zeroizing::new(Plaintext::try_encode(words, Encoding::poly(), p).unwrap());
    let ct: Ciphertext = key.try_encrypt(&*plain, &mut rand::rng()).unwrap();
    Ciphertext::new(ct.iter().cloned().collect(), p)
        .unwrap()
        .to_bytes()
}
/// Public evaluator input consists solely of original ciphertexts and parameters.
fn evaluate(p: &Arc<BfvParameters>, request: &gold::Request) -> Vec<u8> {
    let [left, right] = request
        .ciphertexts()
        .map(|b| Ciphertext::from_bytes(b, p).unwrap());
    let output = &left * &right;
    assert_eq!(output.len(), 3);
    output.to_bytes()
}
struct Frames {
    state: Vec<u8>,
    child: Vec<u8>,
    data: Vec<u8>,
    word: Vec<u8>,
    query: Vec<u8>,
    product: Vec<u8>,
}
impl Frames {
    fn borrowed(&self) -> Evidence<'_> {
        Evidence {
            state: &self.state,
            child: &self.child,
            data: &self.data,
            word: &self.word,
            query: &self.query,
            product: &self.product,
        }
    }
}
fn damage_batch(bytes: &[u8]) -> Vec<u8> {
    let mut proof: BatchProof<Config> = postcard::from_bytes(&bytes[128..]).unwrap();
    proof.opened_values.instances[0]
        .base_opened_values
        .trace_local[0] += Challenge::ONE;
    let payload = postcard::to_allocvec(&proof).unwrap();
    let mut out = bytes[..128].to_vec();
    out[104..108].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend(payload);
    out
}

#[test]
fn original_version_word_data_query_and_real_product_are_all_required_before_client_completion() {
    let began = Instant::now();
    let case = owner_cases::case(Kind::SkipBeforeOffset);
    let state_expected = &case.metadata.source;
    let claim = state_expected.statement();
    let key_commitment = source::commitment::digest(&source::commitment::key_fields(
        &claim.heads[0],
        [0x71; 32],
        [Val::ONE; 4],
    ));
    assert_eq!(key_commitment, claim.key_commitment);
    let plain = Zeroizing::new(
        case.input
            .source
            .iter()
            .flat_map(|v| u32::try_from(v.as_canonical_u64()).unwrap().to_le_bytes())
            .collect::<Vec<_>>(),
    );
    assert_eq!(plain.len(), 2348);
    let p = BfvParametersBuilder::new()
        .set_degree(gold::N)
        .set_plaintext_modulus(gold::T)
        .set_moduli(&gold::Q)
        .set_variance(10)
        .build_arc()
        .unwrap();
    let key = SecretKey::random(&p, &mut rand::rng());
    let sdk = Zeroizing::new(key.to_bytes());
    let cs_salt = [Val::from_u8(7); 4];
    let binding = |cs| {
        KeyBinding::new(
            claim.heads[0][8..24].try_into().unwrap(),
            [0x71; 16],
            1,
            [0x95; 32],
            source::statement::encode_digest(cs),
        )
        .unwrap()
    };
    let context = installed::secret_context(&binding([Val::ZERO; 4]));
    let secret = Zeroizing::new(fhe::proto::bfv::SecretKey::from(&key).coeffs);
    let packed = Zeroizing::new(
        secret
            .as_chunks::<8>()
            .0
            .iter()
            .map(|a| {
                a.iter()
                    .enumerate()
                    .fold(0u64, |v, (i, &x)| v | (((x + 20) as u64) << (6 * i)))
            })
            .collect::<Vec<_>>(),
    );
    let encoding_expected = encoding::statement::Expected::source_version(
        state_expected,
        binding(root(context, cs_salt, &packed)),
    )
    .unwrap();
    let witness = Witness::source_version(&encoding_expected, plain, [2; 4], [5; 4]).unwrap();
    let mut data_words = witness.coefficients();
    let modulus = Modulus::new(gold::T).unwrap();
    modulus.scalar_mul_vec(&mut data_words, modulus.inv(gold::SCALE).unwrap());
    let data_request = data::Request::checked([0x61; 32], encrypt(&key, &p, &data_words)).unwrap();
    let data_expected = installed::Expected::checked(&data_request, &witness.statement()).unwrap();
    let statement = owner_cases::statement(&case.metadata, &case.input, &case.old)
        .try_into()
        .unwrap();
    let mut mask_words = Zeroizing::new(vec![0u64; gold::N]);
    for age in 0..256 {
        mask_words[255 - age] = u64::from((case.input.mask[age / 8] >> (age % 8)) & 1);
    }
    let request = gold::Request::checked(
        [0x49; 32],
        [
            data_request.ciphertext().to_vec(),
            encrypt(&key, &p, &mask_words),
        ],
    )
    .unwrap();
    let context = formation::encoding_context(
        &request,
        data_expected.core_expected(),
        case.metadata.statement,
    )
    .unwrap();
    let salt = [Val::from_u8(9); 4];
    let scaled = Zeroizing::new(
        mask_words
            .iter()
            .map(|v| v * gold::SCALE)
            .collect::<Vec<_>>(),
    );
    let vector = root(context, salt, &scaled);
    let mask_expected =
        super::super::Expected::checked(case.metadata.statement, vector, context, request.nonce())
            .unwrap();
    let query_expected = formation::Expected::checked(
        &request,
        data_expected.core_expected(),
        case.metadata.statement,
        vector,
    )
    .unwrap();

    let started = Instant::now();
    let state = source::version::prove(
        state_expected,
        &source::circuit::Witness::new([0x71; 32], [Val::ONE; 4], [Val::TWO; 4], [0, 1, 128, 255]),
    )
    .unwrap()
    .into_bytes();
    let state_ms = started.elapsed().as_secs_f64() * 1000.;
    let started = Instant::now();
    let child = encoding::prove(&encoding_expected, &witness, &state)
        .unwrap()
        .into_parts()
        .1;
    let child_ms = started.elapsed().as_secs_f64() * 1000.;
    let started = Instant::now();
    let data = installed::prove_dense(
        &data_expected,
        &data_request,
        installed::Prerequisites::checked(&state, &child).unwrap(),
        installed::PrivateInputs::checked(witness, sdk.clone(), Zeroizing::new([7; 4])).unwrap(),
    )
    .unwrap()
    .into_bytes();
    let data_ms = started.elapsed().as_secs_f64() * 1000.;
    let started = Instant::now();
    let word = probe::produce(&case.metadata, &case.input).unwrap();
    let word_ms = started.elapsed().as_secs_f64() * 1000.;
    let started = Instant::now();
    let query = formation::produce(
        &query_expected,
        super::super::writer::Opening::checked(&mask_expected, statement, case.input.mask, salt)
            .unwrap(),
        gold::SecretOpening::checked(
            data_expected.core_expected().contexts()[1],
            data_expected.core_expected().roots()[1],
            sdk,
            Zeroizing::new([7; 4]),
        )
        .unwrap(),
    )
    .unwrap();
    let query_ms = started.elapsed().as_secs_f64() * 1000.;
    let started = Instant::now();
    let output = evaluate(&p, &request);
    let expected =
        Expected::checked(&case.metadata, &data_expected, &request, vector, output).unwrap();
    let product = product::produce(&expected.product).unwrap().into_bytes();
    let product_ms = started.elapsed().as_secs_f64() * 1000.;
    let frames = Frames {
        state,
        child,
        data,
        word,
        query: query.as_bytes().to_vec(),
        product,
    };
    let started = Instant::now();
    let checked =
        verify(&expected, frames.borrowed()).expect("all six genuine independent arguments");
    let receive_ms = started.elapsed().as_secs_f64() * 1000.;
    let started = Instant::now();
    let ct = Ciphertext::from_bytes(checked.output(), &p).unwrap();
    let decrypted: Plaintext = key.try_decrypt(&ct).unwrap();
    let decrypted = Zeroizing::new(decrypted);
    let actual = Zeroizing::new(Vec::<u64>::try_decode(&*decrypted, Encoding::poly()).unwrap());
    let client_ms = started.elapsed().as_secs_f64() * 1000.;
    let owner_setup_and_read_ms = began.elapsed().as_secs_f64() * 1000.;
    // Full-ring oracle belongs only to this PUBLIC fixture, after all verification.
    let mut oracle = Zeroizing::new(vec![0u64; gold::N]);
    for (i, &x) in data_words.iter().enumerate().filter(|(_, v)| **v != 0) {
        for (j, &y) in mask_words.iter().enumerate().filter(|(_, v)| **v != 0) {
            let at = (i + j) % gold::N;
            let term = x * y % gold::T;
            oracle[at] = (oracle[at]
                + if i + j < gold::N {
                    term
                } else {
                    gold::T - term
                })
                % gold::T;
        }
    }
    assert_eq!(*actual, *oracle);
    for (row, age) in [0u64, 1, 128, 255].into_iter().enumerate() {
        assert_eq!(actual[2 * row * 512 + 255], 256 + age);
        assert_eq!(actual[(2 * row + 1) * 512 + 255], row as u64 + 1);
    }
    eprintln!(
        "joined_math_read state_prove_ms={state_ms:.3} role3_prove_ms={child_ms:.3} data_dense_prove_ms={data_ms:.3} word_prove_ms={word_ms:.3} query_fused_prove_ms={query_ms:.3} fhe_product_and_certificate_ms={product_ms:.3} all_cold_receive_ms={receive_ms:.3} client_decrypt_ms={client_ms:.3} owner_setup_and_read_ms={owner_setup_and_read_ms:.3} frames_bytes={} SQL=false freshness=false network=false locks=false security_assessed=false",
        [
            &frames.state,
            &frames.child,
            &frames.data,
            &frames.word,
            &frames.query,
            &frames.product
        ]
        .iter()
        .map(|f| f.len())
        .sum::<usize>()
    );

    // Same version tag and images, but a different complete C_state must not join.
    let mut foreign = owner_cases::case(Kind::SkipBeforeOffset);
    let images: [Vec<u8>; 2] = core::array::from_fn(|i| {
        claim.heads[i]
            .iter()
            .chain(&claim.packets[i])
            .copied()
            .collect()
    });
    let heads = core::array::from_fn::<_, 2, _>(|i| {
        compact_store::Commitment::decode(&claim.heads[i], source::statement::limits()).unwrap()
    });
    let mut changed = claim.open_commitment;
    changed[0] += Val::ONE;
    foreign.metadata.source = source::version::SourceVersionExpected::checked(
        [&images[0], &images[1]],
        [&heads[0], &heads[1]],
        source::statement::encode_digest(claim.key_commitment),
        source::statement::encode_digest(changed),
    )
    .unwrap();
    assert_eq!(
        foreign.metadata.source.version_id(),
        state_expected.version_id()
    );
    assert!(matches!(
        Expected::checked(
            &foreign.metadata,
            &data_expected,
            &request,
            vector,
            expected.product.output_wire().to_vec()
        ),
        Err(Error::Binding)
    ));
    let swapped = gold::Request::checked(
        request.nonce(),
        [
            request.ciphertexts()[1].to_vec(),
            request.ciphertexts()[0].to_vec(),
        ],
    )
    .unwrap();
    assert!(matches!(
        Expected::checked(
            &case.metadata,
            &data_expected,
            &swapped,
            vector,
            expected.product.output_wire().to_vec()
        ),
        Err(Error::Query(formation::Error::Binding))
    ));
    // Explicit namespaces remain closed with all genuine original prerequisites.
    assert!(matches!(
        installed::verify(
            &data_expected,
            &data_request,
            installed::Prerequisites::checked(&frames.state, &frames.child).unwrap(),
            &frames.data
        ),
        Err(installed::Error::Formation(gold::Error::Encoding))
    ));

    let bad_data = damage_batch(&frames.data);
    assert!(matches!(
        verify(
            &expected,
            Evidence {
                data: &bad_data,
                ..frames.borrowed()
            }
        ),
        Err(Error::Data(installed::Error::Formation(
            gold::Error::Verification
        )))
    ));
    let bad_query = damage_batch(&frames.query);
    assert!(matches!(
        verify(
            &expected,
            Evidence {
                query: &bad_query,
                ..frames.borrowed()
            }
        ),
        Err(Error::Query(formation::Error::Formation(
            gold::Error::Verification
        )))
    ));
    let bad_word = damage_batch(&frames.word);
    assert!(matches!(
        verify(
            &expected,
            Evidence {
                word: &bad_word,
                ..frames.borrowed()
            }
        ),
        Err(Error::Word(probe::Error::Verification))
    ));
    let backend = crate::fixed::Backend::source_version(state_expected).unwrap();
    let mut false_state: p3_uni_stark::Proof<Config> = codec::decode(
        &frames.state,
        &backend.shape,
        crate::wire::MAX_SEQUENCE_ELEMENTS,
        crate::wire::SOURCE_SLOTS,
    )
    .unwrap();
    false_state.opened_values.trace_local[0] += Challenge::ONE;
    let false_state = codec::serialize(&false_state, &backend.shape, wire::MAX_SOURCE).unwrap();
    drop(backend);
    assert!(matches!(
        verify(
            &expected,
            Evidence {
                state: &false_state,
                ..frames.borrowed()
            }
        ),
        Err(Error::Data(installed::Error::Prerequisite(
            wire::Error::SourceVersionProof(crate::BackendError::Verification)
        )))
    ));
    let backend = crate::fixed::Backend::two_lane_encoding(data_expected.source()).unwrap();
    let mut false_child: p3_uni_stark::Proof<Config> = codec::decode(
        &frames.child[wire::HEADER..],
        &backend.shape,
        wire::SEQUENCE,
        wire::CHILD_SLOTS,
    )
    .unwrap();
    false_child.opened_values.trace_local[0] += Challenge::ONE;
    let payload =
        codec::serialize(&false_child, &backend.shape, wire::MAX_CHILD - wire::HEADER).unwrap();
    let mut false_child = frames.child[..wire::HEADER].to_vec();
    false_child[144..148].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    false_child.extend(payload);
    drop(backend);
    assert!(matches!(
        verify(
            &expected,
            Evidence {
                child: &false_child,
                ..frames.borrowed()
            }
        ),
        Err(Error::Data(installed::Error::Prerequisite(
            wire::Error::Proof(crate::BackendError::Verification)
        )))
    ));
    let mut product_bad = frames.product.clone();
    product_bad[8] ^= 1;
    assert!(matches!(
        verify(
            &expected,
            Evidence {
                product: &product_bad,
                ..frames.borrowed()
            }
        ),
        Err(Error::Product(product::Error::Binding))
    ));
    for index in 0..6 {
        let mut evidence = frames.borrowed();
        match index {
            0 => evidence.state = &[],
            1 => evidence.child = &[],
            2 => evidence.data = &[],
            3 => evidence.word = &[],
            4 => evidence.query = &[],
            _ => evidence.product = &[],
        }
        assert!(matches!(verify(&expected, evidence), Err(Error::Resource)));
    }
    assert_ne!(profile(), installed::dense_profile_digest());
}
