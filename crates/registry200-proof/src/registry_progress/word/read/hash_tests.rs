//! Genuine five-AIR/PIT composition on the same public owner fixture.
use super::super::query as formation;
use super::super::tests::{input_binding, ring_oracle, word_expected, word_inputs};
use super::*;
use crate::registry_progress::word_inventory::owner_cases::{self, Kind};
use crate::{
    Val, source,
    two_lane_encoding::{self as encoding, circuit::Witness, statement::KeyBinding},
};
use bfv_ciphertext_formation::gold::{self, data, query as fused};
use bfv_hiding_stark::{Challenge, hash as suite};
use bfv_query_core::gold as protected;
use fhe_math::zq::Modulus;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use std::time::Instant;
use zeroize::Zeroizing;

#[path = "hash_tests/runtime_trace.rs"]
mod runtime_trace;

struct Frames {
    state: Vec<u8>,
    child: Vec<u8>,
    data: Vec<u8>,
    word: Vec<u8>,
    query: Vec<u8>,
    product: Vec<u8>,
}
impl Frames {
    fn evidence(&self) -> Evidence<'_> {
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
    let mut proof: p3_batch_stark::BatchProof<suite::Config> =
        postcard::from_bytes(&bytes[128..]).unwrap();
    proof.opened_values.instances[0]
        .base_opened_values
        .trace_local[0] += Challenge::ONE;
    let payload = postcard::to_allocvec(&proof).unwrap();
    let mut out = bytes[..128].to_vec();
    out[104..108].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend(payload);
    out
}
fn damage_uni(bytes: &[u8], header: usize) -> Vec<u8> {
    let mut proof: p3_uni_stark::Proof<suite::Config> =
        postcard::from_bytes(&bytes[header..]).unwrap();
    proof.opened_values.trace_local[0] += Challenge::ONE;
    let payload = postcard::to_allocvec(&proof).unwrap();
    let mut out = bytes[..header].to_vec();
    let length = if header == 44 { 40 } else { 104 };
    out[length..length + 4].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend(payload);
    out
}

#[test]
fn five_real_hash_air_proofs_and_original_product_bind_all_endpoints_before_completion() {
    let began = Instant::now();
    let mut case = owner_cases::case(Kind::SkipBeforeOffset);
    let state_expected_owned = case.metadata.source.clone();
    let state_expected = &state_expected_owned;
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
    let owner =
        protected::Owner::generate([0x95; 32], context.map(|v| v.as_canonical_u64())).unwrap();
    let pinned_key = owner.key_expected().clone();
    // Explicit PUBLIC fixture wrapping key. No raw SDK key ever leaves Owner.
    let custody = protected::CustodyKey::new(Zeroizing::new([0xd1; 32]));
    let identity = protected::CustodyIdentity::checked([0xd2; 32]).unwrap();
    let sealed = owner.seal_key(&identity, &custody).unwrap();
    drop(owner);
    let owner = protected::Owner::restore_key(pinned_key, &identity, &custody, &sealed).unwrap();
    let encoding_expected = encoding::statement::Expected::source_version(
        state_expected,
        binding(owner.key_expected().root_words().map(Val::from_u64)),
    )
    .unwrap();
    let source_plain = plain.clone();
    let witness = Witness::source_version(&encoding_expected, plain, [2; 4], [5; 4]).unwrap();
    let mut data_words = witness.coefficients();
    let modulus = Modulus::new(gold::T).unwrap();
    modulus.scalar_mul_vec(&mut data_words, modulus.inv(gold::SCALE).unwrap());
    let original_data = owner.originate_data(data_words.clone()).unwrap();
    let data_request =
        data::Request::checked([0x61; 32], original_data.ciphertext().to_vec()).unwrap();
    let data_expected = installed::Expected::checked(&data_request, &witness.statement()).unwrap();
    let statement: [Val; 96] = owner_cases::statement(&case.metadata, &case.input, &case.old)
        .try_into()
        .unwrap();
    let mut mask_words = Zeroizing::new(vec![0u64; gold::N]);
    for age in 0..256 {
        mask_words[255 - age] = u64::from((case.input.mask[age / 8] >> (age % 8)) & 1);
    }
    let original = owner
        .originate(
            protected::Mask256::new(case.input.mask),
            input_binding(&case, &data_expected),
            data_expected.core_expected(),
        )
        .unwrap();
    let request = original.public_request().formation_request().unwrap();
    let context = formation::encoding_context(
        &request,
        data_expected.core_expected(),
        case.metadata.statement,
    )
    .unwrap();
    let salt = [9; 4];
    let vector = owner
        .query_commitment(&original, context.map(|v| v.as_canonical_u64()), &salt)
        .unwrap()
        .map(Val::from_u64);
    let query_expected = formation::expected(
        &request,
        data_expected.core_expected(),
        case.metadata.statement,
        vector,
    )
    .unwrap();

    let started = Instant::now();
    let state = source::hash::prove(
        state_expected,
        &source::circuit::Witness::new([0x71; 32], [Val::ONE; 4], [Val::TWO; 4], [0, 1, 128, 255]),
    )
    .unwrap();
    let state_ms = started.elapsed().as_secs_f64() * 1000.;
    let started = Instant::now();
    let child = encoding::hash::prove(&witness.statement(), &witness).unwrap();
    let child_ms = started.elapsed().as_secs_f64() * 1000.;
    let started = Instant::now();
    let data = installed::hash::prove_prepared(
        &data_expected,
        &data_request,
        installed::hash::Prerequisites::checked(&state, &child).unwrap(),
        owner
            .prepare_data(
                &original_data,
                data_expected.core_expected(),
                Zeroizing::new([5; 4]),
            )
            .unwrap(),
    )
    .unwrap();
    let data_ms = started.elapsed().as_secs_f64() * 1000.;
    let started = Instant::now();
    let word_prover = word::hash::Prover::new().unwrap();
    let word = word_prover
        .produce(&word_expected(&case), word_inputs(&mut case))
        .unwrap()
        .into_bytes();
    let word_ms = started.elapsed().as_secs_f64() * 1000.;
    let started = Instant::now();
    let query = fused::hash::prove(
        &query_expected,
        owner
            .prepare_query(
                &original,
                &query_expected,
                Zeroizing::new(statement.map(|v| v.as_canonical_u64())),
                Zeroizing::new(salt),
            )
            .unwrap(),
    )
    .unwrap();
    let query_ms = started.elapsed().as_secs_f64() * 1000.;
    let started = Instant::now();
    let response = protected::Evaluator::new()
        .unwrap()
        .evaluate(original.public_request())
        .unwrap();
    let expected = Expected::checked(
        &word_expected(&case),
        &data_expected,
        &request,
        vector,
        response.output().to_vec(),
    )
    .unwrap();
    let product = response.certificate().to_vec();
    let product_ms = started.elapsed().as_secs_f64() * 1000.;
    let frames = Frames {
        state,
        child,
        data,
        word,
        query,
        product,
    };
    // Capture the actual closed native receiving stack. Configurations are
    // created inside this scope; no synthetic transcript driver replaces it.
    let ((receiver, checked, retained, receiving_setup_ms, receive_ms), traces) =
        suite::audit::capture(|| {
            let started = Instant::now();
            let receiver = Verifier::new(&expected).unwrap();
            let receiving_setup_ms = started.elapsed().as_secs_f64() * 1000.;
            let started = Instant::now();
            let (checked, retained) = receiver.verify_and_retain(frames.evidence()).unwrap();
            let receive_ms = started.elapsed().as_secs_f64() * 1000.;
            (receiver, checked, retained, receiving_setup_ms, receive_ms)
        })
        .unwrap();
    let started = Instant::now();
    let completed = owner
        .complete_checked_product(&original, checked.product())
        .unwrap();
    let client_ms = started.elapsed().as_secs_f64() * 1000.;
    assert_eq!(
        completed.coefficients(),
        ring_oracle(&data_words, &mask_words).as_slice()
    );
    for (row, age) in [0u64, 1, 128, 255].into_iter().enumerate() {
        assert_eq!(completed.coefficients()[2 * row * 512 + 255], 256 + age);
        assert_eq!(
            completed.coefficients()[(2 * row + 1) * 512 + 255],
            row as u64 + 1
        );
    }
    eprintln!(
        "hash_read state_ms={state_ms:.3} role3_ms={child_ms:.3} data_ms={data_ms:.3} word_ms={word_ms:.3} query_ms={query_ms:.3} product_ms={product_ms:.3} receiving_setup_ms={receiving_setup_ms:.3} fresh_six_receive_ms={receive_ms:.3} client_ms={client_ms:.3} full_owner_setup_and_math_ms={:.3} frames_bytes={} SQL=false network=false freshness=false locks=false security_assessed=false",
        began.elapsed().as_secs_f64() * 1000.,
        [
            &frames.state,
            &frames.child,
            &frames.data,
            &frames.word,
            &frames.query,
            &frames.product
        ]
        .iter()
        .map(|v| v.len())
        .sum::<usize>()
    );
    retained.require_expected(&data_expected).unwrap();
    runtime_trace::check(&expected, &traces).unwrap();
    let again = receiver
        .verify_retained(&retained, frames.evidence().query())
        .unwrap();
    assert_eq!(again.output(), checked.output());

    // A second HONEST encoding under the same Source/key, but different Cw.
    let alternate =
        Witness::source_version(&encoding_expected, source_plain, [2; 4], [6; 4]).unwrap();
    let alternate_statement = alternate.statement();
    assert_ne!(alternate_statement.encoded, witness.statement().encoded);
    let alternate_proof = encoding::hash::prove(&alternate_statement, &alternate).unwrap();
    encoding::hash::verify(&alternate_statement, &alternate_proof).unwrap();
    assert!(matches!(
        receiver.verify_and_retain(Evidence {
            child: &alternate_proof,
            ..frames.evidence()
        }),
        Err(Error::Data(installed::hash::Error::Encoding(_)))
    ));

    // Native OOD corruption preserves canonical framing, reaching real verification.
    let bad = damage_uni(&frames.state, 44);
    assert!(matches!(
        receiver.verify_and_retain(Evidence {
            state: &bad,
            ..frames.evidence()
        }),
        Err(Error::Data(installed::hash::Error::Source(
            source::hash::Error::Verification
        )))
    ));
    let bad = damage_uni(&frames.child, 128);
    assert!(matches!(
        receiver.verify_and_retain(Evidence {
            child: &bad,
            ..frames.evidence()
        }),
        Err(Error::Data(installed::hash::Error::Encoding(
            encoding::wire::Error::Proof(bfv_hiding_stark::Error::Verification)
        )))
    ));
    let bad = damage_batch(&frames.data);
    assert!(matches!(
        receiver.verify_and_retain(Evidence {
            data: &bad,
            ..frames.evidence()
        }),
        Err(Error::Data(installed::hash::Error::Formation(
            gold::Error::Verification
        )))
    ));
    let bad = damage_batch(&frames.word);
    assert!(matches!(
        receiver.verify_retained(
            &retained,
            QueryEvidence {
                word: &bad,
                ..frames.evidence().query()
            }
        ),
        Err(Error::Word(word::Error::Verification))
    ));
    let bad = damage_batch(&frames.query);
    assert!(matches!(
        receiver.verify_retained(
            &retained,
            QueryEvidence {
                query: &bad,
                ..frames.evidence().query()
            }
        ),
        Err(Error::Query(gold::Error::Verification))
    ));
    let mut bad = frames.product.clone();
    bad[8] ^= 1;
    assert!(matches!(
        receiver.verify_retained(
            &retained,
            QueryEvidence {
                product: &bad,
                ..frames.evidence().query()
            }
        ),
        Err(Error::Product(_))
    ));
    for which in 0..6 {
        let mut missing = frames.evidence();
        match which {
            0 => missing.state = &[],
            1 => missing.child = &[],
            2 => missing.data = &[],
            3 => missing.word = &[],
            4 => missing.query = &[],
            _ => missing.product = &[],
        }
        assert!(matches!(
            receiver.verify_and_retain(missing),
            Err(Error::Resource)
        ));
    }

    // Retention compares original full Source/Key29/Cw/Cs/request, not a short tag.
    let mut wrong_cw = data_expected.source().clone();
    wrong_cw.encoded[0] += Val::ONE;
    let wrong_cw = installed::Expected::checked(&data_request, &wrong_cw).unwrap();
    assert!(matches!(
        retained.require_expected(&wrong_cw),
        Err(installed::hash::Error::Binding)
    ));
    let wrong_nonce =
        data::Request::checked([0x62; 32], data_request.ciphertext().to_vec()).unwrap();
    let wrong_nonce = installed::Expected::checked(&wrong_nonce, data_expected.source()).unwrap();
    assert!(matches!(
        retained.require_expected(&wrong_nonce),
        Err(installed::hash::Error::Binding)
    ));
    let reencrypted = owner.originate_data(data_words.clone()).unwrap();
    let wrong_ciphertext =
        data::Request::checked(data_request.nonce(), reencrypted.ciphertext().to_vec()).unwrap();
    let wrong_ciphertext =
        installed::Expected::checked(&wrong_ciphertext, data_expected.source()).unwrap();
    assert!(matches!(
        retained.require_expected(&wrong_ciphertext),
        Err(installed::hash::Error::Binding)
    ));
    let mut wrong_cs = owner.key_expected().root_words().map(Val::from_u64);
    wrong_cs[0] += Val::ONE;
    let mut wrong_key = data_expected.source().clone();
    wrong_key.expected =
        encoding::statement::Expected::source_version(state_expected, binding(wrong_cs)).unwrap();
    let wrong_key = installed::Expected::checked(&data_request, &wrong_key).unwrap();
    assert!(matches!(
        retained.require_expected(&wrong_key),
        Err(installed::hash::Error::Binding)
    ));

    let mut claims = word_expected(&case).claims();
    claims.next[0] += Val::ONE;
    let old_word = word_expected(&case);
    let different_word = word::Expected::checked(
        old_word.source(),
        word::Role::Predicate,
        [0xa7; 32],
        case.metadata
            .parent
            .into_iter()
            .flat_map(|v| u32::try_from(v.as_canonical_u64()).unwrap().to_le_bytes())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        case.metadata.enrollment,
        claims,
    )
    .unwrap();
    assert_eq!(
        different_word.claims().statement,
        old_word.claims().statement
    );
    let different = Expected::checked(
        &different_word,
        &data_expected,
        &request,
        vector,
        response.output().to_vec(),
    )
    .unwrap();
    assert!(matches!(
        Verifier::new(&different)
            .unwrap()
            .verify_retained(&retained, frames.evidence().query()),
        Err(Error::Word(word::Error::Binding))
    ));
    let mut different_vector = vector;
    different_vector[0] += Val::ONE;
    let different = Expected::checked(
        &old_word,
        &data_expected,
        &request,
        different_vector,
        response.output().to_vec(),
    )
    .unwrap();
    assert!(matches!(
        Verifier::new(&different)
            .unwrap()
            .verify_retained(&retained, frames.evidence().query()),
        Err(Error::Query(gold::Error::Binding))
    ));
    let different_request =
        gold::Request::checked([0x63; 32], request.ciphertexts().map(<[u8]>::to_vec)).unwrap();
    let different = Expected::checked(
        &old_word,
        &data_expected,
        &different_request,
        vector,
        response.output().to_vec(),
    )
    .unwrap();
    assert!(matches!(
        Verifier::new(&different)
            .unwrap()
            .verify_retained(&retained, frames.evidence().query()),
        Err(Error::Product(_))
    ));
    let [left, right] = request.ciphertexts();
    let swapped = gold::Request::checked(request.nonce(), [right.to_vec(), left.to_vec()]).unwrap();
    assert!(
        Expected::checked(
            &old_word,
            &data_expected,
            &swapped,
            vector,
            response.output().to_vec()
        )
        .is_err()
    );
    let mut different_output = response.output().to_vec();
    *different_output.last_mut().unwrap() ^= 1;
    if let Ok(different) = Expected::checked(
        &old_word,
        &data_expected,
        &request,
        vector,
        different_output,
    ) {
        assert!(matches!(
            Verifier::new(&different)
                .unwrap()
                .verify_retained(&retained, frames.evidence().query()),
            Err(Error::Product(_))
        ));
    }

    // Original wrappers stay separate; these new frames cannot mint their tokens.
    assert!(source::version::verify(state_expected, &frames.state).is_err());
    assert!(encoding::wire::BorrowedFrame::parse(&encoding_expected, &frames.child).is_err());
    assert!(data::verify_dense(data_expected.core_expected(), &frames.data).is_err());
    assert!(word::verify(&old_word, &frames.word).is_err());
    assert!(fused::verify(&query_expected, &frames.query).is_err());
    // A failed call cannot poison setup or turn a previous success into a cache hit.
    assert_eq!(
        receiver
            .verify_retained(&retained, frames.evidence().query())
            .unwrap()
            .output(),
        checked.output()
    );
    fresh_query(
        &owner,
        &data_expected,
        &retained,
        &data_words,
        &word_prover,
        &frames,
    );
}

fn fresh_query(
    owner: &protected::Owner,
    data_expected: &installed::Expected,
    retained: &installed::hash::CheckedData,
    data_words: &[u64],
    word_prover: &word::hash::Prover,
    previous: &Frames,
) {
    let began = Instant::now();
    let mut case = owner_cases::case(Kind::SkipBeforeOffset);
    case.input.mask[31] &= 0x7f;
    case.input.walk.call += 1;
    case.input.walk.invocation[0] += Val::ONE;
    case.metadata.blind_sql[0] += Val::ONE;
    case.input.walk.sql = case.metadata.blind_sql;
    case.rebuild();
    let statement: [Val; 96] = owner_cases::statement(&case.metadata, &case.input, &case.old)
        .try_into()
        .unwrap();
    let mut mask = Zeroizing::new(vec![0u64; gold::N]);
    for age in 0..256 {
        mask[255 - age] = u64::from((case.input.mask[age / 8] >> (age % 8)) & 1);
    }
    let original = owner
        .originate(
            protected::Mask256::new(case.input.mask),
            input_binding(&case, data_expected),
            data_expected.core_expected(),
        )
        .unwrap();
    let request = original.public_request().formation_request().unwrap();
    let context = formation::encoding_context(
        &request,
        data_expected.core_expected(),
        case.metadata.statement,
    )
    .unwrap();
    let salt = [10; 4];
    let vector = owner
        .query_commitment(&original, context.map(|v| v.as_canonical_u64()), &salt)
        .unwrap()
        .map(Val::from_u64);
    let query_expected = formation::expected(
        &request,
        data_expected.core_expected(),
        case.metadata.statement,
        vector,
    )
    .unwrap();
    let t = Instant::now();
    let response = protected::Evaluator::new()
        .unwrap()
        .evaluate(original.public_request())
        .unwrap();
    let product_ms = t.elapsed().as_secs_f64() * 1000.;
    let expected = Expected::checked(
        &word_expected(&case),
        data_expected,
        &request,
        vector,
        response.output().to_vec(),
    )
    .unwrap();
    let product = response.certificate();
    let ((checked, setup_ms, receive_ms, word, query), word_ms, query_ms) =
        std::thread::scope(|scope| {
            let (send, recv) = std::sync::mpsc::sync_channel::<(Vec<u8>, Vec<u8>)>(1);
            let expected = &expected;
            let receiving = scope.spawn(move || {
                let t = Instant::now();
                let verifier = Verifier::new(expected).unwrap();
                let setup_ms = t.elapsed().as_secs_f64() * 1000.;
                let (word, query) = recv.recv().unwrap();
                let t = Instant::now();
                let checked = verifier
                    .verify_retained(
                        retained,
                        QueryEvidence {
                            word: &word,
                            query: &query,
                            product,
                        },
                    )
                    .unwrap();
                (
                    checked,
                    setup_ms,
                    t.elapsed().as_secs_f64() * 1000.,
                    word,
                    query,
                )
            });
            let t = Instant::now();
            let word = word_prover
                .produce(&word_expected(&case), word_inputs(&mut case))
                .unwrap()
                .into_bytes();
            let word_ms = t.elapsed().as_secs_f64() * 1000.;
            let t = Instant::now();
            let query = fused::hash::prove(
                &query_expected,
                owner
                    .prepare_query(
                        &original,
                        &query_expected,
                        Zeroizing::new(statement.map(|v| v.as_canonical_u64())),
                        Zeroizing::new(salt),
                    )
                    .unwrap(),
            )
            .unwrap();
            let query_ms = t.elapsed().as_secs_f64() * 1000.;
            send.send((word, query)).unwrap();
            (receiving.join().unwrap(), word_ms, query_ms)
        });
    let t = Instant::now();
    let completed = owner
        .complete_checked_product(&original, checked.product())
        .unwrap();
    let client_ms = t.elapsed().as_secs_f64() * 1000.;
    let per_query_ms = began.elapsed().as_secs_f64() * 1000.;
    assert_eq!(
        completed.coefficients(),
        ring_oracle(data_words, &mask).as_slice()
    );
    assert_eq!(completed.coefficients()[6 * 512 + 255], 0);
    assert_eq!(completed.coefficients()[7 * 512 + 255], 0);
    let rayon_threads = p3_maybe_rayon::prelude::current_num_threads();
    eprintln!(
        "hash_query prepared_and_proved=true retained_DATA=true DIFFERENT_query=true word_role_setup_reused=true query_and_receiving_setup_in_budget=true shared_rayon_threads={rayon_threads} word_ms={word_ms:.3} query_ms={query_ms:.3} product_ms={product_ms:.3} receiving_setup_ms={setup_ms:.3} fresh_receive_ms={receive_ms:.3} client_ms={client_ms:.3} per_query_ms={per_query_ms:.3} bytes={} SQL=false network=false freshness=false locks=false security_assessed=false",
        word.len() + query.len() + product.len()
    );
    let verifier = Verifier::new(&expected).unwrap();
    assert!(
        verifier
            .verify_retained(
                retained,
                QueryEvidence {
                    word: &word,
                    query: &previous.query,
                    product
                }
            )
            .is_err()
    );
    let bad = damage_batch(&query);
    assert!(matches!(
        verifier.verify_retained(
            retained,
            QueryEvidence {
                word: &word,
                query: &bad,
                product
            }
        ),
        Err(Error::Query(gold::Error::Verification))
    ));
    let bad = damage_batch(&word);
    assert!(matches!(
        verifier.verify_retained(
            retained,
            QueryEvidence {
                word: &bad,
                query: &query,
                product
            }
        ),
        Err(Error::Word(word::Error::Verification))
    ));
    assert!(
        verifier
            .verify_retained(
                retained,
                QueryEvidence {
                    word: &previous.word,
                    query: &query,
                    product
                }
            )
            .is_err()
    );
    assert!(
        verifier
            .verify_retained(
                retained,
                QueryEvidence {
                    word: &word,
                    query: &query,
                    product: &previous.product
                }
            )
            .is_err()
    );
    assert_eq!(
        verifier
            .verify_retained(
                retained,
                QueryEvidence {
                    word: &word,
                    query: &query,
                    product
                }
            )
            .unwrap()
            .output(),
        checked.output()
    );
}
