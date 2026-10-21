//! One explicit PUBLIC NONSECRET full-chain fixture. Never a SQL/network answer.
use super::super::product;
use super::*;
use crate::{Val, admission::CanonicalSource, source};
use bfv_hiding_stark::{Challenge, Config};
use bfv_unrelinearized_product as arithmetic;
use compact_store::{Layout, Owner};
use fhe::bfv::{BfvParametersBuilder, Ciphertext, Encoding, Plaintext, SecretKey};
use fhe_math::zq::Modulus;
use fhe_traits::{
    DeserializeParametrized, FheDecoder, FheDecrypter, FheEncoder, FheEncrypter, Serialize,
};
use p3_goldilocks::default_goldilocks_poseidon2_12;
use p3_symmetric::Permutation;
use std::time::Instant;

const AEAD_KEY: [u8; 32] = [0x71; 32];
const ROWS: [u8; 12] = [0, 255, 255, 1, 0, 0, 128, 255, 0, 255, 254, 255];
fn public_mask() -> [u8; 32] {
    // Build the private WHERE input over the PUBLIC domain, never owner rows.
    let mut mask = [0; 32];
    for age in 0..256 {
        if age >= 128 {
            mask[age / 8] |= 1 << (age % 8);
        }
    }
    mask
}
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
    fields.extend(context.iter().map(|v| v.as_canonical_u64()));
    fields.extend(salt);
    fields.extend([0; 4]);
    for group in key[3..].as_chunks::<8>().0 {
        let mut word = 0u64;
        for (i, &byte) in group.iter().enumerate() {
            assert!(byte <= 40);
            let s = i64::from(byte >> 1) ^ -i64::from(byte & 1);
            word |= ((s + 20) as u64) << (6 * i);
        }
        fields.push(word);
    }
    assert_eq!(fields.len(), 528);
    let mut state = [Val::ZERO; 12];
    let permutation = default_goldilocks_poseidon2_12();
    for block in fields.as_chunks::<8>().0 {
        for (cell, &v) in state[..8].iter_mut().zip(block) {
            *cell = Val::from_u64(v);
        }
        permutation.permute_mut(&mut state);
    }
    state[..4].try_into().unwrap()
}
/// Fixture owner-only completion; never passed to the public producer/checker.
struct ClientCompletion {
    key: SecretKey,
    parameters: std::sync::Arc<fhe::bfv::BfvParameters>,
    expected: Zeroizing<Vec<u64>>,
}
impl ClientCompletion {
    fn complete(self, actual_output: &[u8]) {
        let output = Ciphertext::from_bytes(actual_output, &self.parameters).unwrap();
        let plaintext: Plaintext = self.key.try_decrypt(&output).unwrap();
        let plaintext = Zeroizing::new(plaintext);
        let actual = Zeroizing::new(Vec::<u64>::try_decode(&*plaintext, Encoding::poly()).unwrap());
        assert!(*actual == *self.expected); // PUBLIC full-ring oracle only after checked response.
    }
}
/// Public encrypted evaluator: no owner key, plaintext, private mask or expected answer.
fn public_product(
    ciphertexts: [&[u8]; 2],
    parameters: &std::sync::Arc<fhe::bfv::BfvParameters>,
) -> Vec<u8> {
    let [a, b] = ciphertexts.map(|bytes| Ciphertext::from_bytes(bytes, parameters).unwrap());
    let output = &a * &b;
    assert_eq!(output.len(), 3);
    output.to_bytes()
}
fn public_ring_oracle(inputs: &[Zeroizing<Vec<u64>>; 2]) -> Zeroizing<Vec<u64>> {
    // Independent PUBLIC fixture oracle. It never feeds the encrypted producer.
    let mut output = Zeroizing::new(vec![0; super::super::N]);
    for (i, &x) in inputs[0].iter().enumerate().filter(|(_, x)| **x != 0) {
        for (j, &y) in inputs[1].iter().enumerate().filter(|(_, y)| **y != 0) {
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
fn encrypted_request(
    key: &SecretKey,
    parameters: &std::sync::Arc<fhe::bfv::BfvParameters>,
) -> (gold::Request, Vec<u8>, Zeroizing<Vec<u64>>) {
    let modulus = Modulus::new(super::super::T).unwrap();
    let inverse = modulus.inv(super::super::SCALE).unwrap();
    let mut inputs = [
        super::super::circuit::compile_source(&ROWS),
        super::super::circuit::compile_mask(&public_mask()),
    ];
    let mut ciphertexts = Vec::with_capacity(2);
    for w in &mut inputs {
        // W is already the source/command compiler output. SDK internally scales
        // plaintext by SCALE exactly ONCE; encrypt m=W*SCALE^-1 modt.
        modulus.scalar_mul_vec(w, inverse);
        let plaintext = Zeroizing::new(
            Plaintext::try_encode(w.as_slice(), Encoding::poly(), parameters).unwrap(),
        );
        let encrypted: Ciphertext = key.try_encrypt(&*plaintext, &mut rand::rng()).unwrap();
        let full = Ciphertext::new(encrypted.iter().cloned().collect(), parameters).unwrap();
        let decrypted: Plaintext = key.try_decrypt(&full).unwrap();
        let decoded = Zeroizing::new(Vec::<u64>::try_decode(&decrypted, Encoding::poly()).unwrap());
        assert!(*decoded == **w); // Fixture-only encryption-input oracle, no selected result.
        ciphertexts.push(full.to_bytes());
    }
    let request = gold::Request::checked([0x61; 32], ciphertexts.try_into().unwrap()).unwrap();
    let began = Instant::now();
    let output = public_product(request.ciphertexts(), parameters);
    eprintln!(
        "two_lane_product phase=sdk_public_product ms={:.3} bytes={}",
        began.elapsed().as_secs_f64() * 1000.,
        output.len()
    );
    let oracle = public_ring_oracle(&inputs);
    (request, output, oracle)
}
fn canonical_source(q: [u8; 32]) -> (CanonicalSource, Zeroizing<Vec<u8>>) {
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
    let mut index = Zeroizing::new(vec![0u8; 2336]);
    index[..112].copy_from_slice(&stored.commitment().encode());
    index[112..144].fill(0x31);
    let ages = [0u8, 1, 128, 255];
    let mut count = 0u32;
    for age in 0..256 {
        let present = ages.contains(&(age as u8));
        index[144 + 4 * age..148 + 4 * age].copy_from_slice(&u32::from(present).to_le_bytes());
        index[1168 + 4 * age..1172 + 4 * age].copy_from_slice(&count.to_le_bytes());
        if present {
            index[2196 + count as usize] =
                ages.iter().position(|x| usize::from(*x) == age).unwrap() as u8;
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
    let key_root = source::commitment::digest(&source::commitment::key_fields(
        &stored.commitment().encode(),
        AEAD_KEY,
        [Val::ONE; 4],
    ));
    let mut claim = source::Statement::checked_relation(
        source::Relation::CanonicalIndex,
        [&stored.encode(), &indexed.encode()],
        [stored.commitment(), indexed.commitment()],
        q,
        source::statement::encode_digest(key_root),
        [0; 32],
    )
    .unwrap();
    let mut plain = Zeroizing::new(Vec::with_capacity(2348));
    plain.extend(ROWS);
    plain.extend_from_slice(&index);
    claim.open_commitment = source::commitment::digest(&source::commitment::opening_fields(
        &claim,
        [Val::TWO; 4],
        &plain,
    ));
    (CanonicalSource::checked_claim(&claim).unwrap(), plain)
}
struct Fixture {
    request: gold::Request,
    expected: Expected,
    original: CanonicalSource,
    source: Witness,
    mask: Witness,
    key: Zeroizing<Vec<u8>>,
    cs_salt: Zeroizing<[u64; 4]>,
    output: Vec<u8>,
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
    let (request, output, oracle) = encrypted_request(&key, &parameters);
    let bytes = Zeroizing::new(key.to_bytes());
    let cs_salt = Zeroizing::new([7; 4]);
    let context = secret_context(&key_binding([Val::ZERO; 4]).values()).unwrap();
    let root = cs_root(context, &bytes, *cs_salt);
    let binding = key_binding(root);
    assert!(secret_context(&binding.values()).unwrap() == context);
    let (original, plain) = canonical_source(request.q());
    let source_expected = statement::Expected::source(&original, binding.clone()).unwrap();
    let draft = statement::Expected::private_mask(
        &original,
        binding.clone(),
        [0x51; 32],
        request.nonce(),
        [0; 32],
    )
    .unwrap();
    let mask = public_mask();
    let command = super::super::commitment::command_digest(
        &super::super::commitment::command_fields(&draft, mask, [Val::from_u8(4); 4]),
    );
    let mask_expected = statement::Expected::private_mask(
        &original,
        binding,
        [0x51; 32],
        request.nonce(),
        source::statement::encode_digest(command),
    )
    .unwrap();
    let source = Witness::source(&source_expected, plain, [2; 4], [5; 4]).unwrap();
    let mask = Witness::private_mask(&mask_expected, Zeroizing::new(mask), [4; 4], [6; 4]).unwrap();
    let expected = Expected::checked(&request, &source.statement(), &mask.statement()).unwrap();
    // The SAME key encrypted both actual operands and supplied Cs/serializedS.
    // Only this private fixture owner retains the actual key for completion AFTER
    // the new receiving checker. Neither public evaluator nor checker sees it.
    let completion = ClientCompletion {
        key,
        parameters,
        expected: oracle,
    };
    Fixture {
        request,
        expected,
        original,
        source,
        mask,
        key: bytes,
        cs_salt,
        output,
        completion,
    }
}
struct Evidence {
    original: Vec<u8>,
    source: Vec<u8>,
    mask: Vec<u8>,
}
impl Evidence {
    fn borrowed(&self) -> Prerequisites<'_> {
        Prerequisites::checked(&self.original, &self.source, &self.mask).unwrap()
    }
}
fn prerequisites(f: &Fixture) -> Evidence {
    let start = Instant::now();
    let witness =
        source::circuit::Witness::new(AEAD_KEY, [Val::ONE; 4], [Val::TWO; 4], [0, 1, 128, 255]);
    let original = source::prove(&f.original, &witness).unwrap().into_bytes();
    eprintln!(
        "two_lane_formation phase=source_prove ms={:.3} bytes={}",
        start.elapsed().as_secs_f64() * 1000.,
        original.len()
    );
    let start = Instant::now();
    let source = super::super::prove(&f.expected.source.expected, &f.source, &original)
        .unwrap()
        .as_bytes()
        .to_vec();
    let mask = super::super::prove(&f.expected.mask.expected, &f.mask, &original)
        .unwrap()
        .as_bytes()
        .to_vec();
    eprintln!(
        "two_lane_formation phase=children_prove ms={:.3} bytes={}",
        start.elapsed().as_secs_f64() * 1000.,
        source.len() + mask.len()
    );
    Evidence {
        original,
        source,
        mask,
    }
}
fn early_rejections(f: &Fixture) {
    assert!(Prerequisites::checked(&[], &[1], &[1]).is_err());
    // Bad Formation size must reject before attempting these invalid proofs.
    for bytes in [&[][..], &vec![0; gold::MAX_EVIDENCE_BYTES + 1]] {
        assert!(matches!(
            verify(
                &f.expected,
                &f.request,
                Prerequisites::checked(&[1], &[1], &[1]).unwrap(),
                bytes
            ),
            Err(Error::Formation(gold::Error::Resource))
        ));
    }
    assert!(Expected::checked(&f.request, &f.expected.mask, &f.expected.source).is_err());
    let mut nonce = f.request.nonce();
    nonce[0] ^= 1;
    let mut raw = f.request.bytes().to_vec();
    raw[40..72].copy_from_slice(&nonce);
    let foreign = gold::Request::decode(&raw).unwrap();
    assert!(Expected::checked(&foreign, &f.expected.source, &f.expected.mask).is_err());
    assert!(f.expected.require_request(&foreign).is_err());
    assert!(
        product::Expected::checked(
            &foreign,
            f.expected.source(),
            f.expected.private_mask(),
            f.output.clone()
        )
        .is_err()
    );
    assert!(
        product::Expected::checked(
            &f.request,
            f.expected.private_mask(),
            f.expected.source(),
            f.output.clone()
        )
        .is_err()
    );
    assert!(
        product::Expected::checked(
            &f.request,
            f.expected.source(),
            f.expected.private_mask(),
            Vec::new()
        )
        .is_err()
    );
    let mut tail = super::super::circuit::compile_source(&ROWS);
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
    let mut secret = f.key.to_vec();
    *secret.last_mut().unwrap() = 41;
    assert!(
        gold::SecretOpening::checked(
            f.expected.core.contexts()[2],
            f.expected.core.roots()[2],
            Zeroizing::new(secret),
            Zeroizing::new([7; 4])
        )
        .is_err()
    );
    let mut cs = f.expected.core.roots()[2];
    cs[3] += Val::ONE;
    assert!(
        gold::SecretOpening::checked(
            f.expected.core.contexts()[2],
            cs,
            Zeroizing::new(f.key.to_vec()),
            Zeroizing::new([7; 4])
        )
        .is_err()
    );
}
fn repaired_ood(frame: &[u8]) -> Vec<u8> {
    // Actual bounded canonical native public proof, never a fabricated capability.
    assert!(frame.len() > 128 && &frame[..8] == b"DCSGFM01");
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
    let bytes = postcard::to_allocvec(&proof).unwrap();
    drop(proof);
    let mut repaired = frame[..128].to_vec();
    repaired[104..108].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
    repaired.extend(bytes);
    repaired
}

#[test]
fn genuine_final_witnesses_form_actual_sdk_ciphertexts_then_require_fresh_receiving_proofs() {
    let started = Instant::now();
    let f = fixture();
    early_rejections(&f);
    let evidence = prerequisites(&f);
    let Fixture {
        request,
        expected,
        original,
        source,
        mask,
        key,
        cs_salt,
        output,
        completion,
    } = f;
    drop(original);
    let query_expected =
        product::Expected::checked(&request, expected.source(), expected.private_mask(), output)
            .unwrap();
    let began = Instant::now();
    let public_arithmetic = arithmetic::produce(query_expected.product())
        .unwrap()
        .into_bytes();
    eprintln!(
        "two_lane_product phase=arithmetic_produce ms={:.3} bytes={}",
        began.elapsed().as_secs_f64() * 1000.,
        public_arithmetic.len()
    );
    let private = PrivateInputs::checked(source, mask, key, cs_salt).unwrap();
    let began = Instant::now();
    let bytes = prove(&expected, &request, evidence.borrowed(), private)
        .unwrap()
        .into_bytes();
    eprintln!(
        "two_lane_formation phase=consuming_prove ms={:.3} bytes={}",
        began.elapsed().as_secs_f64() * 1000.,
        bytes.len()
    );
    let began = Instant::now();
    let verified = product::verify(
        &query_expected,
        product_prerequisites(&evidence, &bytes, &public_arithmetic),
    )
    .unwrap();
    assert!(verified.expected().formation().request().bytes() == request.bytes());
    assert!(verified.expected().product().output_wire() == query_expected.product().output_wire());
    let receive_ms = began.elapsed().as_secs_f64() * 1000.;
    let complete_started = Instant::now();
    completion.complete(verified.expected().product().output_wire());
    eprintln!(
        "two_lane_product phase=checked_client_completion ms={:.3}",
        complete_started.elapsed().as_secs_f64() * 1000.
    );
    drop(verified);
    eprintln!("two_lane_product phase=fresh_receive ms={receive_ms:.3}");
    // Wrong independent Cw cannot pass the cheap unverified-frame association.
    let mut foreign = expected.source.clone();
    foreign.encoded[3] += Val::ONE;
    let foreign = Expected::checked(&request, &foreign, &expected.mask).unwrap();
    assert!(matches!(
        verify(&foreign, &request, evidence.borrowed(), &bytes),
        Err(Error::Binding)
    ));
    let mut bad_header = bytes.clone();
    bad_header[40] ^= 1;
    assert!(matches!(
        verify(&expected, &request, evidence.borrowed(), &bad_header),
        Err(Error::Formation(gold::Error::Binding))
    ));
    assert!(matches!(
        product::verify(
            &query_expected,
            product_prerequisites(&evidence, &bad_header, &public_arithmetic)
        ),
        Err(product::Error::Formation(Error::Formation(
            gold::Error::Binding
        )))
    ));
    let repaired = repaired_ood(&bytes);
    assert!(matches!(
        verify(&expected, &request, evidence.borrowed(), &repaired),
        Err(Error::Formation(gold::Error::Verification))
    ));
    assert!(matches!(
        product::verify(
            &query_expected,
            product_prerequisites(&evidence, &repaired, &public_arithmetic)
        ),
        Err(product::Error::Formation(Error::Formation(
            gold::Error::Verification
        )))
    ));
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(verify(&expected, &request, evidence.borrowed(), &trailing).is_err());
    product_receiving_rejections(&query_expected, &evidence, &bytes, &public_arithmetic);
    eprintln!(
        "two_lane_formation phase=whole ms={:.3}",
        started.elapsed().as_secs_f64() * 1000.
    );
}

fn product_prerequisites<'a>(
    evidence: &'a Evidence,
    formation: &'a [u8],
    product: &'a [u8],
) -> product::BorrowedPrerequisites<'a> {
    product::BorrowedPrerequisites::checked(
        &evidence.original,
        &evidence.source,
        &evidence.mask,
        formation,
        product,
    )
    .unwrap()
}
/// Canonical PUBLIC hostile Ct3, not a produced/checked result or oracle fallback.
fn changed_output_claim(expected: &product::Expected) -> Vec<u8> {
    fn varint(out: &mut Vec<u8>, mut value: usize) {
        while value >= 128 {
            out.push((value as u8 & 127) | 128);
            value >>= 7;
        }
        out.push(value as u8);
    }
    let mut output = Vec::new();
    for component in 0..3 {
        let mut rows = expected.product().output(component).clone();
        if component == 2 {
            rows[1][super::super::N - 1] = (rows[1][super::super::N - 1] + 1) % super::super::Q[1];
        }
        let mut packed = Vec::with_capacity(super::super::N * 60 / 8);
        let mut word = 0u128;
        let mut bits = 0;
        for row in rows {
            for value in row {
                word |= u128::from(value) << bits;
                bits += 30;
                while bits >= 8 {
                    packed.push(word as u8);
                    word >>= 8;
                    bits -= 8;
                }
            }
        }
        assert_eq!(bits, 0);
        let mut polynomial = vec![8, 2, 16];
        varint(&mut polynomial, super::super::N);
        polynomial.push(26);
        varint(&mut polynomial, packed.len());
        polynomial.extend(packed);
        output.push(10);
        varint(&mut output, polynomial.len());
        output.extend(polynomial);
    }
    output
}
fn product_receiving_rejections(
    expected: &product::Expected,
    evidence: &Evidence,
    formation: &[u8],
    frame: &[u8],
) {
    // These caps reject BEFORE touching invalid prerequisite proof bytes.
    for product in [&[][..], &frame[..frame.len() - 1]] {
        assert!(matches!(
            product::BorrowedPrerequisites::checked(&[1], &[1], &[1], &[1], product),
            Err(product::Error::ResourceLimit)
        ));
    }
    assert!(matches!(
        product::BorrowedPrerequisites::checked(&[1], &[1], &[1], &[], frame),
        Err(product::Error::ResourceLimit)
    ));
    // Same authentic input/Formation, different complete canonical output claim.
    let foreign = product::Expected::checked(
        expected.formation().request(),
        expected.formation().source(),
        expected.formation().private_mask(),
        changed_output_claim(expected),
    )
    .unwrap();
    assert!(foreign.product().output_wire() != expected.product().output_wire());
    assert!(matches!(
        product::verify(&foreign, product_prerequisites(evidence, formation, frame)),
        Err(product::Error::Arithmetic(arithmetic::Error::Binding))
    ));
    // A canonical last reduction quotient is still not the proven output relation.
    let mut changed = frame.to_vec();
    *changed.last_mut().unwrap() ^= 1;
    assert!(matches!(
        product::verify(
            expected,
            product_prerequisites(evidence, formation, &changed)
        ),
        Err(product::Error::Arithmetic(arithmetic::Error::Arithmetic))
    ));
}
