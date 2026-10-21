//! NONSECRET examples with real SDK encryption and both actual native verifiers.
use super::super::super::owner_cases::{self, Kind};
use super::*;
use bfv_hiding_stark::{Challenge, Config};
use fhe::bfv::{BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, Plaintext, SecretKey};
use fhe_traits::{FheEncoder, FheEncrypter, Serialize};
use p3_batch_stark::BatchProof;
use p3_goldilocks::default_goldilocks_poseidon2_12;
use p3_symmetric::Permutation;
use std::{
    sync::{Arc, OnceLock},
    time::Instant,
};
use zeroize::Zeroizing;

fn parameters() -> Arc<BfvParameters> {
    static PARAMETERS: OnceLock<Arc<BfvParameters>> = OnceLock::new();
    PARAMETERS
        .get_or_init(|| {
            BfvParametersBuilder::new()
                .set_degree(gold::N)
                .set_plaintext_modulus(gold::T)
                .set_moduli(&gold::Q)
                .set_variance(10)
                .build_arc()
                .unwrap()
        })
        .clone()
}
fn encrypt(key: &SecretKey, p: &Arc<BfvParameters>, values: &[u64]) -> Vec<u8> {
    let plaintext = Zeroizing::new(Plaintext::try_encode(values, Encoding::poly(), p).unwrap());
    let ciphertext: Ciphertext = key.try_encrypt(&*plaintext, &mut rand::rng()).unwrap();
    Ciphertext::new(ciphertext.iter().cloned().collect(), p)
        .unwrap()
        .to_bytes()
}
fn commitment(context: [Val; 8], salt: [Val; 4], words: &[u64]) -> [Val; 4] {
    assert!(matches!(words.len(), 4096 | 512));
    let mut fields = context
        .into_iter()
        .chain(salt)
        .chain([Val::ZERO; 4])
        .chain(words.iter().copied().map(Val::from_u64))
        .collect::<Vec<_>>();
    let mut state = [Val::ZERO; 12];
    let permutation = default_goldilocks_poseidon2_12();
    for block in fields.as_chunks::<8>().0 {
        state[..8].copy_from_slice(block);
        permutation.permute_mut(&mut state);
    }
    let root = state[..4].try_into().unwrap();
    fields.fill(Val::ZERO);
    state.fill(Val::ZERO);
    root
}
struct Example {
    expected: Expected,
    request: gold::Request,
    installed: data::Expected,
    statement: [Val; 96],
    mask: [u8; 32],
    salt: [Val; 4],
    key: Zeroizing<Vec<u8>>,
    key_salt: [Val; 4],
}
impl Example {
    fn new(wrong_query_plaintext: bool) -> Self {
        let p = parameters();
        let key = SecretKey::random(&p, &mut rand::rng());
        let mut case = owner_cases::case(Kind::SkipBeforeOffset);
        // Fixed PUBLIC encoding example exercises all 256 reversed positions.
        // It is not an assertion of this fixture's SQL/lock outcome.
        case.input.mask = core::array::from_fn(|i| (i as u8).wrapping_mul(29) ^ 0xa7);
        let statement: [Val; 96] = owner_cases::statement(&case.metadata, &case.input, &case.old)
            .try_into()
            .unwrap();
        let statement_root = writer::digest(&statement).unwrap();
        let mut raw = Zeroizing::new(vec![0u64; gold::N]);
        for i in 0..256 {
            raw[255 - i] = u64::from((case.input.mask[i / 8] >> (i % 8)) & 1);
        }
        if wrong_query_plaintext {
            raw[256] = 1;
        }
        let query = encrypt(&key, &p, &raw);
        let data_words = Zeroizing::new(
            (0..gold::N)
                .map(|i| (i as u64) % gold::T)
                .collect::<Vec<_>>(),
        );
        let data_ct = encrypt(&key, &p, &data_words);
        let secret = Zeroizing::new(fhe::proto::bfv::SecretKey::from(&key).coeffs);
        let packed = Zeroizing::new(
            secret
                .as_chunks::<8>()
                .0
                .iter()
                .map(|row| {
                    row.iter()
                        .enumerate()
                        .fold(0u64, |word, (i, &v)| word | (((v + 20) as u64) << (6 * i)))
                })
                .collect::<Vec<_>>(),
        );
        let key_salt = [Val::from_u32(0x7149); 4];
        let key_context = [Val::from_u32(0x3b19); 8];
        let data_context = [Val::from_u32(0x3159); 8];
        let data_scaled = Zeroizing::new(
            data_words
                .iter()
                .map(|v| v * gold::SCALE % gold::T)
                .collect::<Vec<_>>(),
        );
        let installed = data::Expected::checked(
            data::Request::checked([0x51; 32], data_ct.clone()).unwrap(),
            [0x52; 64],
            [data_context, key_context],
            [
                commitment(data_context, [Val::from_u32(7); 4], &data_scaled),
                commitment(key_context, key_salt, &packed),
            ],
        )
        .unwrap();
        let request = gold::Request::checked([0x49; 32], [data_ct, query]).unwrap();
        let context = encoding_context(&request, &installed, statement_root).unwrap();
        let salt = [Val::from_u32(0x5519); 4];
        // The compiled mask always has a zero high tail, even in the hostile case.
        let mut scaled = Zeroizing::new(vec![0u64; gold::N]);
        for i in 0..256 {
            scaled[255 - i] = u64::from((case.input.mask[i / 8] >> (i % 8)) & 1) * gold::SCALE;
        }
        let vector = commitment(context, salt, &scaled);
        let expected = Expected::checked(&request, &installed, statement_root, vector).unwrap();
        Self {
            expected,
            request,
            installed,
            statement,
            mask: case.input.mask,
            salt,
            key: Zeroizing::new(key.to_bytes()),
            key_salt,
        }
    }
    fn opening(&self) -> writer::Opening {
        writer::Opening::checked(&self.expected.mask, self.statement, self.mask, self.salt).unwrap()
    }
    fn secret(&self) -> gold::SecretOpening {
        gold::SecretOpening::checked(
            self.installed.contexts()[1],
            self.installed.roots()[1],
            self.key.clone(),
            Zeroizing::new(self.key_salt.map(|v| v.as_canonical_u64())),
        )
        .unwrap()
    }
}

#[test]
fn original_pair_statement_and_complete_data_expectation_fix_the_same_query_and_cs() {
    let e = Example::new(false);
    assert_eq!(
        e.expected.formation.request().ciphertext(),
        e.request.ciphertexts()[1]
    );
    assert_eq!(
        e.expected.formation.contexts()[1],
        e.installed.contexts()[1]
    );
    assert_eq!(e.expected.formation.roots()[1], e.installed.roots()[1]);
    assert_eq!(e.expected.formation.roots()[0], e.expected.mask.vector);
    let mut root = e.expected.mask.statement;
    root[3] += Val::ONE;
    assert_ne!(
        encoding_context(&e.request, &e.installed, root).unwrap(),
        e.expected.mask.context
    );
    let foreign =
        gold::Request::checked([0x48; 32], e.request.ciphertexts().map(<[u8]>::to_vec)).unwrap();
    assert_ne!(
        encoding_context(&foreign, &e.installed, e.expected.mask.statement).unwrap(),
        e.expected.mask.context
    );
    let changed_data = data::Expected::checked(
        e.installed.request().clone(),
        [0x53; 64],
        e.installed.contexts(),
        e.installed.roots(),
    )
    .unwrap();
    assert_ne!(
        encoding_context(&e.request, &changed_data, e.expected.mask.statement).unwrap(),
        e.expected.mask.context
    );
    let swapped = gold::Request::checked(
        e.request.nonce(),
        [
            e.request.ciphertexts()[1].to_vec(),
            e.request.ciphertexts()[0].to_vec(),
        ],
    )
    .unwrap();
    assert!(matches!(
        encoding_context(&swapped, &e.installed, e.expected.mask.statement),
        Err(Error::Binding)
    ));
}

#[test]
fn real_query_formation_and_mask_proofs_both_verify_and_each_corrupted_native_argument_fails() {
    let e = Example::new(false);
    let began = Instant::now();
    let evidence =
        produce(&e.expected, e.opening(), e.secret()).expect("both genuine native proofs");
    let produced = began.elapsed();
    let began = Instant::now();
    verify(&e.expected, &evidence).expect("two independently prepared full native verifiers");
    let received = began.elapsed();
    eprintln!(
        "query_formation_join produce_ms={:.3} cold_receive_ms={:.3} sum_ms={:.3} mask_bytes={} formation_bytes={} original_QueryCt=true same_Cs=true Word=false DATA_admission=false freshness=false SQL=false",
        produced.as_secs_f64() * 1000.,
        received.as_secs_f64() * 1000.,
        (produced + received).as_secs_f64() * 1000.,
        evidence.mask.len(),
        evidence.formation.len()
    );

    // Comparable baseline on the SAME literal ciphertext, key, statement and W.
    // This old backend is test-only comparison, never a receiving fallback.
    let began = Instant::now();
    let opening = e.opening();
    let prepared = data::Prepared::new(
        &e.expected.formation,
        opening.formation_opening(&e.expected.mask).unwrap(),
        e.secret(),
    )
    .unwrap();
    let original = Evidence {
        mask: backend::ProverSetup::new()
            .unwrap()
            .produce(&e.expected.mask, opening)
            .unwrap(),
        formation: data::prove(&e.expected.formation, prepared)
            .unwrap()
            .into_bytes(),
    };
    let original_produced = began.elapsed();
    let began = Instant::now();
    backend::verify(&e.expected.mask, &original.mask).unwrap();
    data::verify(&e.expected.formation, &original.formation).unwrap();
    let original_received = began.elapsed();
    eprintln!(
        "query_formation_join_baseline produce_ms={:.3} cold_receive_ms={:.3} sum_ms={:.3} mask_bytes={} formation_bytes={} SAME_original_pair=true SAME_statement=true SAME_Cs=true SQL=false",
        original_produced.as_secs_f64() * 1000.,
        original_received.as_secs_f64() * 1000.,
        (original_produced + original_received).as_secs_f64() * 1000.,
        original.mask.len(),
        original.formation.len()
    );
    assert!(matches!(
        data::verify(&e.expected.formation, &evidence.formation),
        Err(gold::Error::Encoding)
    ));
    assert!(matches!(
        verify(&e.expected, &original),
        Err(Error::Formation(gold::Error::Encoding))
    ));
    drop(original);

    let gate = super::super::security::assess(&super::super::air::QueryMaskAir::closed().unwrap())
        .unwrap();
    let mut bad: BatchProof<Config> = super::super::wire::decode(
        super::super::wire::payload(&e.expected.mask, &evidence.mask).unwrap(),
        &gate,
    )
    .unwrap();
    bad.opened_values.instances[0]
        .base_opened_values
        .trace_local[0] += Challenge::ONE;
    let forged = Evidence {
        mask: super::super::wire::encode(&e.expected.mask, &bad, &gate).unwrap(),
        formation: evidence.formation.clone(),
    };
    assert!(matches!(
        verify(&e.expected, &forged),
        Err(Error::Mask(backend::Error::Verification))
    ));
    drop(bad);

    // Genuine locally produced lower frame only; production always uses its bounded decoder.
    assert_eq!(&evidence.formation[..8], b"DCSGDD01");
    let mut bad: BatchProof<Config> = postcard::from_bytes(&evidence.formation[128..]).unwrap();
    bad.opened_values.instances[0]
        .base_opened_values
        .trace_local[0] += Challenge::ONE;
    let payload = postcard::to_allocvec(&bad).unwrap();
    let mut forged = Evidence {
        mask: evidence.mask.clone(),
        formation: evidence.formation[..128].to_vec(),
    };
    forged.formation[104..108].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    forged.formation.extend(payload);
    assert!(matches!(
        verify(&e.expected, &forged),
        Err(Error::Formation(gold::Error::Verification))
    ));
    drop(bad);

    let mut foreign_nonce = e.request.nonce();
    foreign_nonce[0] ^= 1;
    let foreign_request =
        gold::Request::checked(foreign_nonce, e.request.ciphertexts().map(<[u8]>::to_vec)).unwrap();
    let foreign = Expected::checked(
        &foreign_request,
        &e.installed,
        e.expected.mask.statement,
        e.expected.mask.vector,
    )
    .unwrap();
    assert!(matches!(
        verify(&foreign, &evidence),
        Err(Error::Mask(backend::Error::Binding))
    ));
    assert!(matches!(
        verify(
            &e.expected,
            &Evidence {
                mask: vec![],
                formation: evidence.formation
            }
        ),
        Err(Error::Resource)
    ));
}

#[test]
fn honest_mask_proof_cannot_substitute_for_original_ciphertext_with_wrong_high_plaintext() {
    let e = Example::new(true);
    // Actual SDK Ct is canonical and uses the SAME secret, but encrypts W[256]!=0.
    // Mask proof is genuine; full Formation equations must reject that query input.
    assert!(matches!(
        produce(&e.expected, e.opening(), e.secret()),
        Err(Error::Formation(gold::Error::Arithmetic))
    ));
}
