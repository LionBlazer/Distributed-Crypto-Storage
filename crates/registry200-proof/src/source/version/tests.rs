//! PUBLIC NONSECRET source fixture; one actual honest proof, no fake verification.
use super::*;
use crate::{Val, admission::CanonicalSource};
use bfv_hiding_stark::{Challenge, codec};
use compact_store::{Commitment, Layout, Owner};
use p3_field::PrimeCharacteristicRing;
use std::sync::OnceLock;
use std::time::Instant;
use zeroize::Zeroizing;

const PUBLIC_KEY: [u8; 32] = [0x51; 32];
const AGES: [u8; 4] = [255, 0, 255, 128];
struct Fixture {
    expected: SourceVersionExpected,
    images: [Vec<u8>; 2],
    heads: [Commitment; 2],
}
impl Fixture {
    fn checked(&self, key: [u8; 32], state: [u8; 32]) -> SourceVersionExpected {
        SourceVersionExpected::checked(
            [&self.images[0], &self.images[1]],
            [&self.heads[0], &self.heads[1]],
            key,
            state,
        )
        .unwrap()
    }
    fn witness(&self) -> Witness {
        Witness::new(PUBLIC_KEY, [Val::ONE; 4], [Val::TWO; 4], AGES)
    }
}
fn fixture() -> &'static Fixture {
    static PUBLIC: OnceLock<Fixture> = OnceLock::new();
    PUBLIC.get_or_init(|| {
        // No live Owner/key/config or SDK object survives in this public fixture.
        let owner = Owner::from_key([0x42; 16], [0x73; 16], Zeroizing::new(PUBLIC_KEY));
        let data = [255, 0, 0, 0, 255, 255, 255, 0, 1, 128, 255, 0];
        let stored = owner
            .seal(
                Layout {
                    schema: super::super::DATA_SCHEMA,
                    row_width: 3,
                    rows_per_page: 256,
                    row_count: 4,
                },
                &data,
                super::super::statement::limits(),
            )
            .unwrap();
        // Reviewed core-owned PUBLIC index vector, shared with the old State fixture.
        let suffix: Vec<u8> =
            include_str!("../../../../compact-query/tests/fixtures/index-v3-four-row-suffix.hex")
                .lines()
                .filter(|line| !line.starts_with('#'))
                .flat_map(str::split_whitespace)
                .map(|hex| u8::from_str_radix(hex, 16).unwrap())
                .collect();
        assert_eq!(suffix.len(), 2224);
        let mut index = stored.commitment().encode().to_vec();
        index.extend_from_slice(&suffix);
        let indexed = owner
            .seal(
                Layout {
                    schema: super::super::INDEX_SCHEMA,
                    row_width: 1,
                    rows_per_page: 4096,
                    row_count: 2336,
                },
                &index,
                super::super::statement::limits(),
            )
            .unwrap();
        let images = [stored.encode(), indexed.encode()];
        let heads = [stored.commitment().clone(), indexed.commitment().clone()];
        let key = super::super::commitment::digest(&super::super::commitment::key_fields(
            &heads[0].encode(),
            PUBLIC_KEY,
            [Val::ONE; 4],
        ));
        let preliminary = SourceVersionExpected::checked(
            [&images[0], &images[1]],
            [&heads[0], &heads[1]],
            encode_digest(key),
            [0; 32],
        )
        .unwrap();
        let mut plain = [0; 2348];
        plain[..12].copy_from_slice(&data);
        plain[12..].copy_from_slice(&index);
        let state = super::super::commitment::digest(&super::super::commitment::opening_fields(
            preliminary.statement(),
            [Val::TWO; 4],
            &plain,
        ));
        let expected = SourceVersionExpected::checked(
            [&images[0], &images[1]],
            [&heads[0], &heads[1]],
            encode_digest(key),
            encode_digest(state),
        )
        .unwrap();
        assert_eq!(preliminary.version_id(), expected.version_id());
        Fixture {
            expected,
            images,
            heads,
        }
    })
}
fn honest_bytes() -> &'static [u8] {
    static BYTES: OnceLock<Vec<u8>> = OnceLock::new();
    BYTES
        .get_or_init(|| {
            let f = fixture();
            let began = Instant::now();
            let unverified = prove(&f.expected, &f.witness()).unwrap();
            assert_eq!(unverified.expected().version_id(), f.expected.version_id());
            eprintln!(
                "source_version_test phase=unverified_prove elapsed_ms={:.3} bytes={}",
                began.elapsed().as_secs_f64() * 1000.,
                unverified.as_bytes().len()
            );
            unverified.into_bytes()
        })
        .as_slice()
}

#[test]
fn constructor_derives_version_but_keeps_the_full_independent_state_expectation() {
    let f = fixture();
    let e = &f.expected;
    assert_eq!(e.statement().relation, Relation::StateCertificate);
    assert_eq!(e.statement().request, e.version_id());
    let mut state = e.statement().open_commitment;
    state[0] += Val::ONE;
    let other = f.checked(
        encode_digest(e.statement().key_commitment),
        encode_digest(state),
    );
    assert_eq!(other.version_id(), e.version_id()); // C_state is acyclic, never omitted by verify.
    assert_ne!(other.state_commitment(), e.state_commitment());
    let mut key = e.statement().key_commitment;
    key[0] += Val::ONE;
    assert_ne!(
        f.checked(encode_digest(key), e.state_commitment())
            .version_id(),
        e.version_id()
    );
    // The old production admission/backend remain closed to this mathematical relation.
    assert!(CanonicalSource::checked_claim(e.statement()).is_err());
    assert!(matches!(
        Backend::source(e.statement()),
        Err(BackendError::Shape)
    ));
}

#[test]
fn complete_image_and_digest_bounds_reject_before_any_proof_or_trace() {
    let f = fixture();
    let key = encode_digest(f.expected.statement().key_commitment);
    let state = f.expected.state_commitment();
    for page in 0..2 {
        let mut images = f.images.clone();
        *images[page].last_mut().unwrap() ^= 1;
        assert!(
            SourceVersionExpected::checked(
                [&images[0], &images[1]],
                [&f.heads[0], &f.heads[1]],
                key,
                state,
            )
            .is_err()
        );
    }
    let mut images = f.images.clone();
    images[1].push(0);
    assert!(
        SourceVersionExpected::checked(
            [&images[0], &images[1]],
            [&f.heads[0], &f.heads[1]],
            key,
            state,
        )
        .is_err()
    );
    assert!(
        SourceVersionExpected::checked(
            [&f.images[0], &f.images[1]],
            [&f.heads[1], &f.heads[0]],
            key,
            state,
        )
        .is_err()
    );
    for (key, state) in [([0xff; 32], state), (key, [0xff; 32])] {
        assert!(
            SourceVersionExpected::checked(
                [&f.images[0], &f.images[1]],
                [&f.heads[0], &f.heads[1]],
                key,
                state,
            )
            .is_err()
        );
    }
    assert!(matches!(
        verify(&f.expected, &[]),
        Err(Error::ResourceLimit)
    ));
    assert!(matches!(
        verify(&f.expected, &vec![0; MAX_CERTIFICATE_BYTES + 1]),
        Err(Error::ResourceLimit)
    ));
}

#[test]
fn genuine_certificate_requires_actual_native_verification_of_the_exact_expected_opening() {
    let f = fixture();
    let bytes = honest_bytes();
    let began = Instant::now();
    let verified = verify(&f.expected, bytes).unwrap();
    eprintln!(
        "source_version_test phase=cold_verify elapsed_ms={:.3}",
        began.elapsed().as_secs_f64() * 1000.
    );
    assert_eq!(
        verified.expected().statement().values(),
        f.expected.statement().values()
    );
    assert_eq!(
        verified.expected().state_commitment(),
        f.expected.state_commitment()
    );
    let mut state = f.expected.statement().open_commitment;
    state[0] += Val::ONE;
    let other = f.checked(
        encode_digest(f.expected.statement().key_commitment),
        encode_digest(state),
    );
    assert_eq!(other.version_id(), f.expected.version_id());
    assert!(matches!(
        verify(&other, bytes),
        Err(Error::Proof(BackendError::Verification))
    ));
    let mut key = f.expected.statement().key_commitment;
    key[0] += Val::ONE;
    let other = f.checked(encode_digest(key), f.expected.state_commitment());
    assert!(matches!(
        verify(&other, bytes),
        Err(Error::Proof(BackendError::Verification))
    ));
    // Repair the exact native codec/shape after corrupting a genuine OOD opening.
    let backend = Backend::source_version(&f.expected).unwrap();
    let mut proof = codec::decode(
        bytes,
        &backend.shape,
        crate::wire::MAX_SEQUENCE_ELEMENTS,
        crate::wire::SOURCE_SLOTS,
    )
    .unwrap();
    proof.opened_values.trace_local[0] += Challenge::ONE;
    let repaired = codec::serialize(&proof, &backend.shape, MAX_CERTIFICATE_BYTES).unwrap();
    drop(proof);
    drop(backend);
    assert!(matches!(
        verify(&f.expected, &repaired),
        Err(Error::Proof(BackendError::Verification))
    ));
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(matches!(
        verify(&f.expected, &trailing),
        Err(Error::Encoding)
    ));
    assert!(verify(&f.expected, &bytes[..bytes.len() - 1]).is_err());
    // No previous failure or producer call minted a reusable checked verdict.
    assert_eq!(
        verify(&f.expected, bytes).unwrap().expected().version_id(),
        f.expected.version_id()
    );
}

#[test]
fn false_private_key_reaches_real_native_proving_or_verification_failure() {
    let f = fixture();
    let mut key = PUBLIC_KEY;
    key[0] ^= 1;
    let wrong = Witness::new(key, [Val::ONE; 4], [Val::TWO; 4], AGES);
    // A real full-size private trace reaches the real SDK, never a shape-only rejection.
    let trace = wrong.trace(f.expected.statement()).unwrap();
    let backend = Backend::source_version(&f.expected).unwrap();
    let attempted = catch_unwind(AssertUnwindSafe(|| backend.prove(trace)));
    let proof = match attempted {
        Ok(Ok(proof)) => proof,
        Ok(Err(BackendError::Proving)) | Err(_) if cfg!(debug_assertions) => {
            // The SDK's debug constraint checker can refuse the false trace.
            // Release must instead reach the real receiving cryptographic check.
            return;
        }
        Ok(Err(error)) => panic!("false trace failed before genuine native proving: {error:?}"),
        Err(_) => panic!("release native prover panicked instead of producing the false argument"),
    };
    let bytes = codec::serialize(&proof, &backend.shape, MAX_CERTIFICATE_BYTES).unwrap();
    drop(proof);
    drop(backend);
    assert!(matches!(
        verify(&f.expected, &bytes),
        Err(Error::Proof(BackendError::Verification))
    ));
}
