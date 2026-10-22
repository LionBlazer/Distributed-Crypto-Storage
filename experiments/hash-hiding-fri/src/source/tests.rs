use super::*;
use crate::{Challenge, Val};
use p3_field::PrimeCharacteristicRing;
use registry200_proof::source::statement::encode_digest;
use std::time::Instant;

#[test]
fn complete_source_air_requires_original_state_key_context_and_native_openings() {
    let began = Instant::now();
    let f = fixture::fixture();
    eprintln!(
        "hash_source phase=public_fixture ms={:.3}",
        began.elapsed().as_secs_f64() * 1000.
    );
    let began = Instant::now();
    let bytes = prove(&f.expected, &f.witness()).unwrap();
    let producer_ms = began.elapsed().as_secs_f64() * 1000.;
    let began = Instant::now();
    verify(&f.expected, &bytes).unwrap();
    let receiver_ms = began.elapsed().as_secs_f64() * 1000.;
    eprintln!(
        "hash_source phase=public_component producer_ms={producer_ms:.3} receiver_ms={receiver_ms:.3} total_ms={:.3} bytes={} sql=false",
        producer_ms + receiver_ms,
        bytes.len()
    );

    // Comparable baseline on the same independently expected source relation.
    // This is also a component measurement, never a network SQL measurement.
    let began = Instant::now();
    let old = source::version::prove(&f.expected, &f.witness()).unwrap();
    let old_producer_ms = began.elapsed().as_secs_f64() * 1000.;
    let began = Instant::now();
    source::version::verify(&f.expected, old.as_bytes()).unwrap();
    let old_receiver_ms = began.elapsed().as_secs_f64() * 1000.;
    eprintln!(
        "hash_source phase=old_source_baseline producer_ms={old_producer_ms:.3} receiver_ms={old_receiver_ms:.3} total_ms={:.3} bytes={} sql=false",
        old_producer_ms + old_receiver_ms,
        old.as_bytes().len()
    );
    assert!(source::version::verify(&f.expected, &bytes).is_err());
    assert_eq!(verify(&f.expected, old.as_bytes()), Err(Error::Encoding));
    drop(old);

    let mut state = f.expected.statement().open_commitment;
    state[0] += Val::ONE;
    let changed_state = f.checked(
        encode_digest(f.expected.statement().key_commitment),
        encode_digest(state),
    );
    assert_eq!(changed_state.version_id(), f.expected.version_id());
    assert_eq!(verify(&changed_state, &bytes), Err(Error::Verification));

    let mut key = f.expected.statement().key_commitment;
    key[0] += Val::ONE;
    let changed_key = f.checked(encode_digest(key), f.expected.state_commitment());
    assert_ne!(changed_key.version_id(), f.expected.version_id());
    assert_eq!(verify(&changed_key, &bytes), Err(Error::Verification));

    let mut proof = decode(&bytes).unwrap();
    proof.opened_values.trace_local[0] += Challenge::ONE;
    let changed = encode(&proof).unwrap();
    assert_eq!(verify(&f.expected, &changed), Err(Error::Verification));

    let proof = decode(&bytes).unwrap();
    let air = air(&f.expected).unwrap();
    let mut altered = f.expected.statement().values();
    altered[0] += Val::ONE;
    assert!(p3_uni_stark::verify(&config().unwrap(), &air, &proof, &altered).is_err());

    // A correctly shaped argument from another transcript context is not valid.
    let mut challenger = crate::challenger::Challenger::new();
    use p3_challenger::CanObserve;
    challenger.observe(Val::ONE);
    use p3_uni_stark::StarkGenericConfig;
    let original_config = config().unwrap();
    let other_config = Config::new(original_config.pcs().clone(), challenger);
    assert!(
        p3_uni_stark::verify(
            &other_config,
            &air,
            &proof,
            &f.expected.statement().values()
        )
        .is_err()
    );

    for prefix in [0, 7, HEADER - 1, bytes.len() - 1] {
        assert!(verify(&f.expected, &bytes[..prefix]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(verify(&f.expected, &trailing), Err(Error::Encoding));
    let mut old_magic = bytes.clone();
    old_magic[..8].copy_from_slice(b"DCSHSF00");
    assert_eq!(verify(&f.expected, &old_magic), Err(Error::Encoding));
    let mut wrong_profile = bytes.clone();
    wrong_profile[8] ^= 1;
    assert_eq!(verify(&f.expected, &wrong_profile), Err(Error::Encoding));

    let mut bad_zero = decode(&bytes).unwrap();
    bad_zero.opening_proof.1.query_pow_witness = Val::ONE;
    assert_eq!(encode(&bad_zero), Err(Error::Shape));
    let mut bad_cap = decode(&bytes).unwrap();
    bad_cap.commitments.random = None;
    assert_eq!(encode(&bad_cap), Err(Error::Shape));
}

#[test]
fn untrusted_dimensions_and_bytes_cannot_select_a_candidate_verifier() {
    let f = fixture::fixture();
    assert_eq!(
        verify(&f.expected, &vec![0; MAX_BYTES + 1]),
        Err(Error::ResourceLimit)
    );
    let mut malformed = Vec::from(MAGIC.as_slice());
    malformed.extend(profile_digest());
    malformed.extend(3u32.to_le_bytes());
    // A submitted enormous sequence cannot allocate a proof-sized vector first.
    // Proof starts with commitments.trace.roots: valid varint length 16385.
    malformed.extend([0x81, 0x80, 0x01]);
    assert_eq!(verify(&f.expected, &malformed), Err(Error::ResourceLimit));
    assert_ne!(
        profile_digest(),
        source::profile_digest(Relation::StateCertificate)
    );
    let air = air(&f.expected).unwrap();
    assert_eq!((air.width(), air.num_public_values()), (7161, 691));
    assert_eq!(PROOF_DEGREE_BITS, 10);
}
