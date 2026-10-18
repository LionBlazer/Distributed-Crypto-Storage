//! PUBLIC NONSECRET owning scenarios. No oracle result supplies a proof endpoint.
use crate::*;
use bfv_query_core::{Geometry, Owner, PublicSetup};
use bfv_relinearization_key_source::PreparedKeyError;
use sha2::{Digest, Sha256};

fn id(setup: &PublicSetup) -> [u8; 32] {
    Sha256::digest(setup.to_bytes().unwrap()).into()
}
fn input_with(input: &Input, query: [u8; 32]) -> Input {
    Input::new(
        query,
        core::array::from_fn(|i| input.component(i).unwrap().to_vec()),
    )
    .unwrap()
}
fn changed_setup(setup: &PublicSetup, key: &[u8], rotation: &[u8]) -> PublicSetup {
    let material = setup.relinearization_material().unwrap();
    PublicSetup::from_public_material(material.geometry(), material.parameters(), key, rotation)
        .unwrap()
}

#[test]
fn original_owner_public_key_preprocessing_matches_all_fifty_sdk_rows_and_rejects_setup_substitution()
 {
    let (_owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let key = PreparedKey::from_original(&setup, id(&setup)).unwrap();
    let sdk = demo::sdk_key_rows(&setup).unwrap();
    for (source, rows) in sdk.iter().enumerate() {
        assert_eq!(key.component(0, source).unwrap(), rows[0]);
        assert_eq!(key.component(1, source).unwrap(), rows[1]); // ALL5 Q rows/all8192, not just an impulse position.
    }
    let mut wrong = id(&setup);
    wrong[31] ^= 1;
    assert!(matches!(
        PreparedKey::from_original(&setup, wrong),
        Err(PreparedKeyError::KeySource(_))
    ));
    let material = setup.relinearization_material().unwrap();
    let rotations = changed_setup(
        &setup,
        material.relinearization_key(),
        b"different public rotations",
    );
    assert!(PreparedKey::from_original(&rotations, id(&setup)).is_err());
    let rotation_key = PreparedKey::from_original(&rotations, id(&rotations)).unwrap();
    for component in 0..2 {
        for source in 0..5 {
            assert_eq!(
                rotation_key.component(component, source),
                key.component(component, source)
            );
        }
    }
    assert_ne!(
        rotation_key.original_setup_digest(),
        key.original_setup_digest()
    );

    // A canonical seed alteration has its own different public constants. It may
    // be a mathematical key under its OWN pin, never under the original Owner pin.
    let mut wire = material.relinearization_key().to_vec();
    *wire.last_mut().unwrap() ^= 1;
    let seeded = changed_setup(&setup, &wire, b"different public rotations");
    let seeded_key = PreparedKey::from_original(&seeded, id(&seeded)).unwrap();
    for source in 0..5 {
        assert_eq!(
            seeded_key.component(0, source),
            rotation_key.component(0, source)
        );
    }
    assert!(
        (0..5).any(|source| seeded_key.component(1, source) != rotation_key.component(1, source))
    );
    assert!(PreparedKey::from_original(&seeded, id(&rotations)).is_err());
}

#[test]
fn malformed_or_unsupported_original_key_is_rejected_by_bounded_source_before_public_ntt_preparation()
 {
    let (_owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let material = setup.relinearization_material().unwrap();
    let original = material.relinearization_key();
    let mut unknown = original.to_vec();
    unknown.extend([0x10, 1]);
    let mut trailing = original.to_vec();
    trailing.push(0);
    for bytes in [
        Vec::new(),
        original[..original.len() - 1].to_vec(),
        unknown,
        trailing,
        vec![0; bfv_relinearization_key_source::MAX_KEY_BYTES + 1],
    ] {
        let candidate = changed_setup(&setup, &bytes, b"public unsupported key fixture");
        assert!(matches!(
            PreparedKey::from_original(&candidate, id(&candidate)),
            Err(PreparedKeyError::KeySource(_))
        ));
    }
}

#[test]
fn native_ntt_input_checks_every_component_modulus_and_last_word_without_sdk_pb_relabeling() {
    let zeros: [Vec<u64>; 3] = core::array::from_fn(|_| vec![0; COEFFICIENTS]);
    Input::new([0; 32], zeros.clone()).unwrap();
    for component in 0..3 {
        for target in 0..5 {
            let mut values = zeros.clone();
            values[component][(target + 1) * DEGREE - 1] = MODULI[target];
            assert!(Input::new([0; 32], values).is_err());
        }
        let mut short = zeros.clone();
        short[component].pop();
        assert!(Input::new([0; 32], short).is_err());
    }
    let request = bfv_ntt_circuit::encode_request(
        bfv_ntt_circuit::Direction::Inverse,
        bfv_ntt_circuit::Basis::new(0).unwrap(),
        [0; 32],
        &vec![0; DEGREE],
    )
    .unwrap();
    assert!(
        Input::new(
            [0; 32],
            core::array::from_fn(|_| request.iter().map(|b| u64::from(*b)).collect())
        )
        .is_err()
    );
}

#[test]
fn incomplete_cancelled_and_exhausted_streams_never_yield_a_checked_result_or_advance_after_rejection()
 {
    let (_owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let key = PreparedKey::from_original(&setup, id(&setup)).unwrap();
    let input = Input::new([8; 32], core::array::from_fn(|_| vec![0; COEFFICIENTS])).unwrap();
    assert!(matches!(
        Verifier::new(&key, &input).finish(),
        Err(Error::Incomplete)
    ));
    let mut verifier = Verifier::new(&key, &input);
    for _ in 0..MAX_ATTEMPTS {
        assert!(verifier.accept(&[]).is_err());
    }
    assert_eq!(verifier.progress(), 0);
    assert!(matches!(verifier.accept(&[]), Err(Error::ResourceLimit)));
    verifier.cancel();
    assert!(matches!(verifier.accept(&[]), Err(Error::Cancelled)));
    assert!(matches!(verifier.finish(), Err(Error::Cancelled)));
    // Exercise the INDEPENDENT lifetime byte quota using ONE reused invalid
    // header buffer. These bytes are explicitly not computation evidence and
    // never enter a primitive backend or allocate an aggregate541MiB stream.
    let mut bytes_verifier = Verifier::new(&key, &input);
    let invalid = vec![0; MAX_COMPONENT_BYTES];
    let within_byte_budget = MAX_STREAM_BYTES / MAX_COMPONENT_BYTES;
    assert!(within_byte_budget + 1 < MAX_ATTEMPTS);
    for _ in 0..within_byte_budget {
        assert!(matches!(
            bytes_verifier.accept(&invalid),
            Err(Error::Component)
        ));
        assert_eq!(bytes_verifier.progress(), 0);
    }
    assert!(matches!(
        bytes_verifier.accept(&invalid),
        Err(Error::ResourceLimit)
    ));
    assert!(matches!(
        bytes_verifier.accept(&[]),
        Err(Error::ResourceLimit)
    ));
    assert_eq!(bytes_verifier.progress(), 0);
    let mut prover = Prover::new(&key, &input);
    prover.cancel();
    assert!(matches!(prover.prove_next(), Err(Error::Cancelled)));
    assert_eq!(prover.progress(), 0);
}

fn damaged_output(frame: &[u8], offset: usize, q: u64) -> Vec<u8> {
    let mut bytes = frame.to_vec();
    let at = HEADER_BYTES + offset;
    let old = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    bytes[at..at + 8].copy_from_slice(&((old + 1) % q).to_le_bytes());
    bytes
}

#[test]
fn all_thirty_two_genuine_components_reverify_after_producer_drop_and_match_actual_owner_sdk_product()
 {
    // Arrange actual original Owner ciphertexts, actual SDK multiplication and an
    // independent full SDK relinearization oracle. Its result never enters proofs.
    let fixture = demo::actual_owner_product().unwrap();
    let original_setup = fixture.setup.to_bytes().unwrap();
    let key = PreparedKey::from_original(&fixture.setup, fixture.keyset_id).unwrap();
    let mut spool = crate::spool::PublicSpool::new().unwrap();
    let mut prover = Prover::new(&key, &fixture.input);
    while let Some(component) = prover.prove_next().unwrap() {
        spool.write_next(component.as_bytes()).unwrap();
    }
    assert_eq!(prover.progress(), COMPONENTS);
    assert!(prover.prove_next().unwrap().is_none());
    drop(prover);
    drop(key);

    // Fresh public verifier owns no old SDK key/prover/backend/Owner state.
    let setup = PublicSetup::from_bytes(&original_setup).unwrap();
    let key = PreparedKey::from_original(&setup, fixture.keyset_id).unwrap();
    let mut verifier = Verifier::new(&key, &fixture.input);
    let first = spool.read(0).unwrap();
    assert!(verifier.accept(&spool.read(1).unwrap()).is_err()); // Correct proof, wrong next basis.
    assert_eq!(verifier.progress(), 0);
    for candidate in [&first[..first.len() - 1], &[0u8; 8][..]] {
        assert!(verifier.accept(candidate).is_err());
        assert_eq!(verifier.progress(), 0);
    }
    let mut reserved = first.clone();
    reserved[191] = 1;
    assert!(verifier.accept(&reserved).is_err());
    let mut alias = first.clone();
    let at = HEADER_BYTES + 112 + (DEGREE - 1) * 8;
    alias[at..at + 8].copy_from_slice(&MODULI[0].to_le_bytes());
    assert!(verifier.accept(&alias).is_err());
    assert!(
        verifier
            .accept(&damaged_output(&first, 112 + (DEGREE - 1) * 8, MODULI[0]))
            .is_err()
    );
    assert_eq!(verifier.progress(), 0);

    // A real foreign primitive first verifies under its OWN complete statement.
    // Rebuild honest outer/output/inner headers but use that foreign proof payload:
    // this forces rejection by the actual cryptographic verifier, not metadata alone.
    let foreign_input = input_with(&fixture.input, [0xA1; 32]);
    let mut foreign = Prover::new(&key, &foreign_input);
    let foreign_first = foreign.prove_next().unwrap().unwrap().into_bytes();
    let mut foreign_verifier = Verifier::new(&key, &foreign_input);
    foreign_verifier.accept(&foreign_first).unwrap();
    assert_eq!(foreign_verifier.progress(), 1);
    let nout = u32::from_le_bytes(first[140..144].try_into().unwrap()) as usize;
    let foreign_nout = u32::from_le_bytes(foreign_first[140..144].try_into().unwrap()) as usize;
    let mut proof = first[HEADER_BYTES + nout..HEADER_BYTES + nout + 256].to_vec();
    let foreign_payload = &foreign_first[HEADER_BYTES + foreign_nout + 256..];
    proof[240..248].copy_from_slice(&(foreign_payload.len() as u64).to_le_bytes());
    proof.extend_from_slice(foreign_payload);
    let repaired = Component::encode(
        crate::profile::identity(&key, &fixture.input),
        crate::state::Stage::at(0).unwrap(),
        &first[HEADER_BYTES..HEADER_BYTES + nout],
        &proof,
    )
    .unwrap();
    assert!(verifier.accept(repaired.as_bytes()).is_err());
    assert_eq!(verifier.progress(), 0);
    drop(foreign);
    drop(foreign_verifier);

    // Each failed call leaves the ordinal unchanged; the genuine repaired control
    // then advances once. Test endpoints of inverse/Embed/forward/MAC without O(32^2) replay.
    for ordinal in 0..COMPONENTS {
        let frame = spool.read(ordinal).unwrap();
        if [4, 5, 6, 30, 31].contains(&ordinal) {
            let mut wrong = frame.clone();
            wrong[136] ^= 1;
            assert!(verifier.accept(&wrong).is_err());
            assert_eq!(verifier.progress(), ordinal);
        }
        if ordinal == 5 {
            let offset = 144 + (25 * DEGREE - 1) * 8;
            assert!(
                verifier
                    .accept(&damaged_output(&frame, offset, MODULI[4]))
                    .is_err()
            );
        }
        if ordinal == 31 {
            let offset = 144 + (10 * DEGREE - 1) * 8;
            assert!(
                verifier
                    .accept(&damaged_output(&frame, offset, MODULI[4]))
                    .is_err()
            );
        }
        verifier.accept(&frame).unwrap();
        assert_eq!(verifier.progress(), ordinal + 1);
    }
    assert!(matches!(verifier.accept(&first), Err(Error::Stage)));
    let checked = verifier.finish().unwrap();
    assert!(checked.matches(&key, &fixture.input));
    assert!(!checked.matches(&key, &foreign_input));
    assert_eq!(checked.output(), &fixture.oracle); // BOTH components, allQ5, all8192.
}
