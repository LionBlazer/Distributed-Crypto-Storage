//! Owning primitive tests. No mock verifier, fixture answer or database claim.
use super::*;
use bfv_hiding_stark::Challenge;
use p3_batch_stark::BatchVerificationError;
use p3_lookup::{LookupError, Lookups};

#[test]
fn genuine_private_wire_proof_and_repaired_hostile_frames() {
    let witness = Witness::new(17, 211);
    let expected = Expected::new([0x61; 32], witness.output()).unwrap();
    let air = air::FixedAir::new(&expected);
    let mut data = setup::public_data(&air, &expected).unwrap();
    let a = assessment::assess(&air, &data.common).unwrap();
    assert!(a.packed_lookup_count() > 0);

    // Native automatic packing and public PP are trusted only after rederivation.
    let independent = setup::public_data(&air, &expected).unwrap();
    assert_eq!(
        data.common.preprocessed.as_ref().unwrap().commitment,
        independent.common.preprocessed.as_ref().unwrap().commitment
    );
    let saved = std::mem::take(&mut data.common.lookups);
    assert!(matches!(
        assessment::assess(&air, &data.common),
        Err(Error::Shape)
    ));
    data.common.lookups = saved;
    let unpacked = Lookups::from_air::<Challenge, _>(&air);
    if unpacked.len() != data.common.lookups[0].len() {
        let saved = std::mem::replace(&mut data.common.lookups[0], unpacked);
        assert!(matches!(
            assessment::assess(&air, &data.common),
            Err(Error::Shape)
        ));
        data.common.lookups[0] = saved;
    }
    data.common.preprocessed.as_mut().unwrap().instances[0]
        .as_mut()
        .unwrap()
        .degree_bits = 9;
    assert!(matches!(
        assessment::assess(&air, &data.common),
        Err(Error::Shape)
    ));
    data.common.preprocessed.as_mut().unwrap().instances[0]
        .as_mut()
        .unwrap()
        .degree_bits = air::DEGREE_BITS;

    // Exactly one honest private proving operation; all attacks reuse its bytes.
    let frame = prove(&expected, witness).unwrap();
    assert_eq!(verify(&expected, &frame).unwrap().output(), expected.output);
    let original = || wire::decode(wire::payload(&expected, &frame).unwrap(), &a).unwrap();

    let foreign = Expected::new([0x62; 32], expected.output).unwrap();
    assert!(verify(&foreign, &frame).is_err());
    assert!(verify(&foreign, &wire::repaired_frame(&foreign, &original())).is_err());
    let changed_output = Expected::new(expected.context, expected.output + 1).unwrap();
    assert!(
        verify(
            &changed_output,
            &wire::repaired_frame(&changed_output, &original())
        )
        .is_err()
    );

    // Wrong locally generated public setup must fail the actual native verifier.
    let wrong_pp = setup::public_data(&air::FixedAir::new(&foreign), &foreign).unwrap();
    assert!(verify_native(&expected, &air, &original(), &wrong_pp.common).is_err());

    let mut proof = original();
    proof.opened_values.instances[0].permutation_local[0] += Challenge::ONE;
    assert!(verify(&expected, &wire::repaired_frame(&expected, &proof)).is_err());
    let mut proof = original();
    proof.opened_values.instances[0].permutation_next.pop();
    assert!(verify(&expected, &wire::repaired_frame(&expected, &proof)).is_err());
    let mut proof = original();
    proof.lookup_terminals[0].as_mut().unwrap().0 += Challenge::ONE;
    assert!(verify(&expected, &wire::repaired_frame(&expected, &proof)).is_err());
    let mut proof = original();
    proof.lookup_terminals.clear();
    assert!(verify(&expected, &wire::repaired_frame(&expected, &proof)).is_err());
    let mut proof = original();
    proof.commitments.permutation = None;
    assert!(verify(&expected, &wire::repaired_frame(&expected, &proof)).is_err());
    let mut proof = original();
    proof.commitments.random = None;
    assert!(verify(&expected, &wire::repaired_frame(&expected, &proof)).is_err());
    let mut proof = original();
    proof.opened_values.instances[0]
        .base_opened_values
        .trace_local[0] += Challenge::ONE;
    assert!(verify(&expected, &wire::repaired_frame(&expected, &proof)).is_err());
    let mut proof = original();
    proof.degree_bits[0] -= 1;
    assert!(verify(&expected, &wire::repaired_frame(&expected, &proof)).is_err());
    let mut proof = original();
    proof
        .opened_values
        .instances
        .push(original().opened_values.instances.pop().unwrap());
    proof.degree_bits.push(air::DEGREE_BITS);
    proof.lookup_terminals.push(None);
    assert!(verify(&expected, &wire::repaired_frame(&expected, &proof)).is_err());
    let mut appended = frame.clone();
    appended.push(0);
    assert!(verify(&expected, &appended).is_err());
    // A repaired outer length must still reject the inner decoder's trailing byte.
    let appended_payload_bytes = (appended.len() - wire::HEADER_BYTES) as u32;
    appended[76..80].copy_from_slice(&appended_payload_bytes.to_le_bytes());
    assert!(matches!(verify(&expected, &appended), Err(Error::Encoding)));
    // The native first root has one digest. Gold's binary codec must reject p,
    // rather than reducing a different eight-byte encoding to zero.
    let mut noncanonical = frame.clone();
    assert_eq!(noncanonical[wire::HEADER_BYTES], 1);
    noncanonical[wire::HEADER_BYTES + 1..wire::HEADER_BYTES + 9]
        .copy_from_slice(&0xffff_ffff_0000_0001_u64.to_le_bytes());
    assert!(matches!(
        verify(&expected, &noncanonical),
        Err(Error::Encoding)
    ));
    let mut proof = original();
    proof.opened_values.instances[0]
        .permutation_local
        .resize(wire::MAX_SEQUENCE + 1, Challenge::ZERO);
    assert!(matches!(
        verify(&expected, &wire::repaired_frame(&expected, &proof)),
        Err(Error::Resource)
    ));
    // Every sequence fits the per-sequence cap, but their combined Gold byte
    // arrays exceed the single shared total budget before native verification.
    let mut proof = original();
    proof.opening_proof.1.input_openings[0].opened_values = vec![vec![vec![Val::ZERO; 512]]; 256];
    assert!(matches!(
        verify(&expected, &wire::repaired_frame(&expected, &proof)),
        Err(Error::Resource)
    ));
    let mut proof = original();
    proof.opening_proof.1.input_openings[0]
        .opening_proof
        .1
        .sibling_hashes
        .resize(
            wire::frontier_bound(air::DEGREE_BITS + bfv_hiding_stark::LOG_BLOWUP) + 1,
            [Val::ZERO; 4],
        );
    assert!(matches!(
        verify(&expected, &wire::repaired_frame(&expected, &proof)),
        Err(Error::Shape)
    ));
    let mut corrupt = frame.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(verify(&expected, &corrupt).is_err());
    // Failure creates no reusable checked source/config token: a fresh call still verifies.
    assert_eq!(verify(&expected, &frame).unwrap().output(), expected.output);
}

#[test]
fn false_wire_is_rejected_after_real_native_proving_with_same_output() {
    let witness = Witness::new(17, 211);
    let expected = Expected::new([0x71; 32], witness.output()).unwrap();
    let air = air::FixedAir::new(&expected);
    let data = setup::public_data(&air, &expected).unwrap();
    let _ = assessment::assess(&air, &data.common).unwrap();
    let mut trace = air.trace(&witness);
    // Receive A+1 and use z-1. All business equations, bounds and SAME public Y
    // remain true. Only the real row0->row1 node1 wire has become false.
    trace.0.values[air::WIDTH + 1] += Val::ONE;
    trace.0.values[air::WIDTH] -= Val::ONE;
    let changed_z = witness.z - 1;
    for bit in 0..16 {
        trace.0.values[air::WIDTH + 3 + bit] = Val::from_u8((changed_z >> bit & 1) as u8);
    }
    let proof = prove_trace(&expected, &air, &trace, &data);
    if cfg!(debug_assertions) {
        // The SDK's debug bus replay rejects before proof generation. The owning
        // release gate below is the required actual proof + final-terminal oracle.
        assert!(matches!(proof, Err(Error::Proving)));
        return;
    }
    let proof = proof.expect("release prover must produce the genuine unbalanced argument");
    assert_ne!(
        proof.lookup_terminals[0].as_ref().unwrap().0,
        Challenge::ZERO
    );
    let config = private_config().unwrap();
    let error = verify_batch(
        &config,
        std::slice::from_ref(&air),
        &proof,
        &[expected.values()],
        &data.common,
    )
    .unwrap_err();
    assert!(
        matches!(
            error,
            BatchVerificationError::Lookup(LookupError::TerminalSumNonZero)
        ),
        "{error:?}"
    );
    // No export/serialization of this nonzero private terminal.
}

#[test]
fn bounded_frontend_rejects_input_and_frame_shape_before_sdk_work() {
    assert!(matches!(
        Expected::new([0; 32], MAX_OUTPUT + 1),
        Err(Error::Shape)
    ));
    let expected = Expected::new([0; 32], 3).unwrap();
    assert!(matches!(
        prove(&expected, Witness::new(1, 0)),
        Err(Error::Shape)
    ));
    assert!(wire::payload(&expected, &[]).is_err());
    let too_large = vec![0; wire::HEADER_BYTES + wire::MAX_PAYLOAD + 1];
    assert!(matches!(
        wire::payload(&expected, &too_large),
        Err(Error::Resource)
    ));
    let mut untrusted = vec![0; wire::HEADER_BYTES];
    untrusted[..8].copy_from_slice(b"HLOGWP01");
    untrusted[8..40].copy_from_slice(&profile());
    untrusted[40..72].copy_from_slice(&expected.context);
    untrusted[72..76].copy_from_slice(&expected.output.to_le_bytes());
    untrusted[76..80].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(wire::payload(&expected, &untrusted).is_err());
    untrusted[76..80].copy_from_slice(&1u32.to_le_bytes());
    untrusted.push(0);
    untrusted[95] = 1;
    assert!(wire::payload(&expected, &untrusted).is_err());
}
