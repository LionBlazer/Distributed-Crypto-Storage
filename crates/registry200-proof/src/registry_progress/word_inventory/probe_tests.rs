//! Actual private native math gates; no SQL/finality/Source admission credit.
use super::{check, expr::Op, owner, plan::WIDTH, probe, probe_wire as wire, witness};
use bfv_hiding_stark::{Challenge, Val};
use p3_batch_stark::{BatchVerificationError, verify_batch};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::LookupError;
use p3_uni_stark::VerificationError;
use std::time::Instant;

#[test]
fn real_hiding_batch_proof_cold_roundtrip_both_roles_and_hostile_wire() {
    for predicate in [false, true] {
        let (m, input) = owner::public_case(predicate);
        let started = Instant::now();
        // Both cold producer walls include its own real role PP. Predicate keeps
        // that public-only setup for a DISTINCT next expectation below.
        let setup = if predicate {
            Some(probe::ProverSetup::new(true).unwrap())
        } else {
            None
        };
        let frame = if let Some(setup) = &setup {
            setup.produce(&m, &input)
        } else {
            probe::produce(&m, &input)
        }
        .expect("actual native hiding producer");
        let produced = started.elapsed();
        assert!(frame.len() <= wire::MAX_FRAME_BYTES);
        let receive = Instant::now();
        probe::verify(&m, &frame).expect("independently rebuilt trusted PP and cold native verify");
        let received = receive.elapsed();
        eprintln!(
            "word_native_probe role={} produce_ms={:.3} cold_receive_ms={:.3} cold_roundtrip_ms={:.3} frame_bytes={} math_only=true Source=false DATA=false fresh_head=false SQL=false system_security=false",
            if predicate { "predicate" } else { "control" },
            produced.as_secs_f64() * 1000.0,
            received.as_secs_f64() * 1000.0,
            (produced + received).as_secs_f64() * 1000.0,
            frame.len()
        );
        if !predicate {
            continue;
        }

        // Reuse ONE honest predicate proof. Header damage fails before native;
        // native OOD/PP/AUX damage preserves the full canonical fixed shape.
        assert_eq!(probe::verify(&m, &[]), Err(probe::Error::Resource));
        let mut bad = frame.clone();
        bad[8] ^= 1;
        assert_eq!(probe::verify(&m, &bad), Err(probe::Error::Binding));
        let (mut foreign, _) = owner::public_case(true);
        foreign.result[0] += Val::ONE;
        assert_eq!(probe::verify(&foreign, &frame), Err(probe::Error::Binding));
        let (opposite, _) = owner::public_case(false);
        assert_eq!(probe::verify(&opposite, &frame), Err(probe::Error::Binding));
        // Independent receiving setup: never producer-supplied PP/CommonData.
        let setup_started = Instant::now();
        let receiver = probe::VerifierSetup::new(true).unwrap();
        let receiver_setup = setup_started.elapsed();
        let warm_m0 = Instant::now();
        receiver.verify(&m, &frame).unwrap();
        let warm_receive_m0 = warm_m0.elapsed();
        let (m1, input1) = owner::public_case_variant(true, 1);
        let p0 = super::public_values::Expected::checked(&m).unwrap();
        let p1 = super::public_values::Expected::checked(&m1).unwrap();
        assert_ne!(p0.values(), p1.values());
        let payload0 = wire::payload(&m, &frame).unwrap();
        let repaired = wire::frame(&m1, payload0).unwrap();
        assert!(
            wire::payload(&m1, &repaired).is_ok(),
            "full independent header repaired"
        );
        let (_, report) = probe::prescreen(&m).unwrap();
        wire::decode(wire::payload(&m1, &repaired).unwrap(), &report).unwrap();
        assert_eq!(
            receiver.verify(&m1, &repaired),
            Err(probe::Error::Verification),
            "valid full shape + foreign PUBLIC must reach actual native failure"
        );
        let warm_started = Instant::now();
        let frame1 = setup
            .as_ref()
            .unwrap()
            .produce(&m1, &input1)
            .expect("same public-only producer setup, new native proof and OS coins");
        let warm_produced = warm_started.elapsed();
        let warm_receive = Instant::now();
        receiver
            .verify(&m1, &frame1)
            .expect("independent same receiver setup verifies DISTINCT current Expected309");
        let warm_received = warm_receive.elapsed();
        eprintln!(
            "word_native_setup_reuse role=predicate receiver_setup_ms={:.3} warm_m0_receive_ms={:.3} warm_m1_produce_ms={:.3} warm_m1_receive_ms={:.3} warm_m1_roundtrip_ms={:.3} frame_bytes={} distinct_public=true fresh_native_proofs=true Source=false DATA=false SQL=false",
            receiver_setup.as_secs_f64() * 1000.0,
            warm_receive_m0.as_secs_f64() * 1000.0,
            warm_produced.as_secs_f64() * 1000.0,
            warm_received.as_secs_f64() * 1000.0,
            (warm_produced + warm_received).as_secs_f64() * 1000.0,
            frame1.len()
        );
        let payload = wire::payload(&m, &frame).unwrap();
        let mut trailing = payload.to_vec();
        trailing.push(0);
        assert_eq!(
            probe::verify(&m, &wire::frame(&m, &trailing).unwrap()),
            Err(probe::Error::Encoding)
        );

        let mut proof = wire::decode(payload, &report).unwrap();
        // Malformed proof containers reuse this honest proof; no new proving.
        let degrees = core::mem::replace(&mut proof.degree_bits, vec![10; 4097]);
        let oversized_sequence = postcard::to_allocvec(&proof).unwrap();
        assert_eq!(
            probe::verify(&m, &wire::frame(&m, &oversized_sequence).unwrap()),
            Err(probe::Error::Resource)
        );
        proof.degree_bits = degrees;

        // Every individual sequence is legal (<=4096). Empty leaf vectors keep
        // the frame below4MiB while the SAME global per-call slot budget expires.
        let leaves = core::mem::replace(
            &mut proof.opening_proof.1.input_openings[0].opened_values,
            vec![vec![vec![]; 4096]; 256],
        );
        let oversized_slots = postcard::to_allocvec(&proof).unwrap();
        let global_budget_frame = wire::frame(&m, &oversized_slots).unwrap();
        assert!(global_budget_frame.len() <= wire::MAX_FRAME_BYTES);
        assert_eq!(
            probe::verify(&m, &global_budget_frame),
            Err(probe::Error::Resource)
        );
        proof.opening_proof.1.input_openings[0].opened_values = leaves;

        let frontier = &mut proof.opening_proof.1.input_openings[0]
            .opening_proof
            .1
            .sibling_hashes;
        let original_frontier = frontier.clone();
        let digest = original_frontier[0];
        *frontier = vec![digest; 1216];
        let oversized_frontier = postcard::to_allocvec(&proof).unwrap();
        assert_eq!(
            probe::verify(&m, &wire::frame(&m, &oversized_frontier).unwrap()),
            Err(probe::Error::Shape)
        );
        proof.opening_proof.1.input_openings[0]
            .opening_proof
            .1
            .sibling_hashes = original_frontier;

        proof.opened_values.instances[0]
            .base_opened_values
            .trace_local[0] += Challenge::ONE;
        assert_eq!(
            probe::verify(&m, &wire::encode(&m, &proof, &report).unwrap()),
            Err(probe::Error::Verification)
        );
        proof.opened_values.instances[0]
            .base_opened_values
            .trace_local[0] -= Challenge::ONE;

        proof.opened_values.instances[0]
            .base_opened_values
            .preprocessed
            .as_mut()
            .unwrap()
            .local[0] += Challenge::ONE;
        assert_eq!(
            probe::verify(&m, &wire::encode(&m, &proof, &report).unwrap()),
            Err(probe::Error::Verification)
        );
        proof.opened_values.instances[0]
            .base_opened_values
            .preprocessed
            .as_mut()
            .unwrap()
            .local[0] -= Challenge::ONE;

        proof.opened_values.instances[0].permutation_local[0] += Challenge::ONE;
        assert_eq!(
            probe::verify(&m, &wire::encode(&m, &proof, &report).unwrap()),
            Err(probe::Error::Verification)
        );
        proof.opened_values.instances[0].permutation_local[0] -= Challenge::ONE;

        proof.opening_proof.1.input_openings[0].opened_values[0][0][0] += Val::ONE;
        assert_eq!(
            probe::verify(&m, &wire::encode(&m, &proof, &report).unwrap()),
            Err(probe::Error::Verification)
        );
        proof.opening_proof.1.input_openings[0].opened_values[0][0][0] -= Val::ONE;

        proof.lookup_terminals[0].as_mut().unwrap().0 = Challenge::ONE;
        assert_eq!(wire::check(&proof, &report), Err(probe::Error::Shape));
        proof.lookup_terminals[0].as_mut().unwrap().0 = Challenge::ZERO;
        probe::verify(&m, &wire::encode(&m, &proof, &report).unwrap())
            .expect("fresh honest verification after all hostile attempts, no cached status");
    }
}

#[test]
fn actual_repaired_add_false_wire_is_native_terminal_failure_then_ood_when_repaired() {
    let (m, input) = owner::public_case(true);
    let (public_air, report) = probe::prescreen(&m).unwrap();
    let data = probe::public_data(&public_air, &report).unwrap();
    let (air, mut trace) = witness::prepare(&m, &input).unwrap();
    for r in 0..512 {
        assert_eq!(public_air.plan.pp_row(r), air.plan.pp_row(r));
    }
    drop(public_air);
    let public = super::public_values::Expected::checked(&m).unwrap();
    check::all(&air, &trace, &public).unwrap();
    let (row, slot) = air
        .plan
        .rows
        .iter()
        .enumerate()
        .find_map(|(row, layout)| {
            layout.ops.iter().enumerate().find_map(|(slot, op)| {
                (*op == Op::Add
                    && layout.ports[3 * slot].constant.is_none()
                    && layout.ports[3 * slot + 2].constant.is_none())
                .then_some((row, slot))
            })
        })
        .expect("actual nonconstant Add in the complete relation");
    trace.0.values[row * WIDTH + 248 + 3 * slot] += Val::ONE;
    trace.0.values[row * WIDTH + 248 + 3 * slot + 2] += Val::ONE;
    assert_eq!(
        check::base(&air, &trace, &public),
        Ok(()),
        "ALL local business equations remain true"
    );
    assert_eq!(
        check::lookups(&air, &trace, &public),
        Err(super::evaluate::Error::Lookup)
    );

    let began = Instant::now();
    let attempted = probe::prove_trace(&air, &trace.0, &data, &public);
    drop(trace);
    if cfg!(debug_assertions) {
        // Official debug proving may replay buses early. ONLY RELEASE below
        // supplies genuine native proof+TerminalSumNonZero rejection credit.
        assert!(matches!(attempted, Err(probe::Error::Proving)));
        return;
    }
    let mut proof = attempted.expect("release must build actual unbalanced argument");
    assert_ne!(
        proof.lookup_terminals[0].as_ref().unwrap().0,
        Challenge::ZERO
    );
    let error = verify_batch(
        &probe::private_config().unwrap(),
        core::slice::from_ref(&air),
        &proof,
        &[public.values().to_vec()],
        &data.common,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        BatchVerificationError::Lookup(LookupError::TerminalSumNonZero)
    ));
    // A forged terminal0 is not a proof. Full topology now passes but real
    // native PCS/OOD verification still rejects the genuinely produced object.
    proof.lookup_terminals[0].as_mut().unwrap().0 = Challenge::ZERO;
    wire::check(&proof, &report).unwrap();
    let error = verify_batch(
        &probe::private_config().unwrap(),
        core::slice::from_ref(&air),
        &proof,
        &[public.values().to_vec()],
        &data.common,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        BatchVerificationError::Verification(
            VerificationError::InvalidOpeningArgument(_)
                | VerificationError::OodEvaluationMismatch { .. }
        )
    ));
    eprintln!(
        "word_native_probe false_wire_ms={} actual_terminal_rejection=true repaired_zero_native_rejection=true SQL=false",
        began.elapsed().as_millis()
    );
}

#[test]
fn closed_codec_bounds_and_all_noncanonical_field_coordinates_fail() {
    use p3_field::PrimeField64;
    assert_eq!(wire::frontier_bound(13), Ok(1215));
    assert_eq!(
        (0..10)
            .map(|r| wire::frontier_bound(12 - r).unwrap())
            .sum::<usize>(),
        3438
    );
    assert_eq!(5 * 1215 + 3438, 9513);
    assert_eq!(wire::frontier_bound(14), Err(probe::Error::Shape));
    let limits = bounded_postcard::Limits {
        max_sequence_elements: 8,
        max_total_elements: 256,
    };
    let p = 0xffff_ffff_0000_0001u64;
    let canonical = (p - 1).to_le_bytes();
    let (v, tail) = bounded_postcard::take_from_bytes::<Val>(&canonical, limits).unwrap();
    assert_eq!(v.as_canonical_u64(), p - 1);
    assert!(tail.is_empty());
    assert!(matches!(
        bounded_postcard::take_from_bytes::<Val>(&p.to_le_bytes(), limits),
        Err(bounded_postcard::Error::Encoding)
    ));
    let zero = postcard::to_allocvec(&Challenge::ZERO).unwrap();
    assert_eq!(zero.len(), 40);
    for i in 0..5 {
        let mut bad = zero.clone();
        bad[8 * i..8 * i + 8].copy_from_slice(&p.to_le_bytes());
        assert!(matches!(
            bounded_postcard::take_from_bytes::<Challenge>(&bad, limits),
            Err(bounded_postcard::Error::Encoding)
        ));
    }
    let (m, _) = owner::public_case(false);
    assert_eq!(wire::frame(&m, &[]), Err(probe::Error::Resource));
    assert_eq!(
        wire::frame(&m, &vec![0; wire::MAX_FRAME_BYTES]),
        Err(probe::Error::Resource)
    );
}
