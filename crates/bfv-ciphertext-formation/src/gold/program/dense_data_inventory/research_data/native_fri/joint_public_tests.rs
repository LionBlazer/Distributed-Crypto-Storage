//! Complete actual-DATA public joint-V/B -> bounded native receiver.
//! Explicitly non-secret metadata and streams; no honest/private witness fixture.
use super::super::{Receiver, ResearchFrame, decode, public_frame};
use super::*;
use rand_public_pp::SeedableRng;

fn assert_walk(walk: &super::super::research_ro::Walk) {
    assert!(
        walk.prefix
            .starts_with(bfv_hiding_stark::hash::TRANSCRIPT_DOMAIN)
    );
    assert_eq!(
        walk.events
            .iter()
            .filter(|event| matches!(event, Event::Sample { .. }))
            .count(),
        277
    );
    assert_eq!(
        walk.events
            .iter()
            .filter(|event| matches!(event, Event::Cap(_)))
            .count(),
        17
    );
    assert!(
        walk.events
            .iter()
            .any(|event| matches!(event, Event::Field(_)))
    );
    assert!(walk.draws.len() >= 277);
}

fn reject_mutation(
    frame: &ResearchFrame,
    receiver: &Receiver,
    change: impl FnOnce(&mut BatchProof<Config>),
) {
    // Invoke actual native verify_batch, not merely the normal shape decoder.
    // This owning temporary is dropped between mutations.
    let mut proof = decode(frame, &receiver.expected, &receiver.assessment).unwrap();
    change(&mut proof);
    assert!(!receiver.verify_native(&proof, Walks::default()));
}

#[test]
#[ignore = "complete actual DATA public V+B native frame; run alone under owning held-process 120s/1792MiB observer"]
fn actual_data_native_receiver_accepts_public_joint_v_b_and_rejects_changed_native_components() {
    let expected = super::super::public_expected();
    let programmer = Programmer::regression([0xc1; 32]);
    let receiver = Receiver::new(&expected, programmer.oracle());
    // Presample every full64-byte FS cell before public V/B construction.
    let plan = TapePlan::sample(&mut StdRng::from_seed([0xc2; 32])).unwrap();
    let (frame, produced) = public_frame(
        &expected,
        programmer,
        &receiver,
        plan,
        [[0xc3; 32], [0xc4; 32], [0xc5; 32], [0xc6; 32]],
    );
    assert_walk(&produced);
    let received = Walks::default();
    let start = std::time::Instant::now();
    assert!(receiver.receive(&frame, received.clone()));
    super::super::phase("bounded_native_receive", start);
    let actual = received.with_draws();
    assert_eq!(actual.as_slice(), core::slice::from_ref(&produced));
    assert_walk(&actual[0]);
    // Same immutable bytes + same query-only dictionary must replay exactly.
    let replay = Walks::default();
    assert!(receiver.receive(&frame, replay.clone()));
    assert_eq!(replay.with_draws(), actual);
    assert!(super::super::super::hash_backend::receive(&expected, frame.as_bytes()).is_err());

    for round in 0..5 {
        reject_mutation(&frame, &receiver, |proof| {
            proof.opening_proof.1.input_openings.remove(round);
        });
    }
    reject_mutation(&frame, &receiver, |proof| {
        proof.opened_values.instances[0].permutation_next[409] += E::ONE;
    });
    reject_mutation(&frame, &receiver, |proof| {
        proof.opened_values.instances[0]
            .base_opened_values
            .quotient_chunks[7][4] += E::ONE;
    });
    reject_mutation(&frame, &receiver, |proof| {
        proof.opened_values.instances[0]
            .base_opened_values
            .random
            .as_mut()
            .unwrap()[4] += E::ONE;
    });
    reject_mutation(&frame, &receiver, |proof| {
        proof.opening_proof.0[0][0][0][4] += E::ONE;
    });
    reject_mutation(&frame, &receiver, |proof| {
        proof.opening_proof.0[1][0][1][4] += E::ONE;
    });
    reject_mutation(&frame, &receiver, |proof| {
        proof.opening_proof.0[4][0][1][4] += E::ONE;
    });
    reject_mutation(&frame, &receiver, |proof| {
        proof.opening_proof.1.input_openings[1].opened_values[0][0][516] += F::ONE;
    });
    reject_mutation(&frame, &receiver, |proof| {
        proof.opening_proof.1.input_openings[4].opened_values[0][0][414] += F::ONE;
    });
    reject_mutation(&frame, &receiver, |proof| {
        proof.opening_proof.1.input_openings[3].opened_values[0][0][667] += F::ONE;
    });
    reject_mutation(&frame, &receiver, |proof| {
        proof.opened_values.instances[0]
            .base_opened_values
            .preprocessed
            .as_mut()
            .unwrap()
            .local[667] += E::ONE;
    });
    reject_mutation(&frame, &receiver, |proof| {
        proof.opening_proof.1.input_openings[3].opening_proof.0[0][0][3] += F::ONE;
    });
    reject_mutation(&frame, &receiver, |proof| {
        proof.opening_proof.1.commit_phase_commits[0] = Cap::new(vec![[0; 32]]);
    });
    reject_mutation(&frame, &receiver, |proof| {
        proof.opening_proof.1.final_poly[0] += E::ONE;
    });
    reject_mutation(&frame, &receiver, |proof| {
        proof.opening_proof.1.batch_pow_witness = F::ONE;
    });
    reject_mutation(&frame, &receiver, |proof| {
        proof.opening_proof.1.query_pow_witness = F::ONE;
    });
    reject_mutation(&frame, &receiver, |proof| {
        proof.ood_pow_witness = F::ONE;
    });
    for offset in [0, 8, 40, 108] {
        let mut wrong = frame.as_bytes().to_vec();
        wrong[offset] ^= 1;
        let no_walk = Walks::default();
        assert!(!receiver.receive_bytes(&wrong, no_walk.clone()));
        assert!(no_walk.with_draws().is_empty());
    }
    let mut trailing = frame.as_bytes().to_vec();
    trailing.push(0);
    assert!(!receiver.receive_bytes(&trailing, Walks::default()));
    assert!(!receiver.receive_bytes(&frame.as_bytes()[..127], Walks::default()));
    eprintln!(
        "research_data complete_public_joint_V_B_native_frame=true actual_DATA_expected_FullAir_PP=true native_batch_accepted=true native_samples=277 native_caps=17 native_input_rounds=5 native_FRI_rounds=12 complete_RAW_FIELD_CAP_SAMPLE_walk_equal=true immutable_query_only_replay=true native_negative=21 bounded_header_negative=6 normal_DATA_SHA_rejected=true no_Query_fixture=true original_private_trace=false restricted_ROM_research_only=true privacy_theorem=false admission=false"
    );
}
