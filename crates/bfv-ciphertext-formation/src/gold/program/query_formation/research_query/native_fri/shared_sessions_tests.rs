//! Two public Query frames in ONE prior-state research dictionary.
//! This owning cfg(test) gate is not an adaptive privacy theorem or admission.
use super::super::public_frames::assert_complete_walk;
use super::super::research_ro::{Tape, Walk};
use super::super::{Receiver, ResearchFrame, public_frame};
use super::*;
use crate::gold::public_hash_trace::{self, Algorithm, Call};
use p3_challenger::{CanObserve, CanSample};
use rand_public_pp::SeedableRng;
use sha2::Digest;
use std::collections::BTreeSet;

/// Receiver holds only query rights. Equality includes the complete raw prefix,
/// EVERY raw64 digest/retry and all FIELD/CAP/SAMPLE observations, not just coins.
fn receive_same_walk(receiver: &Receiver, frame: &ResearchFrame, expected_walk: &Walk) {
    let walks = Walks::default();
    assert!(receiver.receive(frame, walks.clone()));
    let actual = walks.with_draws();
    assert_eq!(actual.as_slice(), core::slice::from_ref(expected_walk));
    assert_complete_walk(&actual[0]);
}

fn reject_existing_different_first_draw(programmer: &Programmer, old: &Walk) {
    let first = old.draws.first().unwrap();
    assert_eq!((first.counter, first.retry), (0, 0));
    let mut changed = first.digest;
    // Keep the native firstLE64 rejection candidate EXACTLY unchanged. This
    // conflict is in the complete raw oracle cell, not merely a changed coin.
    changed[63] ^= 1;
    assert_eq!(&changed[..8], &first.digest[..8]);
    assert_ne!(changed, first.digest);
    let tape: Tape = [((0, 0), changed)].into_iter().collect();
    let mut planter = ResearchChallenger::planter(programmer.clone(), tape, Walks::default());
    for event in &old.events {
        match event {
            Event::Field(value) => planter.observe(F::from_u64(*value)),
            Event::Cap(roots) => planter.observe(MerkleCap::<F, [u8; 32]>::new(roots.clone())),
            Event::Sample { counter, .. } => {
                assert_eq!(*counter, 0);
                break;
            }
        }
    }
    // This is OUTSIDE Receiver's SDK panic guard. The producer's named raw-cell
    // conflict must be observed directly, never converted to a generic rejection.
    let conflict = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: F = planter.sample();
    }))
    .expect_err("existing-different raw FS cell must fail closed");
    let message = conflict
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| conflict.downcast_ref::<&str>().copied());
    assert_eq!(message, Some("programming conflict: ()"));
}

/// Exact finite manifest of the instrumented sites, with concrete SHA results.
/// Other concrete PUBLIC preprocessing helpers are deliberately outside scope.
fn public_manifest(calls: &[Call]) -> BTreeSet<Call> {
    assert!(!calls.is_empty());
    for call in calls {
        let prefixes: &[&[u8]] = match call.algorithm {
            Algorithm::Sha256 => &[
                b"DCS/CoreGold/DATA-Formation/v1/",
                b"DCS/research/CoreGold/FusedQuery57/",
                b"DCS/research/fused-query57/actual-native-frame/",
                b"DCS/CoreGold/closed-hash-formation-frame/",
            ],
            Algorithm::Sha512 => &[
                b"DCS/CoreGold/DATA-complete-Expected/v1",
                b"DCS/fused-query-formation/complete-Expected/v1",
                b"DCS/hash-formation/PUBLIC-PP-ONLY/v1\0",
            ],
        };
        assert!(
            prefixes.iter().any(|prefix| call.input.starts_with(prefix)),
            "unexpected helper outside reviewed PUBLIC sites: {:?}",
            call.algorithm
        );
        for namespace in [
            bfv_hiding_stark::hash::LEAF_DOMAIN,
            bfv_hiding_stark::hash::NODE_DOMAIN,
            bfv_hiding_stark::hash::TRANSCRIPT_DOMAIN,
        ] {
            assert!(!call.input.starts_with(namespace));
            assert!(!namespace.starts_with(&call.input));
        }
        let actual = match call.algorithm {
            Algorithm::Sha256 => sha2::Sha256::digest(&call.input).to_vec(),
            Algorithm::Sha512 => sha2::Sha512::digest(&call.input).to_vec(),
        };
        assert_eq!(call.digest, actual);
    }
    calls.iter().cloned().collect()
}

#[test]
#[ignore = "two complete public Query frames in one prior-state RO; run alone under owning held-process resource observer"]
fn two_fresh_query_frames_share_one_oracle_and_keep_old_answers_after_a_named_programming_conflict()
{
    let (expected, expected_helpers) =
        public_hash_trace::capture(super::super::super::tests::metadata);
    let expected_manifest = public_manifest(&expected_helpers);
    assert!(expected_manifest.iter().any(|call| {
        call.input
            .starts_with(b"DCS/fused-query-formation/complete-Expected/v1")
    }));
    assert!(expected_manifest.iter().any(|call| {
        call.input
            .starts_with(b"DCS/CoreGold/DATA-complete-Expected/v1")
    }));
    let programmer = Programmer::regression([0xb0; 32]);
    let receiver = Receiver::new(&expected, programmer.oracle());
    // Independent full tapes are sampled BEFORE either V/B/frame construction.
    // A common raw-input dictionary does not mean copying a counter-indexed tape.
    let first_plan = TapePlan::sample(&mut StdRng::from_seed([0xb1; 32])).unwrap();
    let second_plan = TapePlan::sample(&mut StdRng::from_seed([0xb2; 32])).unwrap();
    assert_ne!(first_plan.tape, second_plan.tape);

    let ((first_frame, first_walk), first_helpers) = public_hash_trace::capture(|| {
        public_frame(&expected, programmer.clone(), &receiver, first_plan, 0xb3)
    });
    let first_manifest = public_manifest(&first_helpers);
    receive_same_walk(&receiver, &first_frame, &first_walk);

    // The first consuming Inputs, V/B and private sampler streams are gone.
    let ((second_frame, second_walk), second_helpers) = public_hash_trace::capture(|| {
        public_frame(&expected, programmer.clone(), &receiver, second_plan, 0xb7)
    });
    let second_manifest = public_manifest(&second_helpers);
    assert_eq!(first_manifest, second_manifest);
    // Every instrumented helper family must actually have been finalized.
    // Set equality alone would not detect an accidentally removed observer.
    let required: &[(Algorithm, &[u8])] = &[
        (Algorithm::Sha256, b"DCS/CoreGold/DATA-Formation/v1/"),
        (Algorithm::Sha256, b"DCS/research/CoreGold/FusedQuery57/"),
        (
            Algorithm::Sha256,
            b"DCS/research/fused-query57/actual-native-frame/",
        ),
        (
            Algorithm::Sha256,
            b"DCS/CoreGold/closed-hash-formation-frame/",
        ),
        (Algorithm::Sha512, b"DCS/CoreGold/DATA-complete-Expected/v1"),
        (
            Algorithm::Sha512,
            b"DCS/fused-query-formation/complete-Expected/v1",
        ),
        (Algorithm::Sha512, b"DCS/hash-formation/PUBLIC-PP-ONLY/v1\0"),
    ];
    for &(algorithm, prefix) in required {
        assert!(
            expected_manifest
                .union(&first_manifest)
                .any(|call| { call.algorithm == algorithm && call.input.starts_with(prefix) }),
            "missing observed PUBLIC helper family"
        );
    }
    for label in 0..3 {
        assert!(first_manifest.iter().any(|call| {
            call.input
                .starts_with(b"DCS/hash-formation/PUBLIC-PP-ONLY/v1\0")
                && call.input.last() == Some(&label)
        }));
    }
    assert!(
        expected
            .core_expected()
            .request()
            .bytes()
            .starts_with(b"GFMDQ001")
    );
    assert_ne!(first_frame.0, second_frame.0);
    assert_ne!(first_walk, second_walk);
    receive_same_walk(&receiver, &second_frame, &second_walk);
    // Immutable first bytes remain accepted with exactly the old raw answers
    // after the second producer has added cells to that SAME dictionary.
    receive_same_walk(&receiver, &first_frame, &first_walk);

    reject_existing_different_first_draw(&programmer, &first_walk);
    // Never replace the Programmer/dictionary, overwrite a cell, retry a proof
    // producer or resample after the named conflict. Replay both OLD frames.
    receive_same_walk(&receiver, &first_frame, &first_walk);
    receive_same_walk(&receiver, &second_frame, &second_walk);
    assert!(super::super::super::hash_backend::receive(&expected, &first_frame.0).is_err());
    assert!(super::super::super::hash_backend::receive(&expected, &second_frame.0).is_err());
    eprintln!(
        "research_query shared_prior_state_sessions=2 fresh_owned_V_B_opaque_FRI_streams=true independent_presampled_FS_tapes=true complete_RAW_FIELD_CAP_SAMPLE_walks_equal=true immutable_first_replay=true existing_different_raw_cell_named_conflict=true old_frames_replay_after_conflict=true normal_SHA_rejected=true restricted_proof_ROM_with_concrete_PUBLIC_preprocessing=true instrumented_helper_manifest_equal=true initial_helper_calls={} initial_helper_unique={} first_helper_calls={} second_helper_calls={} session_helper_unique={} privacy_theorem=false admission=false",
        expected_helpers.len(),
        expected_manifest.len(),
        first_helpers.len(),
        second_helpers.len(),
        first_manifest.len(),
    );
}
