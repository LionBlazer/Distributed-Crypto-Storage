//! Complete Query and DATA frames retain ONE prior raw-input RO history.
//! Restricted proof-ROM + selected concrete PUBLIC helpers; no privacy/admission.
use super::super::dense_data_inventory::{self, research_data as data};
use super::super::query_formation::research_query as query;
use super::ro::{Event, Programmer, ResearchChallenger, Tape, Walk, Walks};
use crate::gold::public_hash_trace::{self, Algorithm, Call};
use bfv_hiding_stark::Val as F;
use p3_challenger::{CanObserve, CanSample};
use p3_field::PrimeCharacteristicRing;
use p3_symmetric::MerkleCap;
use rand_public_pp::{SeedableRng, rngs::StdRng};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

type Registry = BTreeMap<(Algorithm, Vec<u8>), Vec<u8>>;
const PP_SEED: &[u8] = b"DCS/hash-formation/PUBLIC-PP-ONLY/v1\0";

/// Only the selected actual concrete helper finalizations are classified here.
/// No ROM answer is substituted/registered, and no Rayon-wide capture is claimed.
fn record(calls: &[Call], registry: &mut Registry) -> BTreeSet<Call> {
    assert!(!calls.is_empty());
    for call in calls {
        let prefixes: &[&[u8]] = match call.algorithm {
            Algorithm::Sha256 => &[
                b"DCS/CoreGold/DATA-Formation/v1/",
                b"DCS/research/CoreGold/FusedQuery57/",
                b"DCS/research/fused-query57/actual-native-frame/",
                b"DCS/research/dense-data56/actual-native-frame/",
                b"DCS/CoreGold/closed-hash-formation-frame/",
            ],
            Algorithm::Sha512 => &[
                b"DCS/CoreGold/DATA-complete-Expected/v1",
                b"DCS/fused-query-formation/complete-Expected/v1",
                PP_SEED,
            ],
        };
        assert!(
            prefixes.iter().any(|prefix| call.input.starts_with(prefix)),
            "unreviewed helper prefix: {:?}",
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
        let key = (call.algorithm, call.input.clone());
        if let Some(old) = registry.get(&key) {
            assert_eq!(old, &call.digest, "PUBLIC helper raw cell changed");
        } else {
            registry.insert(key, call.digest.clone());
        }
    }
    calls.iter().cloned().collect()
}

fn require_pp_labels(manifest: &BTreeSet<Call>, binding: [u8; 64]) {
    for label in 0..3 {
        assert!(
            manifest.iter().any(|call| {
                call.algorithm == Algorithm::Sha512
                    && call.input.starts_with(PP_SEED)
                    && call.input.last() == Some(&label)
                    && call.input.len() >= 65
                    && call.input[call.input.len() - 65..call.input.len() - 1] == binding
            }),
            "missing owning PUBLIC PP stream label={label}"
        );
    }
}

fn require_families(manifest: &BTreeSet<Call>, query_family: bool) {
    let mut required: Vec<(Algorithm, &[u8])> = vec![
        (Algorithm::Sha256, b"DCS/CoreGold/DATA-Formation/v1/"),
        (
            Algorithm::Sha256,
            b"DCS/CoreGold/closed-hash-formation-frame/",
        ),
        (Algorithm::Sha512, b"DCS/CoreGold/DATA-complete-Expected/v1"),
        (Algorithm::Sha512, PP_SEED),
    ];
    if query_family {
        required.extend([
            (
                Algorithm::Sha256,
                b"DCS/research/CoreGold/FusedQuery57/".as_slice(),
            ),
            (
                Algorithm::Sha256,
                b"DCS/research/fused-query57/actual-native-frame/".as_slice(),
            ),
            (
                Algorithm::Sha512,
                b"DCS/fused-query-formation/complete-Expected/v1".as_slice(),
            ),
        ]);
    } else {
        required.push((
            Algorithm::Sha256,
            b"DCS/research/dense-data56/actual-native-frame/",
        ));
    }
    for (algorithm, prefix) in required {
        assert!(
            manifest
                .iter()
                .any(|call| call.algorithm == algorithm && call.input.starts_with(prefix)),
            "instrumented owning PUBLIC helper family missing"
        );
    }
}

fn assert_walk(walk: &Walk) {
    assert!(
        walk.prefix
            .starts_with(bfv_hiding_stark::hash::TRANSCRIPT_DOMAIN)
    );
    assert_eq!(
        walk.events
            .iter()
            .filter(|e| matches!(e, Event::Sample { .. }))
            .count(),
        277
    );
    assert_eq!(
        walk.events
            .iter()
            .filter(|e| matches!(e, Event::Cap(_)))
            .count(),
        17
    );
    assert!(walk.events.iter().any(|e| matches!(e, Event::Field(_))));
    assert!(walk.draws.len() >= 277);
}

fn observed_receive(operation: impl FnOnce(Walks) -> bool, expected: &Walk) -> Vec<Call> {
    // Private assertion helper invokes the ACTUAL owning receiver at each call.
    let walks = Walks::default();
    let (accepted, calls) = public_hash_trace::capture(|| operation(walks.clone()));
    assert!(accepted);
    let actual = walks.with_draws();
    assert_eq!(actual.as_slice(), core::slice::from_ref(expected));
    assert_walk(&actual[0]);
    calls
}

fn first_raw_key(walk: &Walk) -> Vec<u8> {
    let first = walk.draws.first().unwrap();
    assert_eq!((first.counter, first.retry), (0, 0));
    let mut input = walk.prefix[..first.prefix_len].to_vec();
    input.push(4);
    input.extend(first.counter.to_le_bytes());
    input.extend(first.retry.to_le_bytes());
    input
}

fn conflict_with_existing_raw_tail(programmer: &Programmer, old: &Walk) {
    let first = old.draws.first().unwrap();
    assert_eq!((first.counter, first.retry), (0, 0));
    let mut different = first.digest;
    different[63] ^= 1;
    assert_eq!(&different[..8], &first.digest[..8]);
    assert_ne!(different, first.digest);
    let tape: Tape = [((0, 0), different)].into_iter().collect();
    let mut plant = ResearchChallenger::planter(programmer.clone(), tape, Walks::default());
    for event in &old.events {
        match event {
            Event::Field(value) => plant.observe(F::from_u64(*value)),
            Event::Cap(roots) => plant.observe(MerkleCap::<F, [u8; 32]>::new(roots.clone())),
            Event::Sample { counter, .. } => {
                assert_eq!(*counter, 0);
                break;
            }
        }
    }
    // Observe the named programming failure OUTSIDE every Receiver SDK guard.
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: F = plant.sample();
    }))
    .expect_err("existing full raw FS cell must not be overwritten");
    let message = failure
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| failure.downcast_ref::<&str>().copied());
    assert_eq!(message, Some("programming conflict: ()"));
}

#[test]
#[ignore = "complete Query+DATA shared prior-state sessions; run alone under held-process 120s/1792MiB observer"]
fn query_and_data_complete_frames_share_one_raw_oracle_and_replay_after_a_named_raw_tail_conflict()
{
    let mut registry = Registry::new();
    let (query_expected, query_initial_calls) = public_hash_trace::capture(query::public_expected);
    let (data_expected, data_initial_calls) = public_hash_trace::capture(data::public_expected);
    let query_initial = record(&query_initial_calls, &mut registry);
    let data_initial = record(&data_initial_calls, &mut registry);
    assert_ne!(query_expected.binding(), data_expected.binding());
    assert!(
        query_expected
            .core_expected()
            .request()
            .bytes()
            .starts_with(b"GFMDQ001")
    );
    assert!(data_expected.request().bytes().starts_with(b"GFMDQ001"));

    // Exactly ONE mutable raw-input dictionary owner for all native PP/INPUT/
    // FRI/FS calls across both families. Receivers get query-only clones.
    let programmer = Programmer::regression([0xd0; 32]);
    let (query_receiver, query_setup_calls) =
        public_hash_trace::capture(|| query::Receiver::new(&query_expected, programmer.oracle()));
    let (data_receiver, data_setup_calls) =
        public_hash_trace::capture(|| data::Receiver::new(&data_expected, programmer.oracle()));
    let query_setup = record(&query_setup_calls, &mut registry);
    let data_setup = record(&data_setup_calls, &mut registry);
    require_pp_labels(&query_setup, query_expected.binding());
    require_pp_labels(&data_setup, data_expected.binding());

    // Independent complete tapes precede BOTH public V/B constructions.
    let query_plan = query::TapePlan::sample(&mut StdRng::from_seed([0xd1; 32])).unwrap();
    let data_plan = data::TapePlan::sample(&mut StdRng::from_seed([0xd2; 32])).unwrap();
    assert_ne!(query_plan.accepted(), data_plan.accepted());

    let start = Instant::now();
    let ((query_frame, query_walk), query_produce_calls) = public_hash_trace::capture(|| {
        query::public_frame(
            &query_expected,
            programmer.clone(),
            &query_receiver,
            query_plan,
            0xd3,
        )
    });
    let query_ms = start.elapsed().as_secs_f64() * 1000.;
    assert_walk(&query_walk);
    let query_produce = record(&query_produce_calls, &mut registry);
    require_pp_labels(&query_produce, query_expected.binding());
    assert!(query_setup.is_subset(&query_produce));
    let query_receive_calls = observed_receive(
        |walks| query_receiver.receive(&query_frame, walks),
        &query_walk,
    );
    let query_receive = record(&query_receive_calls, &mut registry);
    assert!(query_receive.is_subset(&query_produce));

    // Query factory has returned: all its Inputs/producer PP/V/B allocations
    // are gone. Immutable frame/walk and the original shared history remain.
    let start = Instant::now();
    let ((data_frame, data_walk), data_produce_calls) = public_hash_trace::capture(|| {
        data::public_frame(
            &data_expected,
            programmer.clone(),
            &data_receiver,
            data_plan,
            [[0xd7; 32], [0xd8; 32], [0xd9; 32], [0xda; 32]],
        )
    });
    let data_ms = start.elapsed().as_secs_f64() * 1000.;
    assert_walk(&data_walk);
    let data_produce = record(&data_produce_calls, &mut registry);
    require_pp_labels(&data_produce, data_expected.binding());
    assert!(data_setup.is_subset(&data_produce));
    let data_receive_calls = observed_receive(
        |walks| data_receiver.receive(&data_frame, walks),
        &data_walk,
    );
    let data_receive = record(&data_receive_calls, &mut registry);
    assert!(data_receive.is_subset(&data_produce));
    assert_ne!(first_raw_key(&query_walk), first_raw_key(&data_walk));
    assert_ne!(query_walk.draws[0].digest, data_walk.draws[0].digest);
    assert_eq!(&query_frame.as_bytes()[..8], b"DCSHQF01");
    assert_eq!(&data_frame.as_bytes()[..8], b"DCSHDD01");

    let query_all = query_initial.union(&query_produce).cloned().collect();
    let data_all = data_initial.union(&data_produce).cloned().collect();
    require_families(&query_all, true);
    require_families(&data_all, false);

    // Each complete old frame must retain ALL old raw answers after the other
    // family's production. Replayed concrete-helper call vectors also agree.
    let query_replay_calls = observed_receive(
        |walks| query_receiver.receive(&query_frame, walks),
        &query_walk,
    );
    let data_replay_calls = observed_receive(
        |walks| data_receiver.receive(&data_frame, walks),
        &data_walk,
    );
    assert_eq!(query_replay_calls, query_receive_calls);
    assert_eq!(data_replay_calls, data_receive_calls);
    record(&query_replay_calls, &mut registry);
    record(&data_replay_calls, &mut registry);

    // Actual owning foreign byte headers reject BEFORE native challenger work.
    let query_foreign_walks = Walks::default();
    let data_foreign_walks = Walks::default();
    let (query_foreign, query_foreign_calls) = public_hash_trace::capture(|| {
        query_receiver.receive_bytes(data_frame.as_bytes(), query_foreign_walks.clone())
    });
    let (data_foreign, data_foreign_calls) = public_hash_trace::capture(|| {
        data_receiver.receive_bytes(query_frame.as_bytes(), data_foreign_walks.clone())
    });
    assert!(!query_foreign && !data_foreign);
    assert!(query_foreign_walks.with_draws().is_empty());
    assert!(data_foreign_walks.with_draws().is_empty());
    assert!(query_foreign_calls.is_empty() && data_foreign_calls.is_empty());

    let (query_sha, query_sha_calls) = public_hash_trace::capture(|| {
        super::super::query_formation::hash_backend::receive(
            &query_expected,
            query_frame.as_bytes(),
        )
    });
    let (data_sha, data_sha_calls) = public_hash_trace::capture(|| {
        dense_data_inventory::hash_backend::receive(&data_expected, data_frame.as_bytes())
    });
    assert!(query_sha.is_err() && data_sha.is_err());
    record(&query_sha_calls, &mut registry);
    record(&data_sha_calls, &mut registry);

    conflict_with_existing_raw_tail(&programmer, &data_walk);
    // After the forced failure: SAME dictionary, no producer call, reset,
    // overwritten cell, fresh mask or retry tape. Query-only old-frame replay.
    let query_after = observed_receive(
        |walks| query_receiver.receive(&query_frame, walks),
        &query_walk,
    );
    let data_after = observed_receive(
        |walks| data_receiver.receive(&data_frame, walks),
        &data_walk,
    );
    assert_eq!(query_after, query_receive_calls);
    assert_eq!(data_after, data_receive_calls);
    record(&query_after, &mut registry);
    record(&data_after, &mut registry);
    eprintln!(
        "research_mixed Query_DATA_complete_frames=true one_shared_raw_dictionary=true independent_presampled_tapes=true complete_RAW_FIELD_CAP_SAMPLE_walks_equal=true samples_each=277 caps_each=17 prior_history_replays=true foreign_headers_rejected=true existing_full_raw_tail_named_conflict=true old_frames_after_conflict=true concrete_normal_SHA_rejected=true concrete_PUBLIC_helper_cells={} receiver_and_producer_helper_capture=true Query_frame_bytes={} DATA_frame_bytes={} Query_produce_ms={:.3} DATA_produce_ms={:.3} original_private_trace=false restricted_proof_ROM=true all_helper_ROM=false privacy_theorem=false admission=false full_SQL_timing=false",
        registry.len(),
        query_frame.as_bytes().len(),
        data_frame.as_bytes().len(),
        query_ms,
        data_ms
    );
}
