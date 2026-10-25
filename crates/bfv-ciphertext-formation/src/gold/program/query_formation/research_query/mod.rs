//! Candidate child module of gold::program::query_formation, cfg(test) ONLY.
//! Native adapter/reference and public V+B assembly gates; no production authority.
mod joint_disclosures_tests;
mod native_fri;
mod public_deep;

use super::super::research_hash::{config as research_config, opaque_inputs, ro as research_ro};
use super::{Expected, assessment::Assessment, hash_setup, hash_wire, native};
use bfv_hiding_stark::Val;
use p3_batch_stark::{BatchProof, CommonData, ProverData, verify_batch};
use p3_field::PrimeCharacteristicRing;
use rand_public_pp::{SeedableRng, rngs::StdRng};
use research_config::Config;
use research_ro::{Oracle, ResearchChallenger, Walks};

// Actual owner caps, not an incoming proof geometry or sampler's own dimensions.
const MAX_SEQUENCE: usize = 4096;
const MAX_SLOTS: usize = 4 * 1024 * 1024;
const MAX_FRAME: usize = 4 * 1024 * 1024;

/// Private wrapper cannot be passed as normal proof bytes by a public API.
struct ResearchFrame(Vec<u8>);

fn public_data(
    expected: &Expected,
    oracle: Oracle,
) -> (native::FullAir, Assessment, ProverData<Config>) {
    let (air, assessment) = native::prescreen(expected).unwrap();
    hash_wire::require_assessment(&assessment).unwrap();
    let public_config = research_config::config(
        oracle.clone(),
        ResearchChallenger::receiver(oracle, Walks::default()),
        hash_setup::research_public_stream(expected, 0),
        hash_setup::research_public_stream(expected, 1),
        hash_setup::research_public_stream(expected, 2),
    );
    let public =
        ProverData::from_airs_and_degrees(&public_config, core::slice::from_ref(&air), &[12])
            .unwrap();
    drop(public_config);
    // Independent fixed Query association checks, corresponding to hash_setup's
    // concrete-config checks. Native SDK produced both PP and packed contexts.
    let pp = public.common.preprocessed.as_ref().unwrap();
    assert_eq!(pp.commitment.num_roots(), 1);
    assert_eq!(pp.matrix_to_instance, [0]);
    assert_eq!(pp.instances.len(), 1);
    let meta = pp.instances[0].as_ref().unwrap();
    assert_eq!(
        (meta.matrix_index, meta.width, meta.degree_bits),
        (0, 545, 12)
    );
    assert_eq!(public.common.lookups.len(), 1);
    let contexts = &public.common.lookups[0];
    assert_eq!(contexts.len(), 83);
    assert_eq!(contexts.len(), assessment.packed_lookup_count());
    assert_eq!(contexts.total_count_weight(), 4 * 248);
    assert_eq!(
        contexts
            .iter()
            .map(|lookup| lookup.elements.len())
            .sum::<usize>(),
        248
    );
    for (column, lookup) in contexts.iter().enumerate() {
        assert_eq!(lookup.column, column);
        assert_eq!(
            lookup.kind,
            p3_lookup::Kind::Global(super::layout::BUS.to_owned())
        );
        assert!(lookup.flags.is_none());
        assert!(!lookup.elements.is_empty());
        assert_eq!(lookup.elements.len(), lookup.multiplicities.len());
        assert!(lookup.elements.iter().all(|tuple| tuple.len() == 2));
    }
    (air, assessment, public)
}

fn encode(
    expected: &Expected,
    proof: &BatchProof<Config>,
    assessment: &Assessment,
) -> ResearchFrame {
    // The builder holds trusted finite objects. Enforce the ACTUAL normal
    // bounded/canonical shape decoder before emitting a normal-layout frame.
    let payload = postcard::to_allocvec(proof).unwrap();
    assert!(payload.len() < MAX_FRAME);
    let normal_shape = hash_wire::decode(&payload, assessment).unwrap();
    let frame = hash_wire::encode(expected, &normal_shape, assessment).unwrap();
    assert!(frame.len() <= MAX_FRAME);
    ResearchFrame(frame)
}

fn decode(
    frame: &ResearchFrame,
    expected: &Expected,
    assessment: &Assessment,
) -> Option<BatchProof<Config>> {
    // Header/full Expected binding/caps before proof decoding and native verification.
    let payload = hash_wire::payload(expected, &frame.0).ok()?;
    // This first genuine owner decoder pins topology, canonical fields and EOF.
    let normal_shape = hash_wire::decode(payload, assessment).ok()?;
    drop(normal_shape);
    // Same public serde layout, different hash/challenger Rust type. A SECOND
    // bounded parse is intentional here; never use an unbounded conversion.
    let (proof, trailing) = bounded_postcard::take_from_bytes::<BatchProof<Config>>(
        payload,
        bounded_postcard::Limits {
            max_sequence_elements: MAX_SEQUENCE,
            max_total_elements: MAX_SLOTS,
        },
    )
    .ok()?;
    if !trailing.is_empty() || postcard::to_allocvec(&proof).ok()? != payload {
        return None;
    }
    Some(proof)
}

struct Receiver {
    expected: Expected,
    air: native::FullAir,
    assessment: Assessment,
    common: CommonData<Config>,
    oracle: Oracle,
}
impl Receiver {
    fn new(expected: &Expected, oracle: Oracle) -> Self {
        let (air, assessment, public) = public_data(expected, oracle.clone());
        let common = public.common;
        drop(public.prover_only);
        Self {
            expected: expected.clone(),
            air,
            assessment,
            common,
            oracle,
        }
    }
    fn verify_native(&self, proof: &BatchProof<Config>, walks: Walks) -> bool {
        // These public dummy RNG streams are unused by verification. This is
        // not a private prover config and is never offered through normal APIs.
        let config = research_config::config(
            self.oracle.clone(),
            ResearchChallenger::receiver(self.oracle.clone(), walks),
            StdRng::from_seed([0x20; 32]),
            StdRng::from_seed([0x21; 32]),
            StdRng::from_seed([0x22; 32]),
        );
        verify_batch(
            &config,
            core::slice::from_ref(&self.air),
            proof,
            &[self.expected.values().to_vec()],
            &self.common,
        )
        .is_ok()
    }
    fn receive(&self, frame: &ResearchFrame, walks: Walks) -> bool {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            decode(frame, &self.expected, &self.assessment)
                .is_some_and(|proof| self.verify_native(&proof, walks))
        }))
        .unwrap_or(false)
    }
}

// The honest reference is deliberately separate from a public simulator.
// It tests adapter wiring and actual native checks ONLY. No witness getter or
// Prepared parameter appears in Receiver.
mod honest_reference {
    use super::*;
    use p3_batch_stark::{StarkInstance, prove_batch};
    use research_ro::{Event, Programmer};

    #[test]
    #[ignore = "isolated research Query native proof; run explicitly under owning resource observer"]
    fn actual_query_native_verifier_and_complete_walk_use_the_same_research_ro() {
        let (expected, prepared) = crate::gold::data::fused_query_native_fixture(false);
        let programmer = Programmer::regression([0x40; 32]);
        let oracle = programmer.oracle();
        let (air, assessment, public) = public_data(&expected, oracle.clone());
        let produce_walks = Walks::default();
        let config = research_config::config(
            oracle.clone(),
            ResearchChallenger::receiver(oracle.clone(), produce_walks.clone()),
            StdRng::from_seed([0x41; 32]),
            StdRng::from_seed([0x42; 32]),
            StdRng::from_seed([0x43; 32]),
        );
        let trace = prepared.dense_trace(&expected).unwrap();
        let proof = prove_batch(
            &config,
            &[StarkInstance {
                air: &air,
                trace: &trace.0,
                public_values: expected.values().to_vec(),
            }],
            &public,
        )
        .unwrap();
        drop(trace);
        drop(config);
        drop(public);
        drop(air);
        let frame = encode(&expected, &proof, &assessment);
        drop(proof);
        assert!(super::super::hash_backend::receive(&expected, &frame.0).is_err());
        let receiver = Receiver::new(&expected, oracle);
        let receive_walks = Walks::default();
        assert!(receiver.receive(&frame, receive_walks.clone()));
        let produced = produce_walks.with_draws();
        let received = receive_walks.with_draws();
        assert_eq!(produced.len(), 1);
        assert_eq!(received.len(), 1);
        // Exact bytes, observed events, ALL retry digests and SAMPLE histories.
        assert_eq!(produced, received);
        assert_eq!(
            received[0]
                .events
                .iter()
                .filter(|event| matches!(event, Event::Sample { .. }))
                .count(),
            277
        );

        let mut omitted = decode(&frame, &expected, &assessment).unwrap();
        omitted.opening_proof.1.input_openings.clear();
        // Direct native check, not only the owner shape decoder's rejection.
        assert!(!receiver.verify_native(&omitted, Walks::default()));
        drop(omitted);
        let mut altered = decode(&frame, &expected, &assessment).unwrap();
        // Same root/claims/coins, changed real MAIN input row at actual query0.
        altered.opening_proof.1.input_openings[1].opened_values[0][0][0] += Val::ONE;
        assert!(!receiver.verify_native(&altered, Walks::default()));
    }
}
