//! DATA-owned research frame boundary; included ONLY in the unit-test build.
//! Uses the actual DATA Expected/FullAir/codec and one shared proof-ROM adapter.
pub(in crate::gold::program) mod native_fri;

use super::public_image::{DataCoins, DataFoldProgram, public_disclosures};
use super::{Expected, assessment::Assessment, hash_setup, hash_wire, native, public_deep};
use crate::gold::program::research_hash::{
    config as research_config, opaque_inputs, ro as research_ro,
};
use p3_batch_stark::{BatchProof, CommonData, ProverData, verify_batch};
use rand_public_pp::{SeedableRng, rngs::StdRng};
use research_config::Config;
use research_ro::{Oracle, Programmer, ResearchChallenger, Walk, Walks};
use std::time::Instant;

pub(in crate::gold::program) use native_fri::TapePlan;

const MAX_SEQUENCE: usize = 4096;
const MAX_SLOTS: usize = 4 * 1024 * 1024;
const MAX_FRAME: usize = 4 * 1024 * 1024;

/// A DATA test frame, never a production proof capability or Query frame.
pub(in crate::gold::program) struct ResearchFrame(Vec<u8>);
impl ResearchFrame {
    pub(in crate::gold::program) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Independently owned canonical PUBLIC DATA metadata, not a private witness.
pub(in crate::gold::program) fn public_expected() -> Expected {
    super::expected().unwrap()
}

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
    let pp = public.common.preprocessed.as_ref().unwrap();
    assert_eq!(pp.commitment.num_roots(), 1);
    assert_eq!(pp.matrix_to_instance, [0]);
    assert_eq!(pp.instances.len(), 1);
    let meta = pp.instances[0].as_ref().unwrap();
    assert_eq!(
        (meta.matrix_index, meta.width, meta.degree_bits),
        (0, 668, 12)
    );
    assert_eq!(public.common.lookups.len(), 1);
    let contexts = &public.common.lookups[0];
    assert_eq!(contexts.len(), 81);
    assert_eq!(contexts.len(), assessment.packed_lookup_count());
    assert_eq!(contexts.total_count_weight(), 4 * 243);
    assert_eq!(
        contexts
            .iter()
            .map(|lookup| lookup.elements.len())
            .sum::<usize>(),
        243
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
    let payload = postcard::to_allocvec(proof).unwrap();
    assert!(payload.len() < MAX_FRAME);
    // Actual DATA shape/canonical decoder precedes normal-layout frame encoding.
    let normal_shape = hash_wire::decode(&payload, assessment).unwrap();
    let frame = hash_wire::encode(expected, &normal_shape, assessment).unwrap();
    assert!(frame.len() <= MAX_FRAME);
    ResearchFrame(frame)
}

fn decode_bytes(
    frame: &[u8],
    expected: &Expected,
    assessment: &Assessment,
) -> Option<BatchProof<Config>> {
    // DATA magic/profile/full Expected binding before any payload interpretation.
    let payload = hash_wire::payload(expected, frame).ok()?;
    let normal_shape = hash_wire::decode(payload, assessment).ok()?;
    drop(normal_shape);
    // Distinct native hash type, identical canonical serde layout. Keep BOTH
    // owner shape validation and bounded research-config decoding; require EOF.
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

fn decode(
    frame: &ResearchFrame,
    expected: &Expected,
    assessment: &Assessment,
) -> Option<BatchProof<Config>> {
    decode_bytes(frame.as_bytes(), expected, assessment)
}

/// Receiver retains independent DATA CommonData and query rights only.
pub(in crate::gold::program) struct Receiver {
    expected: Expected,
    air: native::FullAir,
    assessment: Assessment,
    common: CommonData<Config>,
    oracle: Oracle,
}
impl Receiver {
    pub(in crate::gold::program) fn new(expected: &Expected, oracle: Oracle) -> Self {
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
        // Verification never reads these public dummy streams and has no
        // Programmer, private input factory or accepting callback.
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
    pub(in crate::gold::program) fn receive(&self, frame: &ResearchFrame, walks: Walks) -> bool {
        self.receive_bytes(frame.as_bytes(), walks)
    }
    /// Raw byte entry is internal to the two-family unit-test owner so foreign
    /// frame rejection can exercise the actual DATA header boundary.
    pub(in crate::gold::program) fn receive_bytes(&self, frame: &[u8], walks: Walks) -> bool {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            decode_bytes(frame, &self.expected, &self.assessment)
                .is_some_and(|proof| self.verify_native(&proof, walks))
        }))
        .unwrap_or(false)
    }
}

fn columns(source: &[public_disclosures::Column]) -> Vec<public_deep::Column> {
    source
        .iter()
        .map(|column| public_deep::Column {
            rows: column.rows.clone(),
            at_z: column.at_z,
            at_hz: column.at_hz,
        })
        .collect()
}

fn phase(name: &str, start: Instant) {
    eprintln!(
        "research_data phase={name} state=end elapsed_ms={:.3}",
        start.elapsed().as_secs_f64() * 1000.
    );
}

/// Owns one complete PUBLIC DATA arithmetic attempt. All producer PP, V/B,
/// forest, proof and private sampler streams die before this function returns.
/// Seeds are reproducible explicitly non-secret regression inputs, not a PRG law.
pub(in crate::gold::program) fn public_frame(
    expected: &Expected,
    programmer: Programmer,
    receiver: &Receiver,
    plan: TapePlan,
    seeds: [[u8; 32]; 4],
) -> (ResearchFrame, Walk) {
    let start = Instant::now();
    let inputs = native_fri::Inputs::new(
        expected,
        programmer,
        StdRng::from_seed(seeds[0]),
        StdRng::from_seed(seeds[1]),
    )
    .unwrap();
    phase("native_public_pp_and_opaque_roots", start);
    let start = Instant::now();
    let pp_coefficients = inputs.public_pp_coefficients();
    let program = DataFoldProgram::from_expected(expected).unwrap();
    assert_eq!(pp_coefficients.as_slice(), program.public_pp_coefficients());
    let coins = DataCoins {
        lookup_alpha: plan.lookup_alpha(),
        lookup_beta: plan.lookup_beta(),
        constraint_alpha: plan.constraint_alpha(),
    };
    let disclosed = public_disclosures::sample(
        &program,
        &coins,
        plan.z(),
        plan.positions(),
        &mut StdRng::from_seed(seeds[2]),
    )
    .unwrap();
    assert_eq!(disclosed.expected_binding, expected.binding());
    assert_eq!(disclosed.s, plan.positions());
    assert_eq!(disclosed.z, plan.z());
    let r = columns(&disclosed.r);
    let main = columns(&disclosed.main);
    let quotient = disclosed
        .quotient
        .iter()
        .map(|matrix| columns(matrix))
        .collect::<Vec<_>>();
    let pp = columns(&disclosed.pp);
    let aux = columns(&disclosed.aux);
    let view = public_deep::PublicView {
        s: &disclosed.s,
        z: disclosed.z,
        theta: plan.theta(),
        r: &r,
        main: &main,
        quotient: &quotient,
        pp: &pp,
        pp_coefficients: &pp_coefficients,
        aux: &aux,
    };
    phase("public_joint_v", start);
    let start = Instant::now();
    let prepared = public_deep::prepare(&view).unwrap();
    assert_eq!(prepared.opening_count(), 2622);
    let b = prepared.sample(&mut StdRng::from_seed(seeds[3]));
    assert_eq!(b.len(), 4095);
    drop(prepared);
    phase("public_whole_b", start);
    let produced = Walks::default();
    let start = Instant::now();
    let proof = inputs.prove(plan, &view, &b, produced.clone()).unwrap();
    phase("native_fri_and_input_openings", start);
    assert_eq!(proof.opening_proof.1.input_openings.len(), 5);
    assert_eq!(proof.opening_proof.1.commit_phase_commits.len(), 12);
    let start = Instant::now();
    let frame = encode(expected, &proof, &receiver.assessment);
    drop(proof);
    phase("bounded_frame_encode", start);
    let mut walks = produced.with_draws();
    assert_eq!(walks.len(), 1);
    let walk = walks.pop().unwrap();
    eprintln!(
        "research_data public_joint_v_and_b=true expected_owned=true true_PP668=true original_MAIN512_AUX410=true native_terms=2622 pp_theta_offset=1124 S_unique={} ideal_Gold_cells={} frame_bytes={} private_trace=false admission=false",
        disclosed.s.len(),
        disclosed.ideal_cells,
        frame.as_bytes().len()
    );
    (frame, walk)
}
