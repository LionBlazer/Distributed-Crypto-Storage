//! Requires the separately authored r790 owning joint-disclosure candidate.
//! Every value, sampler coin and Expected below is public; no honest reference
//! fixture, Prepared, dense_trace, original trace or encryption key is requested.
use super::super::super::public_image::{QueryCoins, QueryFoldProgram, public_disclosures};
use super::super::{Receiver, decode, encode, public_deep};
use super::*;
use rand_public_pp::SeedableRng;

fn convert(columns: &[public_disclosures::Column]) -> Vec<Column> {
    columns
        .iter()
        .map(|column| Column {
            rows: column.rows.clone(),
            at_z: column.at_z,
            at_hz: column.at_hz,
        })
        .collect()
}

#[test]
#[ignore = "joint public V+B to actual native Query frame; run alone under owning held-process resource observer"]
fn current_query_native_receiver_accepts_a_frame_built_from_public_joint_v_b_and_presampled_fs_tape()
 {
    let expected = super::super::super::tests::metadata();
    let programmer = Programmer::regression([0x91; 32]);
    let receiver = Receiver::new(&expected, programmer.oracle());
    // Complete raw64-byte tape is sampled BEFORE any public V/B construction.
    let plan = TapePlan::sample(&mut StdRng::from_seed([0x92; 32])).unwrap();
    let inputs = Inputs::new(
        &expected,
        programmer,
        StdRng::from_seed([0x93; 32]),
        StdRng::from_seed([0x94; 32]),
    )
    .unwrap();
    let pp_coefficients = inputs.public_pp_coefficients();
    let program = QueryFoldProgram::from_expected(&expected).unwrap();
    assert_eq!(pp_coefficients.as_slice(), program.public_pp_coefficients());
    let coins = QueryCoins {
        lookup_alpha: plan.lookup_alpha(),
        lookup_beta: plan.lookup_beta(),
        constraint_alpha: plan.constraint_alpha(),
    };
    // Actual FullAir/ring sampler, actual correlated8-chunk fiber and every
    // wrapper coordinate, NOT independently sampled original quotient chunks.
    let disclosures = public_disclosures::sample(
        &program,
        &coins,
        plan.z(),
        plan.positions(),
        &mut StdRng::from_seed([0x95; 32]),
    )
    .unwrap();
    assert_eq!(disclosures.expected_binding, expected.binding());
    assert_eq!(disclosures.z, plan.z());
    assert_eq!(disclosures.s, plan.positions());
    let r = convert(&disclosures.r);
    let main = convert(&disclosures.main);
    let quotient = disclosures
        .quotient
        .iter()
        .map(|m| convert(m))
        .collect::<Vec<_>>();
    let pp = convert(&disclosures.pp);
    let aux = convert(&disclosures.aux);
    let view = PublicView {
        s: &disclosures.s,
        z: disclosures.z,
        theta: plan.theta(),
        r: &r,
        main: &main,
        quotient: &quotient,
        pp: &pp,
        pp_coefficients: &pp_coefficients,
        aux: &aux,
    };
    // Actual public whole-B affine-image sampler. No witness-dependent V|B
    // inversion or repeated private proof production is used to obtain B.
    let b_sampler = public_deep::prepare(&view).unwrap();
    let b = b_sampler.sample(&mut StdRng::from_seed([0x96; 32]));
    assert_eq!(b.len(), 4095);
    let produce_walks = Walks::default();
    let proof = inputs
        .prove(plan, &view, &b, produce_walks.clone())
        .unwrap();
    let frame = encode(&expected, &proof, &receiver.assessment);
    let receive_walks = Walks::default();
    // GENUINE existing bounded frame decoder + native verify_batch, including
    // AIR/lookup/quotient and ALL5 INPUT/12 FRI checks, with query-only RO access.
    assert!(receiver.receive(&frame, receive_walks.clone()));
    let produced = produce_walks.with_draws();
    let received = receive_walks.with_draws();
    assert_eq!(produced, received);
    assert_eq!(received.len(), 1);
    assert_eq!(
        received[0]
            .events
            .iter()
            .filter(|e| matches!(e, Event::Sample { .. }))
            .count(),
        277
    );
    assert_eq!(
        received[0]
            .events
            .iter()
            .filter(|e| matches!(e, Event::Cap(_)))
            .count(),
        17
    );
    // Research RO assignments have no normal-SHA proof authority/profile.
    assert!(super::super::super::hash_backend::receive(&expected, &frame.0).is_err());
    for round in 0..5 {
        let mut omitted = decode(&frame, &expected, &receiver.assessment).unwrap();
        omitted.opening_proof.1.input_openings.remove(round);
        assert!(
            !receiver.verify_native(&omitted, Walks::default()),
            "omitted native input round={round}"
        );
    }
    let mut changed = decode(&frame, &expected, &receiver.assessment).unwrap();
    changed.opened_values.instances[0].permutation_next[419] += E::ONE;
    assert!(!receiver.verify_native(&changed, Walks::default()));
    let mut changed = decode(&frame, &expected, &receiver.assessment).unwrap();
    changed.opened_values.instances[0]
        .base_opened_values
        .quotient_chunks[7][4] += E::ONE;
    assert!(!receiver.verify_native(&changed, Walks::default()));
    let mut changed = decode(&frame, &expected, &receiver.assessment).unwrap();
    changed.opening_proof.0[0][0][0][4] += E::ONE;
    assert!(!receiver.verify_native(&changed, Walks::default()));
    let mut changed = decode(&frame, &expected, &receiver.assessment).unwrap();
    changed.opening_proof.1.input_openings[3].opening_proof.0[0][0][0] += F::ONE;
    assert!(!receiver.verify_native(&changed, Walks::default()));
    let mut changed = decode(&frame, &expected, &receiver.assessment).unwrap();
    changed.opening_proof.1.query_pow_witness = F::ONE;
    assert!(!receiver.verify_native(&changed, Walks::default()));
    eprintln!(
        "research_query PUBLIC_joint_V_B_native_frame=true native_batch_accepted=true normal_SHA_rejected=true samples=277 caps=17 native_input_rounds=5 FRI_rounds=12 complete_RAW_FIELD_CAP_SAMPLE_walk_equal=true native_negative=10 S_unique={} ideal_Gold_cells={} private_witness_requested=false programmable_RO_research_only=true privacy_theorem=false admission=false",
        disclosures.s.len(),
        disclosures.ideal_cells
    );
}
