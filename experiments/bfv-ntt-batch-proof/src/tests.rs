//! Public nonsecret full-vector fixtures. No query/database acceptance is inferred.
use super::*;
use backend::{Challenge, Val};
use bfv_ntt_circuit::{
    Basis, DEGREE, Direction, Request, decode_request, encode_request, evaluate_with_certificate,
    multistark::BatchSpec,
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
#[path = "attacks.rs"]
mod attacks;

fn expected(context: Context, requests: Vec<Request>) -> Expected {
    let outputs = requests
        .iter()
        .map(|r| evaluate_with_certificate(r).unwrap().output)
        .collect();
    Expected::new(context, requests, outputs).unwrap()
}
fn reframe(frame: &[u8], payload: &[u8]) -> Vec<u8> {
    // Used only by count2 hostile cases, which have exactly ONE component.
    let mut b = frame[..proof::HEADER].to_vec();
    b[268..272].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    b[272..276].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    b.extend(payload);
    b
}
#[test]
fn all_twenty_targets_match_the_actual_native_cpu_sdk_over_every8192_coefficient() {
    use fhe_math::{ntt::NttOperator, zq::Modulus};
    assert_eq!(
        std::any::type_name::<NttOperator>(),
        "fhe_math::ntt::native::NttOperator"
    );
    let mut cases = Vec::new();
    for basis in 0..10 {
        for direction in [Direction::Forward, Direction::Inverse] {
            cases.push(BatchSpec {
                direction,
                basis: Basis::new(basis).unwrap(),
            });
        }
    }
    for specs in cases.as_chunks::<4>().0 {
        for request in fixture::requests(fixture::context(), specs).unwrap() {
            let modulus = Modulus::new(request.basis().modulus()).unwrap();
            let native = NttOperator::new(&modulus, DEGREE).unwrap();
            let mut oracle = request.input().to_vec();
            match request.direction() {
                Direction::Forward => native.forward(&mut oracle),
                Direction::Inverse => native.backward(&mut oracle),
            }
            assert_eq!(
                evaluate_with_certificate(&request)
                    .unwrap()
                    .output
                    .coefficients(),
                oracle
            );
        }
    }
}
#[test]
fn full_envelopes_and_unique_ordered_claims_reject_zero_missing_duplicate_and_rebound_contexts() {
    let context = fixture::context();
    let requests = fixture::requests(context, &fixture::specs(2)).unwrap();
    let e = expected(context, requests);
    assert!(
        Expected::new(
            Context {
                query: [0; 32],
                ..context
            },
            e.requests().to_vec(),
            e.outputs().to_vec()
        )
        .is_err()
    );
    assert!(
        Expected::new(
            Context {
                setup: [0; 32],
                ..context
            },
            e.requests().to_vec(),
            e.outputs().to_vec()
        )
        .is_err()
    );
    assert!(Expected::new(context, Vec::new(), Vec::new()).is_err());
    assert!(Expected::new(context, e.requests().to_vec(), e.outputs()[..1].to_vec()).is_err());
    assert!(
        Expected::new(
            context,
            vec![e.requests()[0].clone(); 2],
            vec![e.outputs()[0].clone(); 2]
        )
        .is_err()
    );
    assert!(
        Expected::new(
            context,
            vec![e.requests()[0].clone(); usize::from(u8::MAX)],
            vec![]
        )
        .is_err()
    );
    assert!(e.component_range(1).is_err());
    let first = initial_challenge(&e, 0);
    let mut outputs = e.outputs().to_vec();
    let mut values = outputs[1].coefficients().to_vec();
    values[DEGREE - 1] = (values[DEGREE - 1] + 1) % e.requests()[1].basis().modulus();
    outputs[1] = fixture::output(&e.requests()[1], &values).unwrap();
    let changed = Expected::new(context, e.requests().to_vec(), outputs).unwrap();
    let second = initial_challenge(&changed, 0);
    assert_ne!(first, second);
    assert_ne!(
        backend::digest(&e.output_wire()),
        backend::digest(&changed.output_wire())
    );
    assert_eq!(4 * backend::COMPONENT_SERIALIZED_BOUND, 10_596_672);
    assert_eq!(4 * backend::COMPONENT_DECODE_SLOTS_BOUND, 6_702_356);
    const {
        assert!(proof::HEADER + 4 * backend::COMPONENT_SERIALIZED_BOUND < MAX_FRAME_BYTES);
        assert!(4 * backend::COMPONENT_DECODE_SLOTS_BOUND < MAX_DECODE_ELEMENTS);
    }
    check_small_frontiers();
}
fn initial_challenge(e: &Expected, ordinal: usize) -> Challenge {
    use p3_challenger::CanSample;
    let targets = e.requests()[e.component_range(ordinal).unwrap()]
        .iter()
        .map(|r| BatchSpec {
            direction: r.direction(),
            basis: r.basis(),
        })
        .collect::<Vec<_>>();
    let shape = bfv_ntt_circuit::multistark::batch_shape(&targets).unwrap();
    let specs = shape
        .airs()
        .iter()
        .map(|a| bfv_multilinear_stark::AirSpec::new(a, a.height().ilog2() as usize))
        .collect::<Vec<_>>();
    let (config, _) = bfv_multilinear_stark::config_for(&specs, backend::domains()).unwrap();
    backend::challenger(&config, e, ordinal).unwrap().sample()
}
fn check_small_frontiers() {
    use std::collections::BTreeSet;
    // Independent exhaustive small binary trees, including repeated-query cases
    // represented by any smaller distinct subset. No SDK proof fixture is assumed.
    for depth in 1..=3 {
        let leaves = 1usize << depth;
        for q in 1..=leaves / 2 {
            for mask in 1usize..1usize << leaves {
                let mut nodes = (0..leaves)
                    .filter(|i| mask & (1 << i) != 0)
                    .collect::<BTreeSet<_>>();
                if nodes.len() > q {
                    continue;
                }
                let mut siblings = 0;
                for _ in 0..depth {
                    let parents = nodes.iter().map(|i| i / 2).collect::<BTreeSet<_>>();
                    siblings += 2 * parents.len() - nodes.len();
                    nodes = parents;
                }
                assert!(siblings <= backend::frontier_bound(q, depth).unwrap());
            }
        }
    }
    assert_eq!(backend::frontier_bound(386, 20).unwrap(), 4372);
    assert_eq!(backend::frontier_bound(386, 19).unwrap(), 3986);
}
fn genuine_batch(count: usize) {
    use fhe_math::{ntt::NttOperator, zq::Modulus};
    let context = fixture::context();
    let requests = fixture::requests(context, &fixture::specs(count)).unwrap();
    let generated = prove(context, &requests).unwrap();
    let e = Expected::new(context, requests, generated.outputs).unwrap();
    assert!(generated.frame.len() <= MAX_FRAME_BYTES);
    assert!(verify(&e, &generated.frame).unwrap().matches(&e));
    for (request, output) in e.requests().iter().zip(e.outputs()) {
        let modulus = Modulus::new(request.basis().modulus()).unwrap();
        let native = NttOperator::new(&modulus, DEGREE).unwrap();
        let mut v = request.input().to_vec();
        match request.direction() {
            Direction::Forward => native.forward(&mut v),
            Direction::Inverse => native.backward(&mut v),
        }
        assert_eq!(output.coefficients(), v);
    }
    assert!(
        generated.report.whole_security_bits >= 144.
            && generated.report.unassessed_components.is_empty()
    );
    assert_eq!(generated.report.component_count, count / 2);
    assert_eq!(generated.report.components.len(), count / 2);
    let minimum = generated
        .report
        .components
        .iter()
        .map(|r| r.whole_security_bits)
        .reduce(f64::min)
        .unwrap();
    assert_eq!(
        generated.report.whole_security_bits,
        minimum - (count / 2).ilog2() as f64
    );
    assert!(generated.report.serialized_bound <= MAX_FRAME_BYTES);
    assert!(generated.report.decode_slots_bound <= MAX_DECODE_ELEMENTS);
    if count == 2 {
        hostile(&e, &generated.frame);
    }
    if count == 8 {
        hostile_full_eight(&e, &generated.frame);
    }
}
#[test]
fn genuine_batch2_verifies_and_rebuilt_foreign_statements_do_not_replay() {
    genuine_batch(2);
}
#[test]
fn genuine_batch4_verifies_all_ordered_native_outputs() {
    genuine_batch(4);
}
#[test]
fn genuine_batch8_verifies_all_ordered_native_outputs() {
    genuine_batch(8);
}

fn hostile(e: &Expected, frame: &[u8]) {
    for at in [
        0, 8, 71, 72, 103, 104, 135, 136, 199, 200, 263, 264, 268, 272, 276, 287, 319,
    ] {
        let mut b = frame.to_vec();
        b[at] ^= 1;
        assert!(verify(e, &b).is_err(), "header {at}");
    }
    assert!(verify(e, &vec![0; MAX_FRAME_BYTES + 1]).is_err());
    for keep in [0, 7, 319, frame.len() - 1] {
        assert!(verify(e, &frame[..keep]).is_err());
    }
    let mut trailing = frame.to_vec();
    trailing.push(0);
    assert!(verify(e, &trailing).is_err());
    let proofs = proof::decode(e, frame).unwrap();
    assert_eq!(proofs.len(), 1);
    assert_eq!(
        postcard::to_allocvec(&[&proofs[0]]).unwrap(),
        frame[proof::HEADER..]
    );
    let raw = &proofs[0];
    let lookup = raw.lookup.as_ref().unwrap();
    let mut bomb = postcard::to_allocvec(&raw.commitment).unwrap();
    bomb.push(1);
    bomb.extend(postcard::to_allocvec(&lookup.root_denominator).unwrap());
    let mut length = usize::MAX;
    while length >= 128 {
        bomb.push((length as u8 & 127) | 128);
        length >>= 7;
    }
    bomb.push(length as u8);
    assert!(matches!(
        codec::decode::<backend::Proof>(&bomb),
        Err(Error::ResourceLimit)
    ));
    assert!(matches!(
        proof::decode(e, &reframe(frame, &bomb)),
        Err(Error::ResourceLimit)
    ));
    let payload = &frame[proof::HEADER..];
    let mut alias = payload.to_vec();
    let mut last = 0;
    while alias[last] & 128 != 0 {
        last += 1;
    }
    alias[last] |= 128;
    alias.insert(last + 1, 0);
    assert!(verify(e, &reframe(frame, &alias)).is_err());
    drop(proofs);
    for attack in 0..9 {
        let mut components = proof::decode(e, frame).unwrap();
        let p = &mut components[0];
        match attack {
            0 => {
                let _ = p.sumcheck.round_polys.pop().unwrap();
            }
            1 => {
                let _ = p.lookup.as_mut().unwrap().layers.pop().unwrap();
            }
            2 => {
                let _ = p.opening.evals.pop();
            }
            3 => {
                p.preprocessed_opening = None;
            }
            4 => {
                p.opening.whir.initial_sumcheck.pow_witnesses.push(Val::ONE);
            }
            5 => {
                p.sumcheck.round_polys[0][0] += Challenge::ONE;
            }
            6 => {
                p.opening
                    .whir
                    .final_sumcheck
                    .as_mut()
                    .unwrap()
                    .pow_witnesses
                    .push(Val::ONE);
            }
            7 => {
                p.opening.whir.initial_ood_answers.push(Challenge::ONE);
            }
            _ => {
                p.lookup.as_mut().unwrap().root_denominator += Challenge::ONE;
            }
        }
        let damaged = proof::encode(e, &components).unwrap();
        drop(components);
        assert!(verify(e, &damaged).is_err(), "proof {attack}");
    }
    for label in 0..2 {
        let mut context = e.context();
        if label == 0 {
            context.query[31] ^= 1;
        } else {
            context.setup[31] ^= 1;
        }
        let rebound = relabel(e, context);
        assert!(verify(&rebound, frame).is_err());
    }
    let mut swapped = e.requests().to_vec();
    swapped.swap(0, 1);
    assert!(Expected::new(e.context(), swapped, e.outputs().to_vec()).is_err());
    for target in 0..2 {
        let requests = e
            .requests()
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let direction = if target == 0 {
                    match r.direction() {
                        Direction::Forward => Direction::Inverse,
                        Direction::Inverse => Direction::Forward,
                    }
                } else {
                    r.direction()
                };
                let basis = if target == 1 {
                    Basis::new((r.basis().index() + 1) % 10).unwrap()
                } else {
                    r.basis()
                };
                let input = r
                    .input()
                    .iter()
                    .map(|v| *v % basis.modulus())
                    .collect::<Vec<_>>();
                decode_request(
                    &encode_request(
                        direction,
                        basis,
                        instance_binding(e.context(), i, direction, basis),
                        &input,
                    )
                    .unwrap(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let outputs = requests
            .iter()
            .zip(e.outputs())
            .map(|(r, o)| {
                fixture::output(
                    r,
                    &o.coefficients()
                        .iter()
                        .map(|v| *v % r.basis().modulus())
                        .collect::<Vec<_>>(),
                )
                .unwrap()
            })
            .collect();
        let different = Expected::new(e.context(), requests, outputs).unwrap();
        assert!(verify(&different, frame).is_err());
    }
    let changed = changed_last_output(e, 0);
    assert!(verify(&changed, frame).is_err());
}
fn relabel(e: &Expected, context: Context) -> Expected {
    let requests = e
        .requests()
        .iter()
        .enumerate()
        .map(|(i, r)| {
            decode_request(
                &encode_request(
                    r.direction(),
                    r.basis(),
                    instance_binding(context, i, r.direction(), r.basis()),
                    r.input(),
                )
                .unwrap(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let outputs = requests
        .iter()
        .zip(e.outputs())
        .map(|(r, o)| fixture::output(r, o.coefficients()).unwrap())
        .collect();
    Expected::new(context, requests, outputs).unwrap()
}
fn changed_last_output(e: &Expected, index: usize) -> Expected {
    let mut outputs = e.outputs().to_vec();
    let mut v = outputs[index].coefficients().to_vec();
    v[DEGREE - 1] = (v[DEGREE - 1] + 1) % e.requests()[index].basis().modulus();
    outputs[index] = fixture::output(&e.requests()[index], &v).unwrap();
    Expected::new(e.context(), e.requests().to_vec(), outputs).unwrap()
}
fn hostile_full_eight(e: &Expected, frame: &[u8]) {
    let components = proof::decode(e, frame).unwrap();
    assert_eq!(components.len(), 4);
    let fixed: [&backend::Proof; 4] = std::array::from_fn(|i| &components[i]);
    assert_eq!(
        postcard::to_allocvec(&fixed).unwrap(),
        frame[proof::HEADER..]
    );
    let payloads = components
        .iter()
        .map(|p| postcard::to_allocvec(p).unwrap())
        .collect::<Vec<_>>();
    // These payloads already passed genuine verification under their ORIGINAL
    // full outer statement and position. Repair every outer length/header.
    let mut swapped = payloads.clone();
    swapped.swap(0, 1);
    assert!(verify(e, &proof::encode_payloads(e, &swapped).unwrap()).is_err());
    let mut duplicated = payloads.clone();
    duplicated[3] = duplicated[0].clone();
    assert!(verify(e, &proof::encode_payloads(e, &duplicated).unwrap()).is_err());
    let mut omitted = proof::encode_payloads(e, &payloads).unwrap();
    omitted.truncate(omitted.len() - payloads[3].len());
    let shortened = omitted.len() - proof::HEADER;
    omitted[268..272].copy_from_slice(&(shortened as u32).to_le_bytes());
    omitted[284..288].fill(0);
    assert!(verify(e, &omitted).is_err());
    let mut extra = frame.to_vec();
    extra.extend(&payloads[0]);
    let extended = extra.len() - proof::HEADER;
    extra[268..272].copy_from_slice(&(extended as u32).to_le_bytes());
    assert!(verify(e, &extra).is_err());
    for label in 0..2 {
        let mut context = e.context();
        if label == 0 {
            context.query[31] ^= 1;
        } else {
            context.setup[31] ^= 1;
        }
        let rebound = relabel(e, context);
        let transplanted = proof::encode_payloads(&rebound, &payloads).unwrap();
        assert!(
            verify(&rebound, &transplanted).is_err(),
            "repaired full outer context {label}"
        );
    }
    let changed = changed_last_output(e, 7);
    // The first unit's request/output bytes and PP have NOT changed. It still
    // must fail under a different FULL outer output, before any partial grant.
    assert_eq!(e.requests()[0].encode(), changed.requests()[0].encode());
    assert_eq!(e.outputs()[0].encode(), changed.outputs()[0].encode());
    assert_ne!(initial_challenge(e, 0), initial_challenge(&changed, 0));
    assert_ne!(
        backend::component_profile(e, 0).unwrap(),
        backend::component_profile(e, 1).unwrap()
    );
    let transplanted = proof::encode_payloads(&changed, &payloads).unwrap();
    assert!(verify(&changed, &transplanted).is_err());
    // Last unit absent despite a genuine complete two-unit prefix cannot return
    // CheckedBatch. The header itself has independently fixed cardinality.
    assert!(proof::encode_payloads(e, &payloads[..3]).is_err());
    shared_nested_budget(e, &components[0]);
}
fn clear_query(
    q: &mut p3_whir::QueryOpenings<Val, Challenge, p3_merkle_tree::PrunedMerklePaths<u64, 8>>,
) {
    match q {
        p3_whir::QueryOpenings::Base(o) => {
            o.rows.clear();
            o.proof.sibling_hashes.clear();
        }
        p3_whir::QueryOpenings::Extension(o) => {
            o.rows.clear();
            o.proof.sibling_hashes.clear();
        }
    }
}
fn shared_nested_budget(e: &Expected, genuine: &backend::Proof) {
    let mut p: backend::Proof = codec::decode(&postcard::to_allocvec(genuine).unwrap()).unwrap();
    p.preprocessed_opening = None;
    for round in &mut p.opening.whir.rounds {
        clear_query(&mut round.openings);
    }
    clear_query(&mut p.opening.whir.final_openings);
    p.opening.evals = (0..3)
        .map(|_| {
            p3_sumcheck::OpeningBatch::new(vec![Challenge::ZERO; MAX_SEQUENCE_ELEMENTS], Vec::new())
        })
        .collect();
    let payload = postcard::to_allocvec(&p).unwrap();
    drop(p);
    assert!(payload.len() < backend::COMPONENT_SERIALIZED_BOUND);
    // Every length and each individual proof fits. Four malformed proofs must
    // share ONE total budget rather than receive four fresh8Mi allowances.
    let _ = codec::decode::<backend::Proof>(&payload).unwrap();
    let frame = proof::encode_payloads(e, &vec![payload; 4]).unwrap();
    assert!(frame.len() < MAX_FRAME_BYTES);
    assert!(matches!(
        proof::decode(e, &frame),
        Err(Error::ResourceLimit)
    ));
}
