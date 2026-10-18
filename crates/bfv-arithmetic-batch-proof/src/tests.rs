//! Observable full-statement contracts; cryptographic attacks live beside these tests.
use super::*;
use bfv_scale_circuit as scale;
use bfv_tensor_circuit as tensor;
use std::sync::OnceLock;
mod attacks;
mod sdk;
struct Genuine {
    expected: Expected,
    frame: Vec<u8>,
    report: backend::SecurityReport,
}
fn genuine() -> &'static Genuine {
    static CELL: OnceLock<Genuine> = OnceLock::new();
    CELL.get_or_init(|| {
        let context = fixture::context();
        let requests = fixture::requests(context).unwrap();
        let generated = prove(context, &requests).unwrap();
        let expected = Expected::new(context, requests, generated.outputs).unwrap();
        assert!(
            verify(&expected, &generated.frame)
                .unwrap()
                .matches(&expected)
        );
        Genuine {
            expected,
            frame: generated.frame,
            report: generated.report,
        }
    })
}
fn public_statement() -> Expected {
    let context = fixture::context();
    let requests = fixture::requests(context).unwrap();
    let (outputs, aux) = proof::evaluate(&requests).unwrap();
    drop(aux);
    Expected::new(context, requests, outputs).unwrap()
}
fn component_payloads(expected: &Expected, frame: &[u8]) -> Vec<Vec<u8>> {
    proof::decode(expected, frame)
        .unwrap()
        .iter()
        .map(|p| postcard::to_allocvec(p).unwrap())
        .collect()
}
fn changed_output(expected: &Expected, index: usize) -> Expected {
    let mut outputs = expected.outputs().to_vec();
    let mut b = outputs[index].encode();
    let modulus = match &expected.requests()[index] {
        RelationRequest::Scale(r) => *r.role().output_moduli().last().unwrap(),
        RelationRequest::Tensor(r) => r.basis().modulus(),
    };
    let at = b.len() - 8;
    let old = u64::from_le_bytes(b[at..].try_into().unwrap());
    b[at..].copy_from_slice(&((old + 1) % modulus).to_le_bytes());
    outputs[index] = match &outputs[index] {
        RelationOutput::Scale(_) => RelationOutput::Scale(scale::decode_output(&b).unwrap()),
        RelationOutput::Tensor(_) => RelationOutput::Tensor(tensor::decode_output(&b).unwrap()),
    };
    Expected::new(expected.context(), expected.requests().to_vec(), outputs).unwrap()
}
fn changed_request(request: &RelationRequest) -> RelationRequest {
    match request {
        RelationRequest::Scale(r) => {
            let mut values = r.input().to_vec();
            let at = values.len() - 1;
            let modulus = *r.role().input_moduli().last().unwrap();
            values[at] = (values[at] + 1) % modulus;
            RelationRequest::Scale(
                scale::decode_request(
                    &scale::encode_request(r.role(), r.binding(), &values).unwrap(),
                )
                .unwrap(),
            )
        }
        RelationRequest::Tensor(r) => {
            let mut values = r.input().to_vec();
            let at = values.len() - 1;
            values[at] = (values[at] + 1) % r.basis().modulus();
            RelationRequest::Tensor(
                tensor::decode_request(
                    &tensor::encode_request(r.basis(), r.binding(), &values).unwrap(),
                )
                .unwrap(),
            )
        }
    }
}

#[test]
fn fixed_full_envelopes_preserve_all_seventeen_roles_and_reject_omission_order_and_aliases() {
    let expected = public_statement();
    let input = expected.request_wire();
    let output = expected.output_wire();
    let decoded = Expected::from_wires(&input, &output).unwrap();
    assert_eq!(decoded.request_wire(), input);
    assert_eq!(decoded.output_wire(), output);
    for index in 0..RELATIONS {
        assert_eq!(
            decoded.requests()[index].binding(),
            instance_binding(expected.context(), index).unwrap()
        );
    }
    let mut missing = expected.requests().to_vec();
    missing.pop();
    assert!(Expected::new(expected.context(), missing, expected.outputs().to_vec()).is_err());
    for (a, b) in [(0, 1), (4, 13), (14, 16), (0, 4)] {
        let mut wrong = expected.requests().to_vec();
        wrong.swap(a, b);
        assert!(Expected::new(expected.context(), wrong, expected.outputs().to_vec()).is_err());
    }
    let mut context = expected.context();
    context.setup[31] ^= 1;
    assert!(
        Expected::new(
            context,
            expected.requests().to_vec(),
            expected.outputs().to_vec()
        )
        .is_err()
    );
    context.query = [0; 32];
    assert!(
        fixture::requests(context)
            .and_then(|r| Expected::new(context, r, expected.outputs().to_vec()))
            .is_err()
    );
    for bytes in [&input[..input.len() - 1], &input[..143]] {
        assert!(Expected::from_wires(bytes, &output).is_err());
    }
    let mut extra = input.clone();
    extra.push(0);
    assert!(Expected::from_wires(&extra, &output).is_err());
    let mut alias = input;
    let at = alias.len() - 8;
    let p = *scale::Role::Scale10To5.input_moduli().last().unwrap();
    alias[at..].copy_from_slice(&p.to_le_bytes());
    assert!(Expected::from_wires(&alias, &output).is_err());
}
#[test]
fn genuine_fixed_union_has_one_provider_per_range_and_actual_whole_security() {
    let g = genuine();
    let report = &g.report;
    assert_eq!(
        (
            report.relations,
            report.component_count,
            report.coefficients_per_relation
        ),
        (17, 3, 8192)
    );
    assert!(report.whole_security_bits.is_finite() && report.whole_security_bits >= 144.);
    assert!(report.unassessed_components.is_empty());
    assert_eq!(report.union_loss_bits, 2);
    let minimum = report
        .components
        .iter()
        .map(|c| c.whole_security_bits)
        .fold(f64::INFINITY, f64::min);
    assert_eq!(report.whole_security_bits, minimum - 2.);
    assert_eq!(
        report
            .components
            .iter()
            .map(|c| c.lookup_count_weight)
            .sum::<usize>(),
        8192 * (7 * 160 + 10 * 54)
    );
    for (ordinal, c) in report.components.iter().enumerate() {
        let range = statement::component_range(ordinal).unwrap();
        let supports = machine::ranges(ordinal).unwrap();
        assert_eq!(
            (c.first_relation, c.end_relation, c.relations, c.air_count),
            (
                range.start,
                range.end,
                range.len(),
                range.len() + supports.len()
            )
        );
        assert!(c.whole_security_bits.is_finite() && c.whole_security_bits >= 144.);
        assert!(c.unassessed_components.is_empty());
        assert!(!c.terms.is_empty());
        assert_eq!(c.outer_degree, if ordinal == 1 { 3 } else { 2 });
        assert_eq!(
            c.tables[range.len()..]
                .iter()
                .map(|t| t.height)
                .collect::<Vec<_>>(),
            supports.iter().map(|r| r.height()).collect::<Vec<_>>()
        );
        assert!(
            c.tables[range.len()..]
                .iter()
                .all(|t| t.main_width == 2 && t.preprocessed_width == 1 && t.count_weight == 0)
        );
        let wanted = match ordinal {
            0 => (5_473_312, 1_425_936, 23, 21, 1 << 23),
            1 => (4_555_776, 2_359_808, 23, 22, 1 << 23),
            _ => (4_178_976, 1_597_968, 22, 21, 1 << 22),
        };
        assert_eq!(
            (
                c.main_cells,
                c.preprocessed_cells,
                c.main_pcs.variables,
                c.preprocessed_pcs.variables,
                c.lookup_padded
            ),
            wanted
        );
    }
    assert!(g.frame.len() <= report.serialized_bound && report.serialized_bound <= MAX_FRAME_BYTES);
    assert!(report.decode_slots_bound <= MAX_DECODE_ELEMENTS);
    let input = g.expected.request_wire();
    let output = g.expected.output_wire();
    let fresh = Expected::from_wires(&input, &output).unwrap();
    assert!(verify(&fresh, &g.frame).unwrap().matches(&fresh));
}
#[test]
fn complete_last_words_bind_all_relations_and_repaired_frame_cannot_replace_a_false_output() {
    let g = genuine();
    for index in 0..RELATIONS {
        let wrong = changed_output(&g.expected, index);
        assert_eq!(
            verify(&wrong, &g.frame).unwrap_err(),
            Error::Frame,
            "relation{index}"
        );
    }
    let raw = proof::decode(&g.expected, &g.frame).unwrap();
    let wrong = changed_output(&g.expected, 16);
    let repaired = proof::encode(&wrong, &raw).unwrap();
    assert!(verify(&wrong, &repaired).is_err());
    let mut requests = g.expected.requests().to_vec();
    requests[13] = changed_request(&requests[13]);
    let (outputs, aux) = proof::evaluate(&requests).unwrap();
    drop(aux);
    let foreign = Expected::new(g.expected.context(), requests, outputs).unwrap();
    let repaired = proof::encode(&foreign, &raw).unwrap();
    assert!(verify(&foreign, &repaired).is_err());
    assert!(!verify(&g.expected, &g.frame).unwrap().matches(&foreign));
}
#[test]
fn canonical_header_caps_truncation_nested_budget_and_actual_sdk_shapes_reject() {
    let g = genuine();
    for offset in [
        0, 8, 71, 72, 103, 104, 135, 136, 199, 200, 263, 264, 295, 296, 299, 300, 303, 304, 307,
        308, 319,
    ] {
        let mut b = g.frame.clone();
        b[offset] ^= 1;
        assert_eq!(
            verify(&g.expected, &b).unwrap_err(),
            Error::Frame,
            "byte{offset}"
        );
    }
    assert_eq!(
        verify(&g.expected, &vec![0; MAX_FRAME_BYTES + 1]).unwrap_err(),
        Error::ResourceLimit
    );
    assert_eq!(
        verify(&g.expected, &g.frame[..319]).unwrap_err(),
        Error::ResourceLimit
    );
    let mut b = g.frame.clone();
    b.push(0);
    assert!(verify(&g.expected, &b).is_err());
    for offset in [268, 271, 272, 275, 276, 279, 280, 283, 284, 287, 288, 293] {
        let mut b = g.frame.clone();
        b[offset] ^= 1;
        assert!(
            verify(&g.expected, &b).is_err(),
            "component header byte{offset}"
        );
    }
    for length in [0u32, u32::MAX] {
        let mut b = g.frame.clone();
        b[276..280].copy_from_slice(&length.to_le_bytes());
        assert_eq!(verify(&g.expected, &b).unwrap_err(), Error::ResourceLimit);
    }
    for case in 0..5 {
        let mut raw = proof::decode(&g.expected, &g.frame).unwrap();
        let first = &mut raw[0];
        match case {
            0 => {
                first.sumcheck.round_polys.pop();
            }
            1 => first.preprocessed_opening = None,
            2 => {
                first.opening.evals.pop();
            }
            3 => {
                first.lookup.as_mut().unwrap().layers.pop();
            }
            _ => first.opening.whir.final_poly = None,
        };
        let b = proof::encode(&g.expected, &raw).unwrap();
        assert_eq!(verify(&g.expected, &b).unwrap_err(), Error::Encoding);
    }
    let mut n = MAX_SEQUENCE_ELEMENTS + 1;
    let mut bomb = Vec::new();
    while n >= 128 {
        bomb.push((n as u8 & 127) | 128);
        n >>= 7;
    }
    bomb.push(n as u8);
    assert_eq!(
        codec::decode::<Vec<u8>>(&bomb).unwrap_err(),
        Error::ResourceLimit
    );
    let mut trailing = postcard::to_allocvec(&vec![1u64, 2]).unwrap();
    trailing.push(0);
    assert_eq!(
        codec::decode::<Vec<u64>>(&trailing).unwrap_err(),
        Error::TrailingBytes
    );
}

#[test]
fn three_genuine_phases_are_individually_valid_but_only_the_complete_ordered_frame_is_accepted() {
    let g = genuine();
    let proofs = proof::decode(&g.expected, &g.frame).unwrap();
    // Each phase really verifies with its own trusted VK and full outer transcript.
    for (ordinal, raw) in proofs.into_iter().enumerate() {
        let report = proof::verify_component(&g.expected, ordinal, raw).unwrap();
        assert_eq!(report.ordinal, ordinal);
    }
    let payloads = component_payloads(&g.expected, &g.frame);
    for (a, b) in [(0, 1), (0, 2), (1, 2)] {
        let mut swapped = payloads.clone();
        swapped.swap(a, b);
        let repaired = proof::encode_payloads(&g.expected, &swapped).unwrap();
        assert!(
            verify(&g.expected, &repaired).is_err(),
            "swapped phases{a}/{b}"
        );
    }
    for target in 0..COMPONENTS {
        for source in 0..COMPONENTS {
            if source == target {
                continue;
            }
            let mut repeated = payloads.clone();
            repeated[target] = payloads[source].clone();
            let repaired = proof::encode_payloads(&g.expected, &repeated).unwrap();
            assert!(
                verify(&g.expected, &repaired).is_err(),
                "duplicated phase{source} at{target}"
            );
        }
    }
    assert_eq!(
        proof::encode_payloads(&g.expected, &payloads[..2]).unwrap_err(),
        Error::Frame
    );
    let mut extra = payloads.clone();
    extra.push(payloads[0].clone());
    assert_eq!(
        proof::encode_payloads(&g.expected, &extra).unwrap_err(),
        Error::Frame
    );
    // Also construct repaired length/header claims with missing/extra SDK values:
    // the fixed array and exact canonical boundaries remain mandatory.
    let mut omitted = payloads.clone();
    omitted[1] = vec![0];
    let repaired = proof::encode_payloads(&g.expected, &omitted).unwrap();
    assert!(proof::decode(&g.expected, &repaired).is_err());
    let mut extra_value = payloads.clone();
    extra_value[2].extend_from_slice(&payloads[0]);
    let repaired = proof::encode_payloads(&g.expected, &extra_value);
    match repaired {
        Ok(frame) => assert!(proof::decode(&g.expected, &frame).is_err()),
        Err(error) => assert_eq!(error, Error::ResourceLimit),
    }
}

#[test]
fn every_phase_transcript_binds_the_full_query_setup_and_last_outer_output() {
    let g = genuine();
    let payloads = component_payloads(&g.expected, &g.frame);
    for change_setup in [false, true] {
        let mut context = g.expected.context();
        if change_setup {
            context.setup[31] ^= 1;
        } else {
            context.query[31] ^= 1;
        }
        let requests = fixture::requests(context).unwrap();
        let (outputs, aux) = proof::evaluate(&requests).unwrap();
        drop(aux);
        let changed = Expected::new(context, requests, outputs).unwrap();
        let repaired = proof::encode_payloads(&changed, &payloads).unwrap();
        assert!(
            verify(&changed, &repaired).is_err(),
            "changed setup={change_setup}"
        );
    }
    let changed = changed_output(&g.expected, 16);
    assert_eq!(
        g.expected.requests()[0].encode(),
        changed.requests()[0].encode()
    );
    assert_eq!(
        g.expected.outputs()[0].encode(),
        changed.outputs()[0].encode()
    );
    let first: backend::Proof = codec::decode(&payloads[0]).unwrap();
    // A valid Extend proof cannot be transplanted even when only a Down output
    // outside that phase changes and the entire public header is repaired.
    assert!(proof::verify_component(&changed, 0, first).is_err());
    let repaired = proof::encode_payloads(&changed, &payloads).unwrap();
    assert!(verify(&changed, &repaired).is_err());
    assert_ne!(
        backend::component_profile(&g.expected, 0).unwrap(),
        backend::component_profile(&g.expected, 1).unwrap()
    );
}

fn clear_query(
    q: &mut p3_whir::QueryOpenings<
        backend::Val,
        backend::Challenge,
        p3_merkle_tree::PrunedMerklePaths<u64, 8>,
    >,
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
#[test]
fn three_individually_bounded_nested_proofs_cannot_reset_the_one_aggregate_decode_budget() {
    use p3_field::PrimeCharacteristicRing;
    let g = genuine();
    let payloads = component_payloads(&g.expected, &g.frame);
    // Obtain one owned proof through the exact codec; Config is deliberately not Clone.
    let mut raw: backend::Proof = codec::decode(&payloads[0]).unwrap();
    raw.preprocessed_opening = None;
    for round in &mut raw.opening.whir.rounds {
        clear_query(&mut round.openings);
    }
    clear_query(&mut raw.opening.whir.final_openings);
    raw.opening.evals = [16384, 16384, 16384, 13348]
        .into_iter()
        .map(|n| p3_sumcheck::OpeningBatch::new(vec![backend::Challenge::ZERO; n], Vec::new()))
        .collect();
    let payload = postcard::to_allocvec(&raw).unwrap();
    drop(raw);
    assert!(payload.len() < backend::COMPONENT_SERIALIZED_BOUND);
    let _ = codec::decode::<backend::Proof>(&payload).unwrap();
    // 62,500 EF5 values per proof charge at least46 slots each; three proofs
    // exceed8Mi even though every individual sequence and proof fits.
    let frame = proof::encode_payloads(&g.expected, &vec![payload; COMPONENTS]).unwrap();
    assert!(frame.len() < MAX_FRAME_BYTES);
    assert!(matches!(
        proof::decode(&g.expected, &frame),
        Err(Error::ResourceLimit)
    ));
}
