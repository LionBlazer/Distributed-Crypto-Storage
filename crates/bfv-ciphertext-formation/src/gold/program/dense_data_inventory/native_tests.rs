//! Genuine native tests only; one explicitly non-secret SDK fixture, no SQL grant.
use super::*;
use bfv_hiding_stark::{Challenge, Challenger, Pcs};
use p3_air::{BaseAir, check_all_constraints, symbolic::AirLayout};
use p3_batch_stark::{
    BatchVerificationError,
    symbolic::{get_log_num_quotient_chunks_for_domain, get_symbolic_constraints},
};
use p3_commit::{PolynomialSpace, UnivariateStarkPcs};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_lookup::{LogUpGadget, LookupError, Lookups};
use p3_uni_stark::VerificationError;

fn symbolic_tuple<A>(air: &A) -> Vec<u8>
where
    A: BaseAir<Val> + p3_air::Air<p3_lookup::InteractionSymbolicBuilder<Val, Challenge>>,
{
    let layout = AirLayout::from_air(air);
    let domain = TwoAdicMultiplicativeCoset::<Val>::new(Val::ONE, LOG_H).unwrap();
    let zk = usize::from(<Pcs as UnivariateStarkPcs<Challenge, Challenger>>::ZK);
    let gadget = LogUpGadget::new();
    let original = Lookups::<Val>::from_air::<Challenge, _>(air);
    let log = get_log_num_quotient_chunks_for_domain::<Val, Challenge, _, _>(
        air, layout, domain, &original, zk, &gadget,
    );
    let packed = original
        .clone()
        .pack_same_bus_with_degree((1 << log) + 1 - zk, |l| {
            gadget.constraint_degree_with_transition(l, domain.transition_degree_multiple())
        });
    let (base, extension) =
        get_symbolic_constraints::<Val, Challenge, _, _>(air, layout, &packed, &gadget);
    assert_eq!(
        [base.len(), extension.len(), original.len(), packed.len()],
        [1248, 84, 243, 81]
    );
    postcard::to_allocvec(&(base, extension, original, packed)).unwrap()
}
#[test]
fn full_pp_wrapper_preserves_complete_native_order_and_every_original_public_pp_cell() {
    let e = expected().unwrap();
    let metadata = air::MetadataAir::new(&e).unwrap();
    let full = native::FullAir(metadata.clone());
    assert_eq!(symbolic_tuple(&metadata), symbolic_tuple(&full));
    let bytes = symbolic_tuple(&full);
    assert_eq!(bytes.len(), 571450);
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(b"/ordered-native-postcard-p3-0.8/v1");
    hash.update(&bytes);
    assert_eq!(
        hex(hash.finalize()),
        "6fe109f433d7f0c66dc51ec403cd103bdbf0056a72634af2cc0888a8ba8b3814"
    );
    let pp = full.preprocessed_trace().unwrap();
    assert_eq!(pp.values.len(), H * PP);
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(b"/fullPP/LE64");
    hash_word(&mut hash, H);
    hash_word(&mut hash, PP);
    for (row, actual) in pp.values.as_chunks::<PP>().0.iter().enumerate() {
        assert_eq!(*actual, metadata.plan.row(row).unwrap());
        for x in actual {
            hash.update(x.as_canonical_u64().to_le_bytes())
        }
    }
    assert_eq!(
        hex(hash.finalize()),
        "6f4bdb87a034d70a662a9948098c5c6aefb1d69f67b0c8aedee50f3e1e465170"
    );
}
fn raw_frame(e: &data::Expected, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"DCSGDD01");
    out.extend_from_slice(&native_wire::profile());
    out.extend_from_slice(&e.binding());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&[0; 20]);
    out.extend_from_slice(payload);
    out
}
#[test]
fn one_real_data_fixture_proves_cold_verifies_and_false_local_wire_fails_real_native_verification()
{
    let (e, honest_prepared, false_prepared) = data::dense_native_fixture();
    let start = native::phase_start("honest_complete_producer");
    let frame = native::produce(&e, honest_prepared).unwrap();
    native::phase_end("honest_complete_producer", start);
    let start = native::phase_start("honest_complete_cold_receive");
    native::receive(&e, &frame).unwrap();
    native::phase_end("honest_complete_cold_receive", start);
    eprintln!(
        "dense_data_native frame_bytes={} honest_native=true cold_receiver_independent=true accepted_Data_or_Query=false",
        frame.len()
    );
    // Wrong outer scope rejects BEFORE PP. Repairing only that public header must
    // still reach actual native Verification under the independent foreign values.
    let foreign =
        data::Expected::checked(e.request().clone(), [0x55; 64], e.contexts(), e.roots()).unwrap();
    assert!(matches!(
        native::receive(&foreign, &frame),
        Err(Error::Binding)
    ));
    let mut repaired = frame.clone();
    repaired[40..104].copy_from_slice(&foreign.binding());
    assert!(matches!(
        native::receive(&foreign, &repaired),
        Err(Error::Verification)
    ));
    let (_, report) = native::prescreen(&e).unwrap();
    let payload = native_wire::payload(&e, &frame).unwrap();
    let mut proof = native_wire::decode(payload, &report).unwrap();
    proof.opened_values.instances[0]
        .base_opened_values
        .trace_local[0] += Challenge::ONE;
    let ood = native_wire::encode(&e, &proof, &report).unwrap();
    assert!(matches!(
        native::receive(&e, &ood),
        Err(Error::Verification)
    ));
    drop(proof);
    // Canonical EOF/sequence/frontier/resource cases reuse the ONE honest proof.
    let mut eof = payload.to_vec();
    eof.push(0);
    assert!(matches!(
        native_wire::decode(&eof, &report),
        Err(Error::Encoding)
    ));
    assert!(matches!(
        native_wire::payload(&e, &vec![0; native_wire::MAX_FRAME_BYTES + 1]),
        Err(Error::Resource)
    ));
    let mut proof = native_wire::decode(payload, &report).unwrap();
    proof.opened_values.instances[0]
        .base_opened_values
        .trace_local
        .resize(4097, Challenge::ZERO);
    let encoded = postcard::to_allocvec(&proof).unwrap();
    assert!(encoded.len() + native_wire::HEADER_BYTES < native_wire::MAX_FRAME_BYTES);
    assert!(matches!(
        native_wire::decode(&encoded, &report),
        Err(Error::Resource)
    ));
    let mut proof = native_wire::decode(payload, &report).unwrap();
    let siblings = &mut proof.opening_proof.1.input_openings[0]
        .opening_proof
        .1
        .sibling_hashes;
    let sibling = siblings[0];
    siblings.resize(1600, sibling);
    assert!(matches!(
        native_wire::check(&proof, &report),
        Err(Error::Shape)
    ));
    // Same native Gold Deserialize handles all coordinates in the bounded proof.
    let limits = bounded_postcard::Limits {
        max_sequence_elements: 8,
        max_total_elements: 256,
    };
    assert!(matches!(
        bounded_postcard::take_from_bytes::<Val>(&Val::ORDER_U64.to_le_bytes(), limits),
        Err(bounded_postcard::Error::Encoding)
    ));
    let valid = postcard::to_allocvec(&Challenge::ZERO).unwrap();
    for coordinate in 0..5 {
        let mut bytes = valid.clone();
        bytes[8 * coordinate..8 * coordinate + 8].copy_from_slice(&Val::ORDER_U64.to_le_bytes());
        assert!(matches!(
            bounded_postcard::take_from_bytes::<Challenge>(&bytes, limits),
            Err(bounded_postcard::Error::Encoding)
        ))
    }
    let mut bad_magic = frame.clone();
    bad_magic[..8].copy_from_slice(b"DCSGFD01");
    assert!(matches!(
        native::receive(&e, &bad_magic),
        Err(Error::Encoding)
    ));
    assert_eq!(raw_frame(&e, payload), frame);
    drop(proof);
    // Genuine malicious MAIN: preserve BOTH first local equations while leaving
    // every other row/final AS/range/W/Cs input unchanged.
    let (air, report) = native::prescreen(&e).unwrap();
    let public = native_setup::public_data(&air, &e, &report).unwrap();
    let mut trace = false_prepared.inner.dense_trace(&e).unwrap();
    assert!(check_all_constraints(&air, &trace.0, e.values(), Some(1)).is_ok());
    for cell in [
        (GRAPH_ROWS - 1) * W + 48 * 4,
        RANGE_ONLY_FIRST * W,
        BITS + RANGE_BITS,
        509,
        RANGE_VALUES + 18,
        CW_FIRST * W + CHECKPOINT,
    ] {
        let saved = trace.0.values[cell];
        trace.0.values[cell] = Val::ONE;
        assert!(
            !check_all_constraints(&air, &trace.0, e.values(), Some(1)).is_ok(),
            "unused/inactive/first-checkpoint cells must be constrained"
        );
        trace.0.values[cell] = saved;
    }
    let row = air.0.plan.row(0).unwrap();
    assert_eq!(
        (row[COEFFICIENTS], row[COEFFICIENTS + 2]),
        (Val::ONE, Val::ONE)
    );
    trace.0.values[0] += Val::ONE;
    trace.0.values[2] += Val::ONE;
    trace.0.values[3] += Val::ONE;
    assert_eq!(
        trace.0.values[2],
        row[COEFFICIENTS] * trace.0.values[0] + row[COEFFICIENTS + 1] * trace.0.values[1]
    );
    assert_eq!(
        trace.0.values[3],
        row[COEFFICIENTS + 2] * trace.0.values[0] + row[COEFFICIENTS + 3] * trace.0.values[1]
    );
    assert!(
        check_all_constraints(&air, &trace.0, e.values(), Some(1)).is_ok(),
        "local equations cannot replace global wire verification"
    );
    let attempt = native::prove_trace(&e, &air, &trace, &public);
    drop(trace);
    if cfg!(debug_assertions) {
        assert!(matches!(attempt, Err(Error::Proving)));
        return;
    }
    let mut bad = attempt.expect("release must genuinely prove the unbalanced wire");
    assert_ne!(bad.lookup_terminals[0].as_ref().unwrap().0, Challenge::ZERO);
    let error = p3_batch_stark::verify_batch(
        &native::config().unwrap(),
        core::slice::from_ref(&air),
        &bad,
        &[e.values().to_vec()],
        &public.common,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        BatchVerificationError::Lookup(LookupError::TerminalSumNonZero)
    ));
    bad.lookup_terminals[0].as_mut().unwrap().0 = Challenge::ZERO;
    native_wire::check(&bad, &report).unwrap();
    let error = p3_batch_stark::verify_batch(
        &native::config().unwrap(),
        core::slice::from_ref(&air),
        &bad,
        &[e.values().to_vec()],
        &public.common,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        BatchVerificationError::Verification(
            VerificationError::InvalidOpeningArgument(_)
                | VerificationError::OodEvaluationMismatch { .. }
        )
    ));
}
