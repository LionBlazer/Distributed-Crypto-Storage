//! Complete owning math checks. No SQL/Word/Source or fresh-head capability.
use super::*;
use bfv_hiding_stark::Challenge;
use p3_air::{check_all_constraints, symbolic::AirLayout};
use p3_batch_stark::symbolic::{get_log_num_quotient_chunks_for_domain, get_symbolic_constraints};
use p3_commit::PolynomialSpace;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_lookup::{LogUpGadget, Lookups};
pub(super) fn metadata() -> Expected {
    let request = data::Request::checked(
        [0xa9; 32],
        super::super::super::tests::pair_snapshot_ciphertext(0),
    )
    .unwrap();
    let e = data::Expected::checked(
        request,
        [0xab; 64],
        [[Val::from_u32(8); 8], [Val::from_u32(9); 8]],
        [[Val::from_u32(10); 4], [Val::from_u32(11); 4]],
    )
    .unwrap();
    Expected::checked(&e, [Val::from_u32(12); 4], [Val::from_u32(13); 13]).unwrap()
}
#[test]
fn complete_inventory_symbolics_and_every_public_field_are_captured_before_private_proving() {
    let e = metadata();
    let air = air::MetadataAir::new(&e).unwrap();
    let inventory = air.plan.inventory().unwrap();
    for row_index in 0..GRAPH_ROWS {
        let row = air.plan.row(row_index).unwrap();
        for slot in 0..SLOTS {
            if let Some(gate) = air.plan.gate(row_index * SLOTS + slot).unwrap() {
                for (port, node) in gate.inputs.iter().chain(&gate.outputs).enumerate() {
                    assert_eq!(
                        row[4 * slot + port],
                        node.map_or(Val::ZERO, |n| Val::from_u64(n.id()))
                    );
                }
                for (offset, &coefficient) in gate.linear.iter().flatten().enumerate() {
                    assert_eq!(
                        row[COEFFICIENTS + 4 * slot + offset],
                        Val::from_u64(coefficient)
                    );
                }
            }
        }
    }
    assert_eq!(
        (
            inventory.gates,
            inventory.hash_rows,
            inventory.coefficients,
            inventory.producers
        ),
        (81920, 592, 4096, 40 * 4096 + 512 + 8)
    );
    assert_eq!(
        Val::from_u64(16389) * Val::from_u64(SCALE_INVERSE),
        Val::ONE
    );
    let report = assessment::assess(&air).unwrap();
    report.require_resources().unwrap();
    native_wire::require_assessment(&report).unwrap();
    assert_eq!(
        (
            report.packed_lookup_count(),
            report.aux_width(),
            report.chunks()
        ),
        (83, 420, 8)
    );
    let domain = TwoAdicMultiplicativeCoset::<Val>::new(Val::ONE, LOG_H).unwrap();
    let layout = AirLayout::from_air(&air);
    let gadget = LogUpGadget::new();
    let original = Lookups::<Val>::from_air::<Challenge, _>(&air);
    let log = get_log_num_quotient_chunks_for_domain::<Val, Challenge, _, _>(
        &air, layout, domain, &original, 1, &gadget,
    );
    let packed = original.clone().pack_same_bus_with_degree(1 << log, |l| {
        gadget.constraint_degree_with_transition(l, domain.transition_degree_multiple())
    });
    let (base, ext) =
        get_symbolic_constraints::<Val, Challenge, _, _>(&air, layout, &packed, &gadget);
    let bytes = postcard::to_allocvec(&(base, ext, original, packed)).unwrap();
    let mut pp = Sha256::new();
    pp.update(DOMAIN);
    let mut fixed = 0;
    let mut masks = 0;
    for i in 0..H {
        let row = air.plan.row(i).unwrap();
        fixed += row[FIXED..FIXED + 8]
            .iter()
            .filter(|&&v| v == Val::ONE)
            .count();
        masks += row[STMT_LOOKUP..STMT_LOOKUP + 8]
            .iter()
            .filter(|&&v| v == Val::ONE)
            .count();
        for word in row {
            pp.update(word.as_canonical_u64().to_le_bytes());
        }
    }
    assert_eq!((fixed, masks), (14, 8));
    let pp = pp.finalize();
    eprintln!(
        "fused_query_metadata ordered={:x} symbolic_bytes={} full_pp={:x} profile={:x} frame_profile={:x} PP_fields={} workspace={} MAIN=false proof=false SQL=false",
        Sha256::digest(&bytes),
        bytes.len(),
        pp,
        Sha256::digest(profile()),
        Sha256::digest(native_wire::profile()),
        H * PP,
        report.workspace_bytes()
    );
    // Literal v3 capture r477 follows every-cell old-PP expansion checks, before native proving.
    assert_eq!(bytes.len(), 564835);
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        "b7461b6ec1579cca0c3e42d2f64cfcf0446e1854be4ee309c6237ef609629149"
    );
    assert_eq!(
        format!("{pp:x}"),
        "8ced166061c407c6b5c0ee9d53d94085604087ee626c772592117482ad9a53d3"
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(profile())),
        "eee4eafdabf0b273da352046d993bc3fc16f426a0a935309bd1bb505e4470f81"
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(native_wire::profile())),
        "c456e707462ac315c45d4849f97034c4ac6538b19765329e9a014ddd85cfb038"
    );
}
#[test]
fn real_fused_proof_cold_verifies_and_damaged_native_argument_fails() {
    let (e, p) = data::fused_query_native_fixture(false);
    let begin = std::time::Instant::now();
    let frame = crate::gold::query::prove(&e, p).unwrap().into_bytes();
    let produced = begin.elapsed();
    let begin = std::time::Instant::now();
    let verified = crate::gold::query::verify(&e, &frame).unwrap();
    assert_eq!(verified.expected().binding(), e.binding());
    let received = begin.elapsed();
    eprintln!(
        "fused_query_native produce_ms={:.3} cold_receive_ms={:.3} sum_ms={:.3} frame_bytes={} rayon_threads={} SQL=false Word=false fresh_head=false",
        produced.as_secs_f64() * 1000.,
        received.as_secs_f64() * 1000.,
        (produced + received).as_secs_f64() * 1000.,
        frame.len(),
        p3_maybe_rayon::prelude::current_num_threads()
    );
    let begin = std::time::Instant::now();
    let receiver = crate::gold::query::Verifier::new(&e).unwrap();
    let setup = begin.elapsed();
    assert_eq!(receiver.expected().binding(), e.binding());
    let begin = std::time::Instant::now();
    receiver.verify(&frame).unwrap();
    let warm = begin.elapsed();
    for old_magic in [b"DCSGQF01", b"DCSGQF02"] {
        let mut legacy = frame.clone();
        legacy[..8].copy_from_slice(old_magic);
        assert!(matches!(receiver.verify(&legacy), Err(Error::Encoding)));
        assert!(matches!(
            crate::gold::query::verify(&e, &legacy),
            Err(Error::Encoding)
        ));
    }
    eprintln!(
        "fused_query_prepared setup_ms={:.3} receive_ms={:.3} total_receiver_ms={:.3} setup_in_budget=true SQL=false",
        setup.as_secs_f64() * 1000.,
        warm.as_secs_f64() * 1000.,
        (setup + warm).as_secs_f64() * 1000.
    );
    let (_, report) = native::prescreen(&e).unwrap();
    let mut proof =
        native_wire::decode(native_wire::payload(&e, &frame).unwrap(), &report).unwrap();
    proof.opened_values.instances[0]
        .base_opened_values
        .trace_local[0] += Challenge::ONE;
    let bad = native_wire::encode(&e, &proof, &report).unwrap();
    assert!(matches!(
        native::receive(&e, &bad),
        Err(Error::Verification)
    ));
    assert!(matches!(receiver.verify(&bad), Err(Error::Verification)));
    // Neither a successful nor a failed call is a reusable verification verdict.
    receiver.verify(&frame).unwrap();
    assert!(matches!(
        data::verify_dense(&e.core, &frame),
        Err(Error::Encoding)
    ));
    let mut foreign = e.clone();
    foreign.header[0] += Val::ONE;
    // Rebuild complete independent association, not a public-header acceptance flag.
    let foreign = Expected::checked(&foreign.core, foreign.statement, foreign.header).unwrap();
    let mut repaired = frame.clone();
    repaired[40..104].copy_from_slice(&foreign.binding());
    assert!(matches!(receiver.verify(&repaired), Err(Error::Binding)));
    assert!(matches!(
        native::receive(&foreign, &repaired),
        Err(Error::Verification)
    ));
}
#[test]
fn public_preparation_rejects_changed_statement_and_foreign_captured_expectation() {
    use crate::gold::query;
    let (e, p) = data::fused_query_native_fixture(false);
    let mut words = p.statement.0;
    words[20] += Val::ONE;
    assert!(matches!(
        query::Prepared::new(&e, p.input, words),
        Err(Error::Binding)
    ));
    let (e, p) = data::fused_query_native_fixture(false);
    let foreign = query::Expected::checked(&e.core, e.statement, e.header).unwrap();
    // Same ciphertext, roots, header and statement; a different complete binding.
    assert_ne!(foreign.binding(), e.binding());
    assert!(matches!(
        query::Prepared::new(&foreign, p.input, p.statement.0),
        Err(Error::Binding)
    ));
    let (e, p) = data::fused_query_native_fixture(false);
    let foreign = query::Expected::checked(&e.core, e.statement, e.header).unwrap();
    assert!(matches!(query::prove(&foreign, p), Err(Error::Binding)));
}
fn repair_statement(trace: &mut crate::gold::witness::PrivateTrace, words: &[Val; 96]) {
    let mut state = [Val::ZERO; 12];
    for (block, input) in words.as_chunks::<8>().0.iter().enumerate() {
        let row = &mut trace.0.values[(STMT_FIRST + block) * W..(STMT_FIRST + block + 1) * W];
        row[CHECKPOINT..CHECKPOINT + 12].copy_from_slice(&state);
        state[..8].copy_from_slice(input);
        state = bfv_hiding_stark::poseidon::write(&mut row[..248], state);
    }
}
#[test]
fn all_reversed_mask_words_and_the_original_header_are_actual_air_constraints() {
    let (e, p) = data::fused_query_native_fixture(false);
    let words = p.statement.0;
    let mut trace = p.dense_trace(&e).unwrap();
    let (air, _) = native::prescreen(&e).unwrap();
    assert!(check_all_constraints(&air, &trace.0, e.values(), Some(1)).is_ok());
    for coefficient in 0..4096 {
        let value =
            trace.0.values[(coefficient / 2) * W + RANGE_VALUES + (coefficient % 2) * 9 + 4];
        let want = if coefficient < 256 {
            let bit = 255 - coefficient;
            Val::from_u64(((words[78 + bit / 32].as_canonical_u64() >> (bit % 32)) & 1) * 16389)
        } else {
            Val::ZERO
        };
        assert_eq!(value, want, "coefficient {coefficient}");
    }
    for word in 0..8 {
        assert_eq!(
            trace.0.values[((7 - word) * 16 + 15) * W + MASK_WORD],
            words[78 + word]
        );
    }
    let mut bad = words;
    bad[0] += Val::ONE;
    let foreign = Expected::checked(&e.core, statement_root(&bad), e.header).unwrap();
    repair_statement(&mut trace, &bad);
    let (air, _) = native::prescreen(&foreign).unwrap();
    assert!(
        !check_all_constraints(&air, &trace.0, foreign.values(), Some(1)).is_ok(),
        "all hashes repaired; old header must still constrain the preimage"
    );
}
#[test]
fn repaired_statement_mask_word_fails_global_lookup_and_terminal_repair_fails_native() {
    use p3_batch_stark::{BatchVerificationError, verify_batch};
    use p3_lookup::LookupError;
    let (e, p) = data::fused_query_native_fixture(false);
    let mut words = p.statement.0;
    words[78] += Val::ONE;
    let foreign = Expected::checked(&e.core, statement_root(&words), e.header).unwrap();
    let mut trace = p.dense_trace(&e).unwrap();
    repair_statement(&mut trace, &words);
    let (air, report) = native::prescreen(&foreign).unwrap();
    let public = native_setup::public_data(&air, &foreign, &report).unwrap();
    assert!(
        check_all_constraints(&air, &trace.0, foreign.values(), Some(1)).is_ok(),
        "only the cross-mask lookup is false; every local equation and hash is repaired"
    );
    let mut proof = native::prove_trace(&foreign, &air, &trace, &public).unwrap();
    assert_ne!(
        proof.lookup_terminals[0].as_ref().unwrap().0,
        Challenge::ZERO
    );
    let failure = verify_batch(
        &native::config().unwrap(),
        core::slice::from_ref(&air),
        &proof,
        &[foreign.values().to_vec()],
        &public.common,
    )
    .unwrap_err();
    assert!(matches!(
        failure,
        BatchVerificationError::Lookup(LookupError::TerminalSumNonZero)
    ));
    proof.lookup_terminals[0].as_mut().unwrap().0 = Challenge::ZERO;
    let frame = native_wire::encode(&foreign, &proof, &report).unwrap();
    drop(trace);
    drop(public);
    drop(air);
    assert!(matches!(
        crate::gold::query::Verifier::new(&foreign)
            .unwrap()
            .verify(&frame),
        Err(Error::Verification)
    ));
    assert!(matches!(
        native::receive(&foreign, &frame),
        Err(Error::Verification)
    ));
}
#[test]
fn honest_writer_rejects_genuine_data_equations_for_a_nonzero_high_query_coefficient() {
    let (e, p) = data::fused_query_native_fixture(true);
    assert!(matches!(p.dense_trace(&e), Err(Error::Arithmetic)));
}
#[test]
fn genuine_false_high_w_proof_fails_native_verification_after_all_hashes_are_honest() {
    let (e, p) = data::fused_query_native_fixture(true);
    let (air, report) = native::prescreen(&e).unwrap();
    let public = native_setup::public_data(&air, &e, &report).unwrap();
    let trace = p
        .input
        .inner
        .fused_query_negative_trace(&e.core, &p.statement.0, e.statement)
        .unwrap();
    assert!(!check_all_constraints(&air, &trace.0, e.values(), Some(1)).is_ok());
    let proof =
        native::prove_trace(&e, &air, &trace, &public).expect("release genuine false-input proof");
    let frame = native_wire::encode(&e, &proof, &report).unwrap();
    drop(trace);
    drop(public);
    drop(air);
    assert!(matches!(
        crate::gold::query::Verifier::new(&e)
            .unwrap()
            .verify(&frame),
        Err(Error::Verification)
    ));
    assert!(matches!(
        native::receive(&e, &frame),
        Err(Error::Verification)
    ));
}
