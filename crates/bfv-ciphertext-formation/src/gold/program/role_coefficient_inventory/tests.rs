//! Metadata and PUBLIC-only diagnostic tests; not proof/SQL/admission acceptance.
use super::air::MetadataAir;
use super::*;
use bfv_hiding_stark::{Challenge, poseidon};
use p3_air::{Air, BaseAir, DebugConstraintBuilder, symbolic::AirLayout};
use p3_batch_stark::symbolic::{get_log_num_quotient_chunks_for_domain, get_symbolic_constraints};
use p3_commit::PolynomialSpace;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_goldilocks::default_goldilocks_poseidon2_12;
use p3_lookup::{LogUpGadget, Lookups};
use p3_matrix::{dense::RowMajorMatrixView, stack::ViewPair};
use p3_symmetric::Permutation;

fn expected(which: usize) -> data::Expected {
    // Explicitly NONSECRET literal canonical public metadata, NOT an encryption witness.
    let request = data::Request::checked(
        [0xc7 + which as u8; 32],
        crate::gold::tests::pair_snapshot_ciphertext(which),
    )
    .unwrap();
    data::Expected::checked(
        request,
        [0xd7 + which as u8; 64],
        [
            [Val::from_usize(9 + which); 8],
            [Val::from_usize(10 + which); 8],
        ],
        [
            [Val::from_usize(11 + which); 4],
            [Val::from_usize(12 + which); 4],
        ],
    )
    .unwrap()
}
fn digest_plan(p: &plan::Plan) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(public::profile());
    for row in 0..H {
        for v in p.row(row).unwrap() {
            h.update(v.as_canonical_u64().to_le_bytes());
        }
        for v in plan::hash_row(row).unwrap() {
            h.update(v.as_canonical_u64().to_le_bytes());
        }
    }
    h.finalize().into()
}
fn hex(bytes: impl AsRef<[u8]>) -> String {
    use core::fmt::Write;
    let mut out = String::new();
    for b in bytes.as_ref() {
        write!(&mut out, "{b:02x}").unwrap();
    }
    out
}
#[test]
fn static_role_schedule_preserves_old_row32_gates_and_all_combined_sources() {
    // Static role is built BEFORE and WITHOUT any sample Expected.
    let role = plan::Plan::new().unwrap();
    let i = plan::inventory(&role).unwrap();
    assert_eq!(
        (
            i.gates,
            i.hashes,
            i.range_coefficients,
            i.public_coefficients
        ),
        (81920, 580, 4096, 16384)
    );
    assert_eq!(i.producers, 44 * N + 512);
    assert!(i.weighted_uses > i.producers);
    let expected = expected(0);
    let public = public::PublicExpected::checked(&expected).unwrap();
    let original =
        graph::Plan::new(crate::gold::geometry::Inputs::data(expected.request()).unwrap()).unwrap();
    for index in 0..GATES {
        let old = original.row(index / graph::SLOTS).unwrap().gates[index % graph::SLOTS];
        match role.scheduled(index).unwrap() {
            graph::ScheduledGate::Butterfly(gate) => assert!(gate == old),
            graph::ScheduledGate::Pointwise(point) => {
                assert_eq!(old.inputs[0].unwrap().id(), point.input.id());
                assert!(old.inputs[1].is_none() && old.outputs[1].is_none());
                assert_eq!(old.outputs[0].unwrap().id(), point.output.id());
                assert_eq!(
                    old.linear,
                    [
                        [
                            public.coefficients[point.job * N + point.coefficient]
                                .as_canonical_u64(),
                            0
                        ],
                        [0, 0]
                    ]
                );
                assert_eq!(old.output_uses, [1, 0]);
            }
        }
    }
    // Whole original Pair/Data PP + ordered symbolic literal regressions are
    // separate existing tests and MUST also pass after the shared extraction.
    let tail = role.row(GRAPH_ROWS - 1).unwrap();
    assert_eq!(
        tail[ACTIVE..ACTIVE + SLOTS]
            .iter()
            .filter(|&&v| v == Val::ONE)
            .count(),
        48
    );
    for slot in 48..56 {
        assert!(tail[4 * slot..4 * slot + 4].iter().all(|&x| x == Val::ZERO));
        assert!(
            tail[COEFFICIENTS + 4 * slot..COEFFICIENTS + 4 * slot + 4]
                .iter()
                .all(|&x| x == Val::ZERO)
        );
    }
    assert!(matches!(role.row(H), Err(Error::Shape)));
    assert!(matches!(node(40, 512), Err(Error::Shape)));
    assert!(matches!(node(45, 0), Err(Error::Shape)));
}
#[test]
fn distinct_expected_changes_full_public_binding_and_root_but_never_structural_pp() {
    let p0 = plan::Plan::new().unwrap();
    let digest0 = digest_plan(&p0);
    // Root's first actual native r50 capture, before any private proof stage.
    assert_eq!(
        hex(digest0),
        "7593a725266c1cd508b1f78b8b5bc0e1fe86581351f853fcb58518225d88451a"
    );
    let e0 = expected(0);
    let e1 = expected(1);
    let a = public::PublicExpected::checked(&e0).unwrap();
    let b = public::PublicExpected::checked(&e1).unwrap();
    assert_ne!(a.request_bytes(), b.request_bytes());
    assert_ne!(a.binding, b.binding);
    assert_ne!(a.hash_values, b.hash_values);
    assert_ne!(a.data_values, b.data_values);
    let p1 = plan::Plan::new().unwrap();
    for row in 0..H {
        assert_eq!(p0.row(row).unwrap(), p1.row(row).unwrap());
    }
    assert_eq!(digest0, digest_plan(&p1));
    assert_eq!(
        public::iv().map(|v| v.as_canonical_u64()),
        [
            4533083410485068889,
            3810787125653393502,
            4166276515102124294,
            18416595238704041011
        ]
    );
    assert_eq!(
        hex(public::profile()),
        "0f390643bb7d2371181d3ba24dd6f70b165f82278482120460f763ccd1b7784c"
    );
    // Exact fresh profile and IV are fixed before future proof-stage goldens.
    assert_ne!(public::profile(), data::profile_digest());
    assert_ne!(public::profile(), crate::gold::profile_digest());
    eprintln!(
        "role_coeff_structural_pp profile={} full_streamed_pp={} IV={:?} literal_words=16384 PV48+4=true committed=false proof=false",
        hex(public::profile()),
        hex(digest0),
        public::iv().map(|v| v.as_canonical_u64())
    );
}
fn failures(
    air: &MetadataAir,
    row: &[Val],
    next: &[Val],
    pre: &[Val],
    pv: &[Val],
    index: usize,
) -> usize {
    let main = ViewPair {
        top: RowMajorMatrixView::new(row, row.len()),
        bottom: RowMajorMatrixView::new(next, next.len()),
    };
    let pp = ViewPair {
        top: RowMajorMatrixView::new(pre, pre.len()),
        bottom: RowMajorMatrixView::new(pre, pre.len()),
    };
    let mut b = DebugConstraintBuilder::new(
        index,
        main,
        pp,
        pv,
        Val::from_bool(index == 0),
        Val::from_bool(index + 1 == H),
        Val::from_bool(index + 1 < H),
        &[],
    );
    air.eval(&mut b);
    b.failures().len()
}
#[test]
fn fixed_iv_all16384_public_words_match_independent_native_permutation_and_actual_row_constraints()
{
    let e = public::PublicExpected::checked(&expected(0)).unwrap();
    let air = MetadataAir::PublicCoefficientHash;
    let native = default_goldilocks_poseidon2_12();
    let mut state = [Val::ZERO; 12];
    state[8..].copy_from_slice(&public::iv());
    let mut first = None;
    let mut last = None;
    for index in 0..H {
        let before = state;
        let mut input = before;
        for (i, value) in input.iter_mut().take(8).enumerate() {
            *value += e.coefficients[8 * index + i];
        }
        state = native.permute(input);
        let mut row = [Val::ZERO; HASH_W];
        row[248..].copy_from_slice(&before);
        let via_gadget = poseidon::write(&mut row[..248], input);
        assert_eq!(state, via_gadget);
        for i in 0..8 {
            assert_eq!(row[i] - row[248 + i], e.coefficients[8 * index + i]);
        }
        let mut next = [Val::ZERO; HASH_W];
        next[248..].copy_from_slice(&state);
        if index == 0 {
            first = Some((row, next));
        }
        if index + 1 == H {
            last = Some((row, next));
        }
    }
    assert_eq!(state[..4], e.hash_values);
    let (mut row, next) = first.unwrap();
    let pp = plan::hash_row(0).unwrap();
    assert_eq!(failures(&air, &row, &next, &pp, &e.hash_values, 0), 0);
    row[256] += Val::ONE; // Capacity IV constraint, not an arbitrary hash comparison.
    assert!(failures(&air, &row, &next, &pp, &e.hash_values, 0) > 0);
    let (row, next) = last.unwrap();
    let mut foreign_root = e.hash_values;
    foreign_root[3] += Val::ONE;
    assert!(
        failures(
            &air,
            &row,
            &next,
            &plan::hash_row(H - 1).unwrap(),
            &foreign_root,
            H - 1
        ) > 0
    );
    let mut changed = e.coefficients.clone();
    changed[COEFFICIENT_WORDS - 1] += Val::ONE;
    assert_ne!(public::coefficient_root(&changed).unwrap(), e.hash_values);
    assert!(matches!(
        public::coefficient_root(&changed[..COEFFICIENT_WORDS - 1]),
        Err(Error::Shape)
    ));
}
#[test]
fn actual_two_air_default_packing_geometry_and_candidate_report_remain_nonaccepting() {
    let airs = MetadataAir::closed().unwrap();
    for air in &airs {
        assert!(air.preprocessed_trace().is_none());
    }
    let a = assessment::assess(&airs).unwrap();
    a.require_resources().unwrap();
    assert!(matches!(a.require_proof_security(), Err(Error::Security)));
    assert_eq!(
        a.total_openings,
        a.instances.iter().map(|i| i.openings).sum::<usize>()
    );
    assert!(a.deep_envelope_chunks.is_power_of_two());
    let domain = TwoAdicMultiplicativeCoset::<Val>::new(Val::ONE, LOG_H).unwrap();
    let gadget = LogUpGadget::new();
    let mut h = Sha256::new();
    h.update(public::profile());
    h.update(b"/ordered-native-metadata-only/v1");
    let mut bytes = 0;
    for air in &airs {
        let layout = AirLayout::from_air(air);
        let original = Lookups::<Val>::from_air::<Challenge, _>(air);
        let log = get_log_num_quotient_chunks_for_domain::<Val, Challenge, _, _>(
            air, layout, domain, &original, 1, &gadget,
        );
        let packed = original
            .clone()
            .pack_same_bus_with_degree(1 << log, |lookup| {
                gadget
                    .constraint_degree_with_transition(lookup, domain.transition_degree_multiple())
            });
        let (base, ext) =
            get_symbolic_constraints::<Val, Challenge, _, _>(air, layout, &packed, &gadget);
        let serialized = postcard::to_allocvec(&(base, ext, original, packed)).unwrap();
        assert!(serialized.len() <= 4 * 1024 * 1024);
        bytes += serialized.len();
        h.update((serialized.len() as u64).to_le_bytes());
        h.update(serialized);
    }
    let digest = hex(h.finalize());
    assert_eq!(bytes, 1_050_159);
    assert_eq!(
        digest,
        "945255af8155abb0893782f1e4e8de40001b918043a818be91df274e351c9578"
    );
    eprintln!(
        "role_coeff_ordered_native_snapshot sha256={} bytes={} workspace={} per_air_base={:?} per_air_extension={:?} degree={:?} chunks={:?} original={:?} packed={:?} AUX={:?} security_UNASSESSED=true MAIN=false proof=false accepted=false",
        digest,
        bytes,
        a.workspace,
        a.instances.each_ref().map(|i| i.base),
        a.instances.each_ref().map(|i| i.extension),
        a.instances.each_ref().map(|i| i.degree),
        a.instances.each_ref().map(|i| i.chunks),
        a.instances.each_ref().map(|i| i.original),
        a.instances.each_ref().map(|i| i.packed),
        a.instances.each_ref().map(|i| i.aux)
    );
}
