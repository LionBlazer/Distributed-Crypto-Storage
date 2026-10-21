//! Public nonsecret projection oracle. No legacy proof producer or wire acceptance.
use super::*;
use bfv_hiding_stark::Challenge;
use p3_air::{Air, BaseAir, check_all_constraints, symbolic::AirLayout};
use p3_batch_stark::symbolic::{get_log_num_quotient_chunks_for_domain, get_symbolic_constraints};
use p3_commit::PolynomialSpace;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_lookup::{InteractionBuilder, LogUpGadget, Lookups};
use p3_matrix::dense::RowMajorMatrix;

#[test]
fn compact_metadata_preserves_every_original_preprocessed_cell_and_security_floor() {
    let e = tests::metadata();
    let (air, report) = native::prescreen(&e).unwrap();
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
    assert_eq!((base.len(), ext.len()), (1098, 86));
    assert_eq!((original.len(), packed.len()), (248, 83));
    assert_eq!((report.chunks(), report.aux_width()), (8, 420));
    let bytes = postcard::to_allocvec(&(base, ext, original, packed)).unwrap();
    let mut current = Sha256::new();
    current.update(DOMAIN);
    let mut legacy = Sha256::new();
    legacy.update(b"DCS/research/CoreGold/FusedQuery57/H2048/PP708/v1");
    for row in 0..H {
        for value in air.0.plan.row(row).unwrap() {
            let word = value.as_canonical_u64().to_le_bytes();
            current.update(word);
            legacy.update(word);
        }
    }
    // Retained v1 literal: full public matrix values and order did not change.
    assert_eq!(
        format!("{:x}", legacy.finalize()),
        "d37135fbf16749c8cb08669b109fec4af772cf5fe6906c5ae4394c6fb3bd1932"
    );
    eprintln!(
        "query_range_projection_metadata ordered={:x} symbolic_bytes={} full_pp={:x} profile={:x} frame_profile={:x} MAIN={} RANGE_BITS={} workspace={} PRIVATE_MAIN=false proof=false SQL=false",
        Sha256::digest(&bytes),
        bytes.len(),
        current.finalize(),
        Sha256::digest(profile()),
        Sha256::digest(native_wire::profile()),
        W,
        RANGE_BITS,
        report.workspace_bytes()
    );
}

/// Full old constraints on the expanded private trace. This wrapper supplies
/// the SAME complete public PP for constraint checking only, never native setup.
struct FullWordRange(air::FullWordRangeAir);
impl BaseAir<Val> for FullWordRange {
    fn width(&self) -> usize {
        self.0.width()
    }
    fn preprocessed_width(&self) -> usize {
        PP
    }
    fn num_public_values(&self) -> usize {
        PV
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        self.0.main_next_row_columns()
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        let mut words = Vec::with_capacity(H * PP);
        for row in 0..H {
            words.extend(self.0.plan.row(row).unwrap());
        }
        Some(RowMajorMatrix::new(words, PP))
    }
}
impl<AB: InteractionBuilder<F = Val>> Air<AB> for FullWordRange {
    fn eval(&self, b: &mut AB) {
        self.0.eval(b)
    }
}
fn extend(compact: &crate::gold::witness::PrivateTrace) -> crate::gold::witness::PrivateTrace {
    let mut full =
        crate::gold::witness::PrivateTrace(RowMajorMatrix::new(Val::zero_vec(H * 512), 512));
    for row in 0..H {
        let from = &compact.0.values[row * W..(row + 1) * W];
        let to = &mut full.0.values[row * 512..(row + 1) * 512];
        to[..BITS].copy_from_slice(&from[..BITS]);
        for coefficient in 0..2 {
            let at = BITS + 98 * coefficient;
            to[at..at + 64]
                .copy_from_slice(&from[BITS + 64 * coefficient..BITS + 64 * (coefficient + 1)]);
            let word = from[RANGE_VALUES + coefficient * 9 + 4].as_canonical_u64();
            assert!(matches!(word, 0 | 16389));
            // Unique canonical extension, independently reconstructed from W.
            for bit in 0..17 {
                to[at + 64 + bit] = Val::from_u64((word >> bit) & 1);
                to[at + 81 + bit] = Val::from_u64(((65536 - word) >> bit) & 1);
            }
        }
        to[496..512].copy_from_slice(&from[CHECKPOINT..W]);
    }
    full
}
#[test]
fn compact_private_trace_extends_to_every_original_complete_constraint() {
    let (e, p) = data::fused_query_native_fixture(false);
    let (air, _) = native::prescreen(&e).unwrap();
    let compact = p.dense_trace(&e).unwrap();
    assert!(check_all_constraints(&air, &compact.0, e.values(), Some(1)).is_ok());
    let full = extend(&compact);
    let original = FullWordRange(air::FullWordRangeAir::new(&e).unwrap());
    assert!(check_all_constraints(&original, &full.0, e.values(), Some(1)).is_ok());
    // The original range boolean/slack constraints are live in the oracle.
    let mut bad = extend(&compact);
    bad.0.values[BITS + 64] += Val::ONE;
    assert!(!check_all_constraints(&original, &bad.0, e.values(), Some(1)).is_ok());
    // The omitted cells are exactly 68 bits plus 28 padding cells per row.
    assert_eq!((H * 512 - compact.0.values.len()) * 8, 1_572_864);
}
