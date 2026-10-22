//! Public nonsecret projection oracle. No legacy proof producer or wire acceptance.
use super::*;
use bfv_hiding_stark::Challenge;
use p3_air::{Air, BaseAir, check_all_constraints, symbolic::AirLayout};
use p3_batch_stark::symbolic::{get_log_num_quotient_chunks_for_domain, get_symbolic_constraints};
use p3_commit::PolynomialSpace;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_lookup::{InteractionBuilder, LogUpGadget, Lookups};
use p3_matrix::dense::RowMajorMatrix;

const ORIGINAL_PP: usize = 708;

/// Restore the former physical columns without providing a legacy native AIR.
fn expand_public(compact: &[Val; PP]) -> [Val; ORIGINAL_PP] {
    let mut original = [Val::ZERO; ORIGINAL_PP];
    original[..509].copy_from_slice(&compact[..ACTIVE]);
    for slot in 0..57 {
        original[509 + slot] = compact[active_column(slot)];
        original[566 + slot] = compact[pointwise_column(slot)];
        original[623 + slot] = compact[fanout_column(slot)];
    }
    original[680..].copy_from_slice(&compact[STMT_LOOKUP..]);
    original
}

/// Independent original geometry: adapt the existing 32-gate PP rows, rather
/// than the compact Plan or its flag aliases. Literal offsets pin the old matrix.
fn original_public_row(d: &Descriptor, e: &Expected, index: usize) -> [Val; ORIGINAL_PP] {
    let mut original = [Val::ZERO; ORIGINAL_PP];
    let range = old_pp::row(d, d.kind.range_first() + index).unwrap();
    original[228..247].copy_from_slice(&range[..19]);
    original[476..480].copy_from_slice(&range[old_pp::COEFFICIENTS..old_pp::COEFFICIENTS + 4]);
    original[480] = range[old_pp::COEFFICIENTS + 8];
    for flag in [old_pp::RANGE, old_pp::RESET, old_pp::EMIT] {
        original[493 + flag] = range[old_pp::FLAGS + flag];
    }
    if index < 128 {
        original[704] = Val::ONE;
        original[705] = Val::from_bool(index.is_multiple_of(16));
        original[706] = Val::from_bool(index % 16 == 15);
        original[707] = Val::from_u64(1 << (30 - 2 * (index % 16)));
        if index % 16 == 15 {
            original[247] = Val::from_u64(old_pp::node(41, 7 - index / 16).unwrap());
        }
    }
    if index < 1438 {
        original[493 + old_pp::ARITH] = Val::ONE;
        let first = index * 57;
        let end = (first + 57).min(81920);
        for source_index in first / 32..=(end - 1) / 32 {
            let source = old_pp::row(d, source_index).unwrap();
            for source_slot in 0..32 {
                let gate = source_index * 32 + source_slot;
                if !(first..end).contains(&gate) {
                    continue;
                }
                let slot = gate - first;
                original[4 * slot..4 * slot + 4]
                    .copy_from_slice(&source[4 * source_slot..4 * source_slot + 4]);
                let coefficient = old_pp::COEFFICIENTS + 4 * source_slot;
                original[248 + 4 * slot..252 + 4 * slot]
                    .copy_from_slice(&source[coefficient..coefficient + 4]);
                original[509 + slot] = source[old_pp::FLAGS + old_pp::ARITH];
                original[566 + slot] = source[old_pp::FLAGS + old_pp::POINTWISE];
                original[623 + slot] = source[old_pp::FLAGS + old_pp::FANOUT];
            }
        }
    } else if index < 2018 {
        let source = old_pp::row(d, d.kind.cw_first(0) + index - 1438).unwrap();
        original[..8].copy_from_slice(&source[..8]);
        original[481..489].copy_from_slice(&source[old_pp::COEFFICIENTS..old_pp::COEFFICIENTS + 8]);
        original[489..493]
            .copy_from_slice(&source[old_pp::COEFFICIENTS + 8..old_pp::COEFFICIENTS + 12]);
        for flag in 0..16 {
            original[493 + flag] += source[old_pp::FLAGS + flag];
        }
    } else if index < 2030 {
        let block = index - 2018;
        original[493 + old_pp::HASH] = Val::ONE;
        original[493 + old_pp::MASK] = Val::ONE;
        original[493 + old_pp::FIRST] = Val::from_bool(block == 0);
        original[493 + old_pp::LAST] = Val::from_bool(block == 11);
        original[489..493].copy_from_slice(&e.statement);
        for lane in 0..8 {
            let word = 8 * block + lane;
            if word < 13 || word == 95 {
                original[688 + lane] = Val::ONE;
                original[696 + lane] = if word < 13 { e.header[word] } else { Val::ZERO };
            }
            if (78..86).contains(&word) {
                original[lane] = Val::from_u64(old_pp::node(41, word - 78).unwrap());
                original[680 + lane] = Val::ONE;
            }
        }
    }
    original
}

#[test]
fn compact_metadata_preserves_every_original_preprocessed_cell_and_security_floor() {
    let e = tests::metadata();
    let (air, report) = native::prescreen(&e).unwrap();
    let reference = Descriptor::new(ExpectedRef::Data(&e.core)).unwrap();
    let inventory = air.0.plan.inventory().unwrap();
    assert_eq!(
        (H, PP, SLOTS, ACTIVE, POINTWISE, FANOUT, STMT_LOOKUP),
        (2048, 545, 57, 509, 511, 514, 517)
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
    assert_eq!((base.len(), ext.len()), (1098, 86));
    assert_eq!((original.len(), packed.len()), (248, 83));
    assert_eq!((report.chunks(), report.aux_width()), (8, 420));
    let bytes = postcard::to_allocvec(&(base, ext, original, packed)).unwrap();
    let mut current = Sha256::new();
    current.update(DOMAIN);
    let mut legacy = Sha256::new();
    legacy.update(b"DCS/research/CoreGold/FusedQuery57/H2048/PP708/v1");
    let mut v2 = Sha256::new();
    v2.update(b"DCS/research/CoreGold/FusedQuery57/H2048/MAIN416/PP708/v2/structured-W");
    for row in 0..H {
        let compact = air.0.plan.row(row).unwrap();
        let expanded = expand_public(&compact);
        let original = original_public_row(&reference, &e, row);
        for (column, (&got, &want)) in expanded.iter().zip(&original).enumerate() {
            assert_eq!(got, want, "original public cell row={row} column={column}");
        }
        for value in compact {
            current.update(value.as_canonical_u64().to_le_bytes());
        }
        for value in expanded {
            let word = value.as_canonical_u64().to_le_bytes();
            legacy.update(word);
            v2.update(word);
        }
    }
    // Both original full-matrix captures survive expansion, including every
    // public metadata, range, hash, Stmt96 and per-logical-slot flag cell.
    assert_eq!(
        format!("{:x}", legacy.finalize()),
        "d37135fbf16749c8cb08669b109fec4af772cf5fe6906c5ae4394c6fb3bd1932"
    );
    assert_eq!(
        format!("{:x}", v2.finalize()),
        "c37659509244a5efd78996007d6ad60e9d7e96a0ce5093f0797af85c0c0f4406"
    );
    eprintln!(
        "query_range_projection_metadata ordered={:x} symbolic_bytes={} full_pp={:x} profile={:x} frame_profile={:x} MAIN={} RANGE_BITS={} PP={} original_PP={} physical_flags={} gates={} hash_rows={} coefficients={} positive_uses={} negative_uses={} producers={} workspace={} PRIVATE_MAIN=false proof=false SQL=false",
        Sha256::digest(&bytes),
        bytes.len(),
        current.finalize(),
        Sha256::digest(profile()),
        Sha256::digest(native_wire::profile()),
        W,
        RANGE_BITS,
        PP,
        ORIGINAL_PP,
        ACTIVE_SLOTS.len() + POINTWISE_SLOTS.len() + FANOUT_SLOTS.len(),
        inventory.gates,
        inventory.hash_rows,
        inventory.coefficients,
        inventory.positive_uses,
        inventory.negative_uses,
        inventory.producers,
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
