//! PUBLIC NONSECRET owning examples. Rebuilt attacks recompute genuine P2
//! witnesses and C_sel; they are not limited to wrapper replay rejection.
use super::{
    air::*,
    statement::{self, Plan},
    trace::Witness,
    *,
};
use crate::backend::{self, Backend};
use crate::opening::{commitment, poseidon};
use crate::primitive::PublicStatement;
use p3_air::{BaseAir, check_all_constraints, check_constraints};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

fn mask(ages: &[u8]) -> [u8; 32] {
    let mut mask = [0; 32];
    for age in ages {
        mask[usize::from(*age) / 8] |= 1 << (*age % 8);
    }
    mask
}
fn valid(s: &Statement, w: &Witness) -> RowMajorMatrix<Val> {
    let trace = w.trace(s).unwrap();
    check_constraints(&s.air(), &trace, &s.public_values());
    trace
}
fn rejects(s: &Statement, trace: &RowMajorMatrix<Val>) {
    assert!(!check_all_constraints(&s.air(), trace, &s.public_values(), Some(1)).is_ok());
}
fn rebuilt_rejects(s: &Statement, trace: RowMajorMatrix<Val>) {
    rejects(s, &trace);
    let b = Backend::new(s).unwrap();
    let result = p3_uni_stark::prove(&b.config, &s.air(), trace, &s.public_values());
    if let Ok(proof) = result {
        assert!(b.verify(s, &proof).is_err());
    }
}
fn all_rows(trace: &mut RowMajorMatrix<Val>, mut change: impl FnMut(&mut [Val])) {
    for row in trace.values.as_chunks_mut::<WIDTH>().0 {
        change(row);
    }
}
/// Recompute ALL real permutation/capacity cells from forged banks. An optional
/// selected input override gives an internally valid hash of a forbidden tuple.
fn rehash(
    s: &mut Statement,
    trace: &mut RowMajorMatrix<Val>,
    override_field: Option<(usize, Val)>,
) {
    let air = SelectionAir::new(s);
    let mut checkpoint = [Val::ZERO; 12];
    for (physical, row) in trace
        .values
        .as_chunks_mut::<WIDTH>()
        .0
        .iter_mut()
        .enumerate()
    {
        row[CHECKPOINT..WORDS].copy_from_slice(&checkpoint);
        let mut input = [Val::ZERO; 12];
        if let Some((stream, block)) = absorb(physical) {
            for (slot, value) in input[..8].iter_mut().enumerate() {
                let field = block * 8 + slot;
                *value = air.field(row, stream, field, slot);
                if matches!(stream, Stream::Selected)
                    && let Some((bad, replacement)) = override_field
                    && bad == field
                {
                    *value = replacement;
                }
            }
            if !reset(physical) {
                input[8..].copy_from_slice(&checkpoint[8..]);
            }
        }
        let output = poseidon::write(&mut row[..CHECKPOINT], input);
        if absorb(physical).is_some() {
            checkpoint = output;
        }
        if physical == 267 {
            s.selected = output[..4].try_into().unwrap();
        }
    }
}
fn set_compaction(trace: &mut RowMajorMatrix<Val>, retained: [bool; 4], slots: [Option<usize>; 4]) {
    all_rows(trace, |row| {
        for i in 0..4 {
            row[RETAIN + i] = Val::from_bool(retained[i]);
        }
        row[COMPACT..SALTS].fill(Val::ZERO);
        for (slot, source) in slots.iter().enumerate() {
            if let Some(i) = source {
                row[COMPACT + slot * 4 + i] = Val::ONE;
                row[PRESENCE + slot] = Val::ONE;
            }
        }
    });
}
fn copy_witness(w: &Witness, plan: Plan) -> Witness {
    Witness::new(w.plain, plan, w.salts)
}

#[test]
fn fixed_encodings_open_the_old_source_and_capture_every_original_word() {
    let (_, _, s, w) = fixture(mask(&[0, 255]), Some(2)).unwrap();
    assert_eq!(
        commitment::opening_fields(&s.source, w.salts[0], &w.plain).len(),
        680
    );
    assert_eq!(statement::plan_fields(&s, &w).len(), 112);
    assert_eq!(statement::selected_fields(&s, &w).len(), 88);
    let trace = valid(&s, &w);
    let a = SelectionAir::new(&s);
    for word in 0..587 {
        let field = 87 + word;
        let row = &trace.values[(field / 8) * WIDTH..(field / 8 + 1) * WIDTH];
        let actual = a.field::<Val, _>(row, Stream::Source, field, field % 8);
        assert_eq!(
            actual,
            Val::from_u32(u32::from_le_bytes(
                w.plain[word * 4..word * 4 + 4].try_into().unwrap()
            ))
        );
    }
    // Both data captures straddle source rows10/11; final ID words occupy80..84.
    assert_eq!((87 / 8, 89 / 8), (10, 11));
    assert_eq!((642 / 8, 673 / 8), (80, 84));
}
#[test]
fn empty_full_disjoint_and_every_n4_limit_have_complete_stable_original_slots() {
    for (ages, limit, expected) in [
        (&[][..], None, vec![]),
        (&[0, 128, 255][..], None, vec![0, 1, 2, 3]),
        (&[0, 255][..], Some(0), vec![]),
        (&[0, 255][..], Some(1), vec![0]),
        (&[0, 255][..], Some(2), vec![0, 1]),
        (&[0, 255][..], Some(3), vec![0, 1, 2]),
        (&[255][..], Some(4), vec![0, 2]),
        (&[0, 128, 255][..], Some(usize::MAX), vec![0, 1, 2, 3]),
    ] {
        let (_, _, s, w) = fixture(mask(ages), limit).unwrap();
        drop(valid(&s, &w));
        let fields = statement::selected_fields(&s, &w);
        for slot in 0..4 {
            let tuple = &fields[34 + slot * 12..46 + slot * 12];
            if let Some(&i) = expected.get(slot) {
                assert_eq!(tuple[0], Val::ONE);
                assert_eq!(tuple[1], Val::from_usize(i));
                assert_eq!(tuple[2], Val::from_u8(w.plain[i * 3]));
                assert_eq!(
                    tuple[3],
                    Val::from_u16(u16::from_le_bytes([w.plain[i * 3 + 1], w.plain[i * 3 + 2]]))
                );
                assert_eq!(
                    tuple[4..],
                    source::words(&w.plain[2220 + i * 32..2252 + i * 32]).collect::<Vec<_>>()
                );
            } else {
                assert!(tuple.iter().all(|v| *v == Val::ZERO));
            }
        }
        assert!(fields[82..].iter().all(|v| *v == Val::ZERO));
    }
}
#[test]
fn genuine_composites_verify_nonempty_and_empty_without_exposing_their_counts() {
    for ages in [&[][..], &[255][..]] {
        let (source, sw, s, w) = fixture(mask(ages), None).unwrap();
        let proof = prove_composite(&source, &sw, &s, &w).unwrap();
        verify_composite(&source, &s, &proof).unwrap();
        assert_eq!(s.public_values().len(), 88);
    }
}
#[test]
fn missing_foreign_or_wrong_profile_source_never_credits_a_selection_proof() {
    let (source, sw, s, w) = fixture(mask(&[255]), None).unwrap();
    let mut proof = prove_composite(&source, &sw, &s, &w).unwrap();
    let saved = proof.source.take();
    assert_eq!(verify_composite(&source, &s, &proof), Err(Error::Shape));
    proof.source = saved;
    let mut foreign = source.clone();
    foreign.request[0] ^= 1;
    assert!(verify_composite(&foreign, &s, &proof).is_err());
    let mut old = source.clone();
    old.relation = Relation::Bytes;
    assert_eq!(verify_composite(&old, &s, &proof), Err(Error::Shape));
    // The genuine source passes; a foreign selection context still must reject.
    let mut other = s.clone();
    other.source.request[0] ^= 1;
    assert_eq!(verify_composite(&source, &other, &proof), Err(Error::Shape));
}
#[test]
fn plan_mask_projection_limit_and_same_private_table_id_are_independently_bound() {
    let (_, _, s, w) = fixture(mask(&[0, 255]), Some(2)).unwrap();
    for which in 0..4 {
        let mut plan = Plan::new(
            w.plan.table,
            w.plan.mask,
            w.plan.projection,
            Some(w.plan.limit as usize),
        )
        .unwrap();
        match which {
            0 => plan.mask = mask(&[128]),
            1 => plan.projection ^= 1,
            2 => plan.limit = 1,
            _ => plan.table[31] ^= 1,
        }
        let changed = copy_witness(&w, plan);
        let mut expected = s.clone();
        // Fresh C_sel is honest for the forged plan, while authorized C_plan stays.
        expected.selected = commitment::digest(&statement::selected_fields(&expected, &changed));
        rebuilt_rejects(&expected, changed.trace(&expected).unwrap());
    }
}
#[test]
fn omitted_and_extra_retained_rows_reject_even_with_consistent_forged_commitments() {
    let (_, _, s, w) = fixture(mask(&[0, 255]), Some(2)).unwrap();
    for (retained, slots) in [
        ([false, true, false, false], [Some(1), None, None, None]),
        ([true, true, false, true], [Some(0), Some(1), Some(3), None]),
    ] {
        let mut trace = valid(&s, &w);
        let mut changed = s.clone();
        set_compaction(&mut trace, retained, slots);
        rehash(&mut changed, &mut trace, None);
        rebuilt_rejects(&changed, trace);
    }
}
#[test]
fn duplicate_and_reordered_rows_cannot_replace_canonical_ordinal_compaction() {
    let (_, _, s, w) = fixture(mask(&[0, 255]), Some(2)).unwrap();
    for slots in [
        [Some(0), Some(0), None, None],
        [Some(1), Some(0), None, None],
    ] {
        let mut trace = valid(&s, &w);
        let mut changed = s.clone();
        set_compaction(&mut trace, [true, true, false, false], slots);
        rehash(&mut changed, &mut trace, None);
        rebuilt_rejects(&changed, trace);
    }
}
#[test]
fn coherent_false_membership_cannot_omit_a_true_match_or_include_a_false_one() {
    let (_, _, s, w) = fixture(mask(&[255]), None).unwrap();
    for (matches, retained, slots) in [
        (
            [false, false, true, false],
            [false, false, true, false],
            [Some(2), None, None, None],
        ),
        (
            [true, true, true, false],
            [true, true, true, false],
            [Some(0), Some(1), Some(2), None],
        ),
    ] {
        let mut trace = valid(&s, &w);
        let mut changed = s.clone();
        all_rows(&mut trace, |row| {
            for i in 0..4 {
                row[MATCHES + i] = Val::from_bool(matches[i]);
            }
        });
        // Recompute every rank/limit comparator for the coherent forged bank.
        all_rows(&mut trace, |row| {
            for i in 0..4 {
                let diff = matches[..i].iter().filter(|v| **v).count() + 8 - 4;
                for bit in 0..3 {
                    row[COMPARE + i * 4 + bit] = Val::from_usize((diff >> bit) & 1);
                }
                row[COMPARE + i * 4 + 3] = Val::from_bool(diff >= 8);
            }
        });
        set_compaction(&mut trace, retained, slots);
        rehash(&mut changed, &mut trace, None);
        rebuilt_rejects(&changed, trace);
    }
}
#[test]
fn original_age_amount_and_row_id_remain_tied_to_the_complete_source_opening() {
    let (_, _, s, w) = fixture(mask(&[255]), None).unwrap();
    for byte in [0, 1, 2220] {
        let mut forged = copy_witness(&w, Plan::new(w.plan.table, w.plan.mask, 2, None).unwrap());
        forged.plain[byte] ^= 1;
        // ALL matching, prefix, comparison, compacted-tuple and ID banks agree
        // with the forged original. Restore ONLY the real committed source words.
        let mut trace = forged.trace(&s).unwrap();
        for word in 0..587 {
            let field = 87 + word;
            let value = u32::from_le_bytes(w.plain[word * 4..word * 4 + 4].try_into().unwrap());
            let row = &mut trace.values[(field / 8) * WIDTH..(field / 8 + 1) * WIDTH];
            for bit in 0..32 {
                row[WORDS + (field % 8) * 32 + bit] = Val::from_u32((value >> bit) & 1);
            }
        }
        let mut changed = s.clone();
        rehash(&mut changed, &mut trace, None);
        let report =
            check_all_constraints(&changed.air(), &trace, &changed.public_values(), Some(2));
        assert_eq!(report.failures.len(), 1);
        rebuilt_rejects(&changed, trace);
    }
}
#[test]
fn inactive_tuple_fields_and_final_encoding_padding_are_zero_even_for_limit_zero() {
    let (_, _, s, w) = fixture([255; 32], Some(0)).unwrap();
    for field in [34, 35, 36, 37, 38, 81, 82, 87] {
        let mut trace = valid(&s, &w);
        let mut changed = s.clone();
        rehash(&mut changed, &mut trace, Some((field, Val::ONE)));
        rebuilt_rejects(&changed, trace);
    }
}
#[test]
fn limit_zero_still_opens_the_last_index_word_and_all_u32_words_are_ranged() {
    let (_, _, s, w) = fixture([0; 32], Some(0)).unwrap();
    let mut bad = copy_witness(
        &w,
        Plan::new(w.plan.table, w.plan.mask, 2, Some(0)).unwrap(),
    );
    bad.plain[2347] ^= 1;
    rebuilt_rejects(&s, bad.trace(&s).unwrap());
    let mut trace = valid(&s, &w);
    let mut changed = s.clone();
    trace.values[84 * WIDTH + WORDS + 32] = Val::from_u8(2);
    rehash(&mut changed, &mut trace, None);
    rebuilt_rejects(&changed, trace);
}
#[test]
fn changed_source_opening_salt_plan_salt_and_selection_salt_cannot_replay_commitments() {
    let (_, _, s, w) = fixture(mask(&[255]), None).unwrap();
    for salt in 0..3 {
        let mut changed = copy_witness(&w, Plan::new(w.plan.table, w.plan.mask, 2, None).unwrap());
        changed.salts[salt][0] += Val::ONE;
        rebuilt_rejects(&s, changed.trace(&s).unwrap());
    }
    let mut fresh = copy_witness(&w, Plan::new(w.plan.table, w.plan.mask, 2, None).unwrap());
    fresh.salts[1][0] += Val::ONE;
    fresh.salts[2][0] += Val::ONE;
    let next = statement::commitments(&s.source, &fresh).unwrap();
    assert_ne!(s.plan, next.plan);
    assert_ne!(s.selected, next.selected);
    assert_eq!(s.source.public_values(), next.source.public_values());
    drop(valid(&next, &fresh));
}
#[test]
fn fresh_backends_reject_request_head_plan_and_commitment_replays_at_the_sdk() {
    let (_, _, s, w) = fixture(mask(&[255]), None).unwrap();
    let b = Backend::new(&s).unwrap();
    let proof = b.prove_with_trace(&s, || w.trace(&s)).unwrap();
    for which in 0..5 {
        let mut changed = s.clone();
        match which {
            0 => changed.source.request[0] ^= 1,
            1 => changed.source.heads[0][80] ^= 1,
            2 => changed.source.key_commitment[0] += Val::ONE,
            3 => changed.plan[0] += Val::ONE,
            _ => changed.source.open_commitment[0] += Val::ONE,
        }
        let fresh = Backend::new(&changed).unwrap();
        assert!(
            p3_uni_stark::verify(
                &fresh.config,
                &changed.air(),
                &proof,
                &changed.public_values()
            )
            .is_err()
        );
    }
}
#[test]
fn all_private_banks_are_immutable_from_row_zero_and_geometry_has_no_claimed_degree() {
    let (_, _, s, w) = fixture(mask(&[0, 255]), Some(2)).unwrap();
    let trace = valid(&s, &w);
    for column in [
        MASK, AGES, AMOUNTS, TABLE, IDS, MATCHES, RETAIN, LIMIT, COMPACT, PRESENCE, SALTS,
    ] {
        assert!(
            trace
                .values
                .as_chunks::<WIDTH>()
                .0
                .iter()
                .all(|row| row[column] == trace.values[column])
        );
    }
    let a = s.air();
    assert_eq!(a.width(), 957);
    assert_eq!(a.num_public_values(), 88);
    assert_eq!(a.main_next_row_columns().len(), 957);
    assert_eq!(a.num_periodic_columns(), 512);
    let arrays = backend::AllocationEstimate::for_width(957);
    assert_eq!(arrays.trace_bytes, 3_919_872);
    assert_eq!(arrays.masked_trace_bytes, 7_880_704);
    assert_eq!(arrays.main_lde_bytes, 63_045_632);
    let (_, report) = backend::analyze(&a).unwrap();
    report.require_target().unwrap();
    assert!(report.degree <= 5);
}

#[test]
fn a_fresh_consistent_plan_for_another_private_table_cannot_open_this_source() {
    let (_, _, source_statement, witness) = fixture(mask(&[255]), None).unwrap();
    let mut table = witness.plan.table;
    table[31] ^= 1;
    let changed = copy_witness(
        &witness,
        Plan::new(table, witness.plan.mask, 2, None).unwrap(),
    );
    let expected = statement::commitments(&source_statement.source, &changed).unwrap();
    let trace = changed.trace(&expected).unwrap();
    let report = check_all_constraints(&expected.air(), &trace, &expected.public_values(), Some(2));
    assert_eq!(report.failures.len(), 1);
    assert_eq!(report.failures[0].row, 15);
    rebuilt_rejects(&expected, trace);
}
