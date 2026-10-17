//! Public nonsecret fixtures, upstream oracles and genuine/rebuilt proof checks.
use super::{
    air::*,
    matrix,
    statement::Statement,
    trace::{self, Witness},
    *,
};
use crate::{
    backend,
    opening::{poseidon, selection},
    primitive::PublicStatement,
};
use fhe::bfv::{BfvParametersBuilder, Encoding, Plaintext};
use fhe_math::rq::{Poly, Representation, traits::TryConvertFrom};
use fhe_traits::FheEncoder;
use p3_air::{BaseAir, check_all_constraints, check_constraints};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;

fn source_fixture(
    ages: &[u8],
    limit: Option<usize>,
) -> (
    source::Statement,
    source_trace::Witness,
    Selection,
    SelectedWitness,
) {
    let mut mask = [0; 32];
    for age in ages {
        mask[usize::from(*age) / 8] |= 1 << (age % 8);
    }
    selection::fixture(mask, limit).unwrap()
}
fn witness(s: &Selection, w: &SelectedWitness) -> Witness {
    Witness::from_selection(s, w, [Val::from_u8(0x61); 4]).unwrap()
}
fn valid(s: &Statement, w: &Witness) -> RowMajorMatrix<Val> {
    Backend::new(s).unwrap(); // Numeric gate precedes this test's trace allocation.
    let trace = w.trace(s).unwrap();
    check_constraints(&s.air(), &trace, &s.public_values());
    trace
}
fn rebuilt_rejects(s: &Statement, trace: RowMajorMatrix<Val>) {
    assert!(!check_all_constraints(&s.air(), &trace, &s.public_values(), Some(1)).is_ok());
    let backend = Backend::new(s).unwrap();
    if let Ok(proof) = p3_uni_stark::prove(&backend.config, &s.air(), trace, &s.public_values()) {
        assert!(Backend::new(s).unwrap().verify(s, &proof).is_err());
    }
}
fn packed(w: &Witness) -> Vec<u64> {
    let mut v = vec![0; matrix::N];
    for (i, value) in w.original().into_iter().enumerate() {
        v[matrix::SLOTS[i]] = value;
    }
    v
}
fn upstream(v: &[u64]) -> Vec<u64> {
    let parameters = BfvParametersBuilder::new()
        .set_degree(matrix::N)
        .set_plaintext_modulus(matrix::T)
        .set_moduli(&[
            8796092858369,
            8796092792833,
            17592186028033,
            17592185438209,
            17592184717313,
        ])
        .set_variance(10)
        .build_arc()
        .unwrap();
    let plain = Plaintext::try_encode(v, Encoding::simd(), &parameters).unwrap();
    let poly = Poly::try_convert_from(
        &plain,
        parameters.context_at_level(0).unwrap(),
        false,
        Representation::PowerBasis,
    )
    .unwrap();
    poly.coefficients().row(0).to_vec()
}
fn replace_coefficients(s: &mut Statement, t: &mut RowMajorMatrix<Val>, m: &[u64]) {
    for (r, row) in t.values.as_chunks_mut::<WIDTH>().0.iter_mut().enumerate() {
        for l in 0..16 {
            let value = m[r * 16 + l];
            let w = value * matrix::Q_MOD_T % matrix::T;
            for ((start, len), v) in [(0, 17), (17, 17), (53, 17), (70, 17), (87, 17)]
                .into_iter()
                .zip([
                    value,
                    w,
                    value * matrix::Q_MOD_T / matrix::T,
                    matrix::T - 1 - value,
                    matrix::T - 1 - w,
                ])
            {
                let at = COEFF + l * LANE_BITS + start;
                trace::bits(&mut row[at..at + len], v);
            }
        }
    }
    s.encoded = trace::refresh_hashes(s, t);
}

#[test]
fn all_twelve_public_basis_columns_match_every_pinned_upstream_coefficient() {
    for (k, slot) in matrix::SLOTS.into_iter().enumerate() {
        let mut v = vec![0; matrix::N];
        v[slot] = 1;
        let expected = upstream(&v);
        assert!(
            matrix::coefficients()
                .iter()
                .zip(expected)
                .all(|(a, m)| u64::from(a[k]) == m)
        );
    }
}
#[test]
fn exact_sparse_original_slots_match_the_golden_source_and_all_other_slots_are_zero() {
    let (_, _, s, w) = source_fixture(&[0, 128, 255], Some(4));
    let w = witness(&s, &w);
    let slots = packed(&w);
    let golden = [
        (0, 255),
        (1, 0),
        (2, 255),
        (3, 128),
        (4096, 0),
        (4097, 65535),
        (4098, 256),
        (4099, 255),
        (512, 1),
        (513, 1),
        (514, 1),
        (515, 1),
    ];
    for (i, value) in slots.into_iter().enumerate() {
        assert_eq!(
            value,
            golden
                .iter()
                .find_map(|(slot, v)| (*slot == i).then_some(*v))
                .unwrap_or(0),
            "slot{i}"
        );
    }
}
#[test]
fn every_coefficient_matches_the_real_encoder_for_empty_sparse_full_and_all_n4_limits() {
    for ages in [&[][..], &[0][..], &[255][..], &[0, 128, 255][..]] {
        for limit in 0..=4 {
            let (_, _, s, w) = source_fixture(ages, Some(limit));
            let w = witness(&s, &w);
            let actual = w.coefficients();
            let expected = upstream(&packed(&w));
            assert_eq!(actual.len(), 8192);
            for ((m, scaled), expected) in actual.into_iter().zip(expected) {
                assert_eq!(m, expected);
                assert_eq!(scaled, expected * 78307 % 114689);
            }
        }
    }
}
#[test]
fn fixed_shape_and_integer_ranges_cover_all_coefficients_without_secret_periodics() {
    let (_, _, s, w) = source_fixture(&[255], Some(1));
    let w = witness(&s, &w);
    let s = w.statement(&s);
    let a = s.air();
    assert_eq!(
        (a.width(), a.num_public_values(), a.num_periodic_columns()),
        (3580, 100, 205)
    );
    let (p, r) = backend::analyze(&a).unwrap();
    assert!(r.unique_decoding_bits >= 128 && r.list_decoding_bits >= 128);
    assert_eq!(
        p.num_batched_functions,
        2 * (WIDTH + 5) + 10 * p.num_quotient_chunks + 10
    );
    let allocation = backend::AllocationEstimate::for_width(WIDTH);
    assert_eq!(allocation.main_lde_bytes, 234946560);
    let trace = valid(&s, &w);
    let actual = w.coefficients();
    for (r, row) in trace.values.as_chunks::<WIDTH>().0.iter().enumerate() {
        for l in 0..16 {
            assert_eq!(
                lane::<Val, _>(row, l, 0).as_canonical_u64(),
                actual[r * 16 + l].0
            );
            assert_eq!(
                lane::<Val, _>(row, l, 1).as_canonical_u64(),
                actual[r * 16 + l].1
            );
        }
    }
}
#[test]
fn genuine_composites_verify_nonempty_and_limit_zero_after_both_prerequisite_proofs() {
    for limit in [0, 2] {
        let (source, sw, selected, w) = source_fixture(&[0, 255], Some(limit));
        let ew = witness(&selected, &w);
        let s = ew.statement(&selected);
        let proof = prove_composite(&source, &sw, &selected, &w, &s, &ew).unwrap();
        verify_composite(&source, &selected, &s, &proof).unwrap();
    }
}
#[test]
fn absent_source_and_wrong_independently_expected_selection_never_credit_encoding() {
    let (source, sw, selected, w) = source_fixture(&[0, 255], Some(2));
    let ew = witness(&selected, &w);
    let s = ew.statement(&selected);
    let mut proof = prove_composite(&source, &sw, &selected, &w, &s, &ew).unwrap();
    let old = proof.selection.source.take();
    assert!(verify_composite(&source, &selected, &s, &proof).is_err());
    proof.selection.source = old;
    let mut changed = selected.clone();
    changed.plan[0] += Val::ONE;
    assert!(verify_composite(&source, &changed, &s, &proof).is_err());
    let mut stale = source.clone();
    stale.request[0] ^= 1;
    assert!(verify_composite(&stale, &selected, &s, &proof).is_err());
}
#[test]
fn rebuilt_alternate_originals_with_a_consistent_encoded_commitment_cannot_open_old_selection() {
    let (_, _, selected, w) = source_fixture(&[0, 255], Some(2));
    let mut ew = witness(&selected, &w);
    ew.tuples[0][2] ^= 1;
    let s = ew.statement(&selected);
    let trace = ew.trace(&s).unwrap();
    rebuilt_rejects(&s, trace);
}
#[test]
fn a_real_upstream_thirteenth_nonzero_slot_is_rejected_even_with_its_complete_rebound_digest() {
    let (_, _, selected, w) = source_fixture(&[0, 255], Some(2));
    let ew = witness(&selected, &w);
    let mut s = ew.statement(&selected);
    let mut trace = valid(&s, &ew);
    let mut forbidden = packed(&ew);
    forbidden[1000] = 1;
    let m = upstream(&forbidden);
    replace_coefficients(&mut s, &mut trace, &m);
    rebuilt_rejects(&s, trace);
}
#[test]
fn coefficient_packing_cannot_replace_the_required_simd_permutation_and_inverse_ntt() {
    let (_, _, selected, w) = source_fixture(&[0, 128, 255], Some(4));
    let ew = witness(&selected, &w);
    let mut s = ew.statement(&selected);
    let mut trace = valid(&s, &ew);
    replace_coefficients(&mut s, &mut trace, &packed(&ew));
    rebuilt_rejects(&s, trace);
}
#[test]
fn rebuilt_nonboolean_quotient_range_slack_and_canonical_residue_attacks_reject() {
    let (_, _, selected, w) = source_fixture(&[0, 255], Some(2));
    let ew = witness(&selected, &w);
    let s = ew.statement(&selected);
    for col in [
        COEFF,
        COEFF + 17,
        COEFF + 34,
        COEFF + 53,
        COEFF + 70,
        COEFF + 87,
    ] {
        let mut trace = valid(&s, &ew);
        trace.values[250 * WIDTH + col] = Val::from_u8(2);
        rebuilt_rejects(&s, trace);
    }
}
#[test]
fn boolean_modular_aliases_cannot_bypass_canonical_m_and_w_ranges() {
    let (_, _, selected, w) = source_fixture(&[0, 128, 255], Some(4));
    let ew = witness(&selected, &w);
    let s = ew.statement(&selected);
    for field in [0, 1] {
        let mut t = valid(&s, &ew);
        let index = (0..8192)
            .find(|i| {
                let row = &t.values[(i / 16) * WIDTH..(i / 16 + 1) * WIDTH];
                let l = i % 16;
                let v = lane::<Val, _>(row, l, field).as_canonical_u64();
                let quotient =
                    lane::<Val, _>(row, l, if field == 0 { 2 } else { 3 }).as_canonical_u64();
                v + matrix::T < (1 << 17) && quotient > 0
            })
            .expect("nontrivial public fixture must exercise a canonical alias");
        let row = &mut t.values[(index / 16) * WIDTH..(index / 16 + 1) * WIDTH];
        let l = index % 16;
        let value = lane::<Val, _>(row, l, field).as_canonical_u64() + matrix::T;
        let mut fields: [u64; 6] =
            core::array::from_fn(|f| lane::<Val, _>(row, l, f).as_canonical_u64());
        fields[field] = value;
        if field == 0 {
            fields[2] -= 1;
            fields[3] += matrix::Q_MOD_T;
        } else {
            fields[3] -= 1;
        }
        fields[4 + field] = (matrix::T as i64 - 1 - value as i64).rem_euclid(1 << 17) as u64;
        for ((start, len), v) in [(0, 17), (17, 17), (34, 19), (53, 17), (70, 17), (87, 17)]
            .into_iter()
            .zip(fields)
        {
            assert!(v < (1 << len));
            let at = COEFF + l * LANE_BITS + start;
            trace::bits(&mut row[at..at + len], v);
        }
        let mut forged = s.clone();
        forged.encoded = trace::refresh_hashes(&forged, &mut t);
        rebuilt_rejects(&forged, t);
    }
}
#[test]
fn rebuilt_current_next_carry_and_source_checkpoint_substitutions_reject() {
    let (_, _, selected, w) = source_fixture(&[0, 255], Some(2));
    let ew = witness(&selected, &w);
    let s = ew.statement(&selected);
    for (row, col) in [
        (0, CARRY),
        (1, CARRY + 7),
        (511, CARRY),
        (1, SOURCE_CP),
        (12, SOURCE_CP + 8),
        (511, ENCODED_CP + 8),
    ] {
        let mut trace = valid(&s, &ew);
        trace.values[row * WIDTH + col] += Val::ONE;
        rebuilt_rejects(&s, trace);
    }
}
#[test]
fn a_genuine_recomputed_last_sponge_cannot_omit_or_replace_the_last_word() {
    let (_, _, selected, w) = source_fixture(&[0, 255], Some(2));
    let ew = witness(&selected, &w);
    let mut s = ew.statement(&selected);
    let mut trace = valid(&s, &ew);
    let row = &mut trace.values[511 * WIDTH..512 * WIDTH];
    let mut input: [Val; 12] = row[2 * P2..2 * P2 + 12].try_into().unwrap();
    input[7] += Val::ONE;
    let output = poseidon::write(&mut row[2 * P2..3 * P2], input);
    s.encoded = output[..4].try_into().unwrap();
    rebuilt_rejects(&s, trace);
}
#[test]
fn immutable_original_identity_salt_and_inactive_prefix_bits_cannot_change_after_opening() {
    let (_, _, selected, w) = source_fixture(&[0, 255], Some(2));
    let ew = witness(&selected, &w);
    let s = ew.statement(&selected);
    for (r, col) in [
        (12, BANK + 3),
        (511, BANK + 27),
        (300, SEL_SALT),
        (300, ENC_SALT),
        (4, BANK + 3 * TUPLE_BITS),
    ] {
        let mut trace = valid(&s, &ew);
        let at = r * WIDTH + col;
        trace.values[at] = Val::ONE - trace.values[at];
        rebuilt_rejects(&s, trace);
    }
}
#[test]
fn fresh_salt_profile_request_and_output_replays_reach_a_fresh_sdk_verifier() {
    let (_, _, selected, w) = source_fixture(&[0, 255], Some(2));
    let mut ew = witness(&selected, &w);
    let s = ew.statement(&selected);
    let b = Backend::new(&s).unwrap();
    let proof = b.prove_with_trace(&s, || ew.trace(&s)).unwrap();
    b.verify(&s, &proof).unwrap();
    ew.encoding_salt[0] += Val::ONE;
    let fresh = ew.statement(&selected);
    assert_ne!(fresh.encoded, s.encoded);
    assert_eq!(fresh.selection.public_values(), s.selection.public_values());
    assert!(
        Backend::new(&fresh)
            .unwrap()
            .verify(&fresh, &proof)
            .is_err()
    );
    let mut changed = s.clone();
    changed.selection.source.request[0] ^= 1;
    assert!(
        Backend::new(&changed)
            .unwrap()
            .verify(&changed, &proof)
            .is_err()
    );
    assert!(
        Backend::new(&selected)
            .unwrap()
            .verify(&selected, &proof)
            .is_err()
    );
}

#[test]
fn public_projection_changes_the_context_but_never_replaces_original_amounts() {
    let (source, _, _, mut selected_witness) = source_fixture(&[0, 255], Some(2));
    let mut expected = None;
    for projection in 0..=3 {
        selected_witness.plan.projection = projection;
        let selected = selection::statement::commitments(&source, &selected_witness).unwrap();
        let ew = witness(&selected, &selected_witness);
        let s = ew.statement(&selected);
        let actual = ew.coefficients();
        if let Some((coefficients, commitment)) = &expected {
            assert_eq!(&actual, coefficients);
            assert_ne!(&s.encoded, commitment);
        } else {
            expected = Some((actual, s.encoded));
        }
        assert_eq!(ew.original()[5], 65535);
    }
}
#[test]
fn changed_expected_values_reject_before_the_encoded_witness_factory_runs() {
    let (_, _, selected, w) = source_fixture(&[0, 255], Some(2));
    let ew = witness(&selected, &w);
    let s = ew.statement(&selected);
    let backend = Backend::new(&s).unwrap();
    let mut changed = s.clone();
    changed.selection.plan[0] += Val::ONE;
    let called = std::cell::Cell::new(false);
    assert!(
        backend
            .prove_with_trace(&changed, || {
                called.set(true);
                Err(crate::backend::Error::Shape)
            })
            .is_err()
    );
    assert!(!called.get());
}

#[test]
fn a_genuine_selection88_encoding_proof_is_not_successful_lockreturn168_evidence() {
    let (_, _, selected, w) = source_fixture(&[0, 255], Some(2));
    let ew = witness(&selected, &w);
    let old = ew.statement(&selected);
    let proof = Backend::new(&old)
        .unwrap()
        .prove_with_trace(&old, || ew.trace(&old))
        .unwrap();
    Backend::new(&old).unwrap().verify(&old, &proof).unwrap();
    let returned = crate::opening::locking::encoding::fixture()
        .unwrap()
        .statement;
    assert_ne!(old.kind(), returned.kind());
    assert!(
        Backend::new(&returned)
            .unwrap()
            .verify(&returned, &proof)
            .is_err()
    );
}
