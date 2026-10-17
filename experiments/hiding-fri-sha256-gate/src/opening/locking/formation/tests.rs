//! Public nonsecret actual producers, full upstream ciphertexts, and rebuilt attacks.
use super::{statement::*, *};
use crate::opening::{
    local_formation::{air::*, trace},
    poseidon,
};
use crate::primitive::PublicStatement;
use p3_air::{check_all_constraints, check_constraints};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use std::cell::Cell;

fn fixture() -> CanonicalFixture {
    canonical_fixture(false).unwrap()
}
fn valid(f: &Fixture) -> RowMajorMatrix<Val> {
    let t = f.local.trace_returned(&f.statement).unwrap();
    check_constraints(&f.statement.air(), &t, &f.statement.public_values());
    t
}
fn bits(t: &mut RowMajorMatrix<Val>, j: usize, start: usize, n: usize, v: u64) {
    let at = j / 16 * WIDTH + COEFFICIENTS + j % 16 * LANE_BITS + start;
    for (i, b) in t.values[at..at + n].iter_mut().enumerate() {
        *b = Val::from_u64((v >> i) & 1);
    }
}
fn reject(s: &Statement, t: RowMajorMatrix<Val>) {
    assert!(!check_all_constraints(&s.air(), &t, &s.public_values(), Some(1)).is_ok());
    let b = Backend::new(s).unwrap();
    if let Ok(p) = p3_uni_stark::prove(&b.config, &s.air(), t, &s.public_values()) {
        assert!(b.verify(s, &p).is_err());
    }
}
fn rebind(s: &mut Statement, t: &mut RowMajorMatrix<Val>) {
    let roots = trace::refresh_returned(s, t);
    for (i, r) in roots.iter().enumerate().take(5) {
        s.expected.bases[i].result = *r;
    }
    s.expected.encoding.encoded = roots[5];
    s.noise = trace::refresh_returned(s, t)[6];
    let _ = trace::refresh_returned(s, t);
}
fn no_factory(
    e: &Expected,
    s: &Statement,
    parent: Option<returned::Evidence<'_, '_>>,
    p: &Prerequisites,
) {
    let called = Cell::new(false);
    assert!(
        prove_with_trace(e, s, parent, p, || {
            called.set(true);
            Err(Error::Shape)
        })
        .is_err()
    );
    assert!(!called.get());
}
#[test]
fn skip_and_offset_returned_originals_not_owned_or_projection_define_all8192_words() {
    let f = fixture();
    let walk = f.lock.walk().unwrap();
    assert_eq!(walk.visit.iter().filter(|&&x| x).count(), 2);
    assert_eq!(walk.returned.iter().filter(|&&x| x).count(), 1);
    // Fixture skips locked ordinal0, owns the OFFSET ordinal2, returns ordinal3.
    assert_eq!(
        f.f.encoded.original(),
        [128, 0, 0, 0, 255, 0, 0, 0, 1, 0, 0, 0]
    );
    assert_eq!(
        f.f.statement.contexts()[5],
        f.f.statement.expected.encoding.context()
    );
    assert_eq!(f.f.encoded.coefficients().len(), N);
    let mut t = valid(&f.f);
    let words = f.f.encoded.coefficients();
    for (j, &(_, w)) in words.iter().enumerate() {
        assert_eq!(f.f.local.w[j], w);
        for (i, &delta) in DELTA.iter().enumerate() {
            assert_eq!(
                i128::from(
                    f.f.statement.expected.bases[i]
                        .expected
                        .ciphertext()
                        .b_coefficients()[j]
                ) + f.f.local.r[i][j]
                    - i128::from(f.f.local.error[j])
                    - i128::from(delta) * i128::from(w),
                i128::from(Q[i]) * f.f.local.k[i][j]
            );
        }
    }
    assert_eq!(
        trace::refresh_returned(&f.f.statement, &mut t)[5],
        f.f.statement.expected.encoding.encoded
    );
}
#[test]
fn genuine_canonical_nonempty_and_limit_zero_form_actual_ciphertexts_with_real_prerequisites() {
    for empty in [false, true] {
        let f = canonical_fixture(empty).unwrap();
        if empty {
            assert_eq!(f.f.encoded.original(), [0; 12]);
            assert!(f.f.local.w.iter().all(|&w| w == 0));
        }
        let (parent, p) = prove_canonical(&f).unwrap();
        let s = &f.f.statement;
        let proof = prove_with_trace(
            &s.expected,
            s,
            Some(returned::Evidence::Canonical(&parent)),
            &p,
            || f.f.local.trace_returned(s),
        )
        .unwrap();
        verify(
            &s.expected,
            s,
            Some(returned::Evidence::Canonical(&parent)),
            &p,
            &proof,
        )
        .unwrap();
        // Same actual W/key/full ciphertext, fresh control parent: recomputing
        // legitimate downstream contexts cannot replay the old completed proof.
        let mut changed_parent = f.parent.clone();
        changed_parent.parent[0] ^= 1;
        let raw = super::super::statement::proposed(&changed_parent, &f.lock).unwrap();
        let parent_expected =
            returned::statement::Expected::canonical(&changed_parent, &raw).unwrap();
        let encoding = f.f.encoded.returned_statement(parent_expected.clone());
        let expected = Expected::new(parent_expected, encoding, s.expected.bases.clone()).unwrap();
        let changed = proposed(expected, &f.f.local);
        let native = f.f.local.trace_returned(&changed).unwrap();
        check_constraints(&changed.air(), &native, &changed.public_values());
        drop(native);
        no_factory(
            &changed.expected,
            &changed,
            Some(returned::Evidence::Canonical(&parent)),
            &p,
        );
        assert!(
            Backend::new(&changed)
                .unwrap()
                .verify(&changed, &proof)
                .is_err()
        );
        let mut changed = s.clone();
        changed.noise[0] += Val::ONE;
        assert!(
            Backend::new(&changed)
                .unwrap()
                .verify(&changed, &proof)
                .is_err()
        );
        let mut changed = s.clone();
        changed.expected.encoding.encoded[3] += Val::ONE;
        no_factory(
            &s.expected,
            &changed,
            Some(returned::Evidence::Canonical(&parent)),
            &p,
        );
        assert!(
            Backend::new(&changed)
                .unwrap()
                .verify(&changed, &proof)
                .is_err()
        );
    }
}
#[test]
fn missing_corrupt_swapped_and_foreign_prerequisites_reject_before_local_factory() {
    let f = fixture();
    let (parent, mut p) = prove_canonical(&f).unwrap();
    let s = &f.f.statement;
    no_factory(&s.expected, s, None, &p);
    let encoded = p.encoding.take();
    no_factory(
        &s.expected,
        s,
        Some(returned::Evidence::Canonical(&parent)),
        &p,
    );
    p.encoding = encoded;
    let key = p.key.take();
    no_factory(
        &s.expected,
        s,
        Some(returned::Evidence::Canonical(&parent)),
        &p,
    );
    p.key = key;
    let last = p.bases.pop().unwrap();
    no_factory(
        &s.expected,
        s,
        Some(returned::Evidence::Canonical(&parent)),
        &p,
    );
    p.bases.push(last);
    p.bases.swap(0, 1);
    no_factory(
        &s.expected,
        s,
        Some(returned::Evidence::Canonical(&parent)),
        &p,
    );
    p.bases.swap(0, 1);
    let proof = p.encoding.as_mut().unwrap();
    proof.degree_bits += 1;
    no_factory(
        &s.expected,
        s,
        Some(returned::Evidence::Canonical(&parent)),
        &p,
    );
    p.encoding.as_mut().unwrap().degree_bits -= 1;
    // A different genuine parent+encoding is valid evidence, but not THIS Expected.
    let other = canonical_fixture(true).unwrap();
    let (_, foreign_parent) =
        super::super::prove_composite(&other.parent, &other.source, &other.lock).unwrap();
    let foreign_statement = super::super::statement::proposed(&other.parent, &other.lock).unwrap();
    super::super::verify_composite(&other.parent, &foreign_statement, &foreign_parent).unwrap();
    no_factory(
        &s.expected,
        s,
        Some(returned::Evidence::Canonical(&foreign_parent)),
        &p,
    );
    let other = fixture();
    let foreign_s = other.f.statement.expected.bases[0].expected.key();
    let foreign_key = {
        let b = Backend::new(foreign_s).unwrap();
        let p = b
            .prove_with_trace(foreign_s, || other.f.key.trace(foreign_s))
            .unwrap();
        b.verify(foreign_s, &p).unwrap();
        p
    };
    assert_ne!(
        foreign_s.public_values(),
        s.expected.bases[0].expected.key().public_values()
    );
    let genuine_key = p.key.replace(foreign_key);
    no_factory(
        &s.expected,
        s,
        Some(returned::Evidence::Canonical(&parent)),
        &p,
    );
    p.key = genuine_key;
    // Original evidence remains usable after every rejected attempt.
    verify_inputs(
        &s.expected,
        Some(returned::Evidence::Canonical(&parent)),
        &p,
    )
    .unwrap();
}
#[test]
fn complete_child_root_and_each_independent_expected_field_are_checked_before_factory() {
    let f = fixture();
    let s = &f.f.statement;
    let p = Prerequisites {
        encoding: None,
        key: None,
        bases: Vec::new(),
    };
    for field in 0..9 {
        let mut changed = s.clone();
        match field {
            0 => changed.expected.encoding.encoded[0] += Val::ONE,
            1 => changed.expected.bases[0].result[0] += Val::ONE,
            2 => changed.expected.bases.swap(0, 1),
            _ => {
                let raw = changed.expected.producer.lock();
                let mut e = raw.expected.clone();
                match field {
                    3 => e.parent[0] ^= 1,
                    4 => e.old[0] += Val::ONE,
                    5 => e.plan[0] += Val::ONE,
                    6 => e.source.open_commitment[0] += Val::ONE,
                    7 => e.source.packets[1].truncate(1),
                    _ => e.source.request[0] ^= 1,
                }
                let parent = super::super::statement::proposed(&e, &f.lock).unwrap();
                let expected = returned::statement::Expected::canonical(&e, &parent);
                if field == 7 {
                    assert!(expected.is_err());
                    continue;
                }
                let expected = expected.unwrap();
                changed.expected.producer = expected.clone();
                changed.expected.encoding = f.f.encoded.returned_statement(expected);
            }
        }
        no_factory(&s.expected, &changed, None, &p);
    }
}
#[test]
fn independently_different_database_key_request_and_full_ciphertext_cannot_mix_five_bases() {
    let f = fixture();
    let old = &f.f.statement.expected;
    let other = fixture();
    assert_ne!(
        old.bases[0].expected.ciphertext().bytes(),
        other.f.statement.expected.bases[0]
            .expected
            .ciphertext()
            .bytes()
    );
    for field in 0..5 {
        let mut e = old.clone();
        if field == 0 {
            let mut descriptor = e.bases[0].expected.key().expected.descriptor.clone();
            descriptor.database[0] ^= 1;
            let key = f.f.key.statement(descriptor);
            for (i, w) in f.f.bases.iter().enumerate() {
                let previous = &e.bases[i].expected;
                e.bases[i] = w.statement(
                    basis::statement::Expected::new(
                        key.clone(),
                        previous.ciphertext().parameter_bytes(),
                        previous.ciphertext().bytes(),
                        previous.request(),
                        i,
                    )
                    .unwrap(),
                );
            }
        } else {
            let i = 4;
            let previous = &e.bases[i].expected;
            let mut request = previous.request();
            if field == 1 {
                request[0] ^= 1;
            }
            let key = if field == 2 {
                other.f.statement.expected.bases[0].expected.key().clone()
            } else {
                previous.key().clone()
            };
            let ct = if field == 3 {
                other.f.statement.expected.bases[0].expected.ciphertext()
            } else {
                previous.ciphertext()
            };
            let basis = if field == 4 { 3 } else { i };
            e.bases[i] = f.f.bases[i].statement(
                basis::statement::Expected::new(
                    key,
                    ct.parameter_bytes(),
                    ct.bytes(),
                    request,
                    basis,
                )
                .unwrap(),
            );
        }
        assert!(e.validate().is_err());
    }
}
#[test]
fn genuine_alternate_full_ciphertext_with_same_key_needs_its_own_basis_proofs() {
    let f = fixture();
    let (parent, p) = prove_canonical(&f).unwrap();
    let old = &f.f.statement.expected;
    let (first, _, key) = basis::public_fixture_from_original(
        basis::PublicFixtureInput {
            original: f.f.encoded.original(),
            descriptor: old.bases[0].expected.key().expected.descriptor.clone(),
            request: *old.producer.lock().expected.request(),
            caller_noise_seed: [0x46; 32],
        },
        f.f.local.salts[0],
        f.f.key.salts,
        0,
    )
    .unwrap();
    assert_eq!(
        first.expected.key().public_values(),
        old.bases[0].expected.key().public_values()
    );
    assert_eq!(key.coefficients, f.f.key.coefficients);
    assert_ne!(
        first.expected.ciphertext().bytes(),
        old.bases[0].expected.ciphertext().bytes()
    );
    assert_ne!(
        first.expected.ciphertext().evaluations(),
        old.bases[0].expected.ciphertext().evaluations()
    );
    assert_ne!(
        first.expected.ciphertext().b_coefficients(),
        old.bases[0].expected.ciphertext().b_coefficients()
    );
    let mut e = old.clone();
    for (i, w) in f.f.bases.iter().enumerate() {
        e.bases[i] = w.statement(
            basis::statement::Expected::new(
                first.expected.key().clone(),
                first.expected.ciphertext().parameter_bytes(),
                first.expected.ciphertext().bytes(),
                *old.producer.lock().expected.request(),
                i,
            )
            .unwrap(),
        );
    }
    e.validate().unwrap();
    let s = proposed(e, &f.f.local);
    no_factory(
        &s.expected,
        &s,
        Some(returned::Evidence::Canonical(&parent)),
        &p,
    );
}
#[test]
fn final_w_root_cannot_change_even_with_all_integer_equations_and_other_roots_repaired() {
    let f = fixture();
    let mut s = f.f.statement.clone();
    let mut t = valid(&f.f);
    let j = N - 1;
    let old = s.expected.encoding.encoded;
    let w = (f.f.local.w[j] + 1) % 114689;
    let delta = i128::from(w) - i128::from(f.f.local.w[j]);
    assert_ne!(delta, 0);
    bits(&mut t, j, 427, 17, w);
    bits(&mut t, j, 444, 17, 114688 - w);
    for (i, &d) in DELTA.iter().enumerate() {
        let r = f.f.local.r[i][j] + i128::from(d) * delta;
        assert!((-(1i128 << 62)..(1i128 << 62)).contains(&r));
        assert_eq!(
            i128::from(s.expected.bases[i].expected.ciphertext().b_coefficients()[j]) + r
                - i128::from(f.f.local.error[j])
                - i128::from(d) * i128::from(w)
                - i128::from(Q[i]) * f.f.local.k[i][j],
            0
        );
        bits(&mut t, j, i * 63, 63, (r + (1i128 << 62)) as u64);
    }
    rebind(&mut s, &mut t);
    let computed = s.expected.encoding.encoded;
    assert_ne!(old, computed);
    s.expected.encoding.encoded = old;
    s.noise = trace::refresh_returned(&s, &mut t)[6];
    let _ = trace::refresh_returned(&s, &mut t);
    let report = check_all_constraints(&s.air(), &t, &s.public_values(), Some(5));
    assert!(!report.is_ok() && report.failures.len() <= 4);
    assert!(report.failures.iter().all(|f| f.row == 511));
    let mut repaired = s.clone();
    repaired.expected.encoding.encoded = computed;
    let mut repaired_t = t.clone();
    repaired.noise = trace::refresh_returned(&repaired, &mut repaired_t)[6];
    let _ = trace::refresh_returned(&repaired, &mut repaired_t);
    check_constraints(&repaired.air(), &repaired_t, &repaired.public_values());
    drop(repaired_t);
    reject(&s, t);
}
#[test]
fn independent_noise_salt_changes_only_ce_and_idle_gadgets_still_have_real_equations() {
    let f = fixture();
    let original = &f.f.statement;
    let local = Witness {
        r: f.f.local.r.clone(),
        k: f.f.local.k.clone(),
        error: f.f.local.error.clone(),
        w: f.f.local.w.clone(),
        salts: {
            let mut a = f.f.local.salts;
            a[6][0] += Val::ONE;
            a
        },
    };
    let changed = proposed(original.expected.clone(), &local);
    assert_ne!(changed.noise, original.noise);
    assert_eq!(
        changed.expected.encoding.encoded,
        original.expected.encoding.encoded
    );
    assert_eq!(changed.contexts(), original.contexts());
    let t = local.trace_returned(&changed).unwrap();
    check_constraints(&changed.air(), &t, &changed.public_values());
    drop(t);
    let mut t = valid(&f.f);
    t.values[2 * WIDTH + 2 * poseidon::WIDTH + 12] += Val::ONE;
    reject(original, t);
}

fn wrong_carry_hashes(s: &Statement, t: &mut RowMajorMatrix<Val>) -> [[Val; 4]; 7] {
    let contexts = s.contexts();
    let mut cp = [[Val::ZERO; 12]; 7];
    let mut carry = [[Val::ZERO; 8]; 7];
    for (r, row) in t.values.as_chunks_mut::<WIDTH>().0.iter_mut().enumerate() {
        for st in 0..7 {
            row[CP + st * 12..CP + st * 12 + 12].copy_from_slice(&cp[st]);
            row[CARRY + st * 8..CARRY + st * 8 + 8].copy_from_slice(&carry[st]);
            for g in 0..3 {
                let active = r < 2 || g < 2;
                let mut input = [Val::ZERO; 12];
                if active {
                    for (i, v) in input[..8].iter_mut().enumerate() {
                        *v = match (r, g) {
                            (0, 0) => contexts[st][i],
                            (0, 1) => {
                                if i < 4 {
                                    row[SALTS + st * 4 + i]
                                } else {
                                    Val::ZERO
                                }
                            }
                            (0, 2) | (1, 1) => value::<Val, _>(row, i, st),
                            (1, 0) => carry[st][i],
                            (_, 0) => value::<Val, _>(row, i, st),
                            _ => value::<Val, _>(row, i + 8, st),
                        };
                    }
                    if !(r == 0 && g == 0) {
                        input[8..].copy_from_slice(&cp[st][8..]);
                    }
                }
                let out = poseidon::write(
                    &mut row[(st * 3 + g) * poseidon::WIDTH..(st * 3 + g + 1) * poseidon::WIDTH],
                    input,
                );
                if active {
                    cp[st] = out;
                }
            }
            carry[st] = if r == 0 {
                core::array::from_fn(|i| value::<Val, _>(row, i + 8, st))
            } else {
                [Val::ZERO; 8]
            };
            if r == 0 && st == 5 {
                carry[st][7] += Val::ONE;
            }
        }
    }
    core::array::from_fn(|i| cp[i][..4].try_into().unwrap())
}
#[test]
fn coherent_rebound_encoding_carry_still_must_come_from_the_same_ranged_lane() {
    let f = fixture();
    let mut s = f.f.statement.clone();
    let mut t = valid(&f.f);
    let roots = wrong_carry_hashes(&s, &mut t);
    s.expected.encoding.encoded = roots[5];
    assert_ne!(
        s.expected.encoding.encoded,
        f.f.statement.expected.encoding.encoded
    );
    s.noise = wrong_carry_hashes(&s, &mut t)[6];
    let _ = wrong_carry_hashes(&s, &mut t);
    reject(&s, t);
}
#[test]
fn genuine_blocked_parent_is_not_an_empty_success_formation_prerequisite() {
    let mut f = fixture();
    let (parent, p) = prove_canonical(&f).unwrap();
    verify_inputs(
        &f.f.statement.expected,
        Some(returned::Evidence::Canonical(&parent)),
        &p,
    )
    .unwrap();
    // Same authentic source/request, separately pinned NOWAIT intent. No SQL
    // parser decision or actor/head is supplied by a peer in this example.
    f.lock.plan.wait = 1;
    let mut e = f.parent.clone();
    e.plan = crate::opening::commitment::digest(&super::super::statement::plan_fields(&e, &f.lock));
    assert_eq!(f.lock.walk().unwrap().outcome, 2);
    let (raw, blocked) = super::super::prove_composite(&e, &f.source, &f.lock).unwrap();
    super::super::verify_composite(&e, &raw, &blocked).unwrap();
    let ee = returned::statement::Expected::canonical(&e, &raw).unwrap();
    let ew = encoding::trace::Witness::from_lock(
        &returned::statement::Statement::new(ee.clone(), [Val::ZERO; 4]),
        &f.lock,
        [Val::ZERO; 4],
    )
    .unwrap();
    assert_eq!(ew.original(), [0; 12]);
    let es = ew.returned_statement(ee.clone());
    let expected = Expected::new(ee, es, f.f.statement.expected.bases.clone()).unwrap();
    let s = proposed(expected, &f.f.local);
    // Actual Key/Basis and old encoding proofs are genuine; the required
    // successful encoding of THIS blocked Return168 is absent and cannot exist.
    no_factory(
        &s.expected,
        &s,
        Some(returned::Evidence::Canonical(&blocked)),
        &p,
    );
}
