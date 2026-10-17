//! Explicitly public nonsecret encryption; real prerequisite and rebuilt proof tests.
use super::{air::*, statement::*, trace, *};
use crate::primitive::PublicStatement;
use crate::{backend, opening::poseidon};
use p3_air::{check_all_constraints, check_constraints};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
fn fixture() -> Fixture {
    public_fixture().unwrap()
}
fn valid(f: &Fixture) -> RowMajorMatrix<Val> {
    Backend::new(&f.statement).unwrap();
    let t = f.local.trace(&f.statement).unwrap();
    check_constraints(&f.statement.air(), &t, &f.statement.public_values());
    t
}
fn bits(t: &mut RowMajorMatrix<Val>, j: usize, start: usize, n: usize, v: u64) {
    let at = j / 16 * WIDTH + COEFFICIENTS + j % 16 * LANE_BITS + start;
    for (i, b) in t.values[at..at + n].iter_mut().enumerate() {
        *b = Val::from_u64((v >> i) & 1);
    }
}
fn rebind(s: &mut Statement, t: &mut RowMajorMatrix<Val>) {
    let roots = trace::refresh_hashes(s, t);
    for (i, r) in roots.iter().enumerate().take(5) {
        s.expected.bases[i].result = *r;
    }
    s.expected.encoding.encoded = roots[5];
    s.noise = trace::refresh_hashes(s, t)[6];
    let _ = trace::refresh_hashes(s, t);
}
// Rebuild ALL native P2 cells while deliberately carrying a different W[15].
// Coefficient/range/equation cells remain genuine; only the 0->1 carry link can fail.
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
fn reject(s: &Statement, t: RowMajorMatrix<Val>) {
    assert!(!check_all_constraints(&s.air(), &t, &s.public_values(), Some(1)).is_ok());
    let b = Backend::new(s).unwrap();
    if let Ok(p) = p3_uni_stark::prove(&b.config, &s.air(), t, &s.public_values()) {
        assert!(b.verify(s, &p).is_err());
    }
}
#[test]
fn actual_source_selected_originals_define_sparse_slots_and_all8192_scaled_words() {
    let f = fixture();
    assert_eq!(
        f.encoded.original(),
        [255, 0, 0, 0, 0, 65535, 0, 0, 1, 1, 0, 0]
    );
    let words = f.encoded.coefficients();
    assert_eq!(words.len(), N);
    for (j, (m, w)) in words.into_iter().enumerate() {
        assert!(m < 114689);
        assert_eq!(w, m * 78307 % 114689);
        assert_eq!(w, f.local.w[j]);
    }
}
#[test]
fn genuine_upstream_ciphertext_satisfies_all40960_integer_formation_equations() {
    let f = fixture();
    for i in 0..5 {
        for j in 0..N {
            let b = f.statement.expected.bases[i]
                .expected
                .ciphertext()
                .b_coefficients()[j];
            assert!(b < Q[i]);
            assert_eq!(
                i128::from(b) + f.local.r[i][j]
                    - i128::from(f.local.error[j])
                    - i128::from(DELTA[i]) * i128::from(f.local.w[j])
                    - i128::from(Q[i]) * f.local.k[i][j],
                0
            );
            assert!((-(1i128 << 62)..(1i128 << 62)).contains(&f.local.r[i][j]));
            assert!((-(1i128 << 19)..(1i128 << 19)).contains(&f.local.k[i][j]));
        }
    }
}
#[test]
fn all_seven_exact_producer_openings_and_full_trace_pass_native_constraints() {
    let f = fixture();
    let mut t = valid(&f);
    let roots = trace::refresh_hashes(&f.statement, &mut t);
    for (i, r) in roots.iter().enumerate().take(5) {
        assert_eq!(*r, f.statement.expected.bases[i].result);
        assert_eq!(
            f.statement.contexts()[i],
            f.statement.expected.bases[i].contexts()[1]
        );
    }
    assert_eq!(roots[5], f.statement.expected.encoding.encoded);
    assert_eq!(roots[6], f.statement.noise);
    assert_eq!(
        f.statement.contexts()[5],
        f.statement.expected.encoding.context()
    );
    for st in 0..7 {
        for i in 0..8 {
            assert_eq!(
                t.values[WIDTH + CARRY + st * 8 + i],
                value::<Val, _>(&t.values[..WIDTH], 8 + i, st)
            );
            assert_eq!(t.values[2 * WIDTH + CARRY + st * 8 + i], Val::ZERO);
        }
    }
}
#[test]
fn integer_residual_bounds_exclude_gold_wrap_and_sign_plus20_counterexample() {
    let p = 18446744069414584321i128;
    let (mut lo, mut hi) = (0, 0);
    for i in 0..5 {
        assert_eq!(
            (i128::from(DELTA[i]) * (-114689)).rem_euclid(i128::from(Q[i])),
            1
        );
        let a = -(1i128 << 62)
            - 20
            - i128::from(DELTA[i]) * 114688
            - i128::from(Q[i]) * ((1 << 19) - 1);
        let b = i128::from(Q[i]) - 1 + (1i128 << 62) - 1 + 20 + i128::from(Q[i]) * (1 << 19);
        assert!(a > -p && b < p);
        lo = lo.min(a);
        hi = hi.max(b);
    }
    assert_eq!((lo, hi), (-14835885613567410195, 13835075638878781459));
    assert_eq!(17605069881346 - i128::from(Q[2]) * (-1048575), p);
    assert!(!(-(1i128 << 19)..(1i128 << 19)).contains(&-1048575));
}
#[test]
fn rebuilt_sign_plus20_alias_is_rejected_by_actual_boolean_range_constraints() {
    let f = fixture();
    let mut s = f.statement.clone();
    let mut t = valid(&f);
    let j = N - 1;
    let i = 2;
    let k = -1048575i128;
    let b = i128::from(s.expected.bases[i].expected.ciphertext().b_coefficients()[j]);
    let r = 18446744069414584321i128 - b
        + i128::from(f.local.error[j])
        + i128::from(DELTA[i]) * i128::from(f.local.w[j])
        + i128::from(Q[i]) * k;
    assert!((-(1i128 << 62)..(1i128 << 62)).contains(&r));
    bits(&mut t, j, i * 63, 63, (r + (1i128 << 62)) as u64);
    bits(&mut t, j, 315 + 20 * i, 20, 0);
    t.values[j / 16 * WIDTH + COEFFICIENTS + j % 16 * LANE_BITS + 315 + 20 * i] =
        trace::signed(k + (1 << 19));
    rebind(&mut s, &mut t);
    reject(&s, t);
}
#[test]
fn rebuilt_noise_above_support_cannot_hide_behind_new_roots_and_correct_equations() {
    let f = fixture();
    let mut s = f.statement.clone();
    let mut t = valid(&f);
    for i in 0..5 {
        bits(
            &mut t,
            0,
            i * 63,
            63,
            (f.local.r[i][0] + 21 - i128::from(f.local.error[0]) + (1i128 << 62)) as u64,
        );
    }
    bits(&mut t, 0, 415, 6, 41);
    bits(&mut t, 0, 421, 6, 0);
    t.values[COEFFICIENTS + 421] = -Val::ONE;
    rebind(&mut s, &mut t);
    reject(&s, t);
}
#[test]
fn rebuilt_plaintext_modulus_word_cannot_use_negative_slack_and_rebound_encoding() {
    let f = fixture();
    let mut s = f.statement.clone();
    let mut t = valid(&f);
    let j = 15;
    for (i, delta) in DELTA.iter().enumerate() {
        let r = f.local.r[i][j] + (114689 - i128::from(f.local.w[j])) * i128::from(*delta);
        assert!((-(1i128 << 62)..(1i128 << 62)).contains(&r));
        bits(&mut t, j, i * 63, 63, (r + (1i128 << 62)) as u64);
    }
    bits(&mut t, j, 427, 17, 114689);
    bits(&mut t, j, 444, 17, 0);
    t.values[COEFFICIENTS + j * LANE_BITS + 444] = -Val::ONE;
    rebind(&mut s, &mut t);
    reject(&s, t);
}
#[test]
fn coherent_one_basis_noise_substitution_fails_shared_e_equation() {
    let f = fixture();
    let mut s = f.statement.clone();
    let mut t = valid(&f);
    bits(
        &mut t,
        8,
        63,
        63,
        (f.local.r[1][8] + 1 + (1i128 << 62)) as u64,
    );
    rebind(&mut s, &mut t);
    reject(&s, t);
}
#[test]
fn coherent_last_coefficient_quotient_and_scaled_word_changes_fail_raw_sdk() {
    let f = fixture();
    let j = N - 1;
    for mode in 0..2 {
        let mut s = f.statement.clone();
        let mut t = valid(&f);
        if mode == 0 {
            bits(
                &mut t,
                j,
                395,
                20,
                (f.local.k[4][j] + 1 + (1i128 << 19)) as u64,
            );
        } else {
            // Keep every integer equation valid while changing the LAST canonical W.
            // Rebound C_R/noise cannot authorize changing the independently fixed C_enc.
            let original_encoding = s.expected.encoding.encoded;
            let w = (f.local.w[j] + 1) % 114689;
            let delta = i128::from(w) - i128::from(f.local.w[j]);
            assert_ne!(delta, 0);
            assert!(w < 114689 && 114688 - w < (1 << 17));
            bits(&mut t, j, 427, 17, w);
            bits(&mut t, j, 444, 17, 114688 - w);
            for i in 0..5 {
                let r = f.local.r[i][j] + i128::from(DELTA[i]) * delta;
                assert!((-(1i128 << 62)..(1i128 << 62)).contains(&r));
                assert_eq!(
                    i128::from(s.expected.bases[i].expected.ciphertext().b_coefficients()[j]) + r
                        - i128::from(f.local.error[j])
                        - i128::from(DELTA[i]) * i128::from(w)
                        - i128::from(Q[i]) * f.local.k[i][j],
                    0
                );
                bits(&mut t, j, i * 63, 63, (r + (1i128 << 62)) as u64);
            }
            rebind(&mut s, &mut t);
            let changed_encoding = s.expected.encoding.encoded;
            assert_ne!(changed_encoding, original_encoding);
            s.expected.encoding.encoded = original_encoding;
            s.noise = trace::refresh_hashes(&s, &mut t)[6];
            let _ = trace::refresh_hashes(&s, &mut t);
            // Existing AIR assertions have no SDK labels. Isolate the final C_enc
            // digest equations by full-row report and a coherent claim-only repair.
            let report = check_all_constraints(&s.air(), &t, &s.public_values(), Some(5));
            assert!(!report.is_ok() && report.failures.len() <= 4);
            assert!(
                report
                    .failures
                    .iter()
                    .all(|f| f.row == backend::TRACE_HEIGHT - 1)
            );
            let mut repaired_statement = s.clone();
            repaired_statement.expected.encoding.encoded = changed_encoding;
            let mut repaired_trace = t.clone();
            repaired_statement.noise =
                trace::refresh_hashes(&repaired_statement, &mut repaired_trace)[6];
            let _ = trace::refresh_hashes(&repaired_statement, &mut repaired_trace);
            check_constraints(
                &repaired_statement.air(),
                &repaired_trace,
                &repaired_statement.public_values(),
            );
            drop(repaired_trace);
            reject(&s, t);
            continue;
        }
        rebind(&mut s, &mut t);
        reject(&s, t);
    }
}
#[test]
fn carry_initialization_capture_clearing_and_private_salt_hold_are_mandatory() {
    let f = fixture();
    let mut s = f.statement.clone();
    let mut t = valid(&f);
    let roots = wrong_carry_hashes(&s, &mut t);
    s.expected.encoding.encoded = roots[5];
    assert_ne!(
        s.expected.encoding.encoded,
        f.statement.expected.encoding.encoded
    );
    s.noise = wrong_carry_hashes(&s, &mut t)[6];
    let _ = wrong_carry_hashes(&s, &mut t);
    reject(&s, t);

    let f = fixture();
    for (r, c) in [
        (0, CARRY),
        (1, CARRY + 47),
        (2, CARRY + 48),
        (511, SALTS + 3),
    ] {
        let mut t = valid(&f);
        t.values[r * WIDTH + c] += Val::ONE;
        reject(&f.statement, t);
    }
}
#[test]
fn idle_third_permutation_and_final_public_noise_root_remain_constrained() {
    let f = fixture();
    let mut t = valid(&f);
    t.values[2 * WIDTH + 2 * poseidon::WIDTH + 12] += Val::ONE;
    reject(&f.statement, t);
    let mut s = f.statement.clone();
    s.noise[3] += Val::ONE;
    reject(&s, f.local.trace(&s).unwrap());
}
#[test]
fn malformed_source_foreign_database_and_duplicate_basis_reject_total_expected_admission() {
    let f = fixture();
    let mut e = f.statement.expected.clone();
    let mut descriptor = e.bases[0].expected.key().expected.descriptor.clone();
    descriptor.database[0] ^= 1;
    let foreign = f.key.statement(descriptor);
    for (i, w) in f.bases.iter().enumerate() {
        let previous = &e.bases[i].expected;
        let input = basis::statement::Expected::new(
            foreign.clone(),
            previous.ciphertext().parameter_bytes(),
            previous.ciphertext().bytes(),
            previous.request(),
            i,
        )
        .unwrap();
        e.bases[i] = w.statement(input);
    }
    assert!(e.validate().is_err()); // All five key identities agree; only source DB is foreign.
    for n in 0..5 {
        let mut e = f.statement.expected.clone();
        match n {
            0 => {
                e.source.packets[1].pop();
            }
            1 => e.source.relation = crate::opening::Relation::StateCertificate,
            2 => e.bases.swap(0, 1),
            3 => e.bases[4] = e.bases[3].clone(),
            _ => e.source.heads[0][8] ^= 1,
        }
        assert!(e.validate().is_err());
    }
}
#[test]
fn changing_request_key_or_full_ciphertext_between_bases_has_no_matrix_injection_path() {
    let f = fixture();
    let other = fixture();
    assert_ne!(
        f.statement.expected.bases[0].expected.ciphertext().bytes(),
        other.statement.expected.bases[0]
            .expected
            .ciphertext()
            .bytes()
    );
    for n in 0..3 {
        let mut e = f.statement.expected.clone();
        let old = e.bases[3].expected.clone();
        let mut key = old.key().clone();
        let request = if n == 0 { [0x99; 32] } else { old.request() };
        if n == 1 {
            key.transformed[0] += Val::ONE;
        }
        let bytes = if n == 2 {
            other.statement.expected.bases[0]
                .expected
                .ciphertext()
                .bytes()
        } else {
            old.ciphertext().bytes()
        };
        e.bases[3].expected = basis::statement::Expected::new(
            key,
            old.ciphertext().parameter_bytes(),
            bytes,
            request,
            3,
        )
        .unwrap();
        assert!(e.validate().is_err());
    }
}
#[test]
fn missing_all_evidence_or_changed_expected_reject_before_local_factory() {
    let f = fixture();
    let p = Prerequisites {
        encoding: None,
        key: None,
        bases: Vec::new(),
    };
    let called = std::cell::Cell::new(false);
    assert!(
        prove_with_trace(&f.statement.expected, &f.statement, &p, || {
            called.set(true);
            Err(Error::Shape)
        })
        .is_err()
    );
    assert!(!called.get());
    let mut e = f.statement.expected.clone();
    e.selection.selected[0] += Val::ONE;
    assert!(
        prove_with_trace(&e, &f.statement, &p, || {
            called.set(true);
            Err(Error::Shape)
        })
        .is_err()
    );
    assert!(!called.get());
}
#[test]
fn genuine_full_composite_and_foreign_genuine_encoding_obey_source_first_boundary() {
    let f = fixture();
    let mut p = prove_inputs(&f).unwrap();
    let proof = prove_with_trace(&f.statement.expected, &f.statement, &p, || {
        f.local.trace(&f.statement)
    })
    .unwrap();
    verify(&f.statement.expected, &f.statement, &p, &proof).unwrap();
    let rejects_before_local_factory = |p: &Prerequisites| {
        let called = std::cell::Cell::new(false);
        assert!(
            prove_with_trace(&f.statement.expected, &f.statement, p, || {
                called.set(true);
                Err(Error::Shape)
            })
            .is_err()
        );
        assert!(!called.get());
    };
    p.bases.swap(0, 1);
    assert!(verify(&f.statement.expected, &f.statement, &p, &proof).is_err());
    rejects_before_local_factory(&p);
    p.bases.swap(0, 1);
    let key = p.key.take().unwrap();
    assert!(verify(&f.statement.expected, &f.statement, &p, &proof).is_err());
    rejects_before_local_factory(&p);
    p.key = Some(key);
    let base = p.bases.pop().unwrap();
    assert!(verify(&f.statement.expected, &f.statement, &p, &proof).is_err());
    rejects_before_local_factory(&p);
    p.bases.push(base);
    let other = fixture();
    let e = &other.statement.expected;
    let foreign = encoding::prove_composite(
        &e.source,
        &other.source,
        &e.selection,
        &other.selected,
        &e.encoding,
        &other.encoded,
    )
    .unwrap();
    encoding::verify_composite(&e.source, &e.selection, &e.encoding, &foreign).unwrap();
    p.encoding = Some(foreign);
    let called = std::cell::Cell::new(false);
    assert!(
        prove_with_trace(&f.statement.expected, &f.statement, &p, || {
            called.set(true);
            Err(Error::Shape)
        })
        .is_err()
    );
    assert!(!called.get());
}
#[test]
fn fresh_noise_salt_and_exact_profile_output_replay_reach_fresh_sdk_verifier() {
    let mut f = fixture();
    let s = f.statement.clone();
    let b = Backend::new(&s).unwrap();
    let proof = b.prove_with_trace(&s, || f.local.trace(&s)).unwrap();
    b.verify(&s, &proof).unwrap();
    drop(b);
    f.local.salts[6][0] += Val::ONE;
    let fresh = f.local.statement(s.expected.clone());
    assert_ne!(fresh.noise, s.noise);
    assert!(
        Backend::new(&fresh)
            .unwrap()
            .verify(&fresh, &proof)
            .is_err()
    );
    assert!(
        Backend::new(&s.expected.encoding)
            .unwrap()
            .verify(&s.expected.encoding, &proof)
            .is_err()
    );
}
#[test]
fn fixed_geometry_and_signed_zero_noise_support_do_not_certify_resources_or_entropy() {
    assert_eq!((WIDTH, PERIODICS, PUBLIC_VALUES), (12752, 592, 44));
    let a = backend::AllocationEstimate::for_width(WIDTH);
    assert_eq!(
        (a.trace_bytes, a.masked_trace_bytes, a.main_lde_bytes),
        (52232192, 104505344, 836042752)
    );
    assert_eq!(trace::centered(Val::ZERO).unwrap(), 0);
    assert!(trace::centered(Val::from_u64(1 << 62)).is_err());
    assert!(trace::centered(-Val::from_u64(1 << 62)).is_ok());
}
