//! Real cached state admission, fresh warm requests and successful formation evidence.
use super::*;
use crate::opening::locking::{encoding as returned, formation};
use crate::opening::selection::encoding::trace::Witness as EW;
use p3_field::PrimeCharacteristicRing;
use std::cell::Cell;

#[test]
fn cold_state_then_two_fresh_warm_queries_form_only_returned_originals_with_actual_proofs() {
    let (state, cold, plain, salt) = super::super::fixture().unwrap();
    let proof = {
        let b = Backend::new(&state).unwrap();
        b.prove_with_trace(&state, || cold.trace(state.source()))
            .unwrap()
    };
    let mut cache = CertificateCache::new(super::super::CACHE_BYTES).unwrap();
    cache
        .admit(&state, Candidate::new(state.clone(), Some(proof)).unwrap())
        .unwrap();
    let charged = cache.owned_bytes();
    let lease = cache.lease(&state).unwrap();
    let mut previous = None;
    for (sql, nonce, parent) in [
        (
            "SELECT amount FROM records WHERE age>=128 OFFSET 1 LIMIT 1 FOR UPDATE SKIP LOCKED",
            [1; 32],
            [0xB1; 32],
        ),
        (
            "SELECT age FROM records WHERE FALSE LIMIT 0 FOR SHARE NOWAIT",
            [2; 32],
            [0xB2; 32],
        ),
    ] {
        let compiled = crate::opening::locking::sql::CompiledLockPlan::compile(sql, nonce).unwrap();
        let (mut expected, mut w) = sql_fixture(&state, plain, salt, &compiled, parent).unwrap();
        if let Some((old, old_salt)) = previous.take() {
            w.old = old;
            w.salts[1] = old_salt;
        } else {
            w.old.tx[1].held[0] = 4;
        }
        pin(&mut expected, &w);
        let lock = Statement::proposed(&expected, &w).unwrap();
        let lp = lease.prove_lock(&expected, &lock, &w).unwrap();
        let ee = returned::statement::Expected::certified(&expected, &lock).unwrap();
        let ew = EW::from_lock(
            &returned::statement::Statement::new(ee.clone(), [Val::ZERO; 4]),
            &w,
            [Val::from_u8(0x62); 4],
        )
        .unwrap();
        if w.plan.limit == 0 {
            assert_eq!(ew.original(), [0; 12]);
        } else {
            assert_eq!(ew.original(), [128, 0, 0, 0, 255, 0, 0, 0, 1, 0, 0, 0]);
        }
        let es = ew.returned_statement(ee.clone());
        let ep = returned::prove_with_trace(
            &ee,
            &es,
            Some(returned::Evidence::Certified {
                lease: &lease,
                proof: &lp,
            }),
            || ew.trace_returned(&es),
        )
        .unwrap();
        let f = formation::from_encoding(ee, es, ew, [0x45; 32]).unwrap();
        let s = &f.statement;
        assert_ne!(*lock.source().expected.request(), state.source().request);
        for bs in &s.expected.bases {
            assert_eq!(bs.expected.request(), *lock.source().expected.request());
        }
        let p = formation::prove_bases(&f, ep).unwrap();
        let proof = formation::prove_with_trace(
            &s.expected,
            s,
            Some(returned::Evidence::Certified {
                lease: &lease,
                proof: &lp,
            }),
            &p,
            || f.local.trace_returned(s),
        )
        .unwrap();
        formation::verify(
            &s.expected,
            s,
            Some(returned::Evidence::Certified {
                lease: &lease,
                proof: &lp,
            }),
            &p,
            &proof,
        )
        .unwrap();
        // Complete independent C_enc is pinned, not merely the same parent.
        let different_w =
            EW::from_lock(s.expected.encoding(), &w, [Val::from_u8(0x63); 4]).unwrap();
        let different_s = different_w.returned_statement(s.expected.producer().clone());
        assert_ne!(different_s.encoded, s.expected.encoding().encoded);
        let changed = formation::from_encoding(
            s.expected.producer().clone(),
            different_s,
            different_w,
            [0x45; 32],
        )
        .unwrap();
        let called = Cell::new(false);
        assert!(
            formation::prove_with_trace(
                &s.expected,
                &changed.statement,
                Some(returned::Evidence::Certified {
                    lease: &lease,
                    proof: &lp
                }),
                &p,
                || {
                    called.set(true);
                    Err(Error::Shape)
                }
            )
            .is_err()
        );
        assert!(!called.get());
        assert!(
            Backend::new(&changed.statement)
                .unwrap()
                .verify(&changed.statement, &proof)
                .is_err()
        );
        let mut wrong = s.expected.clone();
        for (i, bw) in f.bases.iter().enumerate() {
            let old = &wrong.bases[i].expected;
            wrong.bases[i] = bw.statement(
                crate::opening::basis_convolution::statement::Expected::new(
                    old.key().clone(),
                    old.ciphertext().parameter_bytes(),
                    old.ciphertext().bytes(),
                    state.source().request,
                    i,
                )
                .unwrap(),
            );
        }
        let wrong = formation::proposed(wrong, &f.local);
        let called = Cell::new(false);
        assert!(
            formation::prove_with_trace(
                &wrong.expected,
                &wrong,
                Some(returned::Evidence::Certified {
                    lease: &lease,
                    proof: &lp
                }),
                &p,
                || {
                    called.set(true);
                    Err(Error::Shape)
                }
            )
            .is_err()
        );
        assert!(!called.get());
        assert!(
            Backend::new(&wrong)
                .unwrap()
                .verify(&wrong, &proof)
                .is_err()
        );
        previous = Some((w.walk().unwrap().next, w.salts[3]));
    }
    assert_eq!(cache.owned_bytes(), charged);
}
