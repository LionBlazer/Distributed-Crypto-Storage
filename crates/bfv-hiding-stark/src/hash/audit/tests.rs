//! Observable audit lifecycle over the real fixed challenger.
use super::*;
use crate::{Val, hash::Challenger};
use p3_challenger::{CanObserve, CanSample};
use p3_field::PrimeCharacteristicRing;
use sha2::{Digest, Sha512};

#[test]
fn real_forks_retain_distinct_prefixes_and_actual_draw_preimages() {
    let ((left_value, right_value), traces) = capture(|| {
        let mut left = Challenger::new();
        left.observe(Val::ONE);
        let mut right = left.clone();
        left.observe(Val::TWO);
        right.observe(Val::from_u32(3));
        let left_value: Val = left.sample();
        let right_value: Val = right.sample();
        (left_value, right_value)
    })
    .unwrap();
    assert_eq!(traces.len(), 2);
    assert_ne!(traces[0].prefix(), traces[1].prefix());
    assert_ne!(left_value, right_value);
    for trace in traces {
        assert_eq!(trace.draws().len(), 1);
        let draw = &trace.draws()[0];
        let mut raw = trace.prefix()[..draw.prefix_len()].to_vec();
        raw.push(4);
        raw.extend(draw.counter().to_le_bytes());
        raw.extend(draw.retry().to_le_bytes());
        assert_eq!(Sha512::digest(raw).as_slice(), draw.digest());
        assert_eq!(draw.counter(), 0);
        assert_eq!(draw.retry(), 0);
    }
}

#[test]
fn returning_or_unwinding_closes_recording_and_nested_capture_preserves_its_parent() {
    let ((mut escaped, nested), traces) = capture(|| {
        let mut challenger = Challenger::new();
        challenger.observe(Val::ONE);
        let nested = capture(|| panic!("nested body must not execute"));
        (challenger, nested)
    })
    .unwrap();
    assert!(matches!(nested, Err(Error::Nested)));
    let bytes = traces[0].prefix().to_vec();
    escaped.observe(Val::TWO);
    let _: Val = escaped.sample();
    let mut escaped_fork = escaped.clone();
    let _: Val = escaped_fork.sample();
    assert_eq!(traces[0].prefix(), bytes);
    assert!(
        std::panic::catch_unwind(|| {
            let _ = capture(|| {
                let _challenger = Challenger::new();
                panic!("audit scope unwind");
            });
        })
        .is_err()
    );
    assert!(capture(Challenger::new).is_ok());
}

#[test]
fn concurrent_scopes_are_isolated_and_an_enrolled_fork_keeps_its_worker_history() {
    let (ready_send, ready_receive) = std::sync::mpsc::channel();
    let (release_send, release_receive) = std::sync::mpsc::channel();
    let timeout = std::time::Duration::from_secs(5);
    let (left, right) = std::thread::scope(|scope| {
        let other = scope.spawn(move || {
            capture(|| {
                let mut challenger = Challenger::new();
                challenger.observe(Val::from_u32(3));
                ready_send.send(()).unwrap();
                release_receive.recv_timeout(timeout).unwrap();
                let value: Val = challenger.sample();
                value
            })
            .unwrap()
        });
        let left = capture(|| {
            let mut challenger = Challenger::new();
            challenger.observe(Val::ONE);
            let mut fork = challenger.clone();
            scope
                .spawn(move || {
                    fork.observe(Val::TWO);
                    ready_receive.recv_timeout(timeout).unwrap();
                    release_send.send(()).unwrap();
                    let value: Val = fork.sample();
                    value
                })
                .join()
                .unwrap()
        })
        .unwrap();
        (left, other.join().unwrap())
    });
    assert_eq!(left.1.len(), 2);
    assert!(left.1[0].draws().is_empty());
    assert_eq!(left.1[1].draws().len(), 1);
    assert_eq!(right.1.len(), 1);
    assert_eq!(right.1[0].draws().len(), 1);
    let mut reference = Challenger::new();
    reference.observe(Val::ONE);
    reference.observe(Val::TWO);
    let expected: Val = reference.sample();
    assert_eq!(left.0, expected);
    assert_ne!(left.0, right.0);
    assert_ne!(left.1[1].prefix(), right.1[0].prefix());
}

#[test]
fn audit_limits_fail_observation_without_changing_the_challenge() {
    let mut reference = Challenger::new();
    reference.observe(Val::ONE);
    let expected: Val = reference.sample();
    let mut sampled = Val::ZERO;
    let result = capture(|| {
        for _ in 0..=MAX_TRACES {
            let _challenger = Challenger::new();
        }
        let mut challenger = Challenger::new();
        challenger.observe(Val::ONE);
        sampled = challenger.sample();
    });
    assert!(matches!(result, Err(Error::Limit)));
    assert_eq!(sampled, expected);
    assert!(capture(Challenger::new).is_ok());
}

fn audit_sample(word: u32) -> Val {
    let mut challenger = Challenger::new();
    challenger.observe(Val::from_u32(word));
    challenger.sample()
}

#[test]
fn join_enrolls_new_worker_challengers_and_keeps_concurrent_captures_distinct() {
    let barrier = std::sync::Barrier::new(2);
    let run = |word: u32| {
        capture(|| {
            barrier.wait();
            crate::hash::join(
                || {
                    assert!(matches!(
                        capture(|| -> () { panic!("nested body") }),
                        Err(Error::Nested)
                    ));
                    audit_sample(word)
                },
                || audit_sample(word + 1),
            )
        })
        .unwrap()
    };
    let (left, right) = std::thread::scope(|scope| {
        let other = scope.spawn(|| run(20));
        (run(10), other.join().unwrap())
    });
    assert_eq!(left.0, (audit_sample(10), audit_sample(11)));
    assert_eq!(right.0, (audit_sample(20), audit_sample(21)));
    for traces in [&left.1, &right.1] {
        assert_eq!(traces.len(), 2);
        assert!(traces.iter().all(|trace| trace.draws().len() == 1));
    }
    assert!(
        left.1
            .iter()
            .all(|left| right.1.iter().all(|right| left.prefix() != right.prefix()))
    );
}

#[test]
fn worker_context_masks_foreign_capture_and_restores_it_after_both_panics() {
    let (((), foreign), parent) = capture(|| {
        let inherited = Context::current();
        // Use raw join deliberately: install a different capture on a real
        // worker, then exercise explicit Some/None task context switching.
        p3_maybe_rayon::prelude::join(
            move || {
                Context(None).run(|| {
                    capture(|| {
                        let _ = audit_sample(30);
                        assert!(
                            std::panic::catch_unwind(|| {
                                Context(None).run(|| {
                                    let _ = audit_sample(99);
                                    panic!("unenrolled task");
                                });
                            })
                            .is_err()
                        );
                        assert!(
                            std::panic::catch_unwind(|| {
                                inherited.run(|| {
                                    let _ = audit_sample(40);
                                    panic!("inherited task");
                                });
                            })
                            .is_err()
                        );
                        let _ = audit_sample(31);
                    })
                    .unwrap()
                })
            },
            || (),
        )
        .0
    })
    .unwrap();
    assert_eq!(parent.len(), 1);
    assert_eq!(foreign.len(), 2);
    let (_, reference) = capture(|| audit_sample(40)).unwrap();
    assert_eq!(parent[0].prefix(), reference[0].prefix());
    for (actual, word) in foreign.iter().zip([30, 31]) {
        let (_, expected) = capture(|| audit_sample(word)).unwrap();
        assert_eq!(actual.prefix(), expected[0].prefix());
    }
}

#[test]
fn finished_context_stays_closed_and_join_unwind_leaves_a_fresh_capture_usable() {
    let ((context, mut escaped), traces) = capture(|| {
        let context = Context::current();
        let mut challenger = Challenger::new();
        challenger.observe(Val::ONE);
        (context, challenger)
    })
    .unwrap();
    let prefix = traces[0].prefix().to_vec();
    context.run(|| {
        let _ = audit_sample(50);
        // A closed inherited context is unenrolled; it does not block a fresh
        // independent capture and never mutates the already returned trace.
        let (_, fresh) = capture(|| audit_sample(51)).unwrap();
        assert_eq!(fresh.len(), 1);
    });
    escaped.observe(Val::TWO);
    let _: Val = escaped.sample();
    let mut fork = escaped.clone();
    let _: Val = fork.sample();
    assert_eq!(traces[0].prefix(), prefix);
    assert!(
        std::panic::catch_unwind(|| {
            let _ = capture(|| {
                crate::hash::join(|| -> () { panic!("first task") }, || audit_sample(60))
            });
        })
        .is_err()
    );
    let (_, fresh) =
        capture(|| crate::hash::join(|| audit_sample(61), || audit_sample(62))).unwrap();
    assert_eq!(fresh.len(), 2);
    assert!(fresh.iter().all(|trace| trace.draws().len() == 1));
}
