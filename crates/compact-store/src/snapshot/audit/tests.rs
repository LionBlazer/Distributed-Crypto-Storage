use super::{AuditWorkers, MIN_PARALLEL_IMAGE_BYTES, Spawn, leaf_hashes_with, run_halves};
use crate::{Layout, Limits, Owner};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

const GATE_TIMEOUT: Duration = Duration::from_secs(10);

fn large_image() -> (Vec<u8>, Layout) {
    let owner = Owner::generate([161; 16]).unwrap();
    let layout = Layout {
        schema: [162; 16],
        row_width: 1,
        rows_per_page: 65_536,
        row_count: 65 * 65_536 - 17,
    };
    let source = owner
        .seal(
            layout,
            &vec![23; layout.row_count as usize],
            Limits {
                max_rows: 64 * 1024 * 1024,
                ..Limits::default()
            },
        )
        .unwrap();
    let bytes = source.encode();
    assert!(bytes.len() >= MIN_PARALLEL_IMAGE_BYTES);
    (bytes, layout)
}

#[test]
fn two_worker_leaf_ranges_match_serial_hashes_and_the_independent_owner_root() {
    let (bytes, layout) = large_image();
    let busy = AtomicBool::new(false);
    let expected = leaf_hashes_with(&bytes, layout, AuditWorkers::One, &busy, Spawn::Os);

    let actual = leaf_hashes_with(&bytes, layout, AuditWorkers::Two, &busy, Spawn::Os);

    assert_eq!(actual, expected);
    let head = crate::Commitment::decode(
        &bytes[..crate::MANIFEST_BYTES],
        Limits {
            max_rows: 64 * 1024 * 1024,
            ..Limits::default()
        },
    )
    .unwrap();
    let levels = super::super::build_levels(actual);
    assert_eq!(
        head.with_tree_root(super::super::tree_root(&levels)),
        head.root()
    );
    assert!(run_halves(&busy, Spawn::Os, || {}, || {}));
}
#[test]
fn failed_spawn_hashes_every_leaf_serially_and_releases_the_shared_budget() {
    let (mut bytes, layout) = large_image();
    // The last physical byte still contributes to fallback hashing.
    *bytes.last_mut().unwrap() ^= 1;
    let busy = AtomicBool::new(false);
    let expected = leaf_hashes_with(&bytes, layout, AuditWorkers::One, &busy, Spawn::Os);

    let actual = leaf_hashes_with(&bytes, layout, AuditWorkers::Two, &busy, Spawn::Fail);

    assert_eq!(actual, expected);
    assert!(run_halves(&busy, Spawn::Os, || {}, || {}));
}

#[test]
fn overlapping_audits_share_one_helper_and_fully_hash_the_serial_fallbacks() {
    let (bytes, layout) = large_image();
    let busy = Arc::new(AtomicBool::new(false));
    let helper_starts = Arc::new(AtomicUsize::new(0));
    let expected = leaf_hashes_with(&bytes, layout, AuditWorkers::One, &busy, Spawn::Os);
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let first_budget = busy.clone();
    let first_starts = helper_starts.clone();
    let first = thread::spawn(move || {
        run_halves(
            &first_budget,
            Spawn::Os,
            || {},
            move || {
                first_starts.fetch_add(1, Ordering::SeqCst);
                entered_tx.send(()).unwrap();
                release_rx.recv_timeout(GATE_TIMEOUT).unwrap();
            },
        )
    });
    let entered = entered_rx.recv_timeout(GATE_TIMEOUT);
    let outcomes = if entered.is_ok() {
        thread::scope(|scope| {
            let jobs: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        let extra_helper = run_halves(
                            &busy,
                            Spawn::Os,
                            || {},
                            || {
                                helper_starts.fetch_add(1, Ordering::SeqCst);
                            },
                        );
                        let leaves =
                            leaf_hashes_with(&bytes, layout, AuditWorkers::Two, &busy, Spawn::Os);
                        (extra_helper, leaves)
                    })
                })
                .collect();
            jobs.into_iter().map(|job| job.join()).collect::<Vec<_>>()
        })
    } else {
        Vec::new()
    };
    // Release and join before assertions, including an unexpected worker error.
    let released = release_tx.send(());
    let first_result = first.join();

    assert!(entered.is_ok());
    assert!(released.is_ok());
    assert!(first_result.unwrap());
    assert_eq!(outcomes.len(), 8);
    for outcome in outcomes {
        let (extra_helper, leaves) = outcome.unwrap();
        assert!(!extra_helper);
        assert_eq!(leaves, expected);
    }
    assert_eq!(helper_starts.load(Ordering::SeqCst), 1);
    assert!(run_halves(&busy, Spawn::Os, || {}, || {}));
}

#[test]
fn helper_panic_never_returns_success_and_the_budget_can_be_reused() {
    let busy = AtomicBool::new(false);
    let caller_finished = AtomicBool::new(false);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_halves(
            &busy,
            Spawn::Os,
            || caller_finished.store(true, Ordering::SeqCst),
            || panic!("deliberate helper panic"),
        )
    }));

    assert!(result.is_err());
    assert!(caller_finished.load(Ordering::SeqCst));
    assert!(run_halves(&busy, Spawn::Os, || {}, || {}));
}

#[test]
fn caller_unwind_joins_the_helper_before_releasing_the_shared_budget() {
    let busy = Arc::new(AtomicBool::new(false));
    let helper_finished = Arc::new(AtomicBool::new(false));
    let worker_budget = busy.clone();
    let worker_finished = helper_finished.clone();
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (body_exited_tx, body_exited_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_halves(
                &worker_budget,
                Spawn::ObserveScopeExit(body_exited_tx),
                || panic!("deliberate caller panic"),
                move || {
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(GATE_TIMEOUT).unwrap();
                    worker_finished.store(true, Ordering::SeqCst);
                },
            )
        }));
        (result.is_err(), worker_budget.load(Ordering::SeqCst))
    });
    let entered = entered_rx.recv_timeout(GATE_TIMEOUT);
    // The scope body has fully unwound, while its child is still blocked. A
    // permit owned inside that body would already have been released here.
    let body_exited = body_exited_rx.recv_timeout(GATE_TIMEOUT);
    let competing = if entered.is_ok() && body_exited.is_ok() {
        Some(run_halves(&busy, Spawn::Os, || {}, || {}))
    } else {
        None
    };
    let released = release_tx.send(());
    let outcome = worker.join();

    assert!(entered.is_ok());
    assert!(body_exited.is_ok());
    assert_eq!(competing, Some(false));
    assert!(released.is_ok());
    assert_eq!(outcome.unwrap(), (true, false));
    assert!(helper_finished.load(Ordering::SeqCst));
    assert!(run_halves(&busy, Spawn::Os, || {}, || {}));
}
