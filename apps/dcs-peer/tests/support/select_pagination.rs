//! Public fixtures traverse actual peer BFV arithmetic, proof checking and final freshness.
//! Pagination retains the existing owner-assisted source/formation limitation.
use super::*;
use std::sync::{Arc, Mutex};

#[test]
fn interleaved_shards_apply_one_global_offset_after_complete_prefix_proofs() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let a = Process::start(owner.fingerprint(), 1, None);
    let b = Process::start(owner.fingerprint(), 2, None);
    let source: Vec<_> = (0..3001)
        .map(|i| PlainRow {
            age: if i % 2 == 0 || i % 5 == 1 { 42 } else { 7 },
            amount: i,
        })
        .collect();
    let events = Arc::new(Mutex::new(Vec::new()));
    let participants = [&a, &b]
        .into_iter()
        .enumerate()
        .map(|(slot, process)| {
            let mut participant = process.participant(slot as u64 + 1, &connector);
            let sink = events.clone();
            participant.remote = participant.remote.with_trace(Arc::new(move |event| {
                if matches!(event.operation.as_str(), "read-image" | "fhe-proof") {
                    sink.lock().unwrap().push(event);
                }
            }));
            participant
        })
        .collect();
    let mut session = Session::create(
        "global-window".into(),
        &source,
        participants,
        test_contract(),
    )
    .unwrap();
    for (offset, limit) in [(1, 3), (100, 100), (128, 128), (1000, 0)] {
        events.lock().unwrap().clear();
        let expected: Vec<_> = source
            .iter()
            .filter(|row| row.age == 42)
            .skip(offset)
            .take(limit)
            .map(|row| vec![u32::from(row.amount), 42])
            .collect();
        assert_eq!(
            rows(
                session
                    .execute(&format!(
                        "SELECT amount,age FROM records WHERE age=42 OFFSET {offset} LIMIT {limit}"
                    ))
                    .unwrap()
            ),
            expected
        );
        let events = events.lock().unwrap();
        for operation in ["read-image", "fhe-proof"] {
            assert_eq!(
                events
                    .iter()
                    .filter(|event| event.operation == operation && event.succeeded)
                    .count(),
                2
            );
        }
    }
    // The output would have only one row, but its required shard prefix exceeds 256.
    events.lock().unwrap().clear();
    let error = session
        .execute("SELECT * FROM records WHERE age=42 LIMIT 1 OFFSET 256")
        .unwrap_err();
    assert!(
        matches!(error, storage_client::Error::Cryptography(ref message) if message.contains("SelectionBudget")),
        "{error}"
    );
    assert!(
        !events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event.operation == "fhe-proof")
    );
}

#[test]
fn all_null_empty_and_beyond_end_windows_still_use_every_actual_shard_proof() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let a = Process::start(owner.fingerprint(), 1, None);
    let b = Process::start(owner.fingerprint(), 2, None);
    let proof_replies = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let participants = [&a, &b]
        .into_iter()
        .enumerate()
        .map(|(slot, process)| {
            let mut participant = process.participant(slot as u64 + 1, &connector);
            let count = proof_replies.clone();
            participant.remote = participant.remote.with_trace(Arc::new(move |event| {
                if event.operation == "fhe-proof" && event.succeeded {
                    count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }));
            participant
        })
        .collect();
    let source = [
        PlainRow {
            age: 42,
            amount: 10,
        },
        PlainRow { age: 7, amount: 11 },
        PlainRow {
            age: 42,
            amount: 12,
        },
        PlainRow {
            age: 42,
            amount: 13,
        },
    ];
    let mut session = Session::create(
        "nullable-window".into(),
        &source,
        participants,
        test_contract(),
    )
    .unwrap();
    let version = session.version();
    for (clause, expected) in [
        ("LIMIT ALL OFFSET 1", vec![vec![12], vec![13]]),
        ("OFFSET NULL LIMIT NULL", vec![vec![10], vec![12], vec![13]]),
        ("OFFSET 3 LIMIT 1", vec![]),
        ("LIMIT 0 OFFSET 1000000", vec![]),
    ] {
        proof_replies.store(0, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            rows(
                session
                    .execute(&format!("SELECT amount FROM records WHERE age=42 {clause}"))
                    .unwrap()
            ),
            expected
        );
        assert_eq!(
            proof_replies.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "{clause}"
        );
        assert_eq!(session.version(), version);
    }
}

#[test]
fn cancellation_after_a_real_window_proof_refuses_completion_and_the_same_query_recovers() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let process = Process::start(owner.fingerprint(), 1, None);
    let requests = peer_transport::RequestControl::default();
    let armed = Arc::new(AtomicBool::new(false));
    let gate = armed.clone();
    let replies = Arc::new(AtomicUsize::new(0));
    let count = replies.clone();
    let control = requests.clone();
    let mut participant = process.participant(1, &connector);
    participant.remote = participant
        .remote
        .with_control(requests.clone())
        .with_trace(Arc::new(move |event| {
            if event.operation == "fhe-proof"
                && event.succeeded
                && gate.swap(false, Ordering::SeqCst)
            {
                count.fetch_add(1, Ordering::SeqCst);
                control.cancel();
            }
        }));
    let mut session = Session::create(
        "cancel-window".into(),
        &[
            PlainRow {
                age: 42,
                amount: 10,
            },
            PlainRow {
                age: 42,
                amount: 11,
            },
            PlainRow {
                age: 42,
                amount: 12,
            },
        ],
        vec![participant],
        test_contract(),
    )
    .unwrap();
    let version = session.version();
    let sql = "SELECT amount FROM records LIMIT 1 OFFSET 1";
    let scope = requests.begin().unwrap();
    armed.store(true, Ordering::SeqCst);
    let error = session.execute(sql).unwrap_err();
    assert!(
        matches!(error, storage_client::Error::Transport(ref e) if e.kind() == std::io::ErrorKind::Interrupted),
        "{error}"
    );
    assert_eq!(replies.load(Ordering::SeqCst), 1);
    assert_eq!(session.version(), version);
    drop(scope);
    let _next = requests.begin().unwrap();
    assert_eq!(rows(session.execute(sql).unwrap()), vec![vec![11]]);
}
