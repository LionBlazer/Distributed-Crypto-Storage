//! Boolean WHERE conditions feed the actual complete selection/FHE/proof/freshness path.
use super::*;
use std::sync::{Arc, Mutex};

#[test]
fn boolean_reads_null_aggregates_and_full_updates_complete_real_peer_proofs() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let process = Process::start(owner.fingerprint(), 1, None);
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = events.clone();
    let mut participant = process.participant(1, &connector);
    participant.remote = participant.remote.with_trace(Arc::new(move |event| {
        sink.lock().unwrap().push(event);
    }));
    let mut session = Session::create(
        "boolean-full".into(),
        &[
            PlainRow {
                age: 7,
                amount: 255,
            },
            PlainRow { age: 18, amount: 1 },
            PlainRow {
                age: 99,
                amount: 256,
            },
            PlainRow {
                age: 42,
                amount: 65534,
            },
            PlainRow { age: 7, amount: 2 },
            PlainRow { age: 99, amount: 3 },
        ],
        vec![participant],
        test_contract(),
    )
    .unwrap();
    events.lock().unwrap().clear();
    assert_eq!(rows(session.execute("SELECT amount,age FROM records WHERE (age IN(7,99,NULL) OR age=42) AND NOT(age=42)").unwrap()),vec![vec![255,7],vec![256,99],vec![2,7],vec![3,99]]);
    assert_eq!(
        rows(
            session
                .execute("SELECT age FROM records WHERE age=7 OR age=99 LIMIT 2")
                .unwrap()
        ),
        vec![vec![7], vec![99]]
    );
    let VerifiedResult::Aggregated { count, sum, .. } = session
        .execute("SELECT COUNT(*),SUM(amount) FROM records WHERE age=7 OR age=99 OR age=7")
        .unwrap()
    else {
        panic!("aggregate expected")
    };
    assert_eq!((count, sum), (4, Some(516)));
    let VerifiedResult::Aggregated { count, sum, .. } = session
        .execute("SELECT COUNT(*),SUM(amount) FROM records WHERE age NOT IN(7,99,NULL)")
        .unwrap()
    else {
        panic!("aggregate expected")
    };
    assert_eq!((count, sum), (0, None));
    assert!(
        rows(
            session
                .execute("SELECT * FROM records WHERE NOT NULL")
                .unwrap()
        )
        .is_empty()
    );
    let read_events = events.lock().unwrap();
    assert_eq!(
        read_events
            .iter()
            .filter(|event| event.operation == "fhe-proof" && event.succeeded)
            .count(),
        5,
        "Empty SQL TRUE sets still require actual peer evidence"
    );
    let sizes: Vec<_> = read_events
        .iter()
        .filter(|event| event.operation == "read-image")
        .map(|event| event.response_bytes)
        .collect();
    assert_eq!(sizes.len(), 5);
    assert!(
        sizes.iter().all(|size| *size == sizes[0]),
        "Predicate syntax/NULL/limit do not alter source geometry"
    );
    drop(read_events);
    events.lock().unwrap().clear();
    assert!(matches!(
        session
            .execute("UPDATE records SET amount=amount+1 WHERE age=7 OR age IN(7,99)")
            .unwrap(),
        VerifiedResult::Updated {
            affected_rows: 4,
            ..
        }
    ));
    assert!(
        events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event.operation == "store" && event.succeeded),
        "This small public geometry uses the preplanned full-write path"
    );
    assert_eq!(
        rows(session.execute("SELECT * FROM records").unwrap()),
        vec![
            vec![7, 256],
            vec![18, 1],
            vec![99, 257],
            vec![42, 65534],
            vec![7, 3],
            vec![99, 4]
        ]
    );
    let version = session.version();
    assert!(matches!(
        session
            .execute("UPDATE records SET amount=amount+0 WHERE NOT(age BETWEEN NULL AND 10)")
            .unwrap(),
        VerifiedResult::Updated {
            affected_rows: 4,
            ..
        }
    ));
    assert_eq!(session.version(), version);
    events.lock().unwrap().clear();
    assert!(
        session
            .execute("UPDATE records SET amount=amount+2 WHERE age IN(42,99)")
            .is_err()
    );
    assert_eq!(session.version(), version);
    assert!(session.resume_pending().unwrap().is_none());
    assert!(
        !events
            .lock()
            .unwrap()
            .iter()
            .any(|event| matches!(event.operation.as_str(), "store" | "store-delta"))
    );
}

#[test]
fn entire_union_hits_materialization_budget_before_any_proof_or_write() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let process = Process::start(owner.fingerprint(), 1, None);
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = events.clone();
    let mut participant = process.participant(1, &connector);
    participant.remote = participant.remote.with_trace(Arc::new(move |event| {
        sink.lock().unwrap().push(event);
    }));
    let input: Vec<_> = (0..400)
        .map(|i| PlainRow {
            age: if i % 2 == 0 { 7 } else { 99 },
            amount: 1,
        })
        .collect();
    let mut session = Session::create(
        "boolean-budget".into(),
        &input,
        vec![participant],
        test_contract(),
    )
    .unwrap();
    let initial = session.version();
    for sql in [
        "SELECT * FROM records WHERE age=7 OR age=99",
        "UPDATE records SET amount=amount+1 WHERE age IN(7,99)",
    ] {
        events.lock().unwrap().clear();
        assert!(
            matches!(session.execute(sql),Err(storage_client::Error::Cryptography(ref message)) if message.contains("SelectionBudget")),
            "{sql}"
        );
        assert_eq!(session.version(), initial);
        assert!(!events.lock().unwrap().iter().any(|event| matches!(
            event.operation.as_str(),
            "fhe-proof" | "store" | "store-delta"
        )));
    }
    assert_eq!(
        rows(
            session
                .execute("SELECT age FROM records WHERE age IN(7,99) LIMIT 1")
                .unwrap()
        ),
        vec![vec![7]]
    );
    let VerifiedResult::Aggregated { count, sum, .. } = session
        .execute("SELECT COUNT(*),SUM(amount) FROM records WHERE age IN(7,99)")
        .unwrap()
    else {
        panic!("aggregate expected")
    };
    assert_eq!((count, sum), (400, Some(400)));
    assert_eq!(session.version(), initial);
}

#[test]
fn noncontiguous_static_update_uses_one_delta_and_preserves_the_complete_encrypted_identity_tail() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let process = Process::start(owner.fingerprint(), 1, None);
    let mut participant = process.participant(1, &connector);
    let control = participant.remote.clone();
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = events.clone();
    participant.remote = participant.remote.with_trace(Arc::new(move |event| {
        sink.lock().unwrap().push(event);
    }));
    let mut input = vec![PlainRow { age: 18, amount: 1 }; 100_000];
    input[0] = PlainRow {
        age: 7,
        amount: 100,
    };
    input[99_999] = PlainRow {
        age: 99,
        amount: 65534,
    };
    let mut session = Session::create(
        "boolean-static".into(),
        &input,
        vec![participant],
        test_contract(),
    )
    .unwrap();
    let old = session.shards().remove(0);
    let Response::RawBundle(before) = control.call(Request::Fetch { object: old.object }).unwrap()
    else {
        panic!("full object expected")
    };
    peer_runtime::CheckedObject::audit(before.clone()).unwrap();
    events.lock().unwrap().clear();
    assert!(matches!(
        session
            .execute("UPDATE records SET amount=amount+1 WHERE age IN(7,99) OR age=7")
            .unwrap(),
        VerifiedResult::Updated {
            affected_rows: 2,
            ..
        }
    ));
    let current = session.shards().remove(0);
    let Response::RawBundle(after) = control
        .call(Request::Fetch {
            object: current.object,
        })
        .unwrap()
    else {
        panic!("full object expected")
    };
    peer_runtime::CheckedObject::audit(after.clone()).unwrap();
    let first_packet_end = compact_store::MANIFEST_BYTES
        + old.index_head.layout().rows_per_page as usize
        + compact_store::PAGE_OVERHEAD;
    assert_eq!(
        &before.index[first_packet_end..],
        &after.index[first_packet_end..]
    );
    let seen = events.lock().unwrap();
    assert_eq!(
        seen.iter()
            .filter(|event| event.operation == "read-image" && event.succeeded)
            .count(),
        1
    );
    assert_eq!(
        seen.iter()
            .filter(|event| event.operation == "fhe-proof" && event.succeeded)
            .count(),
        1
    );
    assert_eq!(
        seen.iter()
            .filter(|event| event.operation == "store-delta" && event.succeeded)
            .count(),
        1
    );
    assert!(!seen.iter().any(|event| event.operation == "store"));
    assert!(
        seen.iter()
            .any(|event| event.operation == "fetch-version" && event.succeeded),
        "The final complete physical-custody audit remains mandatory"
    );
    drop(seen);
    assert_eq!(
        rows(
            session
                .execute("SELECT amount,age FROM records WHERE age IN(7,99)")
                .unwrap()
        ),
        vec![vec![101, 7], vec![65535, 99]]
    );
    events.lock().unwrap().clear();
    let version = session.version();
    assert!(
        session
            .execute("UPDATE records SET amount=amount+1 WHERE age=7 OR age=99")
            .is_err()
    );
    assert_eq!(session.version(), version);
    assert!(
        !events
            .lock()
            .unwrap()
            .iter()
            .any(|event| matches!(event.operation.as_str(), "store" | "store-delta"))
    );
    assert!(session.resume_pending().unwrap().is_none());
}

#[test]
fn historical_unverified_network_adapter_rejects_disjoint_sets_before_any_rpc() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let process = Process::start(owner.fingerprint(), 1, None);
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = events.clone();
    let mut participant = process.participant(1, &connector);
    participant.remote = participant.remote.with_trace(Arc::new(move |event| {
        sink.lock().unwrap().push(event);
    }));
    let database = storage_client::Database::create(
        "historical-rejection".into(),
        &[PlainRow { age: 7, amount: 1 }],
        vec![participant],
    )
    .unwrap();
    events.lock().unwrap().clear();
    assert!(matches!(
        database.execute("SELECT * FROM records WHERE age=7 OR age=99"),
        Err(storage_client::Error::InvalidInput(_))
    ));
    assert!(events.lock().unwrap().is_empty());
    assert!(matches!(
        database.execute("SELECT * FROM records WHERE NOT NULL"),
        Err(storage_client::Error::MissingComputationProof)
    ));
    assert!(events.lock().unwrap().is_empty());
}
