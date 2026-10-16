//! Real-process aggregate input custody and final freshness, with public fixtures.
use super::*;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

#[test]
fn sparse_and_empty_aggregates_share_the_row_select_static_frame_on_a_million_row_shard() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let process = Process::start(owner.fingerprint(), 1, None);
    let events = Arc::new(Mutex::new(Vec::<peer_runtime::Trace>::new()));
    let observed = events.clone();
    let mut participant = process.participant(1, &connector);
    participant.remote = participant.remote.with_trace(Arc::new(move |event| {
        if matches!(
            event.operation.as_str(),
            "read-image" | "fhe-proof" | "fetch" | "fetch-version" | "fetch-pages"
        ) {
            let mut events = observed.lock().unwrap();
            assert!(events.len() < 32, "Bounded metadata recorder overflow");
            events.push(event);
        }
    }));
    let source: Vec<_> = (0..1_000_000usize)
        .map(|ordinal| PlainRow {
            age: if ordinal >= 997_440 { 42 } else { 7 },
            amount: (ordinal % 65_536) as u16,
        })
        .collect();
    let expected_sum: u64 = source[997_440..]
        .iter()
        .map(|row| u64::from(row.amount))
        .sum();
    let mut session = Session::create(
        "static-aggregate".into(),
        &source,
        vec![participant],
        test_contract(),
    )
    .unwrap();
    let initial = session.version();
    let mut read_shape = None;
    for (sql, expected_count, expected_sum) in [
        (
            "SELECT COUNT(*), SUM(amount) FROM records WHERE age = 42",
            2560,
            Some(expected_sum),
        ),
        ("SELECT COUNT(*) FROM records WHERE age = 18", 0, None),
        ("SELECT SUM(amount) FROM records WHERE age > 255", 0, None),
    ] {
        events.lock().unwrap().clear();
        let VerifiedResult::Aggregated {
            count,
            sum,
            version,
            ..
        } = execute(&mut session, sql)
        else {
            panic!("Expected proved aggregate");
        };
        assert_eq!(
            (count, sum, version),
            (expected_count, expected_sum, initial)
        );
        let events = events.lock().unwrap();
        let reads: Vec<_> = events
            .iter()
            .filter(|event| event.operation == "read-image")
            .collect();
        let proofs: Vec<_> = events
            .iter()
            .filter(|event| event.operation == "fhe-proof")
            .collect();
        assert_eq!((reads.len(), proofs.len()), (1, 1));
        assert!(reads[0].succeeded && proofs[0].succeeded);
        assert!(!events.iter().any(|event| matches!(
            event.operation.as_str(),
            "fetch" | "fetch-version" | "fetch-pages"
        )));
        let shape = (reads[0].request_bytes, reads[0].response_bytes);
        assert!(
            shape.1 < 6_000_000,
            "The RowId tail must not cross this RPC"
        );
        if let Some(expected) = read_shape {
            assert_eq!(shape, expected);
        } else {
            read_shape = Some(shape);
        }
    }
    events.lock().unwrap().clear();
    assert!(
        rows(
            session
                .execute("SELECT amount FROM records LIMIT 0")
                .unwrap()
        )
        .is_empty()
    );
    {
        let events = events.lock().unwrap();
        let read = events
            .iter()
            .find(|event| event.operation == "read-image")
            .unwrap();
        assert_eq!(Some((read.request_bytes, read.response_bytes)), read_shape);
    }
    events.lock().unwrap().clear();
    assert!(session.execute("SELECT COUNT(*) FROM records").is_err());
    assert_eq!(session.version(), initial);
    let events = events.lock().unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| event.operation == "read-image")
            .count(),
        1
    );
    assert!(!events.iter().any(|event| matches!(
        event.operation.as_str(),
        "fhe-proof" | "fetch" | "fetch-version" | "fetch-pages"
    )));
}

#[test]
fn cancellation_after_a_real_aggregate_proof_refuses_final_completion_and_next_query_recovers() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let process = Process::start(owner.fingerprint(), 1, None);
    let requests = peer_transport::RequestControl::default();
    let armed = Arc::new(AtomicBool::new(false));
    let active = armed.clone();
    let checked_replies = Arc::new(AtomicUsize::new(0));
    let replies = checked_replies.clone();
    let control = requests.clone();
    let mut participant = process.participant(1, &connector);
    participant.remote = participant
        .remote
        .with_control(requests.clone())
        .with_trace(Arc::new(move |event| {
            // Trace runs after the RPC cancellation check. The real serialized proof
            // reaches verification, then the final freshness RPC observes cancellation.
            if event.operation == "fhe-proof"
                && event.succeeded
                && active.swap(false, Ordering::SeqCst)
            {
                replies.fetch_add(1, Ordering::SeqCst);
                control.cancel();
            }
        }));
    let mut session = Session::create(
        "cancel-final-aggregate".into(),
        &[PlainRow {
            age: 42,
            amount: 65_535,
        }],
        vec![participant],
        test_contract(),
    )
    .unwrap();
    let before = session.version();
    let scope = requests.begin().unwrap();
    armed.store(true, Ordering::SeqCst);

    let error = session
        .execute("SELECT COUNT(*), SUM(amount) FROM records")
        .unwrap_err();

    assert!(
        matches!(error, storage_client::Error::Transport(ref error) if error.kind() == std::io::ErrorKind::Interrupted),
        "{error}"
    );
    assert_eq!(checked_replies.load(Ordering::SeqCst), 1);
    assert!(scope.cancellation().is_cancelled());
    assert_eq!(session.version(), before);
    drop(scope);
    let _next = requests.begin().unwrap();
    let VerifiedResult::Aggregated {
        count,
        sum,
        version,
        ..
    } = session
        .execute("SELECT COUNT(*), SUM(amount) FROM records")
        .unwrap()
    else {
        panic!("Expected recovered aggregate");
    };
    assert_eq!((count, sum, version), (1, Some(65_535), before));
}

#[test]
fn interrupted_aggregate_image_never_uses_an_uncancelled_replica() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let a = Process::start(owner.fingerprint(), 1, None);
    let b = Process::start(owner.fingerprint(), 2, None);
    let requests = peer_transport::RequestControl::default();
    let armed = Arc::new(AtomicBool::new(false));
    let active = armed.clone();
    let control = requests.clone();
    let mut first = a.participant(1, &connector);
    first.remote = first
        .remote
        .with_control(requests.clone())
        .with_activity(Arc::new(move |event| {
            if event.operation == "read-image"
                && event.phase == peer_runtime::ActivityPhase::RequestSent
                && active.swap(false, Ordering::SeqCst)
            {
                control.cancel();
            }
        }));
    let fallback_reads = Arc::new(AtomicUsize::new(0));
    let fallback = fallback_reads.clone();
    let mut second = b.participant(2, &connector);
    second.remote = second.remote.with_activity(Arc::new(move |event| {
        if matches!(event.operation.as_str(), "read-image" | "fhe-proof")
            && event.phase == peer_runtime::ActivityPhase::RequestSent
        {
            fallback.fetch_add(1, Ordering::SeqCst);
        }
    }));
    let mut session = Session::create(
        "cancel-aggregate-source".into(),
        &[PlainRow { age: 42, amount: 1 }],
        vec![first],
        test_contract(),
    )
    .unwrap();
    session.copy_shard(session.shards()[0].id, second).unwrap();
    let before = session.version();
    let scope = requests.begin().unwrap();
    armed.store(true, Ordering::SeqCst);

    let error = session.execute("SELECT COUNT(*) FROM records").unwrap_err();

    assert!(
        matches!(error, storage_client::Error::Transport(ref error) if error.kind() == std::io::ErrorKind::Interrupted),
        "{error}"
    );
    assert!(scope.cancellation().is_cancelled());
    assert_eq!(fallback_reads.load(Ordering::SeqCst), 0);
    assert_eq!(session.version(), before);
    drop(scope);
    let _next = requests.begin().unwrap();
    let VerifiedResult::Aggregated { count, sum, .. } =
        session.execute("SELECT COUNT(*) FROM records").unwrap()
    else {
        panic!("Expected recovered aggregate");
    };
    assert_eq!((count, sum), (1, Some(1)));
}
