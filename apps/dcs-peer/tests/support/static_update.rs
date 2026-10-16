//! Live static-source UPDATE still finishes with independently audited full custody.
use super::*;
use bincode::Options;
use peer_runtime::{ActivityPhase, RawBundle, ReadImageRequest};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

fn fetch(remote: &RemotePeer, object: [u8; 32]) -> RawBundle {
    let Response::RawBundle(raw) = remote.call(Request::Fetch { object }).unwrap() else {
        panic!("Complete encrypted object required");
    };
    peer_runtime::CheckedObject::audit(raw.clone()).unwrap();
    raw
}

#[test]
fn million_row_update_reads_static_source_preserves_identity_tail_and_finishes_with_full_custody() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let process = Process::start(owner.fingerprint(), 1, None);
    let control = process.participant(1, &connector).remote;
    let events = Arc::new(Mutex::new(Vec::new()));
    let armed = Arc::new(AtomicBool::new(false));
    let sink = events.clone();
    let active = armed.clone();
    let participant = Participant {
        id: 1,
        remote: control.clone().with_trace(Arc::new(move |event| {
            if active.load(Ordering::SeqCst) {
                sink.lock().unwrap().push(event);
            }
        })),
    };
    let mut input = vec![PlainRow { age: 7, amount: 1 }; compact_query::MAX_TABLE_ROWS];
    input[999_999] = PlainRow {
        age: 42,
        amount: 255,
    };
    let mut session = Session::create(
        "static-update-million".into(),
        &input,
        vec![participant],
        test_contract(),
    )
    .unwrap();
    drop(input);
    let old = session.shards().remove(0);
    let original = fetch(&control, old.object);
    let expected_read =
        ReadImageRequest::new(old.object, &old.data_head, &old.index_head, 493).unwrap();
    armed.store(true, Ordering::SeqCst);

    let result = session
        .execute("UPDATE records SET amount=amount+1 WHERE age=42")
        .unwrap();

    armed.store(false, Ordering::SeqCst);
    assert!(matches!(
        result,
        VerifiedResult::Updated {
            affected_rows: 1,
            ..
        }
    ));
    let actual = session.shards().remove(0);
    let updated = fetch(&control, actual.object);
    assert_eq!(actual.data_head.revision(), old.data_head.revision() + 1);
    assert_eq!(actual.index_head.revision(), old.index_head.revision() + 1);
    let layout = old.index_head.layout();
    assert!(layout.row_count > u64::from(layout.rows_per_page));
    let after_first_packet = compact_store::MANIFEST_BYTES
        + layout.rows_per_page as usize * layout.row_width as usize
        + compact_store::PAGE_OVERHEAD;
    assert_eq!(
        &updated.index[after_first_packet..],
        &original.index[after_first_packet..],
        "Every encrypted posting/RowId tail packet beyond page zero is exact"
    );
    let events = events.lock().unwrap();
    let reads: Vec<_> = events
        .iter()
        .filter(|event| event.operation == "read-image")
        .collect();
    assert_eq!(reads.len(), 1);
    assert_eq!(
        reads[0].response_bytes,
        expected_read.encoded_response_bytes().unwrap() as u64
    );
    let proof = events
        .iter()
        .position(|event| event.operation == "fhe-proof")
        .unwrap();
    assert_eq!(
        events[..proof]
            .iter()
            .filter(|event| event.operation == "fetch")
            .count(),
        0,
        "The initial source must not fetch the full ID tail"
    );
    assert!(
        events[proof..]
            .iter()
            .any(|event| event.operation == "fetch-version"
                && event.succeeded
                && event.response_bytes > updated.index.len() as u64),
        "Final synchronization independently receives both complete images"
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event.operation == "store-delta")
            .count(),
        1
    );
    assert!(!events.iter().any(|event| event.operation == "store"));
    drop(events);
    assert_eq!(
        rows(
            session
                .execute("SELECT * FROM records WHERE age=42")
                .unwrap()
        ),
        vec![vec![42, 256]]
    );
    // This functional codec control is outside the proved query's observed I/O.
    // It uses the actual stored million-row ciphertext, never fixture answers.
    assert_plain_vec_serialization(&updated);
}

fn assert_plain_vec_serialization(raw: &RawBundle) {
    let options = || {
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(peer_transport::MAX_FRAME_BYTES as u64)
            .reject_trailing_bytes()
    };
    let current = options().serialize(raw).unwrap();
    let plain = options()
        .serialize(&(
            raw.version,
            raw.nonce,
            &raw.data_head,
            &raw.index_head,
            &raw.data,
            &raw.index,
        ))
        .unwrap();
    assert!(
        current == plain,
        "Actual ciphertext keeps its plain-Vec bytes"
    );
    let decoded: RawBundle = options().deserialize(&plain).unwrap();
    assert_eq!(&decoded, raw);
    drop(decoded);
    drop(plain);
    type PlainVecFields = (u16, [u8; 32], Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
    let (version, nonce, data_head, index_head, data, index): PlainVecFields =
        options().deserialize(&current).unwrap();
    assert!(
        version == raw.version
            && nonce == raw.nonce
            && data_head == raw.data_head
            && index_head == raw.index_head
            && data == raw.data
            && index == raw.index,
        "The unchanged plain-Vec decoder restores the exact nonce and images"
    );
}

#[test]
fn interrupted_static_update_source_does_not_try_an_uncancelled_holder_or_publish() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let a = Process::start(owner.fingerprint(), 1, None);
    let b = Process::start(owner.fingerprint(), 2, None);
    let control = peer_transport::RequestControl::default();
    let armed = Arc::new(AtomicBool::new(false));
    let active = armed.clone();
    let cancellation = control.clone();
    let mut first = a.participant(1, &connector);
    first.remote = first
        .remote
        .with_control(control.clone())
        .with_activity(Arc::new(move |event| {
            if event.operation == "read-image"
                && event.phase == ActivityPhase::RequestSent
                && active.swap(false, Ordering::SeqCst)
            {
                cancellation.cancel();
            }
        }));
    let fallbacks = Arc::new(AtomicUsize::new(0));
    let fallback_count = fallbacks.clone();
    let mut second = b.participant(2, &connector);
    second.remote = second.remote.with_activity(Arc::new(move |event| {
        if event.phase == ActivityPhase::RequestSent
            && matches!(
                event.operation.as_str(),
                "read-image" | "fetch" | "fhe-proof" | "store" | "store-delta"
            )
        {
            fallback_count.fetch_add(1, Ordering::SeqCst);
        }
    }));
    let mut input = vec![PlainRow { age: 7, amount: 1 }; 100_000];
    input[0].age = 42;
    let mut session = Session::create(
        "cancel-static-update".into(),
        &input,
        vec![first],
        test_contract(),
    )
    .unwrap();
    session.copy_shard(session.shards()[0].id, second).unwrap();
    fallbacks.store(0, Ordering::SeqCst);
    let before = session.shards();
    let version = session.version();
    let observer = a.participant(1, &connector).remote;
    let objects = observer.status().unwrap().objects.len();
    let scope = control.begin().unwrap();
    armed.store(true, Ordering::SeqCst);

    let error = session
        .execute("UPDATE records SET amount=amount+1 WHERE age=42")
        .unwrap_err();

    assert!(
        matches!(error, storage_client::Error::Transport(ref e) if e.kind() == std::io::ErrorKind::Interrupted),
        "{error}"
    );
    assert!(scope.cancellation().is_cancelled());
    assert_eq!(fallbacks.load(Ordering::SeqCst), 0);
    assert_eq!(observer.status().unwrap().objects.len(), objects);
    assert_eq!(session.version(), version);
    assert_eq!(session.shards()[0].object, before[0].object);
    drop(scope);
    let _next = control.begin().unwrap();
    assert!(session.resume_pending().unwrap().is_none());
    assert!(matches!(
        session
            .execute("UPDATE records SET amount=amount+1 WHERE age=42")
            .unwrap(),
        VerifiedResult::Updated {
            affected_rows: 1,
            ..
        }
    ));
}

#[test]
fn corrupt_identity_tail_after_delta_ack_keeps_exact_pending_and_retry_reuses_the_stored_object() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let process = Process::start(owner.fingerprint(), 1, None);
    let control = process.participant(1, &connector).remote;
    let armed = Arc::new(AtomicBool::new(false));
    let active = armed.clone();
    let saved = Arc::new(Mutex::new(None));
    let retained = saved.clone();
    let directory = process.directory.clone();
    let old_objects = Arc::new(Mutex::new(Vec::new()));
    let initial_objects = old_objects.clone();
    let administrator = control.clone();
    let jobs = Arc::new(AtomicUsize::new(0));
    let writes = Arc::new(AtomicUsize::new(0));
    let job_count = jobs.clone();
    let write_count = writes.clone();
    let remote = control.clone().with_trace(Arc::new(move |event| {
        if event.operation == "fhe-proof" {
            job_count.fetch_add(1, Ordering::SeqCst);
        }
        if matches!(event.operation.as_str(), "store" | "store-delta") {
            write_count.fetch_add(1, Ordering::SeqCst);
        }
        if event.operation == "store-delta"
            && event.succeeded
            && active.swap(false, Ordering::SeqCst)
        {
            let old = initial_objects.lock().unwrap();
            let object = administrator
                .status()
                .unwrap()
                .objects
                .into_iter()
                .find(|object| !old.contains(&object.id))
                .expect("Exactly one newly acknowledged target");
            let raw = fetch(&administrator, object.id);
            let filename = object
                .id
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
                + ".object2";
            let path = directory.join(filename);
            let bytes = std::fs::read(&path).unwrap();
            let mut corrupted = bytes.clone();
            *corrupted.last_mut().unwrap() ^= 1;
            std::fs::write(&path, corrupted).unwrap();
            *retained.lock().unwrap() = Some((object.id, raw, path, bytes));
        }
    }));
    let mut input = vec![PlainRow { age: 7, amount: 1 }; 100_000];
    input[0].age = 42;
    let mut session = Session::create(
        "corrupt-after-delta".into(),
        &input,
        vec![Participant { id: 1, remote }],
        test_contract(),
    )
    .unwrap();
    *old_objects.lock().unwrap() = control
        .status()
        .unwrap()
        .objects
        .into_iter()
        .map(|object| object.id)
        .collect();
    jobs.store(0, Ordering::SeqCst);
    writes.store(0, Ordering::SeqCst);
    armed.store(true, Ordering::SeqCst);
    let sql = "UPDATE records SET amount=amount+1 WHERE age=42";

    let error = session.execute(sql).unwrap_err();

    let storage_client::Error::PendingMutation { query_binding, .. } = error else {
        panic!("Corrupt final custody must retain the exact mutation: {error}");
    };
    assert_eq!(jobs.load(Ordering::SeqCst), 1);
    assert_eq!(writes.load(Ordering::SeqCst), 1);
    assert!(
        matches!(session.execute(sql), Err(storage_client::Error::PendingMutation { query_binding: same, .. }) if same == query_binding)
    );
    let (object, original, path, bytes) = saved
        .lock()
        .unwrap()
        .take()
        .expect("Corrupted real target disk file");
    std::fs::write(path, bytes).unwrap();
    assert!(matches!(
        session.execute(sql).unwrap(),
        VerifiedResult::Updated {
            affected_rows: 1,
            ..
        }
    ));
    assert_eq!(session.shards()[0].object, object);
    assert_eq!(
        fetch(&control, object),
        original,
        "Nonce and both complete encrypted images survive retry"
    );
    assert_eq!(jobs.load(Ordering::SeqCst), 1);
    assert_eq!(writes.load(Ordering::SeqCst), 1);
    assert!(session.resume_pending().unwrap().is_none());
}

#[test]
fn a_preplanned_new_replica_requires_full_source_and_shares_one_target_with_delta_holders() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let processes: Vec<_> = (1..=3)
        .map(|id| Process::start(owner.fingerprint(), id, None))
        .collect();
    let controls: Vec<_> = processes
        .iter()
        .enumerate()
        .map(|(slot, process)| process.participant(slot as u64 + 1, &connector))
        .collect();
    let events = Arc::new(Mutex::new(Vec::new()));
    let armed = Arc::new(AtomicBool::new(false));
    let participants: Vec<_> = controls
        .iter()
        .map(|peer| {
            let id = peer.id;
            let sink = events.clone();
            let active = armed.clone();
            Participant {
                id,
                remote: peer.remote.clone().with_trace(Arc::new(move |event| {
                    if active.load(Ordering::SeqCst) {
                        sink.lock().unwrap().push((id, event));
                    }
                })),
            }
        })
        .collect();
    let mut input = vec![PlainRow { age: 7, amount: 1 }; 150_000];
    input[0] = PlainRow {
        age: 42,
        amount: 255,
    };
    let mut session = Session::create(
        "preplanned-full-source".into(),
        &input,
        participants[..2].to_vec(),
        test_contract(),
    )
    .unwrap();
    let old = session.shards();
    // The third peer becomes a participant by holding the OTHER shard. It is
    // genuinely new placement for the changed shard, fixed before UPDATE starts.
    session
        .copy_shard(old[1].id, participants[2].clone())
        .unwrap();
    let status = controls[0].remote.status().unwrap();
    let used = status.disk_bytes();
    controls[0].remote.call(Request::Quota(used)).unwrap();
    armed.store(true, Ordering::SeqCst);

    let result = session
        .execute("UPDATE records SET amount=amount+1 WHERE age=42")
        .unwrap();

    armed.store(false, Ordering::SeqCst);
    assert!(matches!(
        result,
        VerifiedResult::Updated {
            affected_rows: 1,
            ..
        }
    ));
    let target = session.shards()[0].object;
    let at_delta_holder = fetch(&controls[1].remote, target);
    let at_full_holder = fetch(&controls[2].remote, target);
    assert_eq!(
        at_delta_holder, at_full_holder,
        "Every candidate receives one exact nonce and images"
    );
    let events = events.lock().unwrap();
    let source = events
        .iter()
        .position(|(id, event)| *id == 1 && event.operation == "fetch" && event.succeeded)
        .expect("Full source must be obtained before this shard's proof");
    let proof = events
        .iter()
        .position(|(id, event)| *id == 1 && event.operation == "fhe-proof")
        .expect("A real proof must still execute");
    assert!(source < proof);
    let writes: Vec<_> = events
        .iter()
        .filter(|(_, event)| matches!(event.operation.as_str(), "store" | "store-delta"))
        .collect();
    assert_eq!(writes.len(), 3);
    assert_eq!(
        (
            writes[0].0,
            writes[0].1.operation.as_str(),
            writes[0].1.succeeded
        ),
        (1, "store-delta", false)
    );
    assert_eq!(
        (
            writes[1].0,
            writes[1].1.operation.as_str(),
            writes[1].1.succeeded
        ),
        (2, "store-delta", true)
    );
    assert_eq!(
        (
            writes[2].0,
            writes[2].1.operation.as_str(),
            writes[2].1.succeeded
        ),
        (3, "store", true)
    );
    drop(events);
    assert_eq!(
        rows(
            session
                .execute("SELECT amount FROM records WHERE age=42")
                .unwrap()
        ),
        vec![vec![256]]
    );
}

#[test]
fn overflow_on_one_static_shard_rejects_the_whole_proved_update_before_any_store() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let a = Process::start(owner.fingerprint(), 1, None);
    let b = Process::start(owner.fingerprint(), 2, None);
    let controls = [a.participant(1, &connector), b.participant(2, &connector)];
    let events = Arc::new(Mutex::new(Vec::new()));
    let armed = Arc::new(AtomicBool::new(false));
    let participants = controls
        .iter()
        .map(|peer| {
            let sink = events.clone();
            let active = armed.clone();
            Participant {
                id: peer.id,
                remote: peer.remote.clone().with_trace(Arc::new(move |event| {
                    if active.load(Ordering::SeqCst) {
                        sink.lock().unwrap().push(event);
                    }
                })),
            }
        })
        .collect();
    let mut input = vec![PlainRow { age: 7, amount: 1 }; 200_000];
    input[0] = PlainRow { age: 42, amount: 1 };
    input[1] = PlainRow {
        age: 42,
        amount: u16::MAX,
    };
    let mut session = Session::create(
        "static-cross-shard-overflow".into(),
        &input,
        participants,
        test_contract(),
    )
    .unwrap();
    let initial = session.version();
    let original: Vec<_> = session
        .shards()
        .into_iter()
        .map(|shard| shard.object)
        .collect();
    let inventories: Vec<Vec<_>> = controls
        .iter()
        .map(|peer| {
            peer.remote
                .status()
                .unwrap()
                .objects
                .into_iter()
                .map(|object| object.id)
                .collect()
        })
        .collect();
    armed.store(true, Ordering::SeqCst);

    let error = session
        .execute("UPDATE records SET amount=amount+1 WHERE age=42")
        .unwrap_err();

    armed.store(false, Ordering::SeqCst);
    assert!(
        matches!(error, storage_client::Error::InvalidInput(ref message) if message.contains("overflowed")),
        "{error}"
    );
    assert_eq!(session.version(), initial);
    assert_eq!(
        session
            .shards()
            .into_iter()
            .map(|shard| shard.object)
            .collect::<Vec<_>>(),
        original
    );
    assert!(session.resume_pending().unwrap().is_none());
    for (peer, original) in controls.iter().zip(inventories) {
        assert_eq!(
            peer.remote
                .status()
                .unwrap()
                .objects
                .into_iter()
                .map(|object| object.id)
                .collect::<Vec<_>>(),
            original
        );
    }
    let events = events.lock().unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| event.operation == "read-image" && event.succeeded)
            .count(),
        2
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event.operation == "fhe-proof" && event.succeeded)
            .count(),
        2
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event.operation.as_str(), "store" | "store-delta"))
    );
    drop(events);
    assert!(matches!(
        session
            .execute("UPDATE records SET amount=amount+0 WHERE age=42")
            .unwrap(),
        VerifiedResult::Updated {
            affected_rows: 2,
            ..
        }
    ));
    assert_eq!(session.version(), initial);
}
