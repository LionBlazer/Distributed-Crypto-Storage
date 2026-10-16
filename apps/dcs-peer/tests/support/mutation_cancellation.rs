//! Cancellation is an operation boundary even when another real holder is reachable.
use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

#[test]
fn an_interrupted_update_proof_never_uses_an_uncancelled_holder_or_publishes_a_mutation() {
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
            if event.operation == "fhe-proof"
                && event.phase == peer_runtime::ActivityPhase::RequestSent
                && active.swap(false, Ordering::SeqCst)
            {
                control.cancel();
            }
        }));
    let fallback_proofs = Arc::new(AtomicUsize::new(0));
    let fallback = fallback_proofs.clone();
    let stores = Arc::new(AtomicUsize::new(0));
    let writes = stores.clone();
    let mut second = b.participant(2, &connector);
    second.remote = second.remote.with_activity(Arc::new(move |event| {
        if event.phase != peer_runtime::ActivityPhase::RequestSent {
            return;
        }
        if event.operation == "fhe-proof" {
            fallback.fetch_add(1, Ordering::SeqCst);
        }
        if matches!(
            event.operation.as_str(),
            "store" | "store-delta" | "journal-mine" | "journal-publish"
        ) {
            writes.fetch_add(1, Ordering::SeqCst);
        }
    }));
    let mut session = Session::create(
        "cancel-update-proof".into(),
        &[PlainRow {
            age: 42,
            amount: 255,
        }],
        vec![first],
        test_contract(),
    )
    .unwrap();
    session.copy_shard(session.shards()[0].id, second).unwrap();
    let initial = session.version();
    let initial_shard = session.shards().remove(0);
    fallback_proofs.store(0, Ordering::SeqCst);
    stores.store(0, Ordering::SeqCst);
    let scope = requests.begin().unwrap();
    armed.store(true, Ordering::SeqCst);

    let result = session.execute("UPDATE records SET amount = amount + 1 WHERE age = 42");

    assert!(
        matches!(result, Err(storage_client::Error::Transport(ref error)) if error.kind() == std::io::ErrorKind::Interrupted),
        "{result:?}"
    );
    assert!(scope.cancellation().is_cancelled());
    assert_eq!(
        fallback_proofs.load(Ordering::SeqCst),
        0,
        "A second holder must not compute an interrupted operation"
    );
    assert_eq!(
        stores.load(Ordering::SeqCst),
        0,
        "No Store, signing publication or mining follows cancellation"
    );
    assert_eq!(session.version(), initial);
    assert_eq!(session.shards()[0].object, initial_shard.object);
    assert_eq!(session.shards()[0].data_head, initial_shard.data_head);
    assert_eq!(session.shards()[0].index_head, initial_shard.index_head);
    drop(scope);
    let _next = requests.begin().unwrap();
    assert!(session.resume_pending().unwrap().is_none());
    assert_eq!(
        rows(session.execute("SELECT * FROM records").unwrap()),
        vec![vec![42, 255]]
    );
    assert!(matches!(
        session
            .execute("UPDATE records SET amount = amount + 1 WHERE age = 42")
            .unwrap(),
        VerifiedResult::Updated {
            affected_rows: 1,
            ..
        }
    ));
    assert_eq!(
        rows(session.execute("SELECT * FROM records").unwrap()),
        vec![vec![42, 256]]
    );
}
