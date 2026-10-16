//! Genuine mutation, full disk corruption and changed-head owner import failover.
use super::*;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

#[test]
fn final_full_version_import_rejects_a_corrupt_holder_and_accepts_the_exact_healthy_replica() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let first = Process::start(owner.fingerprint(), 1, None);
    let second = Process::start(owner.fingerprint(), 2, None);
    let administrator = first.participant(1, &connector).remote;
    let armed = Arc::new(AtomicBool::new(false));
    let old_objects = Arc::new(Mutex::new(Vec::new()));
    let imports = Arc::new(Mutex::new(Vec::new()));
    let proofs = Arc::new(AtomicUsize::new(0));
    let writes = Arc::new(AtomicUsize::new(0));
    let active = armed.clone();
    let initial = old_objects.clone();
    let first_imports = imports.clone();
    let jobs = proofs.clone();
    let stored = writes.clone();
    let directory = first.directory.clone();
    let inspect = administrator.clone();
    let mut primary = first.participant(1, &connector);
    primary.remote = primary.remote.with_trace(Arc::new(move |event| {
        if event.operation == "fetch-version" {
            first_imports.lock().unwrap().push((1, event.succeeded));
        }
        if event.operation == "fhe-proof" {
            jobs.fetch_add(1, Ordering::SeqCst);
        }
        if event.operation == "store" {
            stored.fetch_add(1, Ordering::SeqCst);
        }
        if event.operation == "store" && event.succeeded && active.swap(false, Ordering::SeqCst) {
            let old = initial.lock().unwrap();
            let object = inspect
                .status()
                .unwrap()
                .objects
                .into_iter()
                .find(|object| !old.contains(&object.id))
                .unwrap();
            let name = object
                .id
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
                + ".object2";
            let path = directory.join(name);
            let mut bytes = std::fs::read(&path).unwrap();
            // This byte belongs to the complete encrypted identity tail, not
            // the owner index header used during earlier preparation.
            *bytes.last_mut().unwrap() ^= 1;
            std::fs::write(path, bytes).unwrap();
        }
    }));
    let second_imports = imports.clone();
    let mut replica = second.participant(2, &connector);
    replica.remote = replica.remote.with_trace(Arc::new(move |event| {
        if event.operation == "fetch-version" {
            second_imports.lock().unwrap().push((2, event.succeeded));
        }
    }));
    let mut session = Session::create(
        "full-frame-failover".into(),
        &[PlainRow {
            age: 18,
            amount: 10,
        }],
        vec![primary],
        test_contract(),
    )
    .unwrap();
    let before = session.shards().remove(0);
    session.copy_shard(before.id, replica).unwrap();
    *old_objects.lock().unwrap() = administrator
        .status()
        .unwrap()
        .objects
        .into_iter()
        .map(|object| object.id)
        .collect();
    proofs.store(0, Ordering::SeqCst);
    writes.store(0, Ordering::SeqCst);
    imports.lock().unwrap().clear();
    armed.store(true, Ordering::SeqCst);

    let outcome = session
        .execute("INSERT INTO records(age,amount) VALUES(42,7)")
        .unwrap();

    assert!(matches!(outcome, VerifiedResult::Inserted { count: 1, .. }));
    assert_eq!(proofs.load(Ordering::SeqCst), 1);
    assert_eq!(writes.load(Ordering::SeqCst), 1);
    let imported = imports.lock().unwrap();
    assert_eq!(&*imported, &[(1, false), (2, true)]);
    drop(imported);
    let accepted = session.shards().remove(0);
    assert_ne!(accepted.object, before.object);
    assert_eq!(accepted.holders, vec![2]);
    assert!(session.resume_pending().unwrap().is_none());
    assert_eq!(
        rows(session.execute("SELECT * FROM records").unwrap()),
        vec![vec![18, 10], vec![42, 7]]
    );
}
