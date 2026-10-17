//! Front-end recognition never turns into a metadata-only live lock grant.
use super::*;
use std::sync::{Arc, Mutex};

#[test]
fn every_typed_lock_plan_rejects_before_any_peer_io_or_source_version_change() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let process = Process::start(owner.fingerprint(), 1, None);
    let events = Arc::new(Mutex::new(Vec::new()));
    let observed = events.clone();
    let mut participant = process.participant(1, &connector);
    participant.remote = participant
        .remote
        .with_trace(Arc::new(move |event| observed.lock().unwrap().push(event)));
    let mut session = Session::create(
        "lock-plan-rejection".into(),
        &[PlainRow { age: 42, amount: 7 }],
        vec![participant],
        test_contract(),
    )
    .unwrap();
    let initial = session.version();
    for mode in ["KEY SHARE", "SHARE", "NO KEY UPDATE", "UPDATE"] {
        for wait in ["", "NOWAIT", "SKIP LOCKED"] {
            events.lock().unwrap().clear();
            let sql = format!(
                "SELECT amount FROM records WHERE age=42 OFFSET 1 LIMIT 1 FOR {mode} {wait}"
            );
            let error = session.execute(&sql).unwrap_err();
            assert!(
                matches!(error,storage_client::Error::InvalidInput(ref text) if text.contains("composite source/ownership/FHE proof")),
                "{error}"
            );
            assert!(
                events.lock().unwrap().is_empty(),
                "No synchronize, fetch, proof, Mine or Store for {sql}"
            );
            assert_eq!(session.version(), initial);
        }
    }
}
