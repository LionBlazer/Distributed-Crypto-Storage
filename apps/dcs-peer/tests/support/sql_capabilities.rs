//! SQL refusal is observable before any real peer operation, including empty work.
use super::*;
use std::sync::{Arc, Mutex};

#[test]
fn every_unproved_sql_operation_rejects_without_rpc_publication_or_cached_answers() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let mut process = Process::start(owner.fingerprint(), 1, None);
    let events = Arc::new(Mutex::new(Vec::new()));
    let observed = events.clone();
    let mut participant = process.participant(1, &connector);
    participant.remote = participant.remote.with_trace(Arc::new(move |event| {
        observed.lock().unwrap().push(event.operation);
    }));
    let mut retained = None;
    for rows in [
        vec![],
        vec![PlainRow {
            age: 42,
            amount: 65535,
        }],
    ] {
        let mut session = Session::create(
            "capabilities".into(),
            &rows,
            vec![participant.clone()],
            test_contract(),
        )
        .unwrap();
        let initial = session.version();
        let heads: Vec<_> = session
            .shards()
            .into_iter()
            .map(|s| (s.data_head, s.index_head))
            .collect();
        let before = participant.remote.status().unwrap();
        for sql in [
            "SELECT * FROM records",
            "SELECT amount FROM records WHERE FALSE",
            "SELECT * FROM records WHERE TRUE LIMIT 0",
            "SELECT * FROM records OFFSET 1 LIMIT 1",
            "SELECT COUNT(*) FROM records",
            "SELECT SUM(amount) FROM records WHERE FALSE",
            "SELECT COUNT(*),SUM(amount) FROM records WHERE age IN(7,42)",
            "UPDATE records SET amount=amount+0 WHERE TRUE",
            "UPDATE records SET amount=amount+1 WHERE FALSE",
            "INSERT INTO records VALUES(18,20),(42,30)",
        ] {
            events.lock().unwrap().clear();
            let error = session.execute(sql).unwrap_err();
            assert!(
                matches!(error, storage_client::Error::InvalidInput(ref reason) if reason.contains("encrypted SQL execution is unavailable")),
                "{sql}: {error}"
            );
            assert!(
                events.lock().unwrap().is_empty(),
                "No synchronization, read, proof, Store or Mine: {sql}"
            );
            assert_eq!(session.version(), initial);
            assert_eq!(
                session
                    .shards()
                    .into_iter()
                    .map(|s| (s.data_head, s.index_head))
                    .collect::<Vec<_>>(),
                heads
            );
            assert!(session.resume_pending().unwrap().is_none());
        }
        let after = participant.remote.status().unwrap();
        assert_eq!(after.journal_bytes, before.journal_bytes);
        assert_eq!(
            after.objects.iter().map(|o| o.id).collect::<Vec<_>>(),
            before.objects.iter().map(|o| o.id).collect::<Vec<_>>()
        );
        retained = Some(session);
    }
    // An unreachable peer cannot mask the capability rejection with a transport error.
    process.kill();
    events.lock().unwrap().clear();
    let mut session = retained.unwrap();
    assert!(
        session
            .execute("SELECT * FROM records")
            .unwrap_err()
            .to_string()
            .contains("encrypted SQL execution is unavailable")
    );
    assert!(events.lock().unwrap().is_empty());
}

#[test]
fn whole_script_preflight_prevents_database_creation_and_all_earlier_statements() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let process = Process::start(owner.fingerprint(), 1, None);
    let participant = process.participant(1, &connector);
    let before = participant.remote.status().unwrap();
    for tail in [
        "SELECT * FROM records LIMIT 0",
        "INSERT INTO records VALUES(18,20)",
        "UPDATE records SET amount=amount+0",
    ] {
        let sql = format!(
            "CREATE TABLE records (age TINYINT UNSIGNED NOT NULL, amount SMALLINT UNSIGNED NOT NULL); {tail}"
        );
        let mut session = None;
        let mut creations = 0;
        let result = storage_client::SqlScript::parse(&sql).and_then(|script| {
            script.execute(&mut session, || {
                creations += 1;
                Session::create(
                    "must-not-exist".into(),
                    &[],
                    vec![participant.clone()],
                    test_contract(),
                )
            })
        });
        let error = result.unwrap_err();
        assert_eq!(error.failed_statement, 2);
        assert!(error.completed.is_empty());
        assert_eq!(creations, 0);
        assert!(session.is_none());
    }
    let after = participant.remote.status().unwrap();
    assert_eq!(after.objects.len(), before.objects.len());
    assert_eq!(after.public_setup_bytes, before.public_setup_bytes);
    assert_eq!(after.journal_bytes, before.journal_bytes);
}
