//! Synthetic public inputs; SQL results and compact writeback use actual encrypted peer operations.
use fhe_playground::{DatabaseDraft, LabEngine, LabError, PeerConfig, PlainRow, QueryOutcome};
fn lab(rows: Vec<PlainRow>, peers: usize) -> LabEngine {
    let mut engine = LabEngine::default();
    engine
        .create(DatabaseDraft {
            name: "public INSERT fixture".into(),
            rows,
            peers: (1..=peers).map(PeerConfig::numbered).collect(),
        })
        .unwrap();
    engine
}
fn rows(engine: &mut LabEngine) -> Vec<Vec<u32>> {
    let QueryOutcome::Selected { rows, .. } = engine.execute("SELECT * FROM records").unwrap()
    else {
        panic!("expected actual encrypted projection")
    };
    rows
}
#[test]
fn batch_insert_then_update_and_select_use_actual_ciphertext_and_preserve_global_order() {
    let mut engine = lab(
        vec![
            PlainRow { age: 7, amount: 1 },
            PlainRow {
                age: 18,
                amount: 255,
            },
        ],
        3,
    );
    assert_eq!(
        engine
            .snapshot()
            .unwrap()
            .replication
            .unwrap()
            .desired_copies,
        1
    );
    assert!(matches!(
        engine
            .execute("INSERT INTO records (age, amount) VALUES (42, 256),(0,0)")
            .unwrap(),
        QueryOutcome::Inserted { count: 2 }
    ));
    assert_eq!(
        rows(&mut engine),
        vec![vec![7, 1], vec![18, 255], vec![42, 256], vec![0, 0]]
    );
    engine
        .execute("UPDATE records SET amount=amount+1 WHERE age>=18")
        .unwrap();
    assert_eq!(
        rows(&mut engine),
        vec![vec![7, 1], vec![18, 256], vec![42, 257], vec![0, 0]]
    );
    let QueryOutcome::Aggregate { count, sum, .. } = engine
        .execute("SELECT COUNT(*), SUM(amount) FROM records")
        .unwrap()
    else {
        panic!("expected actual encrypted aggregate")
    };
    assert_eq!((count, sum), (4, 514));
    assert_eq!(engine.snapshot().unwrap().revision, 2);
}
#[test]
fn empty_table_batch_insert_preserves_extreme_values_and_cancelled_batch_publishes_nothing() {
    let mut engine = lab(vec![], 1);
    let before = engine.peer_heads_for_experiment().unwrap();
    engine
        .prepare_query("INSERT INTO records VALUES (0,0),(255,65535)", |_| {})
        .unwrap();
    engine.discard_prepared();
    engine.commit_prepared();
    assert_eq!(engine.peer_heads_for_experiment().unwrap(), before);
    assert!(rows(&mut engine).is_empty());
    engine
        .execute("INSERT INTO records VALUES (0,0),(255,65535)")
        .unwrap();
    assert_eq!(rows(&mut engine), vec![vec![0, 0], vec![255, 65535]]);
    assert_eq!(engine.snapshot().unwrap().revision, 1);
}
#[test]
fn stale_offline_copies_keep_their_actual_old_row_payload_after_append_then_repair() {
    let mut engine = lab(vec![PlainRow { age: 18, amount: 1 }], 2);
    engine.set_replication(2).unwrap();
    engine.repair_replicas().unwrap();
    engine.set_peer_online(2, false).unwrap();
    engine
        .execute("INSERT INTO records VALUES (42,2),(7,3)")
        .unwrap();
    let snapshot = engine.snapshot().unwrap();
    let peer = snapshot.peers.iter().find(|peer| peer.id == 2).unwrap();
    // Peer2 originally held both logical shards, including empty shard2. INSERT chooses empty shard2.
    assert_eq!(peer.rows, 1);
    assert_eq!(peer.logical_bytes, 3);
    assert_eq!(peer.owner_row_indices, vec![0]);
    engine.set_peer_online(2, true).unwrap();
    assert_eq!(
        rows(&mut engine),
        vec![vec![18, 1], vec![42, 2], vec![7, 3]]
    );
    engine.repair_replicas().unwrap();
    let peer = engine
        .snapshot()
        .unwrap()
        .peers
        .into_iter()
        .find(|peer| peer.id == 2)
        .unwrap();
    assert_eq!(peer.rows, 3);
    assert_eq!(peer.logical_bytes, 9);
    assert_eq!(peer.owner_row_indices, vec![0, 1, 2]);
}
#[test]
fn quota_and_row_budget_failures_leave_all_physical_heads_and_inspector_unchanged() {
    let mut engine = lab(vec![PlainRow { age: 18, amount: 1 }], 2);
    engine.set_replication(2).unwrap();
    engine.repair_replicas().unwrap();
    let snapshot = engine.snapshot().unwrap();
    let mut config = snapshot.peers[1].config.clone();
    config.storage_limit_bytes = snapshot.peers[1].stored_bytes;
    engine.set_peer_config(2, config).unwrap();
    let before = engine.peer_heads_for_experiment().unwrap();
    assert!(matches!(
        engine.execute("INSERT INTO records VALUES (42,2),(7,3)"),
        Err(LabError::InvalidInput(_))
    ));
    assert_eq!(engine.peer_heads_for_experiment().unwrap(), before);
    assert_eq!(engine.snapshot().unwrap().revision, 0);
    assert_eq!(rows(&mut engine), vec![vec![18, 1]]);
    let mut full = lab(vec![PlainRow { age: 0, amount: 0 }; 127], 1);
    let before = full.peer_heads_for_experiment().unwrap();
    assert!(
        full.execute("INSERT INTO records VALUES (1,1),(2,2)")
            .is_err()
    );
    assert_eq!(full.peer_heads_for_experiment().unwrap(), before);
    assert_eq!(full.snapshot().unwrap().revision, 0);
    assert_eq!(full.snapshot().unwrap().owner_rows.len(), 127);
}
#[test]
fn topology_changes_revoke_staged_insert_and_total_copy_loss_has_no_fixture_recovery() {
    let mut engine = lab(vec![PlainRow { age: 18, amount: 1 }], 1);
    let before = engine.peer_heads_for_experiment().unwrap();
    engine
        .prepare_query("INSERT INTO records VALUES (42,2),(7,3)", |_| {})
        .unwrap();
    engine.set_peer_online(1, false).unwrap();
    engine.commit_prepared();
    assert_eq!(engine.peer_heads_for_experiment().unwrap(), before);
    assert_eq!(engine.snapshot().unwrap().revision, 0);
    engine.repartition(vec![]).unwrap();
    engine
        .repartition(vec![(99, PeerConfig::numbered(99), true)])
        .unwrap();
    assert_eq!(engine.snapshot().unwrap().peers[0].logical_bytes, 0);
    assert!(matches!(
        engine.execute("INSERT INTO records VALUES (42,2)"),
        Err(LabError::UnavailableShards(_))
    ));
    assert!(matches!(
        engine.execute("SELECT * FROM records"),
        Err(LabError::UnavailableShards(_))
    ));
    assert!(engine.repair_replicas().is_err());
}
