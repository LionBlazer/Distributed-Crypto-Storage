//! Public synthetic fixtures; results must come from encrypted current table copies.
use fhe_playground::{
    Column, DatabaseDraft, LabEngine, LabError, PeerConfig, PlainRow, QueryOutcome,
};

fn lab() -> LabEngine {
    let mut engine = LabEngine::default();
    engine
        .create(DatabaseDraft {
            name: "public-row-read-fixture".into(),
            rows: vec![
                PlainRow {
                    age: 42,
                    amount: 255,
                },
                PlainRow { age: 0, amount: 0 },
                PlainRow {
                    age: 18,
                    amount: 10,
                },
                PlainRow {
                    age: 42,
                    amount: 256,
                },
                PlainRow {
                    age: 255,
                    amount: 65535,
                },
            ],
            peers: (1..=3).map(PeerConfig::numbered).collect(),
        })
        .unwrap();
    engine
}
fn selected(engine: &mut LabEngine, sql: &str) -> (Vec<Column>, Vec<Vec<u32>>) {
    let QueryOutcome::Selected { columns, rows } = engine.execute(sql).unwrap() else {
        panic!("expected final decrypted BFV projected rows");
    };
    (columns, rows)
}

#[test]
fn select_star_merges_original_row_order_and_projects_only_requested_columns() {
    let mut engine = lab();
    assert_eq!(
        selected(&mut engine, "SELECT * FROM records"),
        (
            vec![Column::Age, Column::Amount],
            vec![
                vec![42, 255],
                vec![0, 0],
                vec![18, 10],
                vec![42, 256],
                vec![255, 65535]
            ],
        )
    );
    assert_eq!(
        selected(
            &mut engine,
            "SELECT amount, age FROM records WHERE age BETWEEN 18 AND 42 LIMIT 2"
        ),
        (
            vec![Column::Amount, Column::Age],
            vec![vec![255, 42], vec![10, 18]],
        )
    );
    assert_eq!(
        selected(&mut engine, "SELECT age FROM records WHERE age = 42"),
        (vec![Column::Age], vec![vec![42], vec![42]],)
    );
    assert_eq!(
        selected(&mut engine, "SELECT amount FROM records WHERE age > 254"),
        (vec![Column::Amount], vec![vec![65535]],)
    );
    assert!(
        selected(&mut engine, "SELECT * FROM records LIMIT 0")
            .1
            .is_empty()
    );
    for clause in ["age < 0", "age > 255", "age BETWEEN 42 AND 18", "age = 7"] {
        assert!(
            selected(
                &mut engine,
                &format!("SELECT * FROM records WHERE {clause}")
            )
            .1
            .is_empty()
        );
    }
}

#[test]
fn standalone_aggregates_keep_real_peer_bfv_contributions_and_unsigned_sums() {
    let mut engine = lab();
    let QueryOutcome::Count { count, peers } = engine
        .execute("SELECT COUNT(*) FROM records WHERE age >= 18")
        .unwrap()
    else {
        panic!("expected COUNT");
    };
    assert_eq!(count, 4);
    assert_eq!(peers.iter().map(|peer| peer.count).sum::<u32>(), 4);
    assert_eq!(peers.len(), 3);
    let QueryOutcome::Sum { sum, peers } = engine
        .execute("SELECT SUM(amount) FROM records WHERE age >= 18")
        .unwrap()
    else {
        panic!("expected SUM");
    };
    assert_eq!(sum, 66056);
    assert_eq!(peers.iter().map(|peer| peer.sum).sum::<u32>(), 66056);
    assert_eq!(peers.len(), 3);
}

#[test]
fn projections_observe_committed_ciphertext_not_discarded_or_overflowed_updates() {
    let mut engine = lab();
    let before = engine.peer_heads_for_experiment().unwrap();
    engine
        .prepare_query("UPDATE records SET amount=amount+1 WHERE age=42", |_| {})
        .unwrap();
    engine.discard_prepared();
    assert_eq!(
        selected(&mut engine, "SELECT amount FROM records WHERE age=42").1,
        vec![vec![255], vec![256]]
    );
    engine
        .execute("UPDATE records SET amount=amount+1 WHERE age=42")
        .unwrap();
    assert_ne!(engine.peer_heads_for_experiment().unwrap(), before);
    assert_eq!(
        selected(&mut engine, "SELECT amount FROM records WHERE age=42").1,
        vec![vec![256], vec![257]]
    );
    let committed = engine.peer_heads_for_experiment().unwrap();
    assert!(matches!(
        engine
            .execute("UPDATE records SET amount=amount+1 WHERE age>=18")
            .unwrap(),
        QueryOutcome::Updated { committed: false }
    ));
    assert_eq!(engine.peer_heads_for_experiment().unwrap(), committed);
    assert_eq!(
        selected(&mut engine, "SELECT amount FROM records WHERE age=42").1,
        vec![vec![256], vec![257]]
    );
}

#[test]
fn limit_never_hides_offline_shards_even_for_zero_output_or_public_false_bounds() {
    let mut engine = lab();
    engine.set_peer_online(3, false).unwrap();
    for sql in [
        "SELECT * FROM records LIMIT 1",
        "SELECT age FROM records LIMIT 0",
        "SELECT amount FROM records WHERE age < 0",
        "SELECT COUNT(*) FROM records",
        "SELECT SUM(amount) FROM records",
    ] {
        assert!(
            matches!(engine.execute(sql), Err(LabError::Unavailable(peers)) if peers == vec![3]),
            "{sql}"
        );
    }
}

#[test]
fn replicated_reads_fail_over_and_never_use_stale_or_missing_copies_under_limit() {
    let mut engine = lab();
    engine.set_replication(2).unwrap();
    engine.repair_replicas().unwrap();
    engine.set_peer_online(1, false).unwrap();
    engine
        .execute("UPDATE records SET amount=amount+1 WHERE age=42")
        .unwrap();
    engine.set_peer_online(1, true).unwrap();
    assert_eq!(
        selected(&mut engine, "SELECT amount FROM records WHERE age=42").1,
        vec![vec![256], vec![257]]
    );
    // Only the old offline physical holder remains: its valid old ciphertext is stale.
    engine.set_peer_online(2, false).unwrap();
    engine.set_peer_online(3, false).unwrap();
    assert!(matches!(
        engine.execute("SELECT * FROM records LIMIT 1"),
        Err(LabError::UnavailableShards(_))
    ));
    engine
        .repartition(vec![(99, PeerConfig::numbered(99), true)])
        .unwrap();
    assert!(matches!(
        engine.execute("SELECT age FROM records LIMIT 0"),
        Err(LabError::UnavailableShards(_))
    ));
}

#[test]
fn empty_database_still_runs_encrypted_select_on_an_actual_online_peer() {
    let mut engine = LabEngine::default();
    engine
        .create(DatabaseDraft {
            name: "public empty fixture".into(),
            rows: vec![],
            peers: vec![PeerConfig::numbered(1), PeerConfig::numbered(2)],
        })
        .unwrap();
    engine.set_peer_online(2, false).unwrap();
    let visited = std::cell::RefCell::new(Vec::new());
    let result = engine
        .execute_with_progress("SELECT * FROM records", |progress| {
            visited.borrow_mut().push(progress.peer_id)
        })
        .unwrap();
    assert!(matches!(result,QueryOutcome::Selected {rows,..} if rows.is_empty()));
    assert_eq!(visited.into_inner(), vec![1]);
    engine.set_peer_online(1, false).unwrap();
    assert!(matches!(
        engine.execute("SELECT * FROM records"),
        Err(LabError::Unavailable(_))
    ));
}
