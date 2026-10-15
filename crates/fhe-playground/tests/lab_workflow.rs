use std::sync::Once;

use fhe_playground::PlainRow;
use fhe_playground::{DatabaseDraft, LabEngine, LabError, PeerConfig, QueryOutcome, sample_rows};

// Synthetic public fixtures; each test owns fresh, ephemeral FHE keys.
fn lab(rows: Vec<PlainRow>, peers: usize) -> LabEngine {
    static RAYON: Once = Once::new();
    RAYON.call_once(|| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build_global()
            .unwrap()
    });
    let mut engine = LabEngine::default();
    engine
        .create(DatabaseDraft {
            name: "test".into(),
            rows,
            peers: (1..=peers).map(PeerConfig::numbered).collect(),
        })
        .unwrap();
    engine
}

fn aggregate(engine: &mut LabEngine, sql: &str) -> (u32, u32) {
    match engine.execute(sql).unwrap() {
        QueryOutcome::Aggregate { count, sum, .. } => (count, sum),
        _ => panic!("expected an encrypted aggregate"),
    }
}

const ADULTS: &str = "SELECT COUNT(*), SUM(amount) FROM records WHERE age >= 18";
const ALL: &str = "SELECT COUNT(*), SUM(amount) FROM records";

#[test]
fn editing_sql_updates_real_encrypted_shards_and_preserves_their_image_sizes() {
    // Arrange: four rows distributed over three logical peers.
    let mut engine = lab(sample_rows(4).unwrap(), 3);
    let before = engine.snapshot().unwrap();
    assert_eq!(
        before
            .peers
            .iter()
            .map(|peer| peer.rows)
            .collect::<Vec<_>>(),
        [2, 1, 1]
    );
    assert_eq!(aggregate(&mut engine, ADULTS), (2, 50));

    // Act: the same SQL operation is used by the GUI and its one-click preset.
    let outcome = engine
        .execute("UPDATE records SET amount = amount + 5 WHERE age >= 18")
        .unwrap();

    // Assert: results come from updated ciphertexts; nonmatching rows remain unchanged.
    assert!(matches!(outcome, QueryOutcome::Updated { committed: true }));
    assert_eq!(aggregate(&mut engine, ADULTS), (2, 60));
    assert_eq!(aggregate(&mut engine, ALL), (4, 110));
    let after = engine.snapshot().unwrap();
    assert_eq!(after.revision, 1);
    assert_eq!(
        after
            .owner_rows
            .iter()
            .map(|row| row.amount)
            .collect::<Vec<_>>(),
        [10, 25, 35, 40]
    );
    assert_eq!(
        after
            .peers
            .iter()
            .map(|peer| peer.stored_bytes)
            .collect::<Vec<_>>(),
        before
            .peers
            .iter()
            .map(|peer| peer.stored_bytes)
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_missing_required_shard_prevents_incomplete_queries_and_partial_updates() {
    let mut engine = lab(sample_rows(4).unwrap(), 3);
    engine.set_peer_online(2, false).unwrap();

    for sql in [ADULTS, "UPDATE records SET amount = amount + 5"] {
        assert!(matches!(engine.execute(sql), Err(LabError::Unavailable(ids)) if ids == [2]));
    }

    assert_eq!(engine.snapshot().unwrap().revision, 0);
    engine.set_peer_online(2, true).unwrap();
    assert_eq!(aggregate(&mut engine, ALL), (4, 100));
}

#[test]
fn overflow_on_a_later_shard_rolls_back_the_already_staged_shards() {
    // Arrange: peer 1 can update, but peer 2 would overflow.
    let mut engine = lab(
        vec![
            PlainRow {
                age: 18,
                amount: 10,
            },
            PlainRow {
                age: 19,
                amount: u16::MAX,
            },
        ],
        2,
    );

    let before_heads = engine.peer_heads_for_experiment().unwrap();
    let outcome = engine
        .execute("UPDATE records SET amount = amount + 1")
        .unwrap();

    assert!(matches!(
        outcome,
        QueryOutcome::Updated { committed: false }
    ));
    assert_eq!(engine.peer_heads_for_experiment().unwrap(), before_heads);
    assert_eq!(engine.snapshot().unwrap().revision, 0);
    assert_eq!(aggregate(&mut engine, ALL), (2, 65_545));
}

#[test]
fn an_offline_peer_with_no_rows_does_not_make_the_database_incomplete() {
    let mut engine = lab(vec![PlainRow { age: 18, amount: 7 }], 2);
    engine.set_peer_online(2, false).unwrap();

    assert_eq!(aggregate(&mut engine, ALL), (1, 7));
}

#[test]
fn an_empty_database_remains_queryable_when_all_empty_peers_are_offline() {
    let mut engine = lab(vec![], 2);
    engine.set_peer_online(1, false).unwrap();
    engine.set_peer_online(2, false).unwrap();

    assert_eq!(aggregate(&mut engine, ALL), (0, 0));
}

#[test]
fn invalid_replacement_keeps_the_original_database_and_keys_usable() {
    let mut engine = lab(vec![PlainRow { age: 18, amount: 7 }], 1);

    let result = engine.create(DatabaseDraft {
        name: "".into(),
        rows: vec![],
        peers: vec![],
    });

    assert!(matches!(result, Err(LabError::InvalidInput(_))));
    assert_eq!(engine.snapshot().unwrap().name, "test");
    assert_eq!(aggregate(&mut engine, ALL), (1, 7));
    assert!(engine.set_peer_online(0, false).is_err());
    assert!(engine.set_peer_online(2, false).is_err());
}

#[test]
fn removing_middle_peer_preserves_surviving_ids_and_updated_owner_data() {
    let mut engine = lab(sample_rows(3).unwrap(), 3);
    engine
        .execute("UPDATE records SET amount = amount + 1")
        .unwrap();
    engine
        .repartition(vec![
            (1, PeerConfig::numbered(1), true),
            (3, PeerConfig::numbered(3), true),
        ])
        .unwrap();
    let snapshot = engine.snapshot().unwrap();
    assert_eq!(
        snapshot
            .peers
            .iter()
            .map(|peer| peer.id)
            .collect::<Vec<_>>(),
        [1, 3]
    );
    assert_eq!(aggregate(&mut engine, ALL), (3, 63));
    engine.set_peer_online(3, false).unwrap();
    assert!(matches!(engine.execute(ALL),Err(LabError::Unavailable(ids)) if ids==[3]));
}

#[test]
fn deleting_last_peer_retains_owner_data_but_cannot_answer_sql_until_explicit_rebuild() {
    let mut engine = lab(sample_rows(1).unwrap(), 1);
    engine.repartition(vec![]).unwrap();
    assert!(engine.snapshot().unwrap().peers.is_empty());
    assert!(
        matches!(engine.execute(ALL),Err(LabError::InvalidInput(message)) if message.contains("No storage peers"))
    );
    engine
        .repartition(vec![(9, PeerConfig::numbered(9), true)])
        .unwrap();
    assert_eq!(aggregate(&mut engine, ALL), (1, 10));
    assert_eq!(engine.snapshot().unwrap().peers[0].id, 9);
}

#[test]
fn cancelled_staged_update_changes_no_ciphertext_or_owner_revision() {
    let mut engine = lab(sample_rows(1).unwrap(), 1);
    let outcome = engine
        .prepare_query("UPDATE records SET amount = amount + 5", |_| {})
        .unwrap();
    assert!(matches!(outcome, QueryOutcome::Updated { committed: true }));
    assert_eq!(engine.snapshot().unwrap().revision, 0);
    assert_eq!(engine.snapshot().unwrap().owner_rows[0].amount, 10);
    engine.discard_prepared();
    engine.commit_prepared();
    assert_eq!(aggregate(&mut engine, ALL), (1, 10));
    assert_eq!(engine.snapshot().unwrap().revision, 0);
}

#[test]
fn adding_custom_peers_preserves_updated_ciphertexts_revision_and_availability() {
    let mut engine = lab(sample_rows(2).unwrap(), 1);
    engine
        .execute("UPDATE records SET amount = amount + 1")
        .unwrap();
    let before = engine.snapshot().unwrap();
    let mut fast = PeerConfig::numbered(2);
    fast.name = "Fast SSD".into();
    fast.delay_ms = 5;
    let profiles = vec![
        PeerConfig::numbered(1),
        fast.clone(),
        PeerConfig::numbered(3),
    ];

    engine.configure_peers(profiles).unwrap();

    let after = engine.snapshot().unwrap();
    assert_eq!(after.revision, before.revision);
    assert_eq!(after.peers[1].config, fast);
    assert_eq!(
        after
            .peers
            .iter()
            .map(|p| p.owner_row_indices.clone())
            .collect::<Vec<_>>(),
        [vec![0], vec![1], vec![]]
    );
    assert_eq!(aggregate(&mut engine, ALL), (2, 32));
    engine.set_peer_online(2, false).unwrap();
    engine
        .configure_peers((1..=4).map(PeerConfig::numbered).collect())
        .unwrap();
    assert!(!engine.snapshot().unwrap().peers[1].online);
    assert!(matches!(engine.execute(ALL), Err(LabError::Unavailable(ids)) if ids == [2]));
}

#[test]
fn a_quota_failure_after_staging_a_shard_keeps_the_entire_original_layout() {
    let mut engine = lab(sample_rows(2).unwrap(), 1);
    let before = engine.snapshot().unwrap();
    let mut tiny = PeerConfig::numbered(2);
    tiny.storage_limit_bytes = 1024;

    let outcome = engine.configure_peers(vec![PeerConfig::numbered(1), tiny]);

    assert!(
        matches!(outcome, Err(LabError::InvalidInput(message)) if message.contains("storage quota"))
    );
    let after = engine.snapshot().unwrap();
    assert_eq!(after.peers.len(), 1);
    assert_eq!(after.revision, before.revision);
    assert_eq!(after.peers[0].stored_bytes, before.peers[0].stored_bytes);
    assert_eq!(aggregate(&mut engine, ALL), (2, 30));
}

#[test]
fn invalid_peer_settings_leave_the_live_profile_and_query_results_unchanged() {
    let mut engine = lab(sample_rows(1).unwrap(), 1);
    let original = engine.snapshot().unwrap().peers[0].config.clone();
    let mut invalid = original.clone();
    invalid.name = "Rejected settings".into();
    invalid.storage_limit_bytes = 1024;

    assert!(engine.set_peer_config(1, invalid).is_err());

    assert_eq!(engine.snapshot().unwrap().peers[0].config, original);
    assert_eq!(aggregate(&mut engine, ALL), (1, 10));
    let mut invalid_delay = original;
    invalid_delay.delay_ms = 1001;
    assert!(engine.set_peer_config(1, invalid_delay).is_err());
}

#[test]
fn progress_identifies_only_required_nonempty_shards_in_execution_order() {
    let mut engine = lab(sample_rows(2).unwrap(), 3);
    engine.set_peer_online(3, false).unwrap();
    let visited = std::cell::RefCell::new(Vec::new());

    engine
        .execute_with_progress(ALL, |progress| visited.borrow_mut().push(progress.peer_id))
        .unwrap();

    engine
        .execute_with_progress("UPDATE records SET amount = amount + 1", |progress| {
            visited.borrow_mut().push(progress.peer_id)
        })
        .unwrap();
    assert_eq!(*visited.borrow(), [1, 2, 1, 2]);
}

#[test]
fn bfv_full128_no_where_and_duplicate_selection_use_actual_shards_and_writeback() {
    let rows: Vec<_> = (0..128)
        .map(|amount| PlainRow {
            age: if amount % 2 == 0 { 18 } else { 17 },
            amount,
        })
        .collect();
    let mut engine = lab(rows.clone(), 3);
    assert_eq!(aggregate(&mut engine, ALL), (128, 8128));
    assert_eq!(
        aggregate(
            &mut engine,
            "SELECT COUNT(*), SUM(amount) FROM records WHERE age = 18"
        ),
        (64, 4032)
    );
    assert_eq!(
        aggregate(
            &mut engine,
            "SELECT COUNT(*), SUM(amount) FROM records WHERE age = 255"
        ),
        (0, 0)
    );
    assert!(matches!(
        engine
            .execute("UPDATE records SET amount = amount + 1")
            .unwrap(),
        QueryOutcome::Updated { committed: true }
    ));
    assert_eq!(aggregate(&mut engine, ALL), (128, 8256));
    let snapshot = engine.snapshot().unwrap();
    for (actual, original) in snapshot.owner_rows.iter().zip(&rows) {
        assert_eq!(actual.age, original.age);
        assert_eq!(actual.amount, original.amount + 1);
    }
}

#[test]
fn strict_and_closed_age_ranges_use_real_bfv_shards_including_valid_empty_ranges() {
    let mut engine = lab(
        [0, 1, 17, 18, 19, 42, 43, 254, 255]
            .into_iter()
            .enumerate()
            .map(|(index, age)| PlainRow {
                age,
                amount: 1 << index,
            })
            .collect(),
        3,
    );
    for (clause, expected) in [
        ("age < 18", (3, 7)),
        ("age <= 18", (4, 15)),
        ("age > 18", (5, 496)),
        ("age BETWEEN 18 AND 42", (3, 56)),
        ("age BETWEEN 0 AND 0", (1, 1)),
        ("age <= 0", (1, 1)),
        ("age > 254", (1, 256)),
        ("age BETWEEN 255 AND 255", (1, 256)),
        ("age < 255", (8, 255)),
        ("age >= 255", (1, 256)),
        ("age BETWEEN 0 AND 255", (9, 511)),
        ("age BETWEEN 2 AND 16", (0, 0)),
        ("age = 16", (0, 0)),
    ] {
        let sql = format!("SELECT COUNT(*), SUM(amount) FROM records WHERE {clause}");
        let outcome = engine.execute(&sql).unwrap();

        let QueryOutcome::Aggregate { count, sum, peers } = outcome else {
            panic!("expected aggregate for {sql}");
        };
        assert_eq!((count, sum), expected, "{sql}");
        // Even a valid range with no matches completes an actual encrypted operation per shard.
        assert_eq!(
            peers.iter().map(|peer| peer.id).collect::<Vec<_>>(),
            [1, 2, 3]
        );
    }
}

#[test]
fn public_constant_false_bounds_are_successful_noops_without_any_state_change() {
    let mut engine = lab(
        vec![
            PlainRow {
                age: 0,
                amount: u16::MAX,
            },
            PlainRow {
                age: 255,
                amount: u16::MAX,
            },
            PlainRow { age: 18, amount: 7 },
        ],
        3,
    );
    let before = engine.snapshot().unwrap();
    let heads = engine.peer_heads_for_experiment().unwrap();
    for clause in ["age < 0", "age > 255", "age BETWEEN 255 AND 0"] {
        let visited = std::cell::RefCell::new(Vec::new());
        let read = engine
            .execute_with_progress(
                &format!("SELECT COUNT(*), SUM(amount) FROM records WHERE {clause}"),
                |progress| visited.borrow_mut().push(progress.peer_id),
            )
            .unwrap();
        let update = engine
            .execute_with_progress(
                &format!("UPDATE records SET amount = amount + 65535 WHERE {clause}"),
                |progress| visited.borrow_mut().push(progress.peer_id),
            )
            .unwrap();

        assert!(
            matches!(read, QueryOutcome::Aggregate { count: 0, sum: 0, peers } if peers.is_empty())
        );
        assert!(matches!(update, QueryOutcome::Updated { committed: true }));
        assert!(visited.borrow().is_empty());
        let after = engine.snapshot().unwrap();
        assert_eq!(after.owner_rows, before.owner_rows);
        assert_eq!(after.revision, before.revision);
        assert_eq!(engine.peer_heads_for_experiment().unwrap(), heads);
        assert_eq!(
            after
                .peers
                .iter()
                .map(|peer| peer.stored_bytes)
                .collect::<Vec<_>>(),
            before
                .peers
                .iter()
                .map(|peer| peer.stored_bytes)
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn constant_false_plans_still_require_a_database_storage_and_online_shards() {
    let sqls = [
        "SELECT COUNT(*), SUM(amount) FROM records WHERE age < 0",
        "UPDATE records SET amount = amount + 1 WHERE age > 255",
    ];
    let mut empty = LabEngine::default();
    for sql in sqls {
        assert!(matches!(empty.execute(sql), Err(LabError::NoDatabase)));
    }
    let mut engine = lab(sample_rows(2).unwrap(), 2);
    engine.set_peer_online(2, false).unwrap();
    for sql in sqls {
        assert!(matches!(engine.execute(sql), Err(LabError::Unavailable(ids)) if ids == [2]));
    }
    engine.configure_peers(Vec::new()).unwrap();
    for sql in sqls {
        assert!(matches!(
            engine.execute(sql),
            Err(LabError::InvalidInput(_))
        ));
    }
}

#[test]
fn range_update_overflow_rejects_all_shards_then_safe_range_keeps_excluded_rows() {
    // Peers1/2 can update; selected peer3 overflows after both have staged writes.
    let rows = vec![
        PlainRow {
            age: 18,
            amount: 255,
        },
        PlainRow {
            age: 19,
            amount: 256,
        },
        PlainRow {
            age: 42,
            amount: u16::MAX,
        },
        PlainRow {
            age: 17,
            amount: u16::MAX,
        },
    ];
    let mut engine = lab(rows.clone(), 3);
    let before = engine.peer_heads_for_experiment().unwrap();

    let overflow = engine
        .execute("UPDATE records SET amount = amount + 1 WHERE age BETWEEN 18 AND 42")
        .unwrap();

    assert!(matches!(
        overflow,
        QueryOutcome::Updated { committed: false }
    ));
    assert_eq!(engine.peer_heads_for_experiment().unwrap(), before);
    assert_eq!(engine.snapshot().unwrap().owner_rows, rows);
    assert_eq!(engine.snapshot().unwrap().revision, 0);

    let accepted = engine
        .execute("UPDATE records SET amount = amount + 1 WHERE age BETWEEN 18 AND 19")
        .unwrap();

    assert!(matches!(
        accepted,
        QueryOutcome::Updated { committed: true }
    ));
    let after = engine.snapshot().unwrap();
    assert_eq!(after.revision, 1);
    assert_eq!(
        after.owner_rows,
        [
            PlainRow {
                age: 18,
                amount: 256
            },
            PlainRow {
                age: 19,
                amount: 257
            },
            rows[2],
            rows[3],
        ]
    );
    let heads = engine.peer_heads_for_experiment().unwrap();
    for index in [0, 1] {
        assert_ne!(heads[index].data, before[index].data);
        assert_ne!(heads[index].index, before[index].index);
    }
    assert_eq!(heads[2], before[2]);
    assert_eq!(
        aggregate(
            &mut engine,
            "SELECT COUNT(*), SUM(amount) FROM records WHERE age BETWEEN 18 AND 19"
        ),
        (2, 513)
    );
}
