use std::sync::Once;

use fhe_playground::{DatabaseDraft, LabEngine, LabError, QueryOutcome, sample_rows};
use fhe_prototype::PlainRow;

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
            peer_count: peers,
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
            .map(|peer| peer.compressed_bytes)
            .collect::<Vec<_>>(),
        before
            .peers
            .iter()
            .map(|peer| peer.compressed_bytes)
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

    let outcome = engine
        .execute("UPDATE records SET amount = amount + 1")
        .unwrap();

    assert!(matches!(
        outcome,
        QueryOutcome::Updated { committed: false }
    ));
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
        name: "replacement".into(),
        rows: vec![],
        peer_count: 0,
    });

    assert!(matches!(result, Err(LabError::InvalidInput(_))));
    assert_eq!(engine.snapshot().unwrap().name, "test");
    assert_eq!(aggregate(&mut engine, ALL), (1, 7));
    assert!(engine.set_peer_online(0, false).is_err());
    assert!(engine.set_peer_online(2, false).is_err());
}
