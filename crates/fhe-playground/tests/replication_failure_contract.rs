//! Cross-API failure contracts over public synthetic rows and actual BFV queries.
use fhe_playground::{DatabaseDraft, LabEngine, LabError, PeerConfig, PlainRow, QueryOutcome};

const ALL: &str = "SELECT COUNT(*), SUM(amount) FROM records";
const UPDATE: &str = "UPDATE records SET amount = amount + 5 WHERE age >= 18";

fn replicated() -> LabEngine {
    let mut engine = LabEngine::default();
    engine
        .create(DatabaseDraft {
            name: "public-replication-contract".into(),
            rows: [(18, 1), (25, 2), (17, 4), (42, 8), (7, 16), (18, 32)]
                .into_iter()
                .map(|(age, amount)| PlainRow { age, amount })
                .collect(),
            peers: (1..=3).map(PeerConfig::numbered).collect(),
        })
        .unwrap();
    engine.set_replication(2).unwrap();
    engine.repair_replicas().unwrap();
    engine
}

fn read(engine: &mut LabEngine) -> (u32, u32) {
    let QueryOutcome::Aggregate { count, sum, .. } = engine.execute(ALL).unwrap() else {
        panic!("expected an actual BFV aggregate");
    };
    (count, sum)
}

#[test]
fn losing_every_physical_copy_cannot_be_recovered_from_the_owner_fixture() {
    let mut engine = replicated();
    let before = engine.snapshot().unwrap();
    let heads: Vec<_> = before
        .replication
        .as_ref()
        .unwrap()
        .shards
        .iter()
        .map(|shard| (shard.id, shard.data_head.clone(), shard.index_head.clone()))
        .collect();

    engine.repartition(Vec::new()).unwrap();
    engine
        .repartition(vec![(99, PeerConfig::numbered(99), true)])
        .unwrap();

    assert!(engine.repair_replicas().is_err());
    assert!(matches!(engine.execute(ALL), Err(LabError::UnavailableShards(ids)) if ids.len() == 3));
    assert!(
        matches!(engine.execute(UPDATE), Err(LabError::UnavailableShards(ids)) if ids.len() == 3)
    );
    let after = engine.snapshot().unwrap();
    assert_eq!(after.owner_rows, before.owner_rows);
    assert_eq!(after.revision, before.revision);
    let remaining_heads: Vec<_> = after
        .replication
        .as_ref()
        .unwrap()
        .shards
        .iter()
        .map(|shard| (shard.id, shard.data_head.clone(), shard.index_head.clone()))
        .collect();
    assert_eq!(remaining_heads, heads);
    assert_eq!(after.peers.len(), 1);
    assert_eq!(after.peers[0].stored_bytes, 0);
    assert!(
        after
            .replication
            .unwrap()
            .shards
            .iter()
            .all(|shard| shard.executor.is_none())
    );
}

#[test]
fn correlated_copies_do_not_prove_independence_or_inflate_the_query_row_count() {
    let mut engine = replicated();
    let heads = engine.peer_heads_for_experiment().unwrap();
    let before = engine.snapshot().unwrap();
    for id in 1..=3 {
        engine.set_failure_domain(id, 7).unwrap();
    }

    assert!(engine.repair_replicas().is_err());

    assert_eq!(read(&mut engine), (6, 63));
    assert_eq!(engine.peer_heads_for_experiment().unwrap(), heads);
    let after = engine.snapshot().unwrap();
    assert_eq!(after.revision, before.revision);
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
    for shard in after.replication.unwrap().shards {
        let domains: std::collections::BTreeSet<_> = shard
            .replicas
            .iter()
            .filter(|copy| copy.current && copy.online)
            .map(|copy| copy.failure_domain)
            .collect();
        assert_eq!(domains.len(), 1);
    }
}

#[test]
fn availability_change_revokes_every_staged_replica_update_before_commit() {
    let mut engine = replicated();
    let before = engine.snapshot().unwrap();
    let heads = engine.peer_heads_for_experiment().unwrap();
    assert!(matches!(
        engine.prepare_query(UPDATE, |_| {}).unwrap(),
        QueryOutcome::Updated { committed: true }
    ));

    engine.set_peer_online(1, false).unwrap();
    engine.commit_prepared();

    assert_eq!(engine.peer_heads_for_experiment().unwrap(), heads);
    assert_eq!(engine.snapshot().unwrap().revision, before.revision);
    assert_eq!(read(&mut engine), (6, 63));
    engine.set_peer_online(1, true).unwrap();
    assert!(matches!(
        engine.execute(UPDATE).unwrap(),
        QueryOutcome::Updated { committed: true }
    ));
    assert_eq!(read(&mut engine), (6, 83));
    let committed = engine.peer_heads_for_experiment().unwrap();
    engine.repair_replicas().unwrap();
    assert_eq!(engine.peer_heads_for_experiment().unwrap(), committed);
    assert_eq!(engine.snapshot().unwrap().revision, before.revision + 1);
}
