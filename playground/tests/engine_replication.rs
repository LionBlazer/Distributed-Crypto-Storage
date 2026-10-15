//! Explicitly public synthetic rows. Keys and actual encrypted replicas are ephemeral.
use fhe_playground::{DatabaseDraft, LabEngine, PeerConfig, PlainRow, QueryOutcome, sample_rows};

fn engine(rows: Vec<PlainRow>, peers: usize) -> LabEngine {
    let mut engine = LabEngine::default();
    engine
        .create(DatabaseDraft {
            name: "replication-contract".into(),
            rows,
            peers: (1..=peers).map(PeerConfig::numbered).collect(),
        })
        .unwrap();
    engine
}
fn aggregate(engine: &mut LabEngine) -> (u32, u32, usize) {
    let QueryOutcome::Aggregate { count, sum, peers } = engine
        .execute("SELECT COUNT(*), SUM(amount) FROM records")
        .unwrap()
    else {
        panic!("expected encrypted aggregate")
    };
    (count, sum, peers.len())
}

#[test]
fn enabling_is_configure_only_then_actual_ciphertext_repair_does_not_double_count() {
    let mut engine = engine(sample_rows(4).unwrap(), 3);
    let before = engine.snapshot().unwrap();
    let heads = engine.peer_heads_for_experiment().unwrap();

    engine.set_replication(2).unwrap();

    let configured = engine.snapshot().unwrap();
    let replicas = configured.replication.unwrap();
    assert_eq!(replicas.desired_copies, 2);
    assert!(
        replicas
            .shards
            .iter()
            .all(|shard| shard.replicas.len() == 1)
    );
    assert_eq!(engine.peer_heads_for_experiment().unwrap(), heads);
    assert_eq!(
        configured
            .peers
            .iter()
            .map(|peer| peer.stored_bytes)
            .sum::<usize>(),
        before
            .peers
            .iter()
            .map(|peer| peer.stored_bytes)
            .sum::<usize>()
    );

    engine.repair_replicas().unwrap();

    let repaired = engine.snapshot().unwrap();
    let info = repaired.replication.unwrap();
    assert!(info.shards.iter().all(|shard| {
        shard.replicas.len() == 2
            && shard
                .replicas
                .iter()
                .all(|copy| copy.current && copy.online)
    }));
    assert_eq!(
        repaired.peers.iter().map(|peer| peer.rows).sum::<usize>(),
        8
    );
    assert_eq!(
        repaired
            .peers
            .iter()
            .map(|peer| peer.stored_bytes)
            .sum::<usize>(),
        2 * before
            .peers
            .iter()
            .map(|peer| peer.stored_bytes)
            .sum::<usize>()
    );
    for (shard, head) in info.shards.iter().zip(heads) {
        assert_eq!(shard.data_head, head.data);
        assert_eq!(shard.index_head, head.index);
    }
    assert_eq!(aggregate(&mut engine), (4, 100, 3));
}

#[test]
fn routing_uses_one_available_current_low_delay_executor_per_logical_shard() {
    let mut engine = engine(sample_rows(3).unwrap(), 3);
    engine.set_replication(2).unwrap();
    engine.repair_replicas().unwrap();
    for (id, delay) in [(1, 30), (2, 5), (3, 10)] {
        let mut config = PeerConfig::numbered(id);
        config.delay_ms = delay;
        engine.set_peer_config(id, config).unwrap();
    }
    let snapshot = engine.snapshot().unwrap();
    let info = snapshot.replication.unwrap();
    assert_eq!(info.read_peers, [2, 3]);
    assert_eq!(info.write_peers, [1, 2, 3]);
    assert_eq!(
        info.shards
            .iter()
            .map(|shard| shard.executor)
            .collect::<Vec<_>>(),
        [Some(2), Some(2), Some(3)]
    );

    engine.set_peer_online(2, false).unwrap();

    assert!(
        engine
            .snapshot()
            .unwrap()
            .replication
            .unwrap()
            .unavailable_shards
            .is_empty()
    );
    assert_eq!(aggregate(&mut engine), (3, 60, 3));
}

#[test]
fn offline_copies_stay_stale_after_commit_and_cannot_execute_until_repaired() {
    let mut engine = engine(sample_rows(4).unwrap(), 3);
    engine.set_replication(2).unwrap();
    engine.repair_replicas().unwrap();
    engine.set_peer_online(1, false).unwrap();
    let before = engine.snapshot().unwrap().replication.unwrap();

    assert!(matches!(
        engine
            .execute("UPDATE records SET amount = amount + 1")
            .unwrap(),
        QueryOutcome::Updated { committed: true }
    ));

    let after = engine.snapshot().unwrap();
    assert_eq!(after.revision, 1);
    assert_eq!(
        after
            .owner_rows
            .iter()
            .map(|row| row.amount)
            .collect::<Vec<_>>(),
        [11, 21, 31, 41]
    );
    let info = after.replication.unwrap();
    for (old, shard) in before.shards.iter().zip(&info.shards) {
        assert_ne!(old.data_head, shard.data_head);
        assert_ne!(old.index_head, shard.index_head);
        assert!(
            shard
                .replicas
                .iter()
                .filter(|copy| copy.peer_id == 1)
                .all(|copy| !copy.current && !copy.online)
        );
        assert!(
            shard
                .replicas
                .iter()
                .filter(|copy| copy.online)
                .all(|copy| copy.current)
        );
    }
    engine.set_peer_online(1, true).unwrap();
    assert!(
        !engine
            .snapshot()
            .unwrap()
            .replication
            .unwrap()
            .read_peers
            .contains(&1)
    );
    assert_eq!(aggregate(&mut engine), (4, 104, 3));

    engine.repair_replicas().unwrap();

    assert!(
        engine
            .snapshot()
            .unwrap()
            .replication
            .unwrap()
            .shards
            .iter()
            .all(|shard| shard.replicas.iter().all(|copy| copy.current))
    );
    assert_eq!(aggregate(&mut engine), (4, 104, 3));
}

#[test]
fn global_overflow_discards_staged_updates_to_every_physical_holder() {
    let mut engine = engine(
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
    engine.set_replication(2).unwrap();
    engine.repair_replicas().unwrap();
    let before = engine.snapshot().unwrap();
    let heads = engine.peer_heads_for_experiment().unwrap();

    let outcome = engine
        .execute("UPDATE records SET amount = amount + 1")
        .unwrap();

    assert!(matches!(
        outcome,
        QueryOutcome::Updated { committed: false }
    ));
    assert_eq!(engine.peer_heads_for_experiment().unwrap(), heads);
    let after = engine.snapshot().unwrap();
    assert_eq!(after.replication, before.replication);
    assert_eq!(after.owner_rows, before.owner_rows);
    assert_eq!(after.revision, before.revision);
    assert!(matches!(
        engine
            .execute("UPDATE records SET amount = amount + 0")
            .unwrap(),
        QueryOutcome::Updated { committed: true }
    ));
    assert_eq!(engine.peer_heads_for_experiment().unwrap(), heads);
    assert_eq!(engine.snapshot().unwrap().revision, 0);
    assert_eq!(aggregate(&mut engine), (2, 65_545, 2));
}

#[test]
fn quota_failure_keeps_all_real_copies_and_current_authority_unchanged() {
    let mut engine = engine(sample_rows(2).unwrap(), 2);
    engine.set_replication(2).unwrap();
    let before = engine.snapshot().unwrap();
    let heads = engine.peer_heads_for_experiment().unwrap();
    let mut config = before.peers[1].config.clone();
    config.storage_limit_bytes = before.peers[1].stored_bytes;
    engine.set_peer_config(2, config).unwrap();
    let before = engine.snapshot().unwrap();

    assert!(engine.repair_replicas().is_err());

    let after = engine.snapshot().unwrap();
    assert_eq!(after.replication, before.replication);
    assert_eq!(after.owner_rows, before.owner_rows);
    assert_eq!(engine.peer_heads_for_experiment().unwrap(), heads);
    assert_eq!(aggregate(&mut engine), (2, 30, 2));
}

#[test]
fn replicated_quota_cannot_be_lowered_below_actual_images_and_record_metadata() {
    let mut engine = engine(sample_rows(4).unwrap(), 3);
    engine.set_replication(2).unwrap();
    engine.repair_replicas().unwrap();
    let before = engine.snapshot().unwrap();
    let heads = engine.peer_heads_for_experiment().unwrap();
    let mut rejected = before.peers[0].config.clone();
    rejected.storage_limit_bytes = before.peers[0].stored_bytes - 1;

    assert!(engine.set_peer_config(1, rejected).is_err());

    let after = engine.snapshot().unwrap();
    assert_eq!(after.peers[0].config, before.peers[0].config);
    assert_eq!(after.replication, before.replication);
    assert_eq!(after.owner_rows, before.owner_rows);
    assert_eq!(engine.peer_heads_for_experiment().unwrap(), heads);
}

#[test]
fn replicated_topology_changes_keep_shard_heads_and_new_peers_start_empty() {
    let mut engine = engine(sample_rows(4).unwrap(), 3);
    engine.set_replication(2).unwrap();
    engine.repair_replicas().unwrap();
    let old = engine.snapshot().unwrap().replication.unwrap();

    engine
        .repartition(vec![
            (1, PeerConfig::numbered(1), true),
            (2, PeerConfig::numbered(2), true),
            (4, PeerConfig::numbered(4), true),
        ])
        .unwrap();

    let after = engine.snapshot().unwrap();
    assert_eq!(after.peers[2].rows, 0);
    assert_eq!(after.peers[2].stored_bytes, 0);
    for (before, shard) in old.shards.iter().zip(&after.replication.unwrap().shards) {
        assert_eq!(before.id, shard.id);
        assert_eq!(before.data_head, shard.data_head);
        assert_eq!(before.index_head, shard.index_head);
        assert!(
            !shard
                .replicas
                .iter()
                .any(|copy| copy.peer_id == 3 || copy.peer_id == 4)
        );
    }
    assert_eq!(aggregate(&mut engine), (4, 100, 3));
    engine.set_replication(3).unwrap();
    engine.repair_replicas().unwrap();
    assert!(
        engine
            .snapshot()
            .unwrap()
            .replication
            .unwrap()
            .shards
            .iter()
            .all(|shard| shard
                .replicas
                .iter()
                .any(|copy| copy.peer_id == 4 && copy.current))
    );
}

#[test]
fn rejected_policy_changes_are_atomic_and_create_starts_with_real_factor_one() {
    let mut engine = engine(sample_rows(2).unwrap(), 2);
    let heads = engine.peer_heads_for_experiment().unwrap();
    for copies in [0, 17] {
        assert!(engine.set_replication(copies).is_err());
    }
    assert_eq!(
        engine
            .snapshot()
            .unwrap()
            .replication
            .unwrap()
            .desired_copies,
        1
    );
    assert_eq!(engine.peer_heads_for_experiment().unwrap(), heads);
    engine.set_replication(2).unwrap();
    engine.set_replication(1).unwrap();
    assert_eq!(
        engine
            .snapshot()
            .unwrap()
            .replication
            .unwrap()
            .desired_copies,
        1
    );
    engine
        .create(DatabaseDraft {
            name: "replacement".into(),
            rows: sample_rows(1).unwrap(),
            peers: vec![PeerConfig::numbered(1)],
        })
        .unwrap();
    assert_eq!(
        engine
            .snapshot()
            .unwrap()
            .replication
            .unwrap()
            .desired_copies,
        1
    );
}

#[test]
fn explicit_factor_one_enters_ciphertext_custody_and_never_recovers_from_the_fixture() {
    let mut engine = engine(sample_rows(2).unwrap(), 1);
    engine.set_replication(1).unwrap();
    let before = engine.snapshot().unwrap();
    assert_eq!(before.replication.as_ref().unwrap().desired_copies, 1);

    engine.repartition(Vec::new()).unwrap();
    engine
        .repartition(vec![(99, PeerConfig::numbered(99), true)])
        .unwrap();

    let after = engine.snapshot().unwrap();
    assert_eq!(after.owner_rows, before.owner_rows);
    assert_eq!(after.peers[0].stored_bytes, 0);
    assert!(
        after.replication.as_ref().unwrap().shards[0]
            .replicas
            .is_empty()
    );
    assert_eq!(after.replication.as_ref().unwrap().unavailable_shards, [1]);
    assert!(
        matches!(engine.execute("SELECT COUNT(*), SUM(amount) FROM records"), Err(fhe_playground::LabError::UnavailableShards(ids)) if ids == [1])
    );
    assert!(
        matches!(engine.repair_replicas(), Err(fhe_playground::LabError::UnavailableShards(ids)) if ids == [1])
    );
}
#[test]
fn exhausted_peer_identity_can_update_existing_profile_but_never_wraps_a_new_peer() {
    let mut engine = LabEngine::default();
    engine
        .create_with_peer_ids(
            DatabaseDraft {
                name: "public ID limit fixture".into(),
                rows: sample_rows(1).unwrap(),
                peers: vec![PeerConfig::numbered(1)],
            },
            vec![usize::MAX],
        )
        .unwrap();
    let heads = engine.peer_heads_for_experiment().unwrap();
    let mut existing = PeerConfig::numbered(1);
    existing.name = "Existing holder".into();
    engine.configure_peers(vec![existing.clone()]).unwrap();
    assert_eq!(engine.snapshot().unwrap().peers[0].id, usize::MAX);
    assert!(
        engine
            .configure_peers(vec![existing.clone(), PeerConfig::numbered(2)])
            .is_err()
    );
    let snapshot = engine.snapshot().unwrap();
    assert_eq!(snapshot.peers.len(), 1);
    assert_eq!(snapshot.peers[0].config, existing);
    assert_eq!(engine.peer_heads_for_experiment().unwrap(), heads);
    assert_eq!(aggregate(&mut engine).0, 1);
}
