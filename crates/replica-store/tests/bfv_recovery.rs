//! Public synthetic table: actual encrypted data/index repair composed with BFV.
use compact_query::{AgeRange, PlainRow, Table, bfv};
use compact_store::{Commitment, Limits};
use replica_store::{
    Bounds, BundleId, FailureDomainId, ObjectId, PeerConfig, PeerId, ReplicaStore, ReplicaTarget,
};

const DATA: ObjectId = ObjectId(1);
const INDEX: ObjectId = ObjectId(2);

fn network() -> ReplicaStore {
    let mut store = ReplicaStore::new(Bounds::default()).unwrap();
    for id in 1..=3 {
        store
            .register_peer(PeerConfig {
                id: PeerId(id),
                failure_domain: FailureDomainId(id),
                quota_bytes: 64 * 1024,
            })
            .unwrap();
    }
    store
}

fn table(owner: &bfv::Owner) -> Table {
    owner
        .seal(
            &[
                PlainRow {
                    age: 17,
                    amount: 10,
                },
                PlainRow {
                    age: 18,
                    amount: 20,
                },
                PlainRow {
                    age: 18,
                    amount: 30,
                },
                PlainRow {
                    age: 42,
                    amount: 40,
                },
            ],
            2,
            Limits::default(),
        )
        .unwrap()
}

fn targets(table: &Table) -> [ReplicaTarget; 2] {
    [
        ReplicaTarget {
            object: DATA,
            expected: table.commitment().clone(),
            copies: 2,
            bundle: Some(BundleId(1)),
        },
        ReplicaTarget {
            object: INDEX,
            expected: table.index_commitment().clone(),
            copies: 2,
            bundle: Some(BundleId(1)),
        },
    ]
}

fn seed(store: &mut ReplicaStore, table: &Table, peer: PeerId) {
    store
        .seed(peer, DATA, table.commitment(), &table.snapshot().encode())
        .unwrap();
    store
        .seed(
            peer,
            INDEX,
            table.index_commitment(),
            &table.encrypted_index().encode(),
        )
        .unwrap();
}

fn restore(
    owner: &bfv::Owner,
    store: &ReplicaStore,
    peer: PeerId,
    heads: &[ReplicaTarget; 2],
) -> Table {
    owner
        .restore_table_for_experiment(
            store.ciphertext(peer, DATA).unwrap(),
            store.ciphertext(peer, INDEX).unwrap(),
            &heads[0].expected,
            &heads[1].expected,
            Limits::default(),
        )
        .unwrap()
}

fn aggregate(owner: &bfv::Owner, peer: &bfv::Evaluator, table: &Table) -> (u32, u32) {
    let query = owner
        .prepare_exact_aggregate_for_experiment(table, AgeRange::equal(18), 256, Limits::default())
        .unwrap();
    let output = peer.evaluate_exact_aggregate(query.request()).unwrap();
    let answer = owner
        .complete_exact_aggregate_unverified_for_experiment(table, query, &output.output)
        .unwrap();
    assert_eq!(answer.proof, bfv::ProofStatus::Unavailable);
    (answer.count, answer.sum)
}

#[test]
fn repaired_ciphertexts_support_original_owner_bfv_queries_and_checked_updates() {
    let (owner, evaluator) = bfv::Owner::generate([81; 16]).unwrap();
    let original = table(&owner);
    let heads = targets(&original);
    let mut store = network();
    seed(&mut store, &original, PeerId(1));
    seed(&mut store, &original, PeerId(2));
    drop(original);
    store.set_available(PeerId(1), false).unwrap();

    let plan = store.plan_repair(&heads).unwrap();
    let repaired = store.repair_local(plan, &heads).unwrap();

    assert_eq!(repaired.copied.len(), 2);
    assert!(
        repaired
            .copied
            .iter()
            .all(|copy| copy.source == PeerId(2) && copy.destination == PeerId(3))
    );
    let mut restored = restore(&owner, &store, PeerId(3), &heads);
    assert_eq!(aggregate(&owner, &evaluator, &restored), (2, 50));
    let sizes = (
        restored.canonical_data_bytes(),
        restored.encrypted_index_bytes(),
    );
    let update = owner
        .prepare_exact_update_for_experiment(
            &restored,
            AgeRange::equal(18),
            5,
            256,
            Limits::default(),
        )
        .unwrap();
    let evaluated = evaluator.evaluate_indexed_update(update.request()).unwrap();
    let applied = owner
        .apply_exact_update_checked_for_experiment(
            &mut restored,
            update,
            &evaluated.output,
            Limits::default(),
        )
        .unwrap();
    assert!(!applied.rejected);
    assert_eq!(applied.changed_rows, 2);
    assert_eq!(aggregate(&owner, &evaluator, &restored), (2, 60));
    assert_eq!(
        (
            restored.canonical_data_bytes(),
            restored.encrypted_index_bytes()
        ),
        sizes
    );
    // Replica storage was not granted owner authority to publish new heads.
    assert_eq!(
        store.ciphertext(PeerId(2), DATA).unwrap(),
        store.ciphertext(PeerId(3), DATA).unwrap()
    );
}

#[test]
fn stale_index_delivery_rolls_back_the_entire_data_and_index_repair_batch() {
    let (owner, evaluator) = bfv::Owner::generate([82; 16]).unwrap();
    let mut current = table(&owner);
    let old_index = current.encrypted_index().encode();
    let update = owner
        .prepare_exact_update_for_experiment(
            &current,
            AgeRange::equal(18),
            1,
            256,
            Limits::default(),
        )
        .unwrap();
    let output = evaluator.evaluate_indexed_update(update.request()).unwrap();
    owner
        .apply_exact_update_checked_for_experiment(
            &mut current,
            update,
            &output.output,
            Limits::default(),
        )
        .unwrap();
    let heads = targets(&current);
    let current_data = current.snapshot().encode();
    let mut store = network();
    seed(&mut store, &current, PeerId(1));
    seed(&mut store, &current, PeerId(2));
    store.set_available(PeerId(1), false).unwrap();
    let before = store.usage(PeerId(3)).unwrap().charged_bytes;
    let plan = store.plan_repair(&heads).unwrap();

    let result = store.repair_with(plan, &heads, |_, object, buffer| {
        let image = if object == DATA {
            &current_data
        } else {
            &old_index
        };
        assert_eq!(buffer.len(), image.len());
        buffer.copy_from_slice(image);
        Ok(image.len())
    });

    assert!(result.is_err());
    assert_eq!(store.usage(PeerId(3)).unwrap().charged_bytes, before);
    assert!(store.ciphertext(PeerId(3), DATA).is_err());
    assert!(store.ciphertext(PeerId(3), INDEX).is_err());
    let intact = restore(&owner, &store, PeerId(2), &heads);
    assert_eq!(aggregate(&owner, &evaluator, &intact), (2, 52));
    let expected: &Commitment = &heads[0].expected;
    assert_eq!(intact.commitment(), expected);
}
