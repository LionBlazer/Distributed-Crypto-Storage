//! Public fixtures exercise application proof/shape rules; full SQL custody is
//! exercised by the independently running peer tests, not by these index bytes.
use super::*;
use bfv_query_core::{Geometry, Owner, QueryContext, SelectedField};
use compact_store::{Layout, Limits};
use version_journal::{HeadRef, ShardUpdate};

#[test]
fn one_manifest_requires_every_proved_batch_and_each_exact_authorized_row_delta() {
    let database = [87; 16];
    let store = compact_store::Owner::generate(database).unwrap();
    let limits = Limits::default();
    let data = store
        .seal(
            Layout {
                schema: [1; 16],
                row_width: 3,
                rows_per_page: 16,
                row_count: 1,
            },
            &[18, 20, 0],
            limits,
        )
        .unwrap();
    let index = store
        .seal(
            Layout {
                schema: [2; 16],
                row_width: 1,
                rows_per_page: 16,
                row_count: 1,
            },
            &[0],
            limits,
        )
        .unwrap();
    let old = HeadPair {
        data: data.commitment().encode(),
        index: index.commitment().encode(),
    };
    let grow = |count: usize| {
        let next_data = store
            .grow_from_checked_plaintext(
                &data,
                data.commitment(),
                count as u64,
                &vec![1; count * 3],
                limits,
            )
            .unwrap();
        let next_index = store
            .grow_from_checked_plaintext(
                &index,
                index.commitment(),
                count as u64,
                &vec![1; count],
                limits,
            )
            .unwrap();
        HeadPair {
            data: next_data.commitment().encode(),
            index: next_index.commitment().encode(),
        }
    };
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let verifier = JobVerifier::new(setup.update_parameters().unwrap()).unwrap();
    let original = [SelectedField {
        age: 18,
        amount: 20,
        active: true,
    }];
    let mut jobs = Vec::new();
    let mut proofs = Vec::new();
    let mut updates = Vec::new();
    for (id, incoming_count) in [(7u64, 2usize), (9, 1)] {
        let incoming = vec![
            SelectedField {
                age: 42,
                amount: 256,
                active: true
            };
            incoming_count
        ];
        let prepared = owner
            .prepare_indexed_insert_for_experiment(
                QueryContext::new([id as u8; 16], old.data, old.index),
                &original,
                &incoming,
            )
            .unwrap();
        let input = verifier
            .circuit_request(Operation::Insert, &prepared.request)
            .unwrap();
        let genuine = bfv_query_proof::prove(&input).unwrap();
        jobs.push(MutationJob {
            shard: id,
            request: prepared.request,
        });
        proofs.push(ProofReply {
            output: genuine.output().to_vec(),
            proof: genuine.proof().to_vec(),
        });
        updates.push(ShardUpdate {
            id,
            old,
            new: grow(1 + incoming_count),
        });
    }
    let manifest = MutationManifest {
        query_binding: [4; 32],
        operation: Operation::Insert,
        previous_shards: vec![
            ShardState { id: 7, heads: old },
            ShardState { id: 9, heads: old },
        ],
        jobs,
    };
    let request = manifest.encode().unwrap();
    let proof = MutationEvidence { jobs: proofs }.encode().unwrap();
    let statement = TransitionStatement {
        genesis: [5; 32],
        database,
        application_commitment: verifier.application_commitment(),
        parent: HeadRef {
            genesis: [5; 32],
            database,
            block: [6; 32],
            height: 1,
            state_root: [7; 32],
        },
        previous_shards: &manifest.previous_shards,
        next_shards: &[],
        request: &request,
        updates: &updates,
        proof: &proof,
        next_state_root: [8; 32],
    };

    assert!(verifier.verify(TransitionStatement { ..statement }).is_ok());
    assert!(
        verifier
            .verify(TransitionStatement {
                updates: &updates[..1],
                ..statement
            })
            .is_err()
    );
    let duplicate = [updates[0].clone(), updates[0].clone()];
    assert!(
        verifier
            .verify(TransitionStatement {
                updates: &duplicate,
                ..statement
            })
            .is_err()
    );
    let mut extra = updates.clone();
    extra.push(ShardUpdate {
        id: 99,
        old,
        new: grow(2),
    });
    assert!(
        verifier
            .verify(TransitionStatement {
                updates: &extra,
                ..statement
            })
            .is_err()
    );
    let mut wrong_count = updates.clone();
    wrong_count[0].new = grow(2); // A genuine2-row proof cannot authorize a1-row growth.
    assert!(
        verifier
            .verify(TransitionStatement {
                updates: &wrong_count,
                ..statement
            })
            .is_err()
    );
    let mut altered = proof.clone();
    *altered.last_mut().unwrap() ^= 1;
    assert!(
        verifier
            .verify(TransitionStatement {
                proof: &altered,
                ..statement
            })
            .is_err()
    );
    assert!(
        verifier
            .verify(TransitionStatement {
                proof: &[],
                ..statement
            })
            .is_err()
    );
    let mut duplicate_job = manifest.clone();
    duplicate_job.jobs[1].shard = duplicate_job.jobs[0].shard;
    assert!(duplicate_job.encode().is_err());
}
