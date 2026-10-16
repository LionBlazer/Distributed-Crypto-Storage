//! Genuine arithmetic proofs at the durable publication boundary. Public fixture
//! rows and deterministic signing keys are non-secret and used only in this test.
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use bfv_query_core::{Geometry, Owner, QueryContext, SelectedField};
use compact_store::{Layout, Limits, Owner as StorageOwner};
use ed25519_dalek::SigningKey;
use peer_runtime::{
    JobVerifier, MutationEvidence, MutationJob, MutationManifest, Operation, ProofReply,
};
use version_journal::{
    AuthorizedTransition, Body, DurableJournal, Error, Genesis, HeadPair, ProtocolProfile,
    ShardState, ShardUpdate, Target,
};

struct JournalPath(PathBuf);
impl JournalPath {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "dcs-proved-mutation-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        )))
    }
}
impl Drop for JournalPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn profile() -> ProtocolProfile {
    // Explicitly easy public test work, not a production security profile.
    ProtocolProfile {
        initial_target: Target([0x0f; 32]),
        pow_limit: Target([0x0f; 32]),
        block_spacing_secs: 1,
        retarget_interval: 1024,
        max_future_secs: 30,
        confirmation_depth: 1,
        max_headers: 128,
        max_shards: 2,
        max_updates: 2,
        max_body_bytes: 32 * 1024 * 1024,
        max_request_bytes: 32 * 1024 * 1024,
        max_proof_bytes: 32 * 1024 * 1024,
        max_journal_bytes: 256 * 1024 * 1024,
    }
}
fn replace_snapshot(owner: &StorageOwner, schema: u8, value: u8) -> ([u8; 112], [u8; 112]) {
    let limits = Limits::default();
    let mut snapshot = owner
        .seal(
            Layout {
                schema: [schema; 16],
                row_width: 1,
                rows_per_page: 1,
                row_count: 1,
            },
            &[value],
            limits,
        )
        .unwrap();
    let old = snapshot.commitment().clone();
    let new = owner
        .replace_page(&mut snapshot, &old, 0, &[value + 1], limits)
        .unwrap();
    (old.encode(), new.encode())
}

#[test]
fn tampered_second_job_preserves_durable_bytes_and_head_before_genuine_two_job_acceptance() {
    // Arrange two cold genuine proofs, exact old contexts and authorized changed
    // storage manifests. This tests public arithmetic/publication, not the private
    // AEAD-to-FHE linkage, which remains the SQL client's completion responsibility.
    let database = [1; 16];
    let signer = SigningKey::from_bytes(&[2; 32]);
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let parameters = setup.update_parameters().unwrap();
    let verifier = JobVerifier::new(parameters.clone()).unwrap();
    let storage = StorageOwner::generate(database).unwrap();
    let mut previous = Vec::new();
    let mut updates = Vec::new();
    let mut jobs = Vec::new();
    let mut replies = Vec::new();
    for (id, amount) in [(7, 20), (9, 30)] {
        let (data, next_data) = replace_snapshot(&storage, 3, amount);
        let (index, next_index) = replace_snapshot(&storage, 4, amount);
        let heads = HeadPair { data, index };
        previous.push(ShardState { id, heads });
        updates.push(ShardUpdate {
            id,
            old: heads,
            new: HeadPair {
                data: next_data,
                index: next_index,
            },
        });
        let prepared = owner
            .prepare_indexed_update_for_experiment(
                QueryContext::new(database, data, index),
                &[SelectedField {
                    age: 18,
                    amount: u16::from(amount),
                    active: true,
                }],
                1,
            )
            .unwrap();
        let input = verifier
            .circuit_request(Operation::Update, &prepared.request)
            .unwrap();
        let proved = bfv_query_proof::prove(&input).unwrap();
        jobs.push(MutationJob {
            shard: id,
            request: prepared.request,
        });
        replies.push(ProofReply {
            output: proved.output().to_vec(),
            proof: proved.proof().to_vec(),
        });
    }
    let genesis = Genesis {
        network_id: [5; 32],
        database,
        owner: signer.verifying_key().to_bytes(),
        application_commitment: verifier.application_commitment(),
        timestamp: 1000,
        profile: profile(),
        initial_shards: previous.clone(),
    };
    let path = JournalPath::new();
    let durable = DurableJournal::create(&path.0, genesis.clone()).unwrap();
    let original_head = durable.journal().best_validated();
    drop(durable);
    let original_bytes = std::fs::read(&path.0).unwrap();
    let mut durable = DurableJournal::open(&path.0, genesis.clone(), 1001, &verifier).unwrap();
    let request = MutationManifest {
        query_binding: [6; 32],
        operation: Operation::Update,
        previous_shards: previous,
        jobs,
    }
    .encode()
    .unwrap();
    let mut transition = AuthorizedTransition {
        parent: durable.journal().genesis_id(),
        request,
        updates,
        proof: Vec::new(),
        owner_signature: [0; 64],
    };
    let mut tampered = replies.clone();
    let last = tampered[1].proof.len() - 1;
    tampered[1].proof[last] ^= 1;
    transition.proof = MutationEvidence { jobs: tampered }.encode().unwrap();
    transition.sign(genesis.id().unwrap(), &signer);
    let invalid_body = Body::Transition(transition.clone());
    let wire = invalid_body.encode(durable.journal().profile()).unwrap();
    let mut header = durable
        .journal()
        .candidate(transition.parent, &invalid_body, 1001)
        .unwrap();
    header.mine(100_000).unwrap();

    // Act: the second proof is invalid even though its owner signature is genuine.
    assert_eq!(
        durable.append_block(header, &wire, 1001, &verifier),
        Err(Error::RejectedComputationProof)
    );

    // Assert: neither persistent nor published state changes on that error.
    assert_eq!(durable.disk_bytes(), original_bytes.len() as u64);
    assert_eq!(durable.journal().best_validated(), original_head);
    drop(durable);
    assert_eq!(std::fs::read(&path.0).unwrap(), original_bytes);
    let mut durable = DurableJournal::open(&path.0, genesis.clone(), 1001, &verifier).unwrap();

    // The same complete transition with both original proofs is valid. Use a
    // fresh verifier so successful acceptance also exercises two cold workers.
    transition.proof = MutationEvidence { jobs: replies }.encode().unwrap();
    transition.sign(genesis.id().unwrap(), &signer);
    let body = Body::Transition(transition.clone());
    let wire = body.encode(durable.journal().profile()).unwrap();
    let mut header = durable
        .journal()
        .candidate(transition.parent, &body, 1001)
        .unwrap();
    let accepted = header.mine(100_000).unwrap();
    let fresh_verifier = JobVerifier::new(parameters.clone()).unwrap();
    durable
        .append_block(header, &wire, 1001, &fresh_verifier)
        .unwrap();
    assert_eq!(durable.journal().best_validated().block, accepted);
    drop(durable);
    assert_ne!(std::fs::read(&path.0).unwrap(), original_bytes);
    let reopened = DurableJournal::open(
        &path.0,
        genesis,
        1001,
        &JobVerifier::new(parameters).unwrap(),
    )
    .unwrap();
    assert_eq!(reopened.journal().best_validated().block, accepted);
}
