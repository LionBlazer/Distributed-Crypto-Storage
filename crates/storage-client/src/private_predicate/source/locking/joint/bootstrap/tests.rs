//! Explicit PUBLIC NONSECRET inputs and genuine local mathematical QCs.
//! These cases do not substitute for the separate real four-OS consensus gate.
use super::*;
use crate::private_predicate::SourceOwner;
use crate::private_predicate::source::locking::joint::tests::full_acquire_fixture as fixture;
use bfv_query_core::{Geometry, KeyScope, Owner};
use compact_query::{PlainRow, RowIds, TableId};
use p3_field::PrimeCharacteristicRing;
use peer_runtime::RawBundle;
use protocol_storage::ParticipantQuota;
use registry200_finality::{
    CandidateBlock,
    joint::{JointCandidate, JointCheckpoint, JointHistory},
};
use registry200_joint::{JointDepot, JointEvidenceIngress};
use registry200_proof::source::statement::encode_digest;
use sha2::{Digest, Sha256};
use work_finality::{QuorumCertificate, SignedVote, Step, VoteContext, consensus::Context};

fn checkpoint(
    binding: &JointBinding,
    context: &Context,
    block: &CandidateBlock,
) -> JointCheckpoint {
    let candidate = JointCandidate::for_context(binding, context, block.header().clone()).unwrap();
    let mut domain = Sha256::new();
    domain.update(b"dcs/work-finality/consensus-vote-instance/v1");
    domain.update(work_finality::profile_digest());
    domain.update(context.id());
    let vote = VoteContext::new(
        context.set(),
        domain.finalize().into(),
        context.slot(),
        0,
        Step::Precommit,
        Some(context.value_id(&candidate.encode()).unwrap()),
    )
    .unwrap();
    let votes: Vec<_> = fixture::signers()[..3]
        .iter()
        .map(|key| SignedVote::sign(vote, key).unwrap())
        .collect();
    let certificate = QuorumCertificate::assemble(context.set(), &vote, &votes)
        .unwrap()
        .encode()
        .unwrap();
    JointCheckpoint::new(candidate, 0, certificate).unwrap()
}
fn empty(binding: &JointBinding, parent: HeadRef) -> CandidateBlock {
    let body = version_journal::Body::Empty
        .encode(&binding.journal_genesis().profile)
        .unwrap();
    let mut header = version_journal::Header {
        genesis: parent.genesis,
        parent: parent.block,
        height: parent.height + 1,
        timestamp: 1001 + parent.height,
        target: version_journal::Target([255; 32]),
        body_hash: version_journal::hash(&body),
        state_root: parent.state_root,
        nonce: 0,
    };
    header.mine(1).unwrap();
    CandidateBlock::new(header, body).unwrap()
}
fn install_begin(
    prepared: PreparedJointControl,
    binding: &JointBinding,
    history: &mut JointHistory,
    ingress: &JointEvidenceIngress,
) -> (CandidateBlock, JointCheckpoint) {
    let (request, life, kind, candidate) = prepared.into_parts();
    let next = encode_digest(life.statement().next);
    let result = encode_digest(life.statement().result);
    let pair = ingress.retain_public_blob(life.as_bytes()).unwrap();
    let kind = ingress.retain_public_blob(kind.as_bytes()).unwrap();
    let expected = candidate
        .expectation(Manifest::control(next, result, pair, kind).unwrap())
        .unwrap();
    let block = fixture::transition(
        binding,
        history.checked_parent().unwrap().unwrap().head(),
        request,
        Manifest::control(next, result, pair, kind).unwrap(),
        history.checked_parent().unwrap().unwrap().control(),
    );
    let qc = checkpoint(binding, history.context().unwrap(), &block);
    let operation = history.apply_control(&qc, &block, &expected).unwrap();
    assert_eq!(
        candidate.complete(operation).unwrap().outcome(),
        JointControlOutcome::Begun
    );
    (block, qc)
}
fn run_bootstrap(after_empty: bool) {
    let source_owner =
        SourceOwner::new([0x21; 16], [0x42; 16], Zeroizing::new([0x63; 32])).unwrap();
    let rows = [
        PlainRow {
            age: 0,
            amount: 65535,
        },
        PlainRow { age: 1, amount: 0 },
        PlainRow {
            age: 128,
            amount: 255,
        },
        PlainRow {
            age: 255,
            amount: 65534,
        },
    ];
    let table = source_owner
        .seal_partition(
            &TableId::from_bytes([0x19; 32]).unwrap(),
            &rows,
            RowIds::generate(4).unwrap(),
        )
        .unwrap();
    let heads = table.read_heads();
    let bundle = RawBundle::from_snapshots(table.snapshot(), table.encrypted_index()).unwrap();
    let object = *bundle.target_version().unwrap().object();
    drop(table);
    let fetched = || FetchedSource {
        object,
        bundle: &bundle,
        heads: &heads,
    };
    let loaded = source_owner.load(fetched()).unwrap();
    let (bfv, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let handle = bfv
        .key_anchor(
            &setup,
            KeyScope {
                database: [0x21; 16],
                bfv_key_domain: [0x88; 16],
                epoch: 1,
            },
        )
        .unwrap();
    let anchor = handle.public_anchor().clone();
    let mut epoch = handle.proof_epoch(&setup).unwrap();
    epoch.prove_key().unwrap();
    let key = setup
        .verify_key_transform(&anchor, epoch.key_evidence().unwrap().as_bytes())
        .unwrap();
    let directory = fixture::Directory::new();
    let namespace = [0x39 + u8::from(after_empty); 32];
    let quota = ParticipantQuota::create_new(
        directory.path("bootstrap-owner"),
        namespace,
        fixture::CAPACITY,
    )
    .unwrap();
    let binding = fixture::binding(&loaded, &setup, &anchor, key.statement(), object, &quota);
    drop(epoch);
    drop(handle);
    drop(bfv);
    drop(setup);
    drop(loaded);
    let depot = JointDepot::open(quota.depot_budget()).unwrap();
    let ingress = depot.ingress();
    let mut history = JointHistory::new(binding.clone(), depot).unwrap();
    let genesis_parent = history.bootstrap_parent().unwrap();
    let initial = history.context().unwrap().clone();
    assert_eq!(genesis_parent.slot(), 1);
    assert_eq!(genesis_parent.head().height, 0);
    assert_eq!(genesis_parent.context_id(), initial.id());
    let mut originals = Vec::new();
    if after_empty {
        // A real weighted QC and Journal check create Pending at slot2. There is
        // no raw HeadRef/VerifiedParent constructor for this production factory.
        let block = empty(&binding, genesis_parent.head());
        let qc = checkpoint(&binding, &initial, &block);
        let checked = history.apply(&qc, &block).unwrap();
        assert_eq!(checked.control(), Control::Pending);
        originals.push((block, qc));
    }
    let parent = history.bootstrap_parent().unwrap();
    assert_eq!(parent.slot(), if after_empty { 2 } else { 1 });
    assert_eq!(
        parent.head().genesis,
        binding.journal_genesis().id().unwrap()
    );
    if after_empty {
        assert_eq!(parent.head().block, originals[0].0.header().id());
        assert_ne!(parent.context_id(), genesis_parent.context_id());
    }
    let before = parent.head();
    let context = history.context().unwrap().clone();
    // Caller pins and guarded private input fail before any new proof work.
    let mut controllers = fixture::CONTROLLERS;
    controllers[1] = [0; 32];
    assert!(
        source_owner
            .prepare_joint_bootstrap(
                fetched(),
                &binding,
                &parent,
                Zeroizing::new(controllers),
                [1; 32]
            )
            .is_err()
    );
    let mut foreign_genesis = binding.journal_genesis().clone();
    foreign_genesis.timestamp += 1;
    let foreign = JointBinding::for_durable(
        foreign_genesis.network_id,
        binding.rules().clone(),
        binding.work_genesis().clone(),
        foreign_genesis,
        binding.application_descriptor().clone(),
        binding.setup_claim().clone(),
    )
    .unwrap();
    assert!(
        source_owner
            .prepare_joint_bootstrap(
                fetched(),
                &foreign,
                &parent,
                Zeroizing::new(fixture::CONTROLLERS),
                [2; 32]
            )
            .is_err()
    );
    let mut changed_object = object;
    changed_object[0] ^= 1;
    assert!(
        source_owner
            .prepare_joint_bootstrap(
                FetchedSource {
                    object: changed_object,
                    bundle: &bundle,
                    heads: &heads
                },
                &binding,
                &parent,
                Zeroizing::new(fixture::CONTROLLERS),
                [3; 32]
            )
            .is_err()
    );
    let changed_table = source_owner
        .seal_partition(
            &TableId::from_bytes([0x19; 32]).unwrap(),
            &rows,
            RowIds::generate(4).unwrap(),
        )
        .unwrap();
    let changed_heads = changed_table.read_heads();
    drop(changed_table);
    assert!(
        source_owner
            .prepare_joint_bootstrap(
                FetchedSource {
                    object,
                    bundle: &bundle,
                    heads: &changed_heads
                },
                &binding,
                &parent,
                Zeroizing::new(fixture::CONTROLLERS),
                [7; 32]
            )
            .is_err()
    );
    let foreign_owner =
        SourceOwner::new([0x21; 16], [0x42; 16], Zeroizing::new([0x64; 32])).unwrap();
    assert!(
        foreign_owner
            .prepare_joint_bootstrap(
                fetched(),
                &binding,
                &parent,
                Zeroizing::new(fixture::CONTROLLERS),
                [4; 32]
            )
            .is_err()
    );
    drop(foreign_owner);
    // The sealed metadata survives closing the SAME depot. Do not overlap the
    // heavy Source prover with a retained decoded setup/history or ingress lock.
    drop(history);
    drop(ingress);
    let prepared = source_owner
        .prepare_joint_bootstrap(
            fetched(),
            &binding,
            &parent,
            Zeroizing::new(fixture::CONTROLLERS),
            [5; 32],
        )
        .unwrap();
    assert_eq!(prepared.request().lane(), Lane::Bootstrap);
    assert_eq!(prepared.request().inner().command, [0; 32]);
    assert_eq!(prepared.lifecycle().statement().values().len(), 104);
    let depot = JointDepot::open(quota.depot_budget()).unwrap();
    let ingress = depot.ingress();
    let mut history = JointHistory::new(binding.clone(), depot).unwrap();
    for (block, qc) in &originals {
        history.apply(qc, block).unwrap();
    }
    assert_eq!(history.context().unwrap(), &context);
    let (request, life, mut candidate) = prepared.into_parts();
    let next = encode_digest(life.statement().next);
    let pair = ingress.retain_public_blob(life.as_bytes()).unwrap();
    if after_empty {
        assert!(
            BootstrapExpectation::new(
                &binding,
                &genesis_parent,
                &request,
                life.statement(),
                Manifest::bootstrap(next, pair).unwrap()
            )
            .is_err()
        );
    }
    let expected = candidate
        .expectation(Manifest::bootstrap(next, pair).unwrap())
        .unwrap();
    let block = fixture::transition(
        &binding,
        before,
        request,
        Manifest::bootstrap(next, pair).unwrap(),
        Control::Pending,
    );
    let qc = checkpoint(&binding, &context, &block);
    // Correct metadata/signatures/hashes cannot bless damaged real prerequisites.
    let mut damaged = life.as_bytes().to_vec();
    *damaged.last_mut().unwrap() ^= 1;
    let bad_pair = ingress.retain_public_blob(&damaged).unwrap();
    drop(damaged);
    assert!(
        candidate
            .expectation(Manifest::bootstrap(next, bad_pair).unwrap())
            .is_err()
    );
    let own_request = JointRequest::decode(&candidate.request).unwrap();
    let bad_expected = BootstrapExpectation::new(
        &binding,
        &parent,
        &own_request,
        &candidate.statement,
        Manifest::bootstrap(next, bad_pair).unwrap(),
    )
    .unwrap();
    let bad = fixture::transition(
        &binding,
        before,
        own_request,
        Manifest::bootstrap(next, bad_pair).unwrap(),
        Control::Pending,
    );
    let bad_qc = checkpoint(&binding, &context, &bad);
    assert!(
        history
            .apply_bootstrap(&bad_qc, &bad, &bad_expected)
            .is_err()
    );
    assert_eq!(history.context().unwrap(), &context);
    assert_eq!(history.bootstrap_parent().unwrap().head(), before);
    // Entire original proof pair is genuine. A different canonical output claim
    // with repaired owner Body/header/QC still cannot obtain a checked operation.
    let mut foreign_statement = life.statement().clone();
    foreign_statement.next[0] += Val::ONE;
    let foreign_next = encode_digest(foreign_statement.next);
    let own_request = JointRequest::decode(&candidate.request).unwrap();
    let foreign_expected = BootstrapExpectation::new(
        &binding,
        &parent,
        &own_request,
        &foreign_statement,
        Manifest::bootstrap(foreign_next, pair).unwrap(),
    )
    .unwrap();
    let foreign_block = fixture::transition(
        &binding,
        before,
        own_request,
        Manifest::bootstrap(foreign_next, pair).unwrap(),
        Control::Pending,
    );
    let foreign_qc = checkpoint(&binding, &context, &foreign_block);
    assert!(
        history
            .apply_bootstrap(&foreign_qc, &foreign_block, &foreign_expected)
            .is_err()
    );
    assert_eq!(history.context().unwrap(), &context);
    assert_eq!(history.bootstrap_parent().unwrap().head(), before);
    // Own metadata mismatch is rejected BEFORE import, even for a real QC.
    let mut changed = JointRequest::decode(&candidate.request)
        .unwrap()
        .inner()
        .clone();
    changed.nonce[31] ^= 1;
    let app = JointApplication::new(
        binding.application_descriptor().clone(),
        binding.journal_genesis(),
    )
    .unwrap();
    changed.query = registry200_journal::intent_query(
        app.source_spec(),
        app.genesis(),
        changed.parent,
        changed.nonce,
        changed.enrollment,
        changed.operation,
    );
    let changed = fixture::transition(
        &binding,
        before,
        JointRequest::new(&app, Lane::Bootstrap, changed).unwrap(),
        Manifest::bootstrap(next, pair).unwrap(),
        Control::Pending,
    );
    let changed_qc = checkpoint(&binding, &context, &changed);
    assert!(
        history
            .apply_bootstrap(&changed_qc, &changed, &expected)
            .is_err()
    );
    assert_eq!(history.context().unwrap(), &context);
    if after_empty {
        // A genuine old slot1 Empty decision cannot be substituted for the own
        // slot2 Bootstrap expectation, and does not mutate the live lineage.
        assert!(
            history
                .apply_bootstrap(&originals[0].1, &originals[0].0, &expected)
                .is_err()
        );
        assert_eq!(history.context().unwrap(), &context);
    }
    let operation = history.apply_bootstrap(&qc, &block, &expected).unwrap();
    assert_eq!(operation.body_bytes(), block.body());
    assert_eq!(operation.checkpoint_bytes(), qc.encode());
    assert_eq!(operation.checked_parent().slot(), parent.slot());
    assert!(history.bootstrap_parent().is_err());
    candidate.require_operation(&operation).unwrap();
    candidate.controllers[1][31] ^= 1;
    assert!(candidate.require_operation(&operation).is_err());
    candidate.controllers[1][31] ^= 1;
    candidate.table[31] ^= 1;
    assert!(candidate.require_operation(&operation).is_err());
    candidate.table[31] ^= 1;
    candidate.row_ids[3][31] ^= 1;
    assert!(candidate.require_operation(&operation).is_err());
    candidate.row_ids[3][31] ^= 1;
    candidate.salts[1][3] += 1;
    assert!(candidate.require_operation(&operation).is_err());
    candidate.salts[1][3] -= 1;
    candidate.registry.revision = 1;
    assert!(candidate.require_operation(&operation).is_err());
    candidate.registry.revision = 0;
    let duplicate = history.apply_bootstrap(&qc, &block, &expected).unwrap();
    assert_eq!(
        duplicate.checked_parent().head(),
        operation.checked_parent().head()
    );
    drop(duplicate);
    let opening = candidate.complete(operation).unwrap().into_opening();
    originals.push((block, qc));
    drop(life);
    // Only the actual completed opening feeds typed production Begin. No raw
    // Staged-to-current conversion, fake default DATA witness or owner getter.
    let control_parent = JointControlParent::from_verified(
        history.checked_parent().unwrap().unwrap(),
        &binding,
        history.context().unwrap(),
    )
    .unwrap();
    drop(history);
    drop(ingress);
    let begun = source_owner
        .prepare_joint_control(
            fetched(),
            &control_parent,
            opening,
            JointControlIntent::begin(1, 1, [6; 32]).unwrap(),
        )
        .unwrap();
    let depot = JointDepot::open(quota.depot_budget()).unwrap();
    let ingress = depot.ingress();
    let mut history = JointHistory::new(binding.clone(), depot).unwrap();
    for (block, qc) in &originals {
        history.apply(qc, block).unwrap();
    }
    let begin = install_begin(begun, &binding, &mut history, &ingress);
    originals.push(begin);
    assert!(
        history
            .apply_bootstrap(
                &originals[usize::from(after_empty)].1,
                &originals[usize::from(after_empty)].0,
                &expected
            )
            .is_err()
    );
    let completed_head = history.checked_parent().unwrap().unwrap().head();
    let completed_context = history.context().unwrap().clone();
    drop(source_owner);
    drop(history);
    drop(ingress);
    let depot = JointDepot::open(quota.depot_budget()).unwrap();
    let mut fresh = JointHistory::new(binding.clone(), depot).unwrap();
    for (block, qc) in &originals {
        fresh.apply(qc, block).unwrap();
    }
    assert_eq!(
        fresh.checked_parent().unwrap().unwrap().head(),
        completed_head
    );
    assert_eq!(fresh.context().unwrap(), &completed_context);
    assert!(fresh.bootstrap_parent().is_err());
    drop(fresh);
    // Final isolated owned fault: prior successful proof/QC replay cannot make a
    // physically missing prerequisite optional during a new closed reconstruction.
    let name = pair
        .sha256()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let path = quota
        .depot_directory()
        .join(format!("{name}-{:016x}.blob", pair.bytes()));
    let metadata = std::fs::symlink_metadata(&path).unwrap();
    assert!(metadata.is_file() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.len(), pair.bytes());
    std::fs::remove_file(&path).unwrap();
    let reconstructed = JointDepot::open(quota.depot_budget())
        .map_err(registry200_finality::joint::Error::from)
        .and_then(|depot| JointHistory::new(binding, depot))
        .and_then(|mut fresh| {
            for (block, qc) in &originals {
                fresh.apply(qc, block)?;
            }
            Ok(())
        });
    assert!(reconstructed.is_err());
    drop(quota);
    drop(directory);
}

#[test]
fn real_source_bootstrap_from_genesis_requires_exact_proof_qc_and_default_opening_before_begin() {
    run_bootstrap(false);
}
#[test]
fn real_empty_pending_history_can_bootstrap_in_its_actual_successor_slot() {
    run_bootstrap(true);
}
