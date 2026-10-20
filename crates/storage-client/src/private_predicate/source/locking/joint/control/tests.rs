//! PUBLIC NONSECRET owning inputs. These are local genuine proof/QC tests,
//! explicitly NOT an OS-network, SQL-data-commit or production Bootstrap gate.
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
use registry200_joint::{JointDepot, JointEvidenceIngress, Manifest};
use registry200_proof::{
    admission,
    lifecycle::circuit::{self as life, commitment as fields},
    source::{self, statement as ss},
};
use sha2::{Digest, Sha256};
use work_finality::{QuorumCertificate, SignedVote, Step, VoteContext};

fn checkpoint(
    binding: &JointBinding,
    history: &JointHistory,
    block: &CandidateBlock,
) -> JointCheckpoint {
    let context = history.context().unwrap();
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
        .map(|k| SignedVote::sign(vote, k).unwrap())
        .collect();
    let qc = QuorumCertificate::assemble(context.set(), &vote, &votes)
        .unwrap()
        .encode()
        .unwrap();
    JointCheckpoint::new(candidate, 0, qc).unwrap()
}
fn parent(history: &JointHistory, binding: &JointBinding) -> JointControlParent {
    JointControlParent::from_verified(
        history.checked_parent().unwrap().unwrap(),
        binding,
        history.context().unwrap(),
    )
    .unwrap()
}
fn run_control(
    prepared: PreparedJointControl,
    history: &mut JointHistory,
    ingress: &JointEvidenceIngress,
) -> CompletedJointControl {
    let (request, life, kind, mut candidate) = prepared.into_parts();
    let pair = ingress.retain_public_blob(life.as_bytes()).unwrap();
    let kind_id = ingress.retain_public_blob(kind.as_bytes()).unwrap();
    let next = ss::encode_digest(life.statement().next);
    let result = ss::encode_digest(life.statement().result);
    let manifest = Manifest::control(next, result, pair, kind_id).unwrap();
    let binding = candidate.parent.binding.clone();
    let expected = candidate.expectation(manifest).unwrap();
    let block = fixture::transition(
        &binding,
        candidate.parent.head(),
        request,
        Manifest::control(next, result, pair, kind_id).unwrap(),
        candidate.parent.verified.control(),
    );
    let before = history.checked_parent().unwrap().unwrap().head();
    let context = history.context().unwrap().id();
    // Self-consistent hash/ref/signature/QC does not replace actual crypto: this
    // malformed prerequisite must fail without changing the owning history.
    let mut damaged = life.as_bytes().to_vec();
    *damaged.last_mut().unwrap() ^= 1;
    let bad_pair = ingress.retain_public_blob(&damaged).unwrap();
    let bad_expected = candidate
        .expectation(Manifest::control(next, result, bad_pair, kind_id).unwrap())
        .unwrap();
    let bad_request = JointRequest::decode(candidate.request.as_slice()).unwrap();
    let bad = fixture::transition(
        &binding,
        candidate.parent.head(),
        bad_request,
        Manifest::control(next, result, bad_pair, kind_id).unwrap(),
        candidate.parent.verified.control(),
    );
    let bad_qc = checkpoint(&binding, history, &bad);
    assert!(history.apply_control(&bad_qc, &bad, &bad_expected).is_err());
    assert_eq!(history.checked_parent().unwrap().unwrap().head(), before);
    assert_eq!(history.context().unwrap().id(), context);
    // Exact own expectation is checked BEFORE import, even with a genuinely
    // signed QC for a different canonical, owner-signed Body.
    let mut foreign = JointRequest::decode(candidate.request.as_slice())
        .unwrap()
        .inner()
        .clone();
    foreign.nonce[0] ^= 1;
    let app = JointApplication::new(
        binding.application_descriptor().clone(),
        binding.journal_genesis(),
    )
    .unwrap();
    foreign.query = registry200_journal::intent_query(
        app.source_spec(),
        app.genesis(),
        foreign.parent,
        foreign.nonce,
        foreign.enrollment,
        foreign.operation,
    );
    let foreign = fixture::transition(
        &binding,
        candidate.parent.head(),
        JointRequest::new(&app, Lane::Control, foreign).unwrap(),
        Manifest::control(next, result, pair, kind_id).unwrap(),
        candidate.parent.verified.control(),
    );
    let foreign_qc = checkpoint(&binding, history, &foreign);
    assert!(
        history
            .apply_control(&foreign_qc, &foreign, &expected)
            .is_err()
    );
    assert_eq!(history.checked_parent().unwrap().unwrap().head(), before);
    assert_eq!(history.context().unwrap().id(), context);
    let qc = checkpoint(&binding, history, &block);
    let operation = history.apply_control(&qc, &block, &expected).unwrap();
    assert_eq!(operation.body_bytes(), block.body());
    assert_eq!(operation.checkpoint_bytes(), qc.encode());
    candidate.require_operation(&operation).unwrap();
    let original = candidate.command.transaction;
    candidate.command.transaction = original + 1;
    assert!(candidate.require_operation(&operation).is_err());
    candidate.command.transaction = original;
    let mut salt = candidate.result_salt[0];
    candidate.result_salt[0] = u64::from(salt == 0);
    assert!(candidate.require_operation(&operation).is_err());
    candidate.result_salt[0] = salt;
    salt.zeroize();
    candidate.next.revision += 1;
    assert!(candidate.require_operation(&operation).is_err());
    candidate.next.revision -= 1;
    candidate.require_operation(&operation).unwrap();
    // Latest semantic retry replays actual proofs again; it is not a saved
    // success bit. Only one ORIGINAL private candidate is then consumed.
    let duplicate = history.apply_control(&qc, &block, &expected).unwrap();
    assert_eq!(
        duplicate.checked_parent().head(),
        operation.checked_parent().head()
    );
    drop(duplicate);
    candidate.complete(operation).unwrap()
}

/// Test-only genuine FailCurrent prerequisite, not a public arbitrary-opcode
/// producer. It opens real Source and is actually proved/admitted before End.
fn fail_current(
    owner: &SourceOwner,
    fetched: FetchedSource<'_>,
    opening: JointRegistryOpening,
    history: &mut JointHistory,
    ingress: &JointEvidenceIngress,
    transaction: u64,
) -> JointRegistryOpening {
    let p = parent(history, &opening.binding);
    p.require_stamp(&opening.binding, &opening.parent, opening.context)
        .unwrap();
    let loaded = owner.load(fetched).unwrap();
    let app = JointApplication::new(
        p.binding.application_descriptor().clone(),
        p.binding.journal_genesis(),
    )
    .unwrap();
    let Control::Active {
        enrollment,
        registry,
    } = p.verified.control()
    else {
        unreachable!()
    };
    let tx = opening
        .registry
        .transactions
        .iter()
        .find(|tx| tx.id == transaction)
        .unwrap();
    let command = Command::control(
        Operation::FailCurrent,
        transaction,
        tx.principal,
        tx.sequence,
    );
    let nonce = [0x19; 32];
    let q = registry200_journal::intent_query(
        app.source_spec(),
        app.genesis(),
        p.head().block,
        nonce,
        enrollment,
        registry200_journal::Operation::Transition,
    );
    let mut claim = loaded.draft.clone();
    claim.request = q;
    let mut math = life::Witness {
        plain: loaded.plain.as_slice().try_into().unwrap(),
        controllers: *opening.controllers,
        salts: [[Val::ZERO; 4]; 6],
        old: (*opening.registry).clone(),
        command: Some(command.clone()),
    };
    math.salts[0] = [31, 32, 33, 34].map(Val::from_u64);
    math.salts[1] = opening.salts[0].map(Val::from_u64);
    math.salts[2] = opening.salts[1].map(Val::from_u64);
    math.salts[3] = [41, 42, 43, 44].map(Val::from_u64);
    math.salts[4] = [51, 52, 53, 54].map(Val::from_u64);
    math.salts[5] = [61, 62, 63, 64].map(Val::from_u64);
    claim.open_commitment = source::commitment::digest(&source::commitment::opening_fields(
        &claim,
        math.salts[0],
        &loaded.plain,
    ));
    let provisional = lifecycle::statement::Expected::transition(
        &claim,
        app.genesis(),
        p.head().block,
        enrollment,
        registry,
        [0; 32],
    )
    .unwrap();
    let command_fields = fields::command_fields(&provisional, &math, &command);
    let command_root = lifecycle::statement::digest(&command_fields);
    let command_words = command_fields
        .iter()
        .map(|v| v.as_canonical_u64())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let expected = lifecycle::statement::Expected::transition(
        &claim,
        app.genesis(),
        p.head().block,
        enrollment,
        registry,
        ss::encode_digest(command_root),
    )
    .unwrap();
    let step = opening
        .registry
        .step(&command, p.head().block, math.ages())
        .unwrap();
    let proof = source::prove(
        &admission::CanonicalSource::checked_claim(&claim).unwrap(),
        &owner.source_witness(math.salts[0], &loaded.originals),
    )
    .unwrap();
    let checked = admission::Expected::checked_claim(&expected).unwrap();
    let witness = lifecycle::PreparedWitness::new(&checked, math).unwrap();
    let life = lifecycle::prove(&checked, &witness, proof.as_bytes()).unwrap();
    drop(witness);
    drop(proof);
    drop(loaded);
    let kind_expected = control_kind::Expected::new(life.statement()).unwrap();
    let kind_witness = control_kind::circuit::Witness::new(
        &kind_expected,
        control_kind::circuit::Opening::new(command_words).unwrap(),
    )
    .unwrap();
    let kind = control_kind::prove(
        &kind_expected,
        &kind_witness,
        &control_kind::Prerequisites {
            lifecycle: life.as_bytes(),
        },
    )
    .unwrap();
    let request = JointRequest::new(
        &app,
        Lane::Control,
        registry200_journal::Request {
            operation: registry200_journal::Operation::Transition,
            genesis: app.genesis(),
            parent: p.head().block,
            application: app.source_spec().id(),
            nonce,
            query: q,
            enrollment,
            opening: ss::encode_digest(claim.open_commitment),
            command: ss::encode_digest(command_root),
            packets: claim.packets,
        },
    )
    .unwrap();
    let manifest = Manifest::control(
        ss::encode_digest(life.statement().next),
        ss::encode_digest(life.statement().result),
        ingress.retain_public_blob(life.as_bytes()).unwrap(),
        ingress.retain_public_blob(kind.as_bytes()).unwrap(),
    )
    .unwrap();
    let block = fixture::transition(
        &p.binding,
        p.head(),
        request,
        manifest,
        p.verified.control(),
    );
    let qc = checkpoint(&p.binding, history, &block);
    history.apply(&qc, &block).unwrap();
    let next = parent(history, &p.binding);
    JointRegistryOpening::from_private_parts(
        &next,
        step.next,
        *opening.controllers,
        [opening.salts[0], [51, 52, 53, 54]],
    )
    .unwrap()
}

#[test]
fn real_source_control_begin_end_compaction_and_failed_close_require_exact_proofs_qc_and_private_openings()
 {
    let owner = SourceOwner::new([0x21; 16], [0x42; 16], Zeroizing::new([0x63; 32])).unwrap();
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
    let table = owner
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
    let loaded = owner.load(fetched()).unwrap();
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
    let checked = setup
        .verify_key_transform(&anchor, epoch.key_evidence().unwrap().as_bytes())
        .unwrap();
    let directory = fixture::Directory::new();
    let quota = ParticipantQuota::create_new(
        directory.path("control-owner"),
        [0x29; 32],
        fixture::CAPACITY,
    )
    .unwrap();
    let binding = fixture::binding(
        &loaded,
        &setup,
        &anchor,
        checked.statement(),
        object,
        &quota,
    );
    let depot = JointDepot::open(quota.depot_budget()).unwrap();
    let ingress = depot.ingress();
    let mut history = JointHistory::new(binding.clone(), depot).unwrap();
    let genesis = version_journal::Journal::new(binding.journal_genesis().clone())
        .unwrap()
        .genesis_head();
    let mut state = fixture::ControlState::empty();
    // Explicit prerequisite only: production RegistryBootstrap is NOT implemented
    // by this cut. This test uses an actual Source/Life Bootstrap proof and QC.
    let boot = fixture::control_block(
        &owner, &loaded, &binding, genesis, &mut state, &ingress, true,
    );
    let qc = checkpoint(&binding, &history, &boot);
    history.apply(&qc, &boot).unwrap();
    drop(loaded);
    let p = parent(&history, &binding);
    for case in 0..3 {
        let mut controllers = fixture::CONTROLLERS;
        let mut salts = [fixture::ENROLL_SALT, state.salt];
        if case == 0 {
            controllers[1][31] ^= 1
        } else if case == 1 {
            salts[0][3] += 1
        } else {
            salts[1][3] += 1
        }
        let candidate =
            JointRegistryOpening::from_private_parts(&p, Registry::default(), controllers, salts)
                .unwrap();
        let intent = JointControlIntent::begin(1, 1, [case as u8; 32]).unwrap();
        assert!(matches!(
            owner.prepare_joint_control(fetched(), &p, candidate, intent),
            Err(crate::Error::InvalidInput(_))
        ));
    }
    let opening = JointRegistryOpening::from_private_parts(
        &p,
        state.registry,
        fixture::CONTROLLERS,
        [fixture::ENROLL_SALT, state.salt],
    )
    .unwrap();
    let first = owner
        .prepare_joint_control(
            fetched(),
            &p,
            opening,
            JointControlIntent::begin(1, 1, [0x31; 32]).unwrap(),
        )
        .unwrap();
    let first = run_control(first, &mut history, &ingress);
    assert_eq!(first.outcome(), JointControlOutcome::Begun);
    let opening = first.into_opening();
    let p2 = parent(&history, &binding);
    // A genuine old stamp cannot be relabelled as the new parent.
    assert!(
        p.require_stamp(&opening.binding, &opening.parent, opening.context)
            .is_err()
    );
    let second = owner
        .prepare_joint_control(
            fetched(),
            &p2,
            opening,
            JointControlIntent::begin(2, 2, [0x32; 32]).unwrap(),
        )
        .unwrap();
    let opening = run_control(second, &mut history, &ingress).into_opening();
    assert_eq!(
        opening
            .registry
            .transactions
            .iter()
            .map(|tx| tx.id)
            .collect::<Vec<_>>(),
        [1, 2]
    );
    let p3 = parent(&history, &binding);
    let end = owner
        .prepare_joint_control(
            fetched(),
            &p3,
            opening,
            JointControlIntent::end(1, 1, JointEndDisposition::Close, [0x33; 32]).unwrap(),
        )
        .unwrap();
    let end = run_control(end, &mut history, &ingress);
    assert_eq!(end.outcome(), JointControlOutcome::ClosedRegistry);
    let opening = end.into_opening();
    assert_eq!(opening.registry.transactions.len(), 1);
    assert_eq!(opening.registry.transactions[0].id, 2);
    let opening = fail_current(&owner, fetched(), opening, &mut history, &ingress, 2);
    assert!(opening.registry.transactions[0].failed);
    assert_eq!(opening.registry.transactions[0].id, 2);
    // Acquire stays strict, even though End must accept this failed actor.
    let p4 = parent(&history, &binding);
    let failed_copy = JointRegistryOpening::from_private_parts(
        &p4,
        (*opening.registry).clone(),
        *opening.controllers,
        *opening.salts,
    )
    .unwrap();
    assert!(failed_copy.for_acquire(&p4, 2, 2).is_err());
    let end = owner
        .prepare_joint_control(
            fetched(),
            &p4,
            opening,
            JointControlIntent::end(2, 2, JointEndDisposition::Close, [0x34; 32]).unwrap(),
        )
        .unwrap();
    let end = run_control(end, &mut history, &ingress);
    assert_eq!(end.outcome(), JointControlOutcome::AbortedRegistry);
    let opening = end.into_opening();
    assert!(opening.registry.transactions.is_empty());
    drop(opening);
    drop(history);
    drop(ingress);
    drop(quota);
    drop(directory);
}

#[test]
fn begin_and_end_intents_keep_allocator_failed_end_and_stable_id_rules() {
    let empty = Registry::default();
    let begin = JointControlIntent::begin(1, 1, [0; 32]).unwrap();
    assert_eq!(begin.command(&empty).unwrap().sequence, 0);
    assert!(JointControlIntent::begin(0, 1, [0; 32]).is_err());
    assert!(JointControlIntent::end(1, 3, JointEndDisposition::Close, [0; 32]).is_err());
    let begun = empty
        .step(&begin.command(&empty).unwrap(), [0; 32], [0; 4])
        .unwrap()
        .next;
    assert!(
        begun
            .step(&begin.command(&begun).unwrap(), [0; 32], [0; 4])
            .is_err()
    );
    let mut failed = begun;
    failed.transactions[0].failed = true;
    let end = JointControlIntent::end(1, 1, JointEndDisposition::Close, [0; 32])
        .unwrap()
        .command(&failed)
        .unwrap();
    assert!(!end.abort);
    assert_eq!(failed.step(&end, [0; 32], [0; 4]).unwrap().outcome, 3);
}
