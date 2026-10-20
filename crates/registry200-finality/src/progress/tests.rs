//! PUBLIC NONSECRET owning fixtures. Actual Source/Core proofs and signed QCs;
//! these local tests do not claim an OS consensus or Predicate/FHE gate.
use super::*;
use crate::joint::history::tests::{Directory, fixture, keys, work};
use ed25519_dalek::SigningKey;
use p3_field::PrimeCharacteristicRing;
use protocol_storage::ParticipantQuota;
use registry200_joint::progress::{
    Application, Lane, Manifest, ProgressDepot, ProgressEvidenceIngress, Request,
};
use registry200_journal::{Control, Operation, Request as InnerRequest, intent_query};
use registry200_proof::{
    Val, admission::CanonicalSource, lifecycle, registry_progress as core, source,
};
use sha2::{Digest, Sha256};
use version_journal::{AuthorizedTransition, Body, HeadRef, ShardUpdate};
use work_finality::{
    QuorumCertificate, SignedVote, Step, VoteContext,
    consensus::{Context, MAX_RECORD_BYTES, Rules},
};
use zeroize::Zeroizing;

pub(crate) fn rules() -> Rules {
    Rules::multi_slot(
        durable_profile_digest(),
        CANDIDATE_BYTES as u32,
        32,
        [100, 200, 300],
        10,
        MAX_RECORD_BYTES as u64,
    )
    .unwrap()
}
pub(crate) fn install() -> (
    Directory,
    ParticipantQuota,
    Binding,
    DurableFinality,
    History,
    ProgressEvidenceIngress,
) {
    let f = fixture();
    let directory = Directory::new();
    // Local participant namespace deliberately differs from either AppID.
    let quota = ParticipantQuota::create_new(directory.root(), [0xb6; 32], 10_000_000_000).unwrap();
    let depot = ProgressDepot::open(quota.depot_budget(), &f.progress_descriptor).unwrap();
    let claim = depot.retain_setup(&f.setup).unwrap();
    drop(depot);
    let mut genesis = crate::joint::history::tests::genesis(&f.descriptor);
    genesis.application_commitment = f.progress_descriptor.id();
    genesis.profile.max_request_bytes = 4096;
    genesis.profile.max_proof_bytes = registry200_joint::progress::MANIFEST_BYTES as u32;
    let r = rules();
    let binding = Binding::for_durable(
        [0x19; 32],
        r.clone(),
        work(&r),
        genesis,
        f.progress_descriptor.clone(),
        claim,
    )
    .unwrap();
    let owner =
        DurableFinality::create_participant(&quota, binding.clone(), keys().remove(0)).unwrap();
    let ingress = owner.evidence_ingress().unwrap();
    let depot = ProgressDepot::share(ingress.recording_store(), &f.progress_descriptor).unwrap();
    let history = History::new(binding.clone(), depot).unwrap();
    (directory, quota, binding, owner, history, ingress)
}
pub(crate) fn block(h: &History, body: &Body) -> CandidateBlock {
    let timestamp = 1000 + h.context().unwrap().slot();
    let mut header = h.candidate_header(body, timestamp, 2000).unwrap();
    header.mine(16).unwrap();
    CandidateBlock::new(
        header,
        body.encode(&h.binding().journal_genesis().profile).unwrap(),
    )
    .unwrap()
}
pub(crate) fn checkpoint(c: &Context, d: &Candidate, round: u64) -> Checkpoint {
    // Same public fixed consensus vote-domain rule, real distinct signatures.
    let mut h = Sha256::new();
    h.update(b"dcs/work-finality/consensus-vote-instance/v1");
    h.update(work_finality::profile_digest());
    h.update(c.id());
    let e = VoteContext::new(
        c.set(),
        h.finalize().into(),
        c.slot(),
        round,
        Step::Precommit,
        Some(c.value_id(&d.encode()).unwrap()),
    )
    .unwrap();
    let votes: Vec<_> = keys()
        .iter()
        .take(3)
        .map(|key| SignedVote::sign(e, key).unwrap())
        .collect();
    let q = QuorumCertificate::assemble(c.set(), &e, &votes)
        .unwrap()
        .encode()
        .unwrap();
    Checkpoint::new(d.clone(), round, q).unwrap()
}
pub(crate) fn signed_body(a: &Application, r: &Request, m: &Manifest, old: Control) -> Body {
    let mut t = AuthorizedTransition {
        parent: r.inner().parent,
        request: r.encode().unwrap(),
        proof: m.encode(),
        updates: vec![ShardUpdate {
            id: a.source_spec().control_id,
            old: old.heads(a.source_spec()),
            new: Control::Active {
                enrollment: r.inner().enrollment,
                registry: m.next_root(),
            }
            .heads(a.source_spec()),
        }],
        owner_signature: [0; 64],
    };
    t.sign(a.genesis(), &SigningKey::from_bytes(&[0x64; 32]));
    Body::Transition(t)
}
pub(crate) fn enrollment(a: &Application) -> [u8; 32] {
    let f = fixture();
    let e = lifecycle::statement::Expected::bootstrap(&f.source, a.genesis(), a.genesis(), [0; 32])
        .unwrap();
    source::statement::encode_digest(source::commitment::digest(
        &lifecycle::circuit::commitment::enrollment_fields_opening(
            &e,
            &f.witness.plain[124..156].try_into().unwrap(),
            &f.witness.controllers,
            [Val::from_u8(3); 4],
        ),
    ))
}
pub(crate) fn operation(
    a: &Application,
    parent: HeadRef,
    ingress: &ProgressEvidenceIngress,
    old: Control,
) -> (Body, Request, Manifest) {
    let f = fixture();
    let bootstrap = old == Control::Pending;
    let enroll = match old {
        Control::Pending => enrollment(a),
        Control::Active { enrollment, .. } => enrollment,
    };
    let op = if bootstrap {
        Operation::Bootstrap
    } else {
        Operation::Transition
    };
    let nonce = if bootstrap { [0xa1; 32] } else { [0xa2; 32] };
    let q = intent_query(
        a.source_spec(),
        a.genesis(),
        parent.block,
        nonce,
        enroll,
        op,
    );
    let mut claim = f.source.clone();
    claim.request = q;
    claim.open_commitment = source::commitment::digest(&source::commitment::opening_fields(
        &claim,
        [Val::TWO; 4],
        &f.witness.plain,
    ));
    let source = CanonicalSource::checked_claim(&claim).unwrap();
    let raw = source::prove(
        &source,
        &source::circuit::Witness::new(
            [0x71; 32],
            [Val::ONE; 4],
            [Val::TWO; 4],
            [255, 0, 255, 128],
        ),
    )
    .unwrap();
    let source_id = ingress.retain_public_blob(raw.as_bytes()).unwrap();
    let (manifest, command) = if bootstrap {
        let e = core::BootstrapExpected::new(&source, a.genesis(), parent.block, enroll).unwrap();
        let w = core::BootstrapWitness::new(
            &e,
            Zeroizing::new(f.witness.plain),
            Zeroizing::new(f.witness.controllers),
            Zeroizing::new([[2; 4], [3; 4], [6; 4]]),
        )
        .unwrap();
        let proof = core::prove_bootstrap(&e, &w, raw.as_bytes()).unwrap();
        (
            Manifest::bootstrap(
                proof.statement().next(),
                source_id,
                ingress.retain_public_blob(proof.as_bytes()).unwrap(),
            )
            .unwrap(),
            [0; 32],
        )
    } else {
        let Control::Active { registry, .. } = old else {
            unreachable!()
        };
        let draft = core::transition::Expected::control(
            &source,
            a.genesis(),
            parent.block,
            enroll,
            registry,
            [0; 32],
        )
        .unwrap();
        let command = lifecycle::circuit::model::Command::control(
            lifecycle::circuit::model::Operation::Begin,
            1,
            1,
            0,
        );
        let commitment = core::transition::command_commitment(
            &draft,
            &command,
            0,
            &f.witness.controllers,
            [4; 4],
        )
        .unwrap();
        let e = core::transition::Expected::control(
            &source,
            a.genesis(),
            parent.block,
            enroll,
            registry,
            commitment,
        )
        .unwrap();
        let witness = core::transition::Witness::control(
            &e,
            Zeroizing::new(f.witness.plain),
            Zeroizing::new(f.witness.controllers),
            Zeroizing::new(core::circuit::State::default()),
            Zeroizing::new(command),
            Zeroizing::new([[2; 4], [3; 4], [6; 4], [4; 4], [7; 4], [8; 4]]),
        )
        .unwrap();
        let proof = core::transition::prove(
            &e,
            &witness,
            &core::transition::Prerequisites {
                source: raw.as_bytes(),
                query: None,
            },
        )
        .unwrap();
        (
            Manifest::control(
                proof.statement().next(),
                proof.statement().result(),
                source_id,
                ingress.retain_public_blob(proof.as_bytes()).unwrap(),
            )
            .unwrap(),
            commitment,
        )
    };
    let request = Request::new(
        a,
        if bootstrap {
            Lane::Bootstrap
        } else {
            Lane::Control
        },
        InnerRequest {
            operation: op,
            genesis: a.genesis(),
            parent: parent.block,
            application: a.source_spec().id(),
            nonce,
            query: q,
            enrollment: enroll,
            opening: source::statement::encode_digest(source.claim().open_commitment),
            command,
            packets: source.claim().packets.clone(),
        },
    )
    .unwrap();
    (signed_body(a, &request, &manifest, old), request, manifest)
}

#[test]
fn new_profiles_reject_legacy_values_and_empty_pending_has_a_real_successor() {
    let (_directory, quota, binding, mut owner, mut history, ingress) = install();
    assert_ne!(profile_digest(), crate::joint::profile_digest());
    assert_ne!(
        durable_profile_digest(),
        crate::joint::durable_profile_digest()
    );
    assert!(
        Binding::new(
            [0x19; 32],
            binding.rules().clone(),
            binding.work_genesis().clone(),
            binding.journal_genesis().clone(),
            binding.application_descriptor().clone(),
            binding.setup_claim().clone()
        )
        .is_err()
    );
    let legacy_rules = Rules::multi_slot(
        crate::joint::durable_profile_digest(),
        CANDIDATE_BYTES as u32,
        32,
        [100, 200, 300],
        10,
        MAX_RECORD_BYTES as u64,
    )
    .unwrap();
    assert!(
        Binding::for_durable(
            [0x19; 32],
            binding.rules().clone(),
            work(&legacy_rules),
            binding.journal_genesis().clone(),
            binding.application_descriptor().clone(),
            binding.setup_claim().clone()
        )
        .is_err()
    );
    let pending = history.bootstrap_parent().unwrap();
    let empty = block(&history, &Body::Empty);
    let d = owner
        .import_candidate(empty.header().clone(), empty.body())
        .unwrap();
    assert!(crate::joint::JointCandidate::decode(&d.encode()).is_err());
    let q = checkpoint(history.context().unwrap(), &d, 0);
    let before = quota.usage().unwrap();
    let mut wrong = q.encode();
    wrong[..8].copy_from_slice(b"DCSJCQ01");
    assert!(Checkpoint::decode(&wrong).is_err());
    assert_eq!(quota.usage().unwrap(), before);
    owner.receive_checkpoint(&q).unwrap();
    let parent = history.apply(&q, &empty).unwrap();
    assert_eq!(parent.control(), Control::Pending);
    let next = history.bootstrap_parent().unwrap();
    assert_eq!(next.head(), parent.head());
    assert_eq!(next.slot(), 2);
    assert_ne!(pending.context_id(), next.context_id());
    assert_eq!(
        owner.finalized_parent().unwrap().unwrap().head(),
        parent.head()
    );
    drop(history);
    drop(ingress);
    drop(owner);
    drop(quota);
}

#[test]
fn genuine_bootstrap_and_control_bind_own_body_qc_parent_and_strict_reopen() {
    let (directory, quota, binding, mut owner, mut history, ingress) = install();
    let app = Application::new(
        binding.application_descriptor().clone(),
        binding.journal_genesis(),
    )
    .unwrap();
    // Bootstrap after a genuinely admitted EmptyPending, not a genesis-only
    // shortcut. The initial sealed snapshot must not authorize this successor.
    let initial_pending = history.bootstrap_parent().unwrap();
    let empty = block(&history, &Body::Empty);
    let empty_candidate = owner
        .import_candidate(empty.header().clone(), empty.body())
        .unwrap();
    let empty_q = checkpoint(history.context().unwrap(), &empty_candidate, 0);
    owner.receive_checkpoint(&empty_q).unwrap();
    history.apply(&empty_q, &empty).unwrap();
    let pending = history.bootstrap_parent().unwrap();
    assert_eq!(pending.slot(), 2);
    let (body, request, manifest) = operation(&app, pending.head(), &ingress, Control::Pending);
    assert!(
        OperationExpectation::bootstrap(
            &binding,
            &initial_pending,
            &request,
            Manifest::decode(&manifest.encode()).unwrap(),
            &body
        )
        .is_err()
    );
    let expected =
        OperationExpectation::bootstrap(&binding, &pending, &request, manifest, &body).unwrap();
    let boot = block(&history, &body);
    let candidate = owner
        .import_candidate(boot.header().clone(), boot.body())
        .unwrap();
    let q = checkpoint(history.context().unwrap(), &candidate, 0);
    owner.receive_checkpoint(&q).unwrap();
    let completed = history.apply_operation(&q, &boot, &expected).unwrap();
    assert_eq!(completed.body_bytes(), boot.body());
    assert_eq!(
        completed.operation().operation_id(),
        expected.operation_id()
    );
    assert!(completed.operation().bootstrap_statement().is_some());
    assert!(completed.operation().product().is_none());
    assert_eq!(
        completed.checked_parent().head(),
        owner.finalized_parent().unwrap().unwrap().head()
    );
    assert!(history.bootstrap_parent().is_err());
    let first = completed.checked_parent().clone();
    drop(completed);

    let (body, request, manifest) = operation(&app, first.head(), &ingress, first.control());
    let expected = OperationExpectation::transition(
        &binding,
        &first,
        history.context().unwrap(),
        &request,
        Manifest::decode(&manifest.encode()).unwrap(),
        &body,
    )
    .unwrap();
    // A real signed QC is insufficient for a different own Body. Rejection is
    // before import, leaving the actual checked parent/context unchanged.
    let honest = block(&history, &body);
    let d = Candidate::for_context(
        &binding,
        history.context().unwrap(),
        honest.header().clone(),
    )
    .unwrap();
    let honest_q = checkpoint(history.context().unwrap(), &d, 0);
    let before = history.context().unwrap().clone();
    assert!(matches!(
        history.apply_operation(&q, &boot, &expected),
        Err(Error::Context)
    ));
    assert_eq!(history.context().unwrap(), &before);

    // Exact own Body/context/candidate still match. Only an actual signature
    // byte changes; canonical metadata is not a signature-verification receipt.
    let snapshot = history.journal_state_for_test(honest.header().id());
    let honest_certificate = honest_q.certificate();
    let signature_at = work_finality::CERTIFICATE_HEADER_BYTES + 32; // key32, then signature64
    assert!(signature_at < honest_certificate.len());
    let mut certificate = honest_certificate.to_vec();
    certificate[signature_at] ^= 1;
    assert_eq!(
        &certificate[..signature_at],
        &honest_certificate[..signature_at]
    );
    assert_eq!(
        &certificate[signature_at + 1..],
        &honest_certificate[signature_at + 1..]
    );
    assert_eq!(
        certificate[signature_at],
        honest_certificate[signature_at] ^ 1
    );
    let invalid = Checkpoint::new(d.clone(), honest_q.round(), certificate).unwrap();
    let wire = invalid.encode();
    let invalid = Checkpoint::decode(&wire).unwrap();
    assert_eq!(invalid.encode(), wire);
    // There is no public QC decode-only API: the real decoder verifies actual
    // signatures. Require its precise error, not an earlier Context rejection.
    assert!(matches!(
        history.apply_operation(&invalid, &honest, &expected),
        Err(Error::Consensus(work_finality::consensus::Error::Evidence(
            work_finality::Error::InvalidSignature
        )))
    ));
    assert_eq!(
        history.journal_state_for_test(honest.header().id()),
        snapshot
    );
    assert_eq!(history.context().unwrap(), &before);
    assert_eq!(
        history.checked_parent().unwrap().unwrap().head(),
        first.head()
    );

    // Keep the genuine Control child and exact Request/old root, but supply a
    // hash-valid damaged Source premise and actual owner Body/three-key QC.
    let source_ref = manifest.references().next().unwrap().blob_id();
    let mut bad = ingress
        .read_public_blob(source_ref, protocol_storage::MAX_BLOB_BYTES as usize)
        .unwrap();
    let at = bad.len() - 1;
    bad[at] ^= 1;
    let damaged = ingress.retain_public_blob(&bad).unwrap();
    let child = manifest.references().nth(1).unwrap().blob_id();
    let bad_manifest =
        Manifest::control(manifest.next_root(), manifest.result_root(), damaged, child).unwrap();
    let bad_body = signed_body(&app, &request, &bad_manifest, first.control());
    let bad_expected = OperationExpectation::transition(
        &binding,
        &first,
        history.context().unwrap(),
        &request,
        bad_manifest,
        &bad_body,
    )
    .unwrap();
    let bad_block = block(&history, &bad_body);
    let bad_candidate = Candidate::for_context(
        &binding,
        history.context().unwrap(),
        bad_block.header().clone(),
    )
    .unwrap();
    let bad_q = checkpoint(history.context().unwrap(), &bad_candidate, 0);
    assert!(
        history
            .apply_operation(&bad_q, &bad_block, &bad_expected)
            .is_err()
    );
    assert_eq!(history.context().unwrap(), &before);
    assert_eq!(
        history.checked_parent().unwrap().unwrap().head(),
        first.head()
    );
    assert!(matches!(
        history.apply_operation(&bad_q, &bad_block, &expected),
        Err(Error::Context)
    ));
    let candidate = owner
        .import_candidate(honest.header().clone(), honest.body())
        .unwrap();
    assert_eq!(candidate, d);
    owner.receive_checkpoint(&honest_q).unwrap();
    let completed = history
        .apply_operation(&honest_q, &honest, &expected)
        .unwrap();
    assert!(completed.operation().transition_statement().is_some());
    assert_eq!(
        completed.control(),
        owner.finalized_parent().unwrap().unwrap().control()
    );
    let after = history.context().unwrap().clone();
    let final_head = completed.head();
    drop(completed);
    let alternative = checkpoint(&before, &d, 7);
    let historical = history
        .apply_operation(&alternative, &honest, &expected)
        .unwrap();
    assert_eq!(historical.head(), final_head);
    assert_eq!(history.context().unwrap(), &after);
    assert!(matches!(
        history.apply_operation(&q, &boot, &expected),
        Err(Error::Context)
    ));
    drop(historical);
    drop(history);
    drop(ingress);
    drop(owner);
    drop(quota);
    let quota =
        ParticipantQuota::open_existing(directory.root(), [0xb6; 32], 10_000_000_000).unwrap();
    let reopened = DurableFinality::open_participant(&quota, binding, keys().remove(0)).unwrap();
    assert_eq!(reopened.context().unwrap(), &after);
    assert_eq!(
        reopened.finalized_parent().unwrap().unwrap().head(),
        final_head
    );
    drop(reopened);
    drop(quota);
}
