//! PUBLIC NONSECRET fixtures; actual Source/Lifecycle/Kind and signed Work QCs.
use super::*;
use crate::joint::history::tests::{
    Directory, certificate, fixture, genesis, keys, proof_body, proposed, work,
};
use registry200_joint::{Application, Manifest};
use registry200_proof::{lifecycle, source};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};
use version_journal::Body;
use work_finality::consensus::{MAX_RECORD_BYTES, Rules};

const CAPACITY: u64 = 10_000_000_000;
fn rules() -> Rules {
    Rules::multi_slot(
        durable_profile_digest(),
        crate::joint::CANDIDATE_BYTES as u32,
        32,
        [100, 200, 300],
        10,
        MAX_RECORD_BYTES as u64,
    )
    .unwrap()
}
fn install(
    max_headers: u32,
) -> (
    Directory,
    ParticipantQuota,
    JointBinding,
    DurableJointFinality,
) {
    install_with_signer(max_headers, keys().remove(0))
}
fn install_with_signer(
    max_headers: u32,
    signer: SigningKey,
) -> (
    Directory,
    ParticipantQuota,
    JointBinding,
    DurableJointFinality,
) {
    let f = fixture();
    let directory = Directory::new();
    let quota =
        ParticipantQuota::create_new(directory.root(), f.descriptor.id(), CAPACITY).unwrap();
    let depot = JointDepot::open(quota.depot_budget()).unwrap();
    let claim = depot.retain_setup(&f.descriptor, &f.setup).unwrap();
    drop(depot);
    let mut g = genesis(&f.descriptor);
    g.profile.max_headers = max_headers;
    let rules = rules();
    let binding = JointBinding::for_durable(
        [0x19; 32],
        rules.clone(),
        work(&rules),
        g,
        f.descriptor.clone(),
        claim,
    )
    .unwrap();
    let owner = DurableJointFinality::create_participant(&quota, binding.clone(), signer).unwrap();
    (directory, quota, binding, owner)
}
fn empty(owner: &DurableJointFinality) -> CandidateBlock {
    let state = owner.engine.state.lock().unwrap();
    proposed(state.journal.journal(), &Body::Empty)
}
fn import(owner: &mut DurableJointFinality, block: &CandidateBlock) -> JointCandidate {
    owner
        .import_candidate(block.header().clone(), block.body())
        .unwrap()
}
fn checkpoint(
    owner: &DurableJointFinality,
    d: &JointCandidate,
    round: u64,
    start: usize,
) -> JointCheckpoint {
    JointCheckpoint::new(
        d.clone(),
        round,
        certificate(owner.context().unwrap(), d, round, start),
    )
    .unwrap()
}
fn blob_path(directory: &Path, id: protocol_storage::BlobId) -> PathBuf {
    let hex: String = id.sha256().iter().map(|x| format!("{x:02x}")).collect();
    directory.join(format!("{hex}-{:016x}.blob", id.bytes()))
}

#[test]
fn fixed_durable_rules_and_metadata_last_refuse_foreign_or_missing_signer_installations() {
    let (directory, quota, binding, owner) = install(2);
    assert_ne!(durable_profile_digest(), crate::joint::profile_digest());
    assert!(
        JointBinding::new(
            [0x19; 32],
            binding.rules().clone(),
            binding.work_genesis().clone(),
            binding.journal_genesis().clone(),
            binding.application_descriptor().clone(),
            binding.setup_claim().clone()
        )
        .is_err()
    );
    let old_rules = Rules::multi_slot(
        crate::joint::profile_digest(),
        crate::joint::CANDIDATE_BYTES as u32,
        32,
        [100, 200, 300],
        10,
        MAX_RECORD_BYTES as u64,
    )
    .unwrap();
    assert!(
        JointBinding::for_durable(
            [0x19; 32],
            old_rules.clone(),
            work(&old_rules),
            binding.journal_genesis().clone(),
            binding.application_descriptor().clone(),
            binding.setup_claim().clone()
        )
        .is_err()
    );
    assert_eq!(
        fs::read_dir(directory.root().join("control"))
            .unwrap()
            .count(),
        4
    );
    let signer = keys().remove(0);
    let paths = Paths::participant(
        &quota,
        Pins::Joint(&binding),
        signer.verifying_key().to_bytes(),
    );
    assert!(
        DurableJointFinality::create_participant(&quota, binding.clone(), signer.clone()).is_err()
    );
    assert!(
        DurableJointFinality::open_participant(&quota, binding.clone(), keys().remove(1)).is_err()
    );
    assert!(owner.finalized_parent().unwrap().is_none());
    drop(owner);
    drop(quota);
    // Existing marker is checked before any attempt to recreate the signer WAL.
    fs::remove_file(&paths.wal).unwrap();
    let quota =
        ParticipantQuota::open_existing(directory.root(), fixture().descriptor.id(), CAPACITY)
            .unwrap();
    assert!(
        DurableJointFinality::create_participant(&quota, binding.clone(), signer.clone()).is_err()
    );
    assert!(!paths.wal.exists());
    assert!(DurableJointFinality::open_participant(&quota, binding, signer).is_err());
    assert!(!paths.wal.exists());
}

#[test]
fn real_signed_bootstrap_begin_kind_and_alternate_qc_reopen_then_missing_or_corrupt_premise_fail_closed()
 {
    let (directory, quota, binding, mut owner) = install(8);
    let f = fixture();
    let app = Application::new(f.descriptor.clone(), binding.journal_genesis()).unwrap();
    let ingress = owner.evidence_ingress().unwrap();
    let (boot, enrollment) = {
        let state = owner.engine.state.lock().unwrap();
        let journal = state.journal.journal();
        let e = lifecycle::statement::Expected::bootstrap(
            &f.source,
            app.genesis(),
            journal.genesis_head().block,
            [0; 32],
        )
        .unwrap();
        let enrollment = source::statement::encode_digest(source::commitment::digest(
            &lifecycle::circuit::commitment::enrollment_fields(&e, &f.witness),
        ));
        let (body, _) = proof_body(f, &app, journal, &ingress, true, enrollment, [0; 32]);
        (body, enrollment)
    };
    let block = {
        let state = owner.engine.state.lock().unwrap();
        proposed(state.journal.journal(), &boot)
    };
    let boot_d = import(&mut owner, &block);
    let boot_qc = checkpoint(&owner, &boot_d, 0, 0);
    assert!(
        owner.finalized_parent().unwrap().is_none(),
        "a stored genuine proof is not a quorum"
    );
    owner.receive_checkpoint(&boot_qc).unwrap();
    let first = owner.finalized_parent().unwrap().unwrap();
    let Control::Active { registry, .. } = first.control() else {
        panic!("genuine bootstrap must activate")
    };
    let begin = {
        let state = owner.engine.state.lock().unwrap();
        let (body, _) = proof_body(
            f,
            &app,
            state.journal.journal(),
            &ingress,
            false,
            enrollment,
            registry,
        );
        body
    };
    let begin_block = {
        let state = owner.engine.state.lock().unwrap();
        proposed(state.journal.journal(), &begin)
    };
    let d = import(&mut owner, &begin_block);
    let previous = owner.context().unwrap().clone();
    let qc = checkpoint(&owner, &d, 0, 0);
    let mut damaged = qc.certificate().to_vec();
    let at = damaged.len() - 1;
    damaged[at] ^= 1;
    assert!(
        owner
            .receive_checkpoint(&JointCheckpoint::new(d.clone(), 0, damaged).unwrap())
            .is_err()
    );
    assert_eq!(
        owner.finalized_parent().unwrap().unwrap().head(),
        first.head()
    );
    assert_eq!(owner.context().unwrap(), &previous);
    // An honestly signed changed q cannot reuse the genuine Source/Life/Kind.
    let Body::Transition(ref honest) = begin else {
        unreachable!()
    };
    let mut changed = honest.clone();
    let outer = registry200_joint::Request::decode(&changed.request).unwrap();
    let mut inner = outer.inner().clone();
    inner.nonce[31] ^= 1;
    inner.query = registry200_journal::intent_query(
        app.source_spec(),
        app.genesis(),
        inner.parent,
        inner.nonce,
        inner.enrollment,
        inner.operation,
    );
    changed.request =
        registry200_joint::Request::new(&app, registry200_joint::Lane::Control, inner)
            .unwrap()
            .encode()
            .unwrap();
    changed.sign(app.genesis(), &SigningKey::from_bytes(&[0x64; 32]));
    let changed = {
        let state = owner.engine.state.lock().unwrap();
        let journal = state.journal.journal();
        let body = Body::Transition(changed);
        // The honest Begin is already retained but not finalized. This is a
        // competing child of the certified Bootstrap, not a child of Begin.
        let mut header = journal
            .candidate(honest.parent, &body, begin_block.header().timestamp)
            .unwrap();
        header.mine(1).unwrap();
        CandidateBlock::new(header, body.encode(journal.profile()).unwrap()).unwrap()
    };
    assert!(
        owner
            .import_candidate(changed.header().clone(), changed.body())
            .is_err()
    );
    assert_eq!(owner.context().unwrap(), &previous);

    // Preparing a genuine decision does not install it. Dropping the private
    // handoff releases only its exclusive State borrow, with no durable effect.
    let decision = previous
        .verify_commit(&d.encode(), qc.round(), qc.certificate())
        .unwrap();
    let used_before_handoff = quota.usage().unwrap().total_bytes();
    let handoff_paths = Paths::participant(
        &quota,
        Pins::Joint(&binding),
        keys().remove(0).verifying_key().to_bytes(),
    );
    let file_bytes = || {
        [
            &handoff_paths.journal,
            &handoff_paths.floor,
            &handoff_paths.wal,
        ]
        .map(|path| fs::metadata(path).unwrap().len())
    };
    let files_before_handoff = file_bytes();
    let wal_bytes = owner.engine.voter.file_bytes();
    let outbound = owner.outbound().unwrap();
    {
        let mut state = owner.engine.state.lock().unwrap();
        let history_len = state.history.len();
        let journal_bytes = state.journal.disk_bytes();
        {
            let _prepared = state.preflight(&decision).unwrap();
        }
        assert_eq!(state.current, previous);
        assert_eq!(state.journal.journal().ancestry_floor(), first.head());
        assert_eq!(state.finalized.as_ref().unwrap().head(), first.head());
        assert_eq!(state.finalized.as_ref().unwrap().control(), first.control());
        assert_eq!(state.history.len(), history_len);
        assert_eq!(state.journal.disk_bytes(), journal_bytes);
    }
    assert_eq!(file_bytes(), files_before_handoff);
    assert_eq!(owner.engine.voter.file_bytes(), wal_bytes);
    assert_eq!(owner.outbound().unwrap(), outbound);
    assert_eq!(quota.usage().unwrap().total_bytes(), used_before_handoff);
    assert_eq!(
        owner.checkpoint_after(0).unwrap().unwrap().encode(),
        boot_qc.encode()
    );
    assert!(owner.checkpoint_after(1).unwrap().is_none());

    // An actual Source/Life/Kind result cannot finalize a mismatching context.
    // The frame is local; no voter/floor mutation occurs on this rejected take.
    {
        let handoff = owner.engine.state.lock().unwrap().handoff.clone();
        let capture = handoff.begin(previous.id()).unwrap();
        ClosedApplication(owner.engine.state.clone())
            .check(&previous, &d.encode())
            .unwrap();
        let mut checked = capture.take().unwrap();
        checked.application.context[0] ^= 1;
        let mut state = owner.engine.state.lock().unwrap();
        assert!(matches!(
            state.preflight_checked(&decision, checked),
            Err(Error::Context)
        ));
        assert_eq!(state.current, previous);
        assert_eq!(state.journal.journal().ancestry_floor(), first.head());
        assert_eq!(state.finalized.as_ref().unwrap().head(), first.head());
        assert!(
            matches!(capture.take(), Err(Error::Context)),
            "the actual result was consumed even on rejection"
        );
    }
    assert_eq!(file_bytes(), files_before_handoff);
    assert_eq!(owner.engine.voter.file_bytes(), wal_bytes);
    assert_eq!(owner.outbound().unwrap(), outbound);
    assert_eq!(quota.usage().unwrap().total_bytes(), used_before_handoff);

    let before_decision_checks = owner
        .engine
        .state
        .lock()
        .unwrap()
        .completed_application_checks
        .load(std::sync::atomic::Ordering::SeqCst);
    owner.receive_checkpoint(&qc).unwrap();
    assert_eq!(
        owner
            .engine
            .state
            .lock()
            .unwrap()
            .completed_application_checks
            .load(std::sync::atomic::Ordering::SeqCst),
        before_decision_checks + 1,
        "The genuine deciding check supplies this drive's exact floor result; floor and advance do not repeat its math"
    );
    let final_parent = owner.finalized_parent().unwrap().unwrap();
    let next = owner.context().unwrap().clone();
    assert_ne!(first.control(), final_parent.control());
    let before = quota.usage().unwrap().total_bytes();
    let alternate = JointCheckpoint::new(d.clone(), 7, certificate(&previous, &d, 7, 1)).unwrap();
    let before_retry_checks = owner
        .engine
        .state
        .lock()
        .unwrap()
        .completed_application_checks
        .load(std::sync::atomic::Ordering::SeqCst);
    assert!(owner.receive_checkpoint(&alternate).unwrap().is_empty());
    assert_eq!(
        owner
            .engine
            .state
            .lock()
            .unwrap()
            .completed_application_checks
            .load(std::sync::atomic::Ordering::SeqCst),
        before_retry_checks + 1,
        "A later genuine alternate-QC retry still freshly verifies all actual premises"
    );
    assert_eq!(owner.context().unwrap(), &next);
    assert_eq!(
        owner.finalized_parent().unwrap().unwrap().decision_id(),
        final_parent.decision_id()
    );
    assert_eq!(
        quota.usage().unwrap().total_bytes(),
        before,
        "semantic retry adds no floor/WAL record"
    );
    assert_eq!(
        owner.checkpoint_after(0).unwrap().unwrap().encode(),
        boot_qc.encode()
    );
    assert_eq!(
        owner.checkpoint_after(1).unwrap().unwrap().encode(),
        qc.encode()
    );
    assert!(owner.checkpoint_after(2).unwrap().is_none());
    let manifest = Manifest::decode(&honest.proof).unwrap();
    let premise = manifest
        .references()
        .find(|r| r.role() == registry200_joint::ManifestRole::ControlKind)
        .unwrap()
        .blob_id();
    let path = blob_path(&quota.depot_directory(), premise);
    let expected_bytes = fs::read(&path).unwrap();
    let paths = Paths::participant(
        &quota,
        Pins::Joint(&binding),
        keys().remove(0).verifying_key().to_bytes(),
    );
    drop(ingress);
    drop(owner);
    drop(quota);
    let quota =
        ParticipantQuota::open_existing(directory.root(), f.descriptor.id(), CAPACITY).unwrap();
    let fresh =
        DurableJointFinality::open_participant(&quota, binding.clone(), keys().remove(0)).unwrap();
    assert_eq!(fresh.context().unwrap(), &next);
    assert_eq!(
        fresh.finalized_parent().unwrap().unwrap().head(),
        final_parent.head()
    );
    assert_eq!(
        fresh.finalized_parent().unwrap().unwrap().control(),
        final_parent.control()
    );
    assert_eq!(quota.usage().unwrap().total_bytes(), before);
    drop(fresh);
    drop(quota);
    let wal = fs::read(&paths.wal).unwrap();
    let floor = fs::read(&paths.floor).unwrap();
    for corrupt in [false, true] {
        if corrupt {
            let mut bytes = expected_bytes.clone();
            bytes[0] ^= 1;
            fs::write(&path, bytes).unwrap();
        } else {
            fs::remove_file(&path).unwrap();
        }
        let quota = ParticipantQuota::open_existing(directory.root(), f.descriptor.id(), CAPACITY);
        if corrupt {
            assert!(
                matches!(quota, Err(protocol_storage::Error::Identity)),
                "whole-root inventory must reject corrupt depot bytes before any signer opens"
            );
        } else {
            let quota = quota.unwrap();
            assert!(
                DurableJointFinality::open_participant(&quota, binding.clone(), keys().remove(0))
                    .is_err(),
                "a valid QC cannot replace a missing computation premise"
            );
            drop(quota);
        }
        assert_eq!(fs::read(&paths.wal).unwrap(), wal);
        assert_eq!(fs::read(&paths.floor).unwrap(), floor);
        fs::write(&path, &expected_bytes).unwrap();
    }
}

#[test]
fn floor_ack_loss_and_post_floor_advance_refusal_recover_but_torn_floor_never_repairs() {
    for fault in [
        crate::store::Fault::AfterSync,
        crate::store::Fault::Partial(9),
    ] {
        let (directory, quota, binding, mut owner) = install(2);
        let block = empty(&owner);
        let d = import(&mut owner, &block);
        let qc = checkpoint(&owner, &d, 0, 0);
        let paths = Paths::participant(
            &quota,
            Pins::Joint(&binding),
            keys().remove(0).verifying_key().to_bytes(),
        );
        owner.engine.floor.inject(fault);
        assert!(matches!(
            owner.receive_checkpoint(&qc),
            Err(Error::Durable(crate::Error::Io(_)))
        ));
        assert!(owner.finalized_parent().is_err());
        assert!(owner.outbound().is_err());
        assert!(quota.control_budget().reserve(1).is_err());
        assert!(quota.depot_budget().reserve(1).is_err());
        assert!(quota.custody_budget().reserve(1).is_err());
        drop(owner);
        drop(quota);
        let exact = fs::read(&paths.floor).unwrap();
        let quota =
            ParticipantQuota::open_existing(directory.root(), fixture().descriptor.id(), CAPACITY)
                .unwrap();
        let result = DurableJointFinality::open_participant(&quota, binding, keys().remove(0));
        match fault {
            crate::store::Fault::AfterSync => {
                let reopened = result.unwrap();
                assert_eq!(reopened.context().unwrap().slot(), 2);
                assert_eq!(
                    reopened.finalized_parent().unwrap().unwrap().head().block,
                    d.header().id()
                );
                assert!(reopened.outbound().unwrap().is_empty());
            }
            crate::store::Fault::Partial(_) => assert!(matches!(
                result,
                Err(Error::Durable(crate::Error::CorruptFloor))
            )),
        }
        assert_eq!(fs::read(&paths.floor).unwrap(), exact);
    }
    let (directory, quota, binding, mut owner) = install(2);
    let block = empty(&owner);
    let d = import(&mut owner, &block);
    let qc = checkpoint(&owner, &d, 0, 0);
    let paths = Paths::participant(
        &quota,
        Pins::Joint(&binding),
        keys().remove(0).verifying_key().to_bytes(),
    );
    owner.engine.poison_before_advance = true;
    assert!(matches!(
        owner.receive_checkpoint(&qc),
        Err(Error::Consensus(work_finality::consensus::Error::Poisoned))
    ));
    assert!(owner.finalized_parent().is_err());
    assert!(owner.outbound().is_err());
    assert!(quota.control_budget().reserve(1).is_err());
    assert!(quota.depot_budget().reserve(1).is_err());
    drop(owner);
    drop(quota);
    let wal = fs::read(&paths.wal).unwrap();
    let floor = fs::read(&paths.floor).unwrap();
    let quota =
        ParticipantQuota::open_existing(directory.root(), fixture().descriptor.id(), CAPACITY)
            .unwrap();
    let reopened =
        DurableJointFinality::open_participant(&quota, binding, keys().remove(0)).unwrap();
    assert_eq!(reopened.context().unwrap().slot(), 2);
    assert_eq!(
        reopened.finalized_parent().unwrap().unwrap().head().block,
        d.header().id()
    );
    assert!(reopened.outbound().unwrap().is_empty());
    drop(reopened); // Release exclusive floor/WAL ownership before reading the actual files.
    assert!(fs::metadata(&paths.wal).unwrap().len() > wal.len() as u64);
    assert_eq!(fs::read(&paths.floor).unwrap(), floor);
}

#[test]
fn terminal_two_headers_are_both_admissible_and_reopen_retains_last_floor_without_third_slot_actions()
 {
    let (directory, quota, binding, mut owner) = install(2);
    for expected in [1, 2] {
        let block = empty(&owner);
        let d = import(&mut owner, &block);
        let qc = checkpoint(&owner, &d, 0, 0);
        assert_eq!(owner.context().unwrap().slot(), expected);
        owner.receive_checkpoint(&qc).unwrap();
    }
    let final_parent = owner.finalized_parent().unwrap().unwrap();
    let current = owner.context().unwrap().clone();
    assert_eq!(final_parent.slot(), 2);
    assert_eq!(current.slot(), 3);
    assert_eq!(owner.engine.state.lock().unwrap().history.len(), 3);
    let used = quota.usage().unwrap().total_bytes();
    let block = empty(&owner);
    assert!(matches!(
        owner.import_candidate(block.header().clone(), block.body()),
        Err(Error::ResourceLimit)
    ));
    assert!(owner.outbound().is_err());
    assert_eq!(quota.usage().unwrap().total_bytes(), used);
    drop(owner);
    drop(quota);
    let quota =
        ParticipantQuota::open_existing(directory.root(), fixture().descriptor.id(), CAPACITY)
            .unwrap();
    let reopened =
        DurableJointFinality::open_participant(&quota, binding, keys().remove(0)).unwrap();
    assert_eq!(reopened.context().unwrap(), &current);
    assert_eq!(
        reopened.finalized_parent().unwrap().unwrap().head(),
        final_parent.head()
    );
    assert_eq!(
        reopened
            .engine
            .state
            .lock()
            .unwrap()
            .journal
            .journal()
            .header_count(),
        2
    );
    assert_eq!(quota.usage().unwrap().total_bytes(), used);
}

#[test]
fn corrupt_owned_wal_tail_prevents_signer_reopen_and_is_never_truncated() {
    let (directory, quota, binding, owner) = install(2);
    let paths = Paths::participant(
        &quota,
        Pins::Joint(&binding),
        keys().remove(0).verifying_key().to_bytes(),
    );
    drop(owner);
    drop(quota);
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&paths.wal)
        .unwrap();
    file.write_all(&[0xff]).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let original = fs::read(&paths.wal).unwrap();
    let quota =
        ParticipantQuota::open_existing(directory.root(), fixture().descriptor.id(), CAPACITY)
            .unwrap();
    assert!(matches!(
        DurableJointFinality::open_participant(&quota, binding, keys().remove(0)),
        Err(Error::Consensus(
            work_finality::consensus::Error::CorruptWal
        ))
    ));
    assert_eq!(fs::read(&paths.wal).unwrap(), original);
}

#[test]
fn fresh_append_quota_refusal_publishes_nothing_and_retry_commits_exact_record() {
    let (directory, quota, binding, mut owner) = install(2);
    let block = empty(&owner);
    let before = {
        let state = owner.engine.state.lock().unwrap();
        (
            state.journal.disk_bytes(),
            state.charge.bytes().unwrap(),
            state.journal.journal().best_validated(),
            state.journal.journal().accounted_bytes(),
        )
    };
    let context = owner.context().unwrap().clone();
    let budget = quota.control_budget();
    let reservation = budget
        .reserve(protocol_storage::MAX_SHARED_BYTES - budget.used().unwrap())
        .unwrap();
    assert!(matches!(
        owner.import_candidate(block.header().clone(), block.body()),
        Err(Error::Durable(crate::Error::Storage(
            protocol_storage::Error::ResourceLimit
        )))
    ));
    assert!(
        !owner.engine.poisoned,
        "a refused precharge is not uncertain I/O"
    );
    assert_eq!(owner.context().unwrap(), &context);
    {
        let state = owner.engine.state.lock().unwrap();
        assert_eq!(
            (
                state.journal.disk_bytes(),
                state.charge.bytes().unwrap(),
                state.journal.journal().best_validated(),
                state.journal.journal().accounted_bytes()
            ),
            before
        );
        assert!(state.journal.journal().body(block.header().id()).is_none());
    }
    drop(reservation);
    drop(budget);
    let d = import(&mut owner, &block);
    let expected_disk =
        before.0 + (4 + version_journal::HEADER_BYTES + 32 + block.body().len()) as u64;
    {
        let state = owner.engine.state.lock().unwrap();
        assert_eq!(state.journal.disk_bytes(), expected_disk);
        assert_eq!(state.charge.bytes().unwrap(), expected_disk);
    }
    let usage = quota.usage().unwrap();
    assert_eq!(import(&mut owner, &block), d);
    assert_eq!(quota.usage().unwrap(), usage);
    let qc = checkpoint(&owner, &d, 0, 0);
    owner.receive_checkpoint(&qc).unwrap();
    let finalized = owner.finalized_parent().unwrap().unwrap();
    drop(owner);
    drop(quota);
    let quota =
        ParticipantQuota::open_existing(directory.root(), fixture().descriptor.id(), CAPACITY)
            .unwrap();
    let reopened =
        DurableJointFinality::open_participant(&quota, binding, keys().remove(0)).unwrap();
    assert_eq!(
        reopened.finalized_parent().unwrap().unwrap().head(),
        finalized.head()
    );
    assert_eq!(reopened.context().unwrap().slot(), 2);
    assert_eq!(
        reopened.engine.state.lock().unwrap().journal.disk_bytes(),
        expected_disk
    );
}

#[test]
fn known_candidate_import_rechecks_genuine_kind_before_any_charge_or_publication() {
    // Slot two elects this actual participant at round zero. Its private
    // durable signer can therefore publish the real nondeciding proposal.
    let (directory, quota, binding, mut owner) = install_with_signer(8, keys().remove(1));
    let f = fixture();
    let app = Application::new(f.descriptor.clone(), binding.journal_genesis()).unwrap();
    let ingress = owner.evidence_ingress().unwrap();
    let (boot, enrollment) = {
        let state = owner.engine.state.lock().unwrap();
        let journal = state.journal.journal();
        let e = lifecycle::statement::Expected::bootstrap(
            &f.source,
            app.genesis(),
            journal.genesis_head().block,
            [0; 32],
        )
        .unwrap();
        let enrollment = source::statement::encode_digest(source::commitment::digest(
            &lifecycle::circuit::commitment::enrollment_fields(&e, &f.witness),
        ));
        let (body, _) = proof_body(f, &app, journal, &ingress, true, enrollment, [0; 32]);
        (proposed(journal, &body), enrollment)
    };
    let d = import(&mut owner, &boot);
    let qc = checkpoint(&owner, &d, 0, 0);
    owner.receive_checkpoint(&qc).unwrap();
    let first = owner.finalized_parent().unwrap().unwrap();
    let Control::Active { registry, .. } = first.control() else {
        panic!("real bootstrap must activate")
    };
    let (block, kind) = {
        let state = owner.engine.state.lock().unwrap();
        let journal = state.journal.journal();
        let (body, kind) = proof_body(f, &app, journal, &ingress, false, enrollment, registry);
        (proposed(journal, &body), kind.unwrap())
    };
    let candidate = import(&mut owner, &block);
    let context = owner.context().unwrap().clone();
    // A successful NONDECIDING drive must not leave verification authority for
    // the next command. The genuine durable signer owns the elected key.
    assert_eq!(
        context.proposer(0).unwrap(),
        keys().remove(1).verifying_key().to_bytes()
    );
    let actions = owner.propose(&candidate).unwrap();
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, Action::Proposal(_)))
    );
    assert!(
        !actions
            .iter()
            .any(|action| matches!(action, Action::Decided(_)))
    );
    assert!(
        owner
            .engine
            .state
            .lock()
            .unwrap()
            .handoff
            .active
            .lock()
            .unwrap()
            .is_none()
    );
    let genuine_qc = checkpoint(&owner, &candidate, 0, 0);
    let snapshot = |owner: &DurableJointFinality| {
        let state = owner.engine.state.lock().unwrap();
        (
            state.journal.disk_bytes(),
            state.charge.bytes().unwrap(),
            state.journal.journal().accounted_bytes(),
            state.journal.journal().best_validated(),
            state.journal.journal().ancestry_floor(),
        )
    };
    let before = snapshot(&owner);
    let used = quota.usage().unwrap();
    assert_eq!(import(&mut owner, &block), candidate);
    assert_eq!(snapshot(&owner), before);
    assert_eq!(quota.usage().unwrap(), used);
    let path = blob_path(&quota.depot_directory(), kind);
    let original = fs::read(&path).unwrap();
    let mut corrupt = original.clone();
    let at = corrupt.len() - 1;
    corrupt[at] ^= 1;
    fs::write(&path, corrupt).unwrap();
    let voter_bytes = owner.engine.voter.file_bytes();
    let outbound = owner.outbound().unwrap();
    assert!(matches!(
        owner.receive_checkpoint(&genuine_qc),
        Err(Error::Consensus(
            work_finality::consensus::Error::ApplicationRejected
        ))
    ));
    assert_eq!(owner.engine.voter.file_bytes(), voter_bytes);
    assert_eq!(owner.outbound().unwrap(), outbound);
    assert!(
        owner
            .engine
            .state
            .lock()
            .unwrap()
            .handoff
            .active
            .lock()
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        owner.import_candidate(block.header().clone(), block.body()),
        Err(Error::Journal(
            version_journal::Error::RejectedComputationProof
        ))
    ));
    assert_eq!(snapshot(&owner), before);
    assert_eq!(owner.context().unwrap(), &context);
    assert_eq!(
        owner.finalized_parent().unwrap().unwrap().head(),
        first.head()
    );
    assert_eq!(quota.usage().unwrap(), used);
    fs::write(&path, original).unwrap();
    drop(ingress);
    drop(owner);
    drop(quota);
    let quota =
        ParticipantQuota::open_existing(directory.root(), f.descriptor.id(), CAPACITY).unwrap();
    let reopened =
        DurableJointFinality::open_participant(&quota, binding, keys().remove(1)).unwrap();
    assert_eq!(reopened.context().unwrap(), &context);
    assert_eq!(
        reopened.finalized_parent().unwrap().unwrap().head(),
        first.head()
    );
    assert_eq!(snapshot(&reopened), before);
}

#[test]
fn drive_frame_is_one_use_and_cleared_on_drop_unwind_or_reentrant_refusal() {
    let channel = DriveHandoff::default();
    {
        let capture = channel.begin([0x31; 32]).unwrap();
        assert!(matches!(channel.begin([0x32; 32]), Err(Error::Poisoned)));
        assert!(
            matches!(capture.take(), Err(Error::Context)),
            "an empty frame is no acceptance"
        );
    }
    assert!(channel.active.lock().unwrap().is_none());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _capture = channel.begin([0x33; 32]).unwrap();
        panic!("PUBLIC test unwind before any application verification");
    }));
    assert!(result.is_err());
    assert!(channel.active.lock().unwrap().is_none());
    let capture = channel.begin([0x34; 32]).unwrap();
    assert!(matches!(capture.take(), Err(Error::Context)));
}
