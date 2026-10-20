//! SOURCE-ONLY owning gates. Real local proofs/QCs and files; no OS consensus,
//! current lease, full v3 output118 result or generic SQL execution claim.
use super::*;
use crate::private_predicate::{
    JointSqlCall, JointSqlClientBinding, JointSqlHost, JointSqlHostPins, JointSqlPreparation,
    JointSqlReply,
};
use work_finality::consensus::Context;

const CLIENT_A: [u8; 32] = [0x10; 32];
const CLIENT_B: [u8; 32] = [0x20; 32];

fn pins(rig: &Rig) -> JointSqlHostPins {
    // Both clients intentionally have the SAME principal. Stable transaction
    // identity is the allocated id, never the compacted index or principal.
    JointSqlHostPins::new(
        rig.binding.clone(),
        OwnerVaultIdentity::new([0x81; 32]).unwrap(),
        [
            JointSqlClientBinding::new(CLIENT_A, 1).unwrap(),
            JointSqlClientBinding::new(CLIENT_B, 1).unwrap(),
        ],
    )
    .unwrap()
}
fn create(rig: &Rig, opening: control::JointRegistryOpening) -> JointSqlHost {
    JointSqlHost::create_new(
        rig.quota(),
        pins(rig),
        authority(),
        &rig.owner,
        rig.fetched(),
        &rig.replay(),
        opening,
    )
    .unwrap()
}
fn open(rig: &Rig) -> VaultResult<JointSqlHost> {
    JointSqlHost::open_existing(
        rig.quota(),
        pins(rig),
        authority(),
        &rig.owner,
        rig.fetched(),
        &rig.replay(),
    )
}
fn call(host: &JointSqlHost, client: [u8; 32], sequence: u64, sql: &str) -> JointSqlCall {
    host.call(&host.client(client).unwrap(), sequence, sql)
        .unwrap()
}
fn checkpoint(rig: &Rig, context: &Context, block: &CandidateBlock) -> JointCheckpoint {
    let candidate =
        JointCandidate::for_context(&rig.binding, context, block.header().clone()).unwrap();
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
    JointCheckpoint::new(
        candidate,
        0,
        QuorumCertificate::assemble(context.set(), &vote, &votes)
            .unwrap()
            .encode()
            .unwrap(),
    )
    .unwrap()
}
fn successor(context: &Context, checkpoint: &JointCheckpoint) -> Context {
    let decision = context
        .verify_commit(
            &checkpoint.candidate().encode(),
            checkpoint.round(),
            checkpoint.certificate(),
        )
        .unwrap();
    context.after_decision(&decision).unwrap()
}
fn initial_context(rig: &Rig) -> Context {
    successor(rig.binding.initial_context(), &rig.boot.checkpoint)
}
fn draft(rig: &Rig, host: &mut JointSqlHost, call: &JointSqlCall) -> CandidateBlock {
    let JointSqlPreparation::ControlDraft(draft) = host
        .prepare_control(call, &rig.owner, rig.fetched())
        .unwrap()
    else {
        panic!("A new supported call must produce its actual Control proofs")
    };
    fixture::transition(
        &rig.binding,
        draft.parent().head(),
        draft.request().unwrap(),
        draft.manifest().unwrap(),
        draft.parent().control(),
    )
}
fn finish(
    rig: &Rig,
    host: &mut JointSqlHost,
    context: &mut Context,
    call: &JointSqlCall,
) -> JointSqlReply {
    let block = draft(rig, host, call);
    let qc = checkpoint(rig, context, &block);
    let pending = host.seal_body(call, host.cursor().unwrap(), block).unwrap();
    let reply = host
        .complete_control(call, pending, &rig.owner, rig.fetched(), &qc)
        .unwrap();
    *context = successor(context, &qc);
    reply
}
fn wal_path(rig: &Rig) -> std::path::PathBuf {
    let paths: Vec<_> = std::fs::read_dir(rig.directory.path("vault-owner").join("control"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "wal"))
        .collect();
    assert_eq!(paths.len(), 1);
    paths[0].clone()
}

#[test]
fn two_clients_keep_stable_transactions_after_end_compaction_and_replay_original_begin() {
    let (mut rig, opening) = Rig::new();
    let mut host = create(&rig, opening);
    let mut context = initial_context(&rig);
    let a = call(&host, CLIENT_A, 1, "BEGIN");
    let first = finish(&rig, &mut host, &mut context, &a);
    let original = first.invocation_id();
    assert_eq!(
        first.control_outcome(),
        Some(control::JointControlOutcome::Begun)
    );
    host.acknowledge(&a, host.cursor().unwrap()).unwrap();
    let b = call(&host, CLIENT_B, 1, "BEGIN");
    assert_eq!(
        finish(&rig, &mut host, &mut context, &b).control_outcome(),
        Some(control::JointControlOutcome::Begun)
    );
    host.acknowledge(&b, host.cursor().unwrap()).unwrap();
    drop(host);
    rig.fresh_quota();
    let mut host = open(&rig).unwrap();
    let before = host.cursor().unwrap();
    assert!(matches!(
        host.prepare_control(&a, &rig.owner, rig.fetched()).unwrap(),
        JointSqlPreparation::HistoricalLast { .. }
    ));
    let recovered = host.take_recovered_reply(&a).unwrap();
    assert_eq!(recovered.invocation_id(), original);
    assert_eq!(recovered.client_id(), CLIENT_A);
    assert_eq!(recovered.call_sequence(), 1);
    assert_eq!(
        recovered.control_outcome(),
        Some(control::JointControlOutcome::Begun)
    );
    assert!(matches!(
        host.take_recovered_reply(&a),
        Err(OwnerVaultError::RecoveryRequired)
    ));
    assert_eq!(host.cursor().unwrap(), before);
    // Same SQL meaning is insufficient: retry identity includes exact bytes.
    let altered = call(&host, CLIENT_A, 1, "BEGIN;");
    assert!(matches!(
        host.prepare_control(&altered, &rig.owner, rig.fetched()),
        Err(OwnerVaultError::Cas)
    ));
    let end_a = call(&host, CLIENT_A, 2, "COMMIT");
    assert_eq!(
        finish(&rig, &mut host, &mut context, &end_a).control_outcome(),
        Some(control::JointControlOutcome::ClosedRegistry)
    );
    host.acknowledge(&end_a, host.cursor().unwrap()).unwrap();
    // Registry slot zero now contains B's original stable id. Ending B must
    // close that original transaction, not reuse A's removed compacted slot.
    let end_b = call(&host, CLIENT_B, 2, "ROLLBACK");
    assert_eq!(
        finish(&rig, &mut host, &mut context, &end_b).control_outcome(),
        Some(control::JointControlOutcome::AbortedRegistry)
    );
    host.acknowledge(&end_b, host.cursor().unwrap()).unwrap();
    assert_eq!(host.cursor().unwrap().generation(), 4);
    drop(host);
    rig.fresh_quota();
    let mut host = open(&rig).unwrap();
    assert_eq!(
        host.take_recovered_reply(&end_b).unwrap().control_outcome(),
        Some(control::JointControlOutcome::AbortedRegistry)
    );
    assert!(matches!(
        host.prepare_control(&a, &rig.owner, rig.fetched()),
        Err(OwnerVaultError::Cas)
    ));
    assert!(matches!(
        host.take_recovered_reply(&a),
        Err(OwnerVaultError::Cas)
    ));
}

#[test]
fn fsynced_body_completion_and_ack_losses_reopen_exact_phase_without_a_new_begin() {
    let (mut rig, opening) = Rig::new();
    let mut host = create(&rig, opening);
    let initial = host.cursor().unwrap();
    let a = call(&host, CLIENT_A, 1, "BEGIN");
    let block = draft(&rig, &mut host, &a);
    let qc = checkpoint(&rig, &initial_context(&rig), &block);
    let exact = block.encode();
    let b = call(&host, CLIENT_B, 1, "BEGIN");
    assert!(matches!(
        host.seal_body(&b, initial, CandidateBlock::decode(&exact).unwrap()),
        Err(OwnerVaultError::Cas)
    ));
    host.inject_fault(Fault::AfterSync);
    assert!(matches!(
        host.seal_body(&a, initial, block),
        Err(OwnerVaultError::Io(_))
    ));
    assert!(host.phase().is_err());
    drop(host);
    rig.fresh_quota();
    let mut host = open(&rig).unwrap();
    let pending = host.cursor().unwrap();
    let invocation = pending.pending_id();
    assert_eq!(host.phase().unwrap(), OwnerVaultPhase::SubmittedUnknown);
    let submitted = host.submission(&a, pending).unwrap();
    assert_eq!(
        CandidateBlock::new(submitted.header().clone(), submitted.body().to_vec())
            .unwrap()
            .encode(),
        exact
    );
    assert!(matches!(
        host.submission(&b, pending),
        Err(OwnerVaultError::Cas)
    ));
    assert!(matches!(
        host.submission(&a, initial),
        Err(OwnerVaultError::Cas)
    ));
    // A genuine QC for Bootstrap is still the wrong operation and cannot update
    // the private map/bank or the WAL generation.
    assert!(
        host.complete_control(&a, pending, &rig.owner, rig.fetched(), &rig.boot.checkpoint)
            .is_err()
    );
    assert_eq!(host.cursor().unwrap(), pending);
    host.inject_fault(Fault::AfterSync);
    assert!(matches!(
        host.complete_control(&a, pending, &rig.owner, rig.fetched(), &qc),
        Err(OwnerVaultError::Io(_))
    ));
    assert!(host.cursor().is_err());
    drop(host);
    rig.fresh_quota();
    let mut host = open(&rig).unwrap();
    assert_eq!(host.phase().unwrap(), OwnerVaultPhase::Completed);
    let reply = host.take_recovered_reply(&a).unwrap();
    assert_eq!(reply.invocation_id(), invocation);
    assert_eq!(
        reply.control_outcome(),
        Some(control::JointControlOutcome::Begun)
    );
    assert_eq!(host.cursor().unwrap().generation(), 1);
    assert!(matches!(
        host.complete_control(&a, pending, &rig.owner, rig.fetched(), &qc),
        Err(OwnerVaultError::Cas)
    ));
    host.inject_fault(Fault::AfterSync);
    assert!(matches!(
        host.acknowledge(&a, host.cursor().unwrap()),
        Err(OwnerVaultError::Io(_))
    ));
    drop(host);
    rig.fresh_quota();
    assert!(matches!(
        JointSqlHost::open_existing(
            rig.quota(),
            pins(&rig),
            OwnerVaultAuthority::new(Zeroizing::new([0xf1; 32])),
            &rig.owner,
            rig.fetched(),
            &rig.replay(),
        ),
        Err(OwnerVaultError::Authentication)
    ));
    let mut host = open(&rig).unwrap();
    assert_eq!(host.phase().unwrap(), OwnerVaultPhase::Idle);
    assert_eq!(host.cursor().unwrap().generation(), 1);
    assert_eq!(
        host.take_recovered_reply(&a).unwrap().invocation_id(),
        invocation
    );
    assert!(matches!(
        host.prepare_control(&a, &rig.owner, rig.fetched()).unwrap(),
        JointSqlPreparation::HistoricalLast { .. }
    ));
}

#[test]
fn prepaid_control_completion_and_ack_need_no_new_slot_and_invalid_calls_do_no_io() {
    let (mut rig, opening) = Rig::new();
    let mut host = create(&rig, opening);
    let before = host.cursor().unwrap();
    let path = wal_path(&rig);
    let extent = std::fs::metadata(&path).unwrap().len();
    let budget = rig.quota().control_budget();
    for sql in [
        "BEGIN READ ONLY",
        "COMMIT AND CHAIN",
        "ROLLBACK AND NO CHAIN",
        "SELECT age FROM records WHERE age = 1",
        "SELECT age FROM records WHERE age = 1 FOR UPDATE",
        "SELECT age FROM records WHERE age = 1 FOR UPDATE NOWAIT",
    ] {
        assert!(host.call(&host.client(CLIENT_A).unwrap(), 1, sql).is_err());
    }
    assert!(host.client([0x99; 32]).is_err());
    assert!(
        host.call(&host.client(CLIENT_A).unwrap(), 0, "BEGIN")
            .is_err()
    );
    let skipped = call(&host, CLIENT_A, 2, "BEGIN");
    assert!(matches!(
        host.prepare_control(&skipped, &rig.owner, rig.fetched()),
        Err(OwnerVaultError::Cas)
    ));
    let a = call(&host, CLIENT_A, 1, "BEGIN");
    let used = budget.used().unwrap();
    let pressure = budget
        .reserve(
            protocol_storage::MAX_SHARED_BYTES - used - 3 * OWNER_VAULT_MAX_RECORD_BYTES as u64 + 1,
        )
        .unwrap();
    let foreign = FetchedSource {
        object: [0; 32],
        bundle: &rig.bundle,
        heads: &rig.heads,
    };
    assert!(matches!(
        host.prepare_control(&a, &rig.owner, foreign),
        Err(OwnerVaultError::Storage(
            protocol_storage::Error::ResourceLimit
        ))
    ));
    assert_eq!(host.cursor().unwrap(), before);
    assert_eq!(std::fs::metadata(&path).unwrap().len(), extent);
    drop(pressure);
    let block = draft(&rig, &mut host, &a);
    let qc = checkpoint(&rig, &initial_context(&rig), &block);
    let pending = host.seal_body(&a, before, block).unwrap();
    let mut held = Vec::new();
    loop {
        match budget.reserve(0) {
            Ok(lease) => held.push(lease),
            Err(protocol_storage::Error::ResourceLimit) => break,
            Err(error) => panic!("Unexpected actual budget failure: {error:?}"),
        }
    }
    assert!(!held.is_empty());
    let reply = host
        .complete_control(&a, pending, &rig.owner, rig.fetched(), &qc)
        .unwrap();
    assert_eq!(
        reply.control_outcome(),
        Some(control::JointControlOutcome::Begun)
    );
    host.acknowledge(&a, host.cursor().unwrap()).unwrap();
    assert_eq!(host.phase().unwrap(), OwnerVaultPhase::Idle);
    drop(held);
    drop(budget);
    drop(host);
    rig.fresh_quota();
    let mut host = open(&rig).unwrap();
    assert_eq!(
        host.take_recovered_reply(&a).unwrap().control_outcome(),
        Some(control::JointControlOutcome::Begun)
    );
}

#[test]
fn missing_genuine_kind_rejects_before_map_completion_and_record_cap_refuses_before_work() {
    let (rig, opening) = Rig::new();
    let mut host = create(&rig, opening);
    let a = call(&host, CLIENT_A, 1, "BEGIN");
    let JointSqlPreparation::ControlDraft(public) =
        host.prepare_control(&a, &rig.owner, rig.fetched()).unwrap()
    else {
        panic!("A new Begin must produce its actual Control proof pair")
    };
    let manifest = public.manifest().unwrap();
    let kind = manifest
        .references()
        .find(|r| r.role() == registry200_joint::ManifestRole::ControlKind)
        .unwrap()
        .blob_id();
    let block = fixture::transition(
        &rig.binding,
        public.parent().head(),
        public.request().unwrap(),
        manifest,
        public.parent().control(),
    );
    let qc = checkpoint(&rig, &initial_context(&rig), &block);
    let pending = host.seal_body(&a, host.cursor().unwrap(), block).unwrap();
    let path = wal_path(&rig);
    let extent = std::fs::metadata(&path).unwrap().len();
    let name = kind
        .sha256()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    std::fs::remove_file(
        rig.quota()
            .depot_directory()
            .join(format!("{name}-{:016x}.blob", kind.bytes())),
    )
    .unwrap();
    assert!(
        host.complete_control(&a, pending, &rig.owner, rig.fetched(), &qc)
            .is_err()
    );
    assert_eq!(std::fs::metadata(&path).unwrap().len(), extent);
    assert!(matches!(
        rig.quota().depot_budget().reserve(1),
        Err(protocol_storage::Error::Poisoned)
    ));
    drop(host);
    // A different isolated namespace keeps the file-cap oracle independent of
    // the deliberately poisoned/missing-premise namespace above.
    let (rig, opening) = Rig::new();
    let mut host = create(&rig, opening);
    host.fill_physical_record_limit().unwrap();
    let a = call(&host, CLIENT_A, 1, "BEGIN");
    let before = host.cursor().unwrap();
    let path = wal_path(&rig);
    let extent = std::fs::metadata(&path).unwrap().len();
    let used = rig.quota().usage().unwrap().total_bytes();
    let foreign = FetchedSource {
        object: [0; 32],
        bundle: &rig.bundle,
        heads: &rig.heads,
    };
    assert!(matches!(
        host.prepare_control(&a, &rig.owner, foreign),
        Err(OwnerVaultError::ResourceLimit)
    ));
    assert_eq!(host.cursor().unwrap(), before);
    assert_eq!(std::fs::metadata(&path).unwrap().len(), extent);
    assert_eq!(rig.quota().usage().unwrap().total_bytes(), used);
    // This intentionally saturated file has authenticated canonical packets but
    // repeated Idle is not a phase history; it is never adopted or reopened.
}

#[test]
fn acquire_compute_prepays_ack_and_reopens_exact_invocation_request_and_original_key33() {
    let (mut rig, opening) = Rig::new_inner(true);
    let mut host = create(&rig, opening);
    let mut context = initial_context(&rig);
    let begin = call(&host, CLIENT_A, 1, "BEGIN");
    assert_eq!(
        finish(&rig, &mut host, &mut context, &begin).control_outcome(),
        Some(control::JointControlOutcome::Begun)
    );
    host.acknowledge(&begin, host.cursor().unwrap()).unwrap();
    let acquire = call(&host, CLIENT_A, 2, SQL);
    let before = host.cursor().unwrap();
    let path = wal_path(&rig);
    let extent = std::fs::metadata(&path).unwrap().len();
    let budget = rig.quota().control_budget();
    let used = budget.used().unwrap();
    let pressure = budget
        .reserve(
            protocol_storage::MAX_SHARED_BYTES - used - 5 * OWNER_VAULT_MAX_RECORD_BYTES as u64 + 1,
        )
        .unwrap();
    assert!(matches!(
        host.prepare_acquire(
            &acquire,
            SQL,
            &rig.owner,
            rig.fetched(),
            &rig.backups.as_ref().unwrap().material()
        ),
        Err(OwnerVaultError::Storage(
            protocol_storage::Error::ResourceLimit
        ))
    ));
    assert_eq!(host.cursor().unwrap(), before);
    assert_eq!(std::fs::metadata(&path).unwrap().len(), extent);
    drop(pressure);
    drop(budget);
    let JointSqlPreparation::AcquireWork(work) = host
        .prepare_acquire(
            &acquire,
            SQL,
            &rig.owner,
            rig.fetched(),
            &rig.backups.as_ref().unwrap().material(),
        )
        .unwrap()
    else {
        panic!("Real uncontended SKIP UPDATE must prepare actual input16")
    };
    let invocation = work.invocation_id();
    let request = work.encrypted_request().to_vec();
    let key = work.provenance().encodings()[0]
        .expected
        .bfv()
        .key()
        .public_values();
    let pending = host.cursor().unwrap();
    assert_eq!(pending.pending_id(), invocation);
    assert_eq!(
        host.phase().unwrap(),
        OwnerVaultPhase::AcquireComputePrepared
    );
    let altered = SQL.replace("(0, 255)", "(1, 255)");
    assert!(
        host.prepare_acquire(
            &acquire,
            &altered,
            &rig.owner,
            rig.fetched(),
            &rig.backups.as_ref().unwrap().material()
        )
        .is_err()
    );
    let wrong = call(&host, CLIENT_B, 1, SQL);
    assert!(matches!(
        host.acquire_work(
            &wrong,
            pending,
            rig.fetched(),
            &rig.backups.as_ref().unwrap().material()
        ),
        Err(OwnerVaultError::Cas)
    ));
    let altered_call = call(&host, CLIENT_A, 2, &altered);
    let compute_extent = std::fs::metadata(&path).unwrap().len();
    let compute_used = rig.quota().usage().unwrap().total_bytes();
    // No catalog exists yet. The metadata-only recovery accessor must not
    // invent one or bypass logical client, exact intent or actual phase CAS.
    assert!(matches!(
        host.acquire_draft(&acquire, pending),
        Err(OwnerVaultError::Phase)
    ));
    assert!(matches!(
        host.acquire_draft(&wrong, pending),
        Err(OwnerVaultError::Cas)
    ));
    assert!(matches!(
        host.acquire_draft(&altered_call, pending),
        Err(OwnerVaultError::Cas)
    ));
    assert!(matches!(
        host.acquire_draft(&acquire, before),
        Err(OwnerVaultError::Cas)
    ));
    assert_eq!(host.cursor().unwrap(), pending);
    assert_eq!(std::fs::metadata(&path).unwrap().len(), compute_extent);
    assert_eq!(rig.quota().usage().unwrap().total_bytes(), compute_used);
    drop(work);
    drop(host);
    rig.fresh_quota();
    assert!(matches!(open(&rig), Err(OwnerVaultError::RecoveryRequired)));
    let mut host = JointSqlHost::open_existing_acquire(
        rig.quota(),
        pins(&rig),
        authority(),
        &rig.owner,
        rig.fetched(),
        &rig.replay(),
        &rig.backups.as_ref().unwrap().material(),
    )
    .unwrap();
    assert_eq!(host.cursor().unwrap(), pending);
    assert!(
        matches!(host.prepare_acquire(&acquire, SQL, &rig.owner, rig.fetched(), &rig.backups.as_ref().unwrap().material()).unwrap(), JointSqlPreparation::ExistingPending(cursor) if cursor==pending)
    );
    let work = host
        .acquire_work(
            &acquire,
            pending,
            rig.fetched(),
            &rig.backups.as_ref().unwrap().material(),
        )
        .unwrap();
    assert_eq!(work.invocation_id(), invocation);
    assert_eq!(work.encrypted_request(), request);
    assert_eq!(
        work.provenance().encodings()[0]
            .expected
            .bfv()
            .key()
            .public_values(),
        key
    );
    assert!(matches!(
        host.acquire_draft(&acquire, pending),
        Err(OwnerVaultError::Phase)
    ));
    // A valid byte identity is not an output118 catalog or an Acquire result.
    let ingress = host.evidence_ingress().unwrap();
    let fake = bfv_product_evidence::CatalogId::from_blob(
        ingress.retain_public_blob(&[0x37; 256]).unwrap(),
    )
    .unwrap();
    assert!(
        host.save_acquire_catalog(
            &acquire,
            pending,
            fake,
            rig.fetched(),
            &rig.backups.as_ref().unwrap().material()
        )
        .is_err()
    );
    assert_eq!(host.cursor().unwrap(), pending);
    assert_eq!(
        host.phase().unwrap(),
        OwnerVaultPhase::AcquireComputePrepared
    );
    assert!(host.take_recovered_reply(&acquire).is_err());
    // Positive catalog-fsynced/pre-Body reopen and full v3 output118/QC/ACK
    // execution are separate pending OS gates. This real input16 test never
    // substitutes a fake positive catalog or a locally chosen answer.
}
