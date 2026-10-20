//! PUBLIC NONSECRET backups, genuine input16/Source/Life/Link and real files.
//! Local QCs in this module are mathematical fixtures, not four-OS agreement.
use super::*;
use crate::private_predicate::{EncryptedSourceState, SourceStateAuthority, SourceStateIdentity};
use bfv_query_core::{
    BfvKeyAnchor, EncryptedOwnerState, OwnerKeyAnchor, OwnerProofEpoch, OwnerStateAuthority,
    OwnerStateIdentity, PublicSetup,
};

pub(super) struct Backups {
    setup: PublicSetup,
    anchor: BfvKeyAnchor,
    key: bfv_key_transform::Statement,
    owner_identity: OwnerStateIdentity,
    owner_authority: OwnerStateAuthority,
    owner_record: EncryptedOwnerState,
    anchor_record: EncryptedOwnerState,
    ready_record: EncryptedOwnerState,
    source_identity: SourceStateIdentity,
    source_authority: SourceStateAuthority,
    source_record: EncryptedSourceState,
    recovery_identity: super::super::super::JointRecoveryIdentity,
    recovery_key: super::super::super::JointRecoveryKey,
}
impl Backups {
    pub(super) fn capture(
        (source, fetched, ckey): (&SourceOwner, FetchedSource<'_>, [u8; 32]),
        owner: &Owner,
        setup: &PublicSetup,
        handle: &OwnerKeyAnchor<'_>,
        epoch: &OwnerProofEpoch<'_>,
        key: &bfv_key_transform::Statement,
    ) -> Self {
        let anchor = handle.public_anchor().clone();
        let owner_identity = OwnerStateIdentity {
            scope: anchor.scope().clone(),
            record_id: [0xb1; 32],
        };
        let owner_authority = OwnerStateAuthority::new(Zeroizing::new([0xb2; 32]));
        let source_identity = SourceStateIdentity::new([0xb3; 32], ckey).unwrap();
        let source_authority = SourceStateAuthority::new(Zeroizing::new([0xb4; 32]));
        Self {
            setup: setup.clone(),
            anchor,
            key: key.clone(),
            owner_record: owner
                .backup_private_state(setup, &owner_identity, &owner_authority)
                .unwrap(),
            anchor_record: handle
                .backup_private_state(setup, &owner_identity, &owner_authority)
                .unwrap(),
            ready_record: epoch
                .backup_ready_state(setup, &owner_identity, &owner_authority)
                .unwrap(),
            source_record: source
                .backup_private_state(&source_identity, fetched, &source_authority)
                .unwrap(),
            owner_identity,
            owner_authority,
            source_identity,
            source_authority,
            recovery_identity: super::super::super::JointRecoveryIdentity::new([0xb5; 32]),
            recovery_key: super::super::super::JointRecoveryKey::new(Zeroizing::new([0xb6; 32])),
        }
    }
    fn material(&self) -> OwnerVaultAcquireMaterial<'_> {
        OwnerVaultAcquireMaterial {
            setup: &self.setup,
            anchor: &self.anchor,
            key: &self.key,
            owner_identity: &self.owner_identity,
            owner_authority: &self.owner_authority,
            owner_record: &self.owner_record,
            anchor_record: &self.anchor_record,
            ready_record: &self.ready_record,
            source_identity: &self.source_identity,
            source_authority: &self.source_authority,
            source_record: &self.source_record,
            recovery_identity: &self.recovery_identity,
            recovery_key: &self.recovery_key,
        }
    }
}
fn begun() -> (Rig, OwnerVault) {
    let (rig, opening) = Rig::new_inner(true);
    let mut vault = rig.create(opening);
    let (pending, entry) = begin(&rig, &mut vault);
    let completion = vault
        .complete_control(pending, &rig.owner, rig.fetched(), &entry.checkpoint)
        .unwrap();
    vault.acknowledge(completion.cursor()).unwrap();
    (rig, vault)
}
const SQL: &str =
    "SELECT age, amount FROM records WHERE age IN (0, 255) LIMIT 1 FOR UPDATE SKIP LOCKED";
fn compute(rig: &Rig, vault: &mut OwnerVault) -> OwnerVaultAcquireWork {
    match vault
        .prepare_acquire(
            vault.cursor().unwrap(),
            rig.fetched(),
            &rig.backups.as_ref().unwrap().material(),
            SQL,
            1,
            1,
        )
        .unwrap()
    {
        OwnerVaultAcquirePreparation::Prepared(work) => *work,
        OwnerVaultAcquirePreparation::NonAdmitted(_) => {
            panic!("An uncontended real Begin actor must prepare")
        }
    }
}
fn open_acquire(rig: &Rig) -> VaultResult<OwnerVault> {
    let backups = rig.backups.as_ref().unwrap();
    let source = SourceOwner::restore_private_state(
        &backups.source_identity,
        rig.fetched(),
        &backups.source_authority,
        &backups.source_record,
    )?;
    OwnerVault::open_existing_acquire(
        rig.quota(),
        rig.pins(),
        authority(),
        &source,
        rig.fetched(),
        &rig.replay(),
        &backups.material(),
    )
}

#[test]
fn compute_restart_keeps_original_invocation_request_key33_and_rejects_wrong_backups_or_catalog() {
    let (mut rig, mut vault) = begun();
    let work = compute(&rig, &mut vault);
    let request = work.encrypted_request().to_vec();
    let original = work.invocation_id();
    let cursor = work.cursor();
    let values = work.provenance().encodings()[0]
        .expected
        .bfv()
        .key()
        .public_values();
    assert_eq!(
        vault.phase().unwrap(),
        OwnerVaultPhase::AcquireComputePrepared
    );
    assert_eq!(cursor.generation(), 1);
    assert!(vault.submission(cursor).is_err());
    drop(work);
    drop(vault);
    rig.fresh_quota();
    // A Control-only opener may never expose a partially restored owner.
    assert!(matches!(rig.open(), Err(OwnerVaultError::RecoveryRequired)));
    let mut vault = open_acquire(&rig).unwrap();
    let work = vault
        .acquire_work(
            vault.cursor().unwrap(),
            rig.fetched(),
            &rig.backups.as_ref().unwrap().material(),
        )
        .unwrap();
    assert_eq!(work.invocation_id(), original);
    assert_eq!(work.encrypted_request(), request);
    assert_eq!(
        work.provenance().encodings()[0]
            .expected
            .bfv()
            .key()
            .public_values(),
        values
    );
    // A valid, bounded stored blob is not a completed catalog or proof receipt.
    let ingress = vault.evidence_ingress().unwrap();
    let fake = ingress.retain_public_blob(&[0x19; 256]).unwrap();
    let id = bfv_product_evidence::CatalogId::from_blob(fake).unwrap();
    let before = vault.cursor().unwrap();
    assert!(
        vault
            .save_acquire_catalog(
                before,
                id,
                rig.fetched(),
                &rig.backups.as_ref().unwrap().material()
            )
            .is_err()
    );
    assert_eq!(vault.cursor().unwrap(), before);
    assert_eq!(
        vault.phase().unwrap(),
        OwnerVaultPhase::AcquireComputePrepared
    );
    assert!(vault.acquire_draft(before).is_err());
    let wrong = super::super::super::JointRecoveryKey::new(Zeroizing::new([0xfe; 32]));
    let mut wrong_material = rig.backups.as_ref().unwrap().material();
    wrong_material.recovery_key = &wrong;
    assert!(
        vault
            .acquire_work(before, rig.fetched(), &wrong_material)
            .is_err()
    );
    assert_eq!(vault.cursor().unwrap(), before);
    // Real last input proof omission cannot be replaced by the preceding success.
    // No unrelated corruption is tested on a ledger poisoned by this deletion.
    drop(work);
    drop(ingress);
    let state = vault.saved.acquire.as_ref().unwrap();
    let missing = state.last_input();
    let name = missing
        .sha256()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    std::fs::remove_file(
        rig.quota()
            .depot_directory()
            .join(format!("{name}-{:016x}.blob", missing.bytes())),
    )
    .unwrap();
    assert!(
        vault
            .acquire_work(
                before,
                rig.fetched(),
                &rig.backups.as_ref().unwrap().material()
            )
            .is_err()
    );
    assert!(matches!(
        rig.quota().depot_budget().reserve(1),
        Err(protocol_storage::Error::Poisoned)
    ));
    drop(vault);
}

#[test]
fn acquire_reserves_terminal_before_compute_and_lost_compute_sync_ack_reopens_strictly() {
    let (mut rig, mut vault) = begun();
    let before = vault.cursor().unwrap();
    let length = vault.wal.length;
    let budget = rig.quota().control_budget();
    let used = budget.used().unwrap();
    let pressure = budget
        .reserve(
            protocol_storage::MAX_SHARED_BYTES - used - 4 * OWNER_VAULT_MAX_RECORD_BYTES as u64 + 1,
        )
        .unwrap();
    assert!(
        vault
            .prepare_acquire(
                before,
                rig.fetched(),
                &rig.backups.as_ref().unwrap().material(),
                SQL,
                1,
                1
            )
            .is_err()
    );
    assert_eq!(vault.cursor().unwrap(), before);
    assert_eq!(vault.wal.length, length);
    drop(pressure);
    drop(budget);
    vault.wal.fault = Some(Fault::AfterSync);
    assert!(
        vault
            .prepare_acquire(
                before,
                rig.fetched(),
                &rig.backups.as_ref().unwrap().material(),
                SQL,
                1,
                1
            )
            .is_err()
    );
    assert!(matches!(vault.cursor(), Err(OwnerVaultError::Poisoned)));
    assert!(matches!(
        rig.quota().control_budget().reserve(1),
        Err(protocol_storage::Error::Poisoned)
    ));
    drop(vault);
    rig.fresh_quota();
    let vault = open_acquire(&rig).unwrap();
    assert_eq!(
        vault.phase().unwrap(),
        OwnerVaultPhase::AcquireComputePrepared
    );
    let saved = vault.cursor().unwrap();
    assert_ne!(saved.pending_id(), [0; 32]);
    let work = vault
        .acquire_work(
            saved,
            rig.fetched(),
            &rig.backups.as_ref().unwrap().material(),
        )
        .unwrap();
    assert_eq!(work.invocation_id(), saved.pending_id());
    drop(work);
    drop(vault);
    // Reservations are reconstructed, not serialized. Refuse the reopen when
    // the complete remaining three-record allowance no longer fits.
    let budget = rig.quota().control_budget();
    let used = budget.used().unwrap();
    let pressure = budget
        .reserve(
            protocol_storage::MAX_SHARED_BYTES - used - 3 * OWNER_VAULT_MAX_RECORD_BYTES as u64 + 1,
        )
        .unwrap();
    assert!(open_acquire(&rig).is_err());
    drop(pressure);
    drop(budget);
}

// The supervisor is test-only and launches a real executable supplied by Root.
// Production owner code has no dependency on app configuration or fixtures.
use crate::private_predicate::source::locking::joint::tests::os_process;

#[test]
#[ignore = "Actual OS FHE input16/output118/END+EOF and durable owner restarts; requires DCS_PEER_EXE; local genuine QC, not four-validator consensus"]
fn os_fhe_catalog_body_and_completed_lost_ack_recover_original_invocation_then_end() {
    use peer_runtime::{Bootstrap, Connector, RemotePeer, Request, Response};
    let exe = std::path::PathBuf::from(
        std::env::var_os("DCS_PEER_EXE").expect("Actual dcs-peer binary required"),
    );
    assert!(exe.is_absolute() && exe.is_file());
    let (mut rig, mut vault) = begun();
    let owner_identity = fixture::identity();
    let config = Bootstrap {
        identity: fixture::identity(),
        authority: vec![],
        owner: owner_identity.fingerprint(),
        node_id: 207,
        quota_bytes: 16 * 1024 * 1024,
        listen: "127.0.0.1:0".parse().unwrap(),
    };
    let process =
        os_process::Process::start_storage(&exe, &rig.directory.path("Acquire-FHE-peer"), &config)
            .unwrap();
    assert_ne!(process.pid(), std::process::id());
    let remote = RemotePeer::new(
        process.endpoint().clone(),
        Connector::permissionless(&owner_identity).unwrap(),
    );
    // Store/fetch actual original sealed images; no owner-selected row answer.
    let copy = rig.bundle.clone();
    assert!(
        matches!(remote.call(Request::Store(copy)).unwrap(),Response::Stored(info) if info.id==rig.object)
    );
    assert!(matches!(
        remote
            .call(Request::InstallSetup(
                rig.backups.as_ref().unwrap().setup.to_bytes().unwrap()
            ))
            .unwrap(),
        Response::Setup(_)
    ));
    let work = compute(&rig, &mut vault);
    let invocation = work.invocation_id();
    let pending = work.cursor();
    let (provenance, request, frames) = work.into_parts();
    let proofs =
        bfv_mul_relin_proof::InputEvidence::from_frames(frames.each_ref().map(Vec::as_slice))
            .unwrap();
    // ONE actual store handle, no second ProductStore or depot lock across RPC.
    let shared = vault.evidence_ingress().unwrap().recording_store();
    let recorded = remote
        .prove_private_product_recorded_shared(
            rig.object,
            provenance,
            &request,
            &proofs,
            shared.clone(),
        )
        .unwrap();
    let (checked, catalog) = recorded.into_parts();
    drop(checked);
    drop(shared);
    drop(frames);
    let draft = vault
        .save_acquire_catalog(
            pending,
            catalog,
            rig.fetched(),
            &rig.backups.as_ref().unwrap().material(),
        )
        .unwrap();
    let block = fixture::transition(
        &rig.binding,
        draft.parent().head(),
        draft.request().unwrap(),
        draft.manifest().unwrap(),
        draft.parent().control(),
    );
    let exact = block.encode();
    let checkpoint = qc(&rig.binding, &vault.history, &block);
    let before = vault.cursor().unwrap();
    // Real fsync succeeds, acknowledgement is lost: no prepared bytes returned.
    vault.wal.fault = Some(Fault::AfterSync);
    assert!(
        vault
            .seal_acquire_body(
                before,
                block,
                rig.fetched(),
                &rig.backups.as_ref().unwrap().material()
            )
            .is_err()
    );
    drop(vault);
    rig.fresh_quota();
    let mut vault = open_acquire(&rig).unwrap();
    assert_eq!(vault.phase().unwrap(), OwnerVaultPhase::SubmittedUnknown);
    let cursor = vault.cursor().unwrap();
    let submitted = vault.submission(cursor).unwrap();
    assert_eq!(
        CandidateBlock::new(submitted.header().clone(), submitted.body().to_vec())
            .unwrap()
            .encode(),
        exact
    );
    assert!(
        vault
            .complete_acquire(
                cursor,
                rig.fetched(),
                &rig.backups.as_ref().unwrap().material(),
                &rig.boot.checkpoint
            )
            .is_err()
    );
    assert_eq!(vault.cursor().unwrap(), cursor);
    // Actual all-math/QC + one original pending decrypt, then lost completion ACK.
    vault.wal.fault = Some(Fault::AfterSync);
    assert!(
        vault
            .complete_acquire(
                cursor,
                rig.fetched(),
                &rig.backups.as_ref().unwrap().material(),
                &checkpoint
            )
            .is_err()
    );
    assert!(vault.cursor().is_err());
    drop(vault);
    rig.fresh_quota();
    let mut vault = open_acquire(&rig).unwrap();
    let completed = vault
        .take_recovered_acquire(vault.cursor().unwrap())
        .unwrap();
    assert_eq!(completed.invocation_id(), invocation);
    assert!(completed.is_recovered_invocation());
    assert_eq!(completed.cursor().generation(), 2);
    assert_eq!(completed.rows().len(), 1);
    assert_eq!(completed.rows()[0].ordinal, 0);
    assert_eq!(completed.rows()[0].age, Some(0));
    assert_eq!(completed.rows()[0].amount, Some(65535));
    assert!(vault.take_recovered_acquire(completed.cursor()).is_err());
    assert!(matches!(
        vault.complete_acquire(
            cursor,
            rig.fetched(),
            &rig.backups.as_ref().unwrap().material(),
            &checkpoint
        ),
        Err(OwnerVaultError::Cas)
    ));
    let acknowledged = vault.acknowledge(completed.cursor()).unwrap();
    drop(completed);
    // The successor bank is the actual acquired bank, not old Idle or a receipt.
    let end = draft_block(
        &rig,
        &mut vault,
        control::JointControlIntent::end(1, 1, control::JointEndDisposition::Close, [0xc3; 32])
            .unwrap(),
    );
    let end_qc = qc(&rig.binding, &vault.history, &end);
    let sealed = vault.seal_body(acknowledged, end).unwrap();
    let completed = vault
        .complete_control(sealed, &rig.owner, rig.fetched(), &end_qc)
        .unwrap();
    assert_eq!(
        completed.outcome(),
        control::JointControlOutcome::ClosedRegistry
    );
    assert_eq!(completed.cursor().generation(), 3);
    drop(vault);
    drop(remote);
    process.finish().unwrap();
}
