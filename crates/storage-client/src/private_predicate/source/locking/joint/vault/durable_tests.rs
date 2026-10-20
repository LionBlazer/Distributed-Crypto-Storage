//! PUBLIC NONSECRET inputs: actual proof/QC/file failure and recovery gates.
//! These are local genuine QCs, not a network, current-lock or SQL commit test.
use super::super::durable_wal::Fault;
use super::*;
use crate::private_predicate::source::locking::joint::tests::full_acquire_fixture as fixture;
use bfv_query_core::{Geometry, KeyScope, Owner};
use compact_query::{PlainRow, ReadHeads, RowIds, TableId};
use peer_runtime::RawBundle;
use registry200_finality::joint::JointCandidate;
use work_finality::{QuorumCertificate, SignedVote, Step, VoteContext};

const WRAP: [u8; 32] = [0x91; 32];
const NAMESPACE: [u8; 32] = [0x29; 32];
struct Entry {
    checkpoint: JointCheckpoint,
    block: CandidateBlock,
}
struct Rig {
    owner: SourceOwner,
    bundle: RawBundle,
    heads: ReadHeads,
    object: [u8; 32],
    binding: JointBinding,
    quota: Option<ParticipantQuota>,
    boot: Entry,
    directory: fixture::Directory,
}
impl Rig {
    fn new() -> (Self, control::JointRegistryOpening) {
        let owner = SourceOwner::new([0x21; 16], [0x42; 16], Zeroizing::new([0x63; 32])).unwrap();
        let table = owner
            .seal_partition(
                &TableId::from_bytes([0x19; 32]).unwrap(),
                &[
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
                ],
                RowIds::generate(4).unwrap(),
            )
            .unwrap();
        let heads = table.read_heads();
        let bundle = RawBundle::from_snapshots(table.snapshot(), table.encrypted_index()).unwrap();
        let object = *bundle.target_version().unwrap().object();
        drop(table);
        let loaded = owner
            .load(FetchedSource {
                object,
                bundle: &bundle,
                heads: &heads,
            })
            .unwrap();
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
        let quota = ParticipantQuota::create_new(
            directory.path("vault-owner"),
            NAMESPACE,
            fixture::CAPACITY,
        )
        .unwrap();
        let binding = fixture::binding(&loaded, &setup, &anchor, key.statement(), object, &quota);
        let depot = JointDepot::open(quota.depot_budget()).unwrap();
        let ingress = depot.ingress();
        let mut history = JointHistory::new(binding.clone(), depot).unwrap();
        let genesis = version_journal::Journal::new(binding.journal_genesis().clone())
            .unwrap()
            .genesis_head();
        let mut state = fixture::ControlState::empty();
        // Real Source/Life bootstrap is an explicit prerequisite. This helper
        // is NOT a public RegistryBootstrap producer or a WorkGenesis shortcut.
        let block = fixture::control_block(
            &owner, &loaded, &binding, genesis, &mut state, &ingress, true,
        );
        let checkpoint = qc(&binding, &history, &block);
        history.apply(&checkpoint, &block).unwrap();
        let p = parent(&history, &binding).unwrap();
        let opening = control::JointRegistryOpening::from_private_parts(
            &p,
            state.registry,
            fixture::CONTROLLERS,
            [fixture::ENROLL_SALT, state.salt],
        )
        .unwrap();
        drop(history);
        drop(ingress);
        drop(loaded);
        drop(epoch);
        drop(handle);
        drop(bfv);
        (
            Self {
                directory,
                owner,
                bundle,
                heads,
                object,
                binding,
                quota: Some(quota),
                boot: Entry { checkpoint, block },
            },
            opening,
        )
    }
    fn quota(&self) -> &ParticipantQuota {
        self.quota.as_ref().unwrap()
    }
    fn pins(&self) -> OwnerVaultPins {
        OwnerVaultPins::new(
            self.binding.clone(),
            OwnerVaultIdentity::new([0x81; 32]).unwrap(),
        )
    }
    fn fetched(&self) -> FetchedSource<'_> {
        FetchedSource {
            object: self.object,
            bundle: &self.bundle,
            heads: &self.heads,
        }
    }
    fn replay(&self) -> [OwnerVaultReplay<'_>; 1] {
        [OwnerVaultReplay {
            checkpoint: &self.boot.checkpoint,
            block: &self.boot.block,
        }]
    }
    fn create(&self, opening: control::JointRegistryOpening) -> OwnerVault {
        OwnerVault::create_new(
            self.quota(),
            self.pins(),
            authority(),
            &self.owner,
            self.fetched(),
            &self.replay(),
            opening,
        )
        .unwrap()
    }
    fn open(&self) -> VaultResult<OwnerVault> {
        OwnerVault::open_existing(
            self.quota(),
            self.pins(),
            authority(),
            &self.owner,
            self.fetched(),
            &self.replay(),
        )
    }
    fn fresh_quota(&mut self) {
        drop(self.quota.take());
        self.quota = Some(
            ParticipantQuota::open_existing(
                self.directory.path("vault-owner"),
                NAMESPACE,
                fixture::CAPACITY,
            )
            .unwrap(),
        );
    }
}
fn authority() -> OwnerVaultAuthority {
    OwnerVaultAuthority::new(Zeroizing::new(WRAP))
}
fn qc(binding: &JointBinding, history: &JointHistory, block: &CandidateBlock) -> JointCheckpoint {
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
fn draft_block(
    rig: &Rig,
    vault: &mut OwnerVault,
    intent: control::JointControlIntent,
) -> CandidateBlock {
    let cursor = vault.cursor().unwrap();
    let draft = vault
        .prepare_control(cursor, &rig.owner, rig.fetched(), intent)
        .unwrap();
    fixture::transition(
        &rig.binding,
        draft.parent().head(),
        draft.request().unwrap(),
        draft.manifest().unwrap(),
        draft.parent().control(),
    )
}
fn begin(rig: &Rig, vault: &mut OwnerVault) -> (OwnerVaultCursor, Entry) {
    let block = draft_block(
        rig,
        vault,
        control::JointControlIntent::begin(1, 1, [0x31; 32]).unwrap(),
    );
    let checkpoint = qc(&rig.binding, &vault.history, &block);
    let copy = CandidateBlock::decode(&block.encode()).unwrap();
    let cursor = vault.seal_body(vault.cursor().unwrap(), block).unwrap();
    (
        cursor,
        Entry {
            checkpoint,
            block: copy,
        },
    )
}

#[test]
fn durable_begin_end_reopen_exact_retry_and_generation_cas_keep_the_real_private_bank() {
    let (mut rig, opening) = Rig::new();
    let mut vault = rig.create(opening);
    let idle = vault.cursor().unwrap();
    let (pending, entry) = begin(&rig, &mut vault);
    let submitted = vault.submission(pending).unwrap();
    assert_eq!(submitted.header(), entry.block.header());
    assert_eq!(submitted.body(), entry.block.body());
    assert_eq!(submitted.cursor(), pending);
    assert!(matches!(vault.submission(idle), Err(OwnerVaultError::Cas)));
    // Both same-ledger opens and independent quota opens must be excluded.
    assert!(
        matches!(rig.open(),Err(OwnerVaultError::Io(ref e)) if e.kind()==std::io::ErrorKind::WouldBlock)
    );
    assert!(
        ParticipantQuota::open_existing(
            rig.directory.path("vault-owner"),
            NAMESPACE,
            fixture::CAPACITY
        )
        .is_err()
    );
    drop(vault);
    rig.fresh_quota();
    // The independently known target is already finalized. This exact target
    // is allowed and fully replayed; the saved predecessor remains available
    // for original private completion rather than a forged deserialized parent.
    let replay = [
        OwnerVaultReplay {
            checkpoint: &rig.boot.checkpoint,
            block: &rig.boot.block,
        },
        OwnerVaultReplay {
            checkpoint: &entry.checkpoint,
            block: &entry.block,
        },
    ];
    let mut vault = OwnerVault::open_existing(
        rig.quota(),
        rig.pins(),
        authority(),
        &rig.owner,
        rig.fetched(),
        &replay,
    )
    .unwrap();
    assert_eq!(vault.phase().unwrap(), OwnerVaultPhase::SubmittedUnknown);
    assert_eq!(vault.cursor().unwrap(), pending);
    assert_eq!(
        vault.submission(pending).unwrap().body(),
        entry.block.body()
    );
    let budget = rig.quota().control_budget();
    let slots: Vec<_> = (0..protocol_storage::MAX_TRACKED_FILES - 1)
        .map(|_| budget.reserve(0).unwrap())
        .collect();
    assert!(matches!(
        budget.reserve(0),
        Err(protocol_storage::Error::ResourceLimit)
    ));
    // Phase/CAS and genuine completion use the EXISTING terminal lease. They
    // must not require one extra zero-byte slot after all slots are occupied.
    assert_eq!(vault.cursor().unwrap(), pending);
    assert_eq!(vault.phase().unwrap(), OwnerVaultPhase::SubmittedUnknown);
    let completion = vault
        .complete_control(pending, &rig.owner, rig.fetched(), &entry.checkpoint)
        .unwrap();
    drop(slots);
    drop(budget);
    assert_eq!(completion.outcome(), control::JointControlOutcome::Begun);
    assert_eq!(completion.cursor().generation(), 1);
    assert!(matches!(
        vault.acknowledge(pending),
        Err(OwnerVaultError::Cas)
    ));
    drop(vault);
    rig.fresh_quota();
    let mut vault = rig.open().unwrap();
    let completed = vault.recovered_completion().unwrap().unwrap();
    assert_eq!(completed.outcome(), control::JointControlOutcome::Begun);
    vault.acknowledge(completed.cursor()).unwrap();
    let end = draft_block(
        &rig,
        &mut vault,
        control::JointControlIntent::end(1, 1, control::JointEndDisposition::Close, [0x32; 32])
            .unwrap(),
    );
    let end_qc = qc(&rig.binding, &vault.history, &end);
    let pending_end = vault.seal_body(vault.cursor().unwrap(), end).unwrap();
    let completed = vault
        .complete_control(pending_end, &rig.owner, rig.fetched(), &end_qc)
        .unwrap();
    assert_eq!(
        completed.outcome(),
        control::JointControlOutcome::ClosedRegistry
    );
    assert_eq!(completed.cursor().generation(), 2);
    drop(vault);
    rig.fresh_quota();
    let mut vault = rig.open().unwrap();
    let completed = vault.recovered_completion().unwrap().unwrap();
    assert_eq!(
        completed.outcome(),
        control::JointControlOutcome::ClosedRegistry
    );
    vault.acknowledge(completed.cursor()).unwrap();
    let cursor = vault.cursor().unwrap();
    assert!(
        matches!(vault.prepare_control(cursor,&rig.owner,rig.fetched(),control::JointControlIntent::end(1,1,control::JointEndDisposition::Close,[0x33;32]).unwrap()),Err(OwnerVaultError::Owner(crate::Error::InvalidInput(ref message))) if message=="End transaction is absent")
    );
    assert_eq!(vault.cursor().unwrap(), cursor);
    drop(vault);
}

#[test]
fn lost_body_and_completion_sync_acknowledgements_reopen_the_exact_durable_phase() {
    let (mut rig, opening) = Rig::new();
    let mut vault = rig.create(opening);
    let block = draft_block(
        &rig,
        &mut vault,
        control::JointControlIntent::begin(1, 1, [0x41; 32]).unwrap(),
    );
    let checkpoint = qc(&rig.binding, &vault.history, &block);
    let original = block.encode();
    let old_used = rig.quota().usage().unwrap().total_bytes();
    vault.wal.fault = Some(Fault::AfterSync);
    assert!(matches!(
        vault.seal_body(vault.cursor().unwrap(), block),
        Err(OwnerVaultError::Io(_))
    ));
    assert!(vault.cursor().is_err());
    assert!(rig.quota().usage().unwrap().total_bytes() >= old_used);
    assert!(matches!(
        rig.quota().control_budget().reserve(1),
        Err(protocol_storage::Error::Poisoned)
    ));
    drop(vault);
    rig.fresh_quota();
    let mut vault = rig.open().unwrap();
    let pending = vault.cursor().unwrap();
    assert_eq!(vault.phase().unwrap(), OwnerVaultPhase::SubmittedUnknown);
    assert_eq!(vault.saved.block.as_ref().unwrap().encode(), original);
    vault.wal.fault = Some(Fault::AfterSync);
    assert!(matches!(
        vault.complete_control(pending, &rig.owner, rig.fetched(), &checkpoint),
        Err(OwnerVaultError::Io(_))
    ));
    assert!(vault.recovered_completion().is_err());
    assert!(matches!(
        rig.quota().control_budget().reserve(1),
        Err(protocol_storage::Error::Poisoned)
    ));
    drop(vault);
    rig.fresh_quota();
    let mut vault = rig.open().unwrap();
    assert_eq!(vault.phase().unwrap(), OwnerVaultPhase::Completed);
    let completed = vault.recovered_completion().unwrap().unwrap();
    assert_eq!(completed.outcome(), control::JointControlOutcome::Begun);
    assert_eq!(completed.cursor().generation(), 1);
    assert_eq!(vault.saved.block.as_ref().unwrap().encode(), original);
    // A pre-write acknowledgement failure is also terminal for that handle;
    // strict reopen observes the prior completed record, without truncation.
    vault.wal.fault = Some(Fault::BeforeWrite);
    assert!(matches!(
        vault.acknowledge(completed.cursor()),
        Err(OwnerVaultError::Io(_))
    ));
    assert!(vault.cursor().is_err());
    drop(vault);
    rig.fresh_quota();
    let vault = rig.open().unwrap();
    assert_eq!(
        vault.recovered_completion().unwrap().unwrap().outcome(),
        control::JointControlOutcome::Begun
    );
    drop(vault);
}

#[test]
fn pending_reopen_reacquires_terminal_capacity_and_torn_completion_never_repairs_or_returns_a_bank()
{
    let (mut rig, opening) = Rig::new();
    let mut vault = rig.create(opening);
    let (pending, entry) = begin(&rig, &mut vault);
    drop(vault);
    let used = rig.quota().control_budget().used().unwrap();
    let held = rig
        .quota()
        .control_budget()
        .reserve(protocol_storage::MAX_SHARED_BYTES - used - 1)
        .unwrap();
    let path = rig
        .quota()
        .control_file(rig.pins().file_id(), ControlFile::Wal);
    let before = std::fs::metadata(&path).unwrap().len();
    assert!(matches!(
        rig.open(),
        Err(OwnerVaultError::Storage(
            protocol_storage::Error::ResourceLimit
        ))
    ));
    assert_eq!(std::fs::metadata(&path).unwrap().len(), before);
    drop(held);
    let mut vault = rig.open().unwrap();
    assert_eq!(vault.cursor().unwrap(), pending);
    assert_eq!(
        vault.terminal.as_ref().unwrap().bytes(),
        OWNER_VAULT_MAX_RECORD_BYTES as u64
    );
    vault.wal.fault = Some(Fault::PartialWrite);
    assert!(matches!(
        vault.complete_control(pending, &rig.owner, rig.fetched(), &entry.checkpoint),
        Err(OwnerVaultError::Io(_))
    ));
    assert!(vault.cursor().is_err());
    drop(vault);
    let torn = std::fs::metadata(&path).unwrap().len();
    assert!(torn > before);
    rig.fresh_quota();
    assert!(rig.open().is_err());
    assert_eq!(std::fs::metadata(&path).unwrap().len(), torn);
}

#[test]
fn valid_aead_with_foreign_bank_and_unsaved_genuine_successor_fail_without_old_state_fallback() {
    let (rig, opening) = Rig::new();
    let mut vault = rig.create(opening);
    let saved = Snapshot {
        phase: OwnerVaultPhase::Idle,
        generation: 0,
        pending: [0; 32],
        stamp: vault.saved.stamp,
        idle: Zeroizing::new(*vault.saved.idle),
        candidate: None,
        block: None,
        checkpoint: None,
        outcome: None,
    };
    let block = draft_block(
        &rig,
        &mut vault,
        control::JointControlIntent::begin(1, 1, [0x51; 32]).unwrap(),
    );
    let checkpoint = qc(&rig.binding, &vault.history, &block);
    drop(vault); // Draft was never BodyPrepared: no successor bank was saved.
    let replay = [
        OwnerVaultReplay {
            checkpoint: &rig.boot.checkpoint,
            block: &rig.boot.block,
        },
        OwnerVaultReplay {
            checkpoint: &checkpoint,
            block: &block,
        },
    ];
    assert!(matches!(
        OwnerVault::open_existing(
            rig.quota(),
            rig.pins(),
            authority(),
            &rig.owner,
            rig.fetched(),
            &replay
        ),
        Err(OwnerVaultError::RecoveryRequired)
    ));
    assert!(matches!(
        OwnerVault::open_existing(
            rig.quota(),
            rig.pins(),
            OwnerVaultAuthority::new(Zeroizing::new([0x92; 32])),
            &rig.owner,
            rig.fetched(),
            &rig.replay()
        ),
        Err(OwnerVaultError::Authentication)
    ));
    // A known wrapping key can seal arbitrary bytes. Authentication must not
    // replace the real Source/Table/all4IDs + Cenroll/Cold opening check.
    let mut false_idle = saved;
    false_idle.idle[8 + 274] ^= 1; // canonical nonzero controller, wrong commitment
    let other = OwnerVaultPins::new(
        rig.binding.clone(),
        OwnerVaultIdentity::new([0x82; 32]).unwrap(),
    );
    let mut wal = Wal::create_new(
        &rig.quota().control_file(other.file_id(), ControlFile::Wal),
        rig.quota().control_budget(),
        &other,
        authority(),
    )
    .unwrap();
    let lease = wal
        .budget
        .reserve(Wal::record_bytes(&false_idle).unwrap())
        .unwrap();
    drop(wal.append(&false_idle, lease).unwrap());
    drop(wal);
    assert!(
        matches!(OwnerVault::open_existing(rig.quota(),other,authority(),&rig.owner,rig.fetched(),&rig.replay()),Err(OwnerVaultError::Owner(crate::Error::InvalidInput(ref message))) if message=="Private Idle differs from real Source/parent roots")
    );
    let healthy = rig.open().unwrap();
    assert_eq!(healthy.phase().unwrap(), OwnerVaultPhase::Idle);
    assert_eq!(healthy.cursor().unwrap().generation(), 0);
    drop(healthy);
}

#[test]
fn candidate_preflight_requires_actual_owner_and_kind_without_publishing_a_wal_or_history_node() {
    let (rig, opening) = Rig::new();
    let mut vault = rig.create(opening);
    let block = draft_block(
        &rig,
        &mut vault,
        control::JointControlIntent::begin(1, 1, [0x61; 32]).unwrap(),
    );
    let cursor = vault.cursor().unwrap();
    let length = vault.wal.length;
    let head = vault.historical_parent().unwrap().head();
    let context = vault.history.context().unwrap().id();
    let version_journal::Body::Transition(mut altered) =
        version_journal::Body::decode(block.body(), &rig.binding.journal_genesis().profile)
            .unwrap()
    else {
        unreachable!()
    };
    altered.owner_signature[0] ^= 1;
    let body = version_journal::Body::Transition(altered)
        .encode(&rig.binding.journal_genesis().profile)
        .unwrap();
    let mut header = block.header().clone();
    header.body_hash = version_journal::hash(&body);
    header.mine(1).unwrap();
    let unsigned = CandidateBlock::new(header, body).unwrap();
    assert!(matches!(
        vault.seal_body(cursor, unsigned),
        Err(OwnerVaultError::Joint(
            registry200_finality::joint::Error::Journal(version_journal::Error::Unauthorized)
        ))
    ));
    assert_eq!(vault.cursor().unwrap(), cursor);
    assert_eq!(vault.wal.length, length);
    let draft = vault.draft.as_ref().unwrap();
    let manifest = draft.public.manifest().unwrap();
    let kind = manifest
        .references()
        .find(|r| r.role() == registry200_joint::ManifestRole::ControlKind)
        .unwrap();
    let mut damaged = vault
        .ingress
        .read_public_blob(kind.blob_id(), kind.byte_cap())
        .unwrap();
    *damaged.last_mut().unwrap() ^= 1;
    let bad_kind = vault.ingress.retain_public_blob(&damaged).unwrap();
    let pair = manifest
        .references()
        .find(|r| r.role() == registry200_joint::ManifestRole::LifecyclePair)
        .unwrap()
        .blob_id();
    let hostile =
        Manifest::control(manifest.next_root(), manifest.result_root(), pair, bad_kind).unwrap();
    let expected = draft
        .candidate
        .expectation(Manifest::decode(&hostile.encode()).unwrap())
        .unwrap();
    let hostile_block = fixture::transition(
        &rig.binding,
        draft.public.parent.head(),
        draft.public.request().unwrap(),
        hostile,
        draft.public.parent.control(),
    );
    assert!(
        vault
            .history
            .check_control_candidate(&hostile_block, &expected)
            .is_err()
    );
    assert_eq!(vault.historical_parent().unwrap().head(), head);
    assert_eq!(vault.history.context().unwrap().id(), context);
    assert_eq!(vault.wal.length, length);
    let checkpoint = qc(&rig.binding, &vault.history, &block);
    let pending = vault.seal_body(cursor, block).unwrap();
    assert!(
        vault
            .complete_control(pending, &rig.owner, rig.fetched(), &rig.boot.checkpoint)
            .is_err()
    );
    assert_eq!(vault.cursor().unwrap(), pending);
    assert_eq!(vault.historical_parent().unwrap().head(), head);
    assert_eq!(vault.history.context().unwrap().id(), context);
    assert_eq!(
        vault
            .complete_control(pending, &rig.owner, rig.fetched(), &checkpoint)
            .unwrap()
            .outcome(),
        control::JointControlOutcome::Begun
    );
    drop(vault);
}
