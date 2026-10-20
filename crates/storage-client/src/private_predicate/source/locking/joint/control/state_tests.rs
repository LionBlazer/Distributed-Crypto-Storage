//! PUBLIC NONSECRET inputs. Real proofs/QCs below are local, not an OS/Vault durability gate.
use super::super::super::tests::full_acquire_fixture as fixture;
use super::*;
use bfv_query_core::{Geometry, KeyScope, Owner};
use compact_query::{PlainRow, RowIds, TableId};
use peer_runtime::RawBundle;
use protocol_storage::ParticipantQuota;
use registry200_finality::{
    CandidateBlock,
    joint::{JointCandidate, JointCheckpoint, JointHistory},
};
use registry200_joint::{JointDepot, Manifest};
use registry200_proof::lifecycle::circuit::model::{Savepoint, Transaction};
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
        .map(|key| SignedVote::sign(vote, key).unwrap())
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

#[test]
fn fixed_registry_and_command_grammars_preserve_counters_and_reject_aliases() {
    let mut registry = Zeroizing::new(Registry {
        revision: u64::MAX - 1,
        allocator: 2,
        transactions: Vec::new(),
    });
    for id in 1..=2 {
        registry.transactions.push(Transaction {
            id,
            principal: id as u8,
            sequence: u64::MAX - 2,
            failed: false,
            snapshot: [id as u8 + 10; 32],
            held: [1; 4],
            savepoints: vec![
                Savepoint {
                    name: [21; 32],
                    held: [0; 4],
                },
                Savepoint {
                    name: [22; 32],
                    held: [1; 4],
                },
            ],
        });
    }
    registry.require_canonical().unwrap();
    let mut bytes = Zeroizing::new([0; REGISTRY]);
    let mut writer = Writer {
        bytes: bytes.as_mut(),
        at: 0,
    };
    writer.registry(&registry);
    let decoded = Reader {
        bytes: bytes.as_ref(),
        at: 0,
    }
    .registry()
    .unwrap();
    assert_eq!(*decoded, *registry);
    for at in [16, 16 + 18, 16 + 55] {
        let mut bad = Zeroizing::new(*bytes);
        bad[at] = 2;
        assert!(
            Reader {
                bytes: bad.as_ref(),
                at: 0
            }
            .registry()
            .is_err()
        );
    }
    let mut gap = Zeroizing::new(*bytes);
    gap[16..16 + super::super::super::private_state_codec::TRANSACTION].fill(0);
    assert!(
        Reader {
            bytes: gap.as_ref(),
            at: 0
        }
        .registry()
        .is_err()
    );
    let c = Zeroizing::new(Command::control(Operation::End, 2, 2, u64::MAX - 2));
    let mut raw = Zeroizing::new([0; COMMAND_BYTES]);
    command(
        &mut Writer {
            bytes: raw.as_mut(),
            at: 0,
        },
        &c,
    );
    let decoded = read_command(&mut Reader {
        bytes: raw.as_ref(),
        at: 0,
    })
    .unwrap();
    assert_eq!(decoded.operation, c.operation);
    assert_eq!(decoded.transaction, 2);
    assert_eq!(decoded.sequence, u64::MAX - 2);
    assert!(!decoded.abort);
    for (at, value) in [(0, 1), (9, 3), (COMMAND_BYTES - 1, 2), (18, 1)] {
        let mut bad = Zeroizing::new(*raw);
        bad[at] = value;
        assert!(
            read_command(&mut Reader {
                bytes: bad.as_ref(),
                at: 0
            })
            .is_err()
        );
    }
}

#[test]
fn real_begin_end_restore_exact_candidates_and_require_original_source_private_roots_and_qc() {
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
    let key = setup
        .verify_key_transform(&anchor, epoch.key_evidence().unwrap().as_bytes())
        .unwrap();
    let directory = fixture::Directory::new();
    let quota =
        ParticipantQuota::create_new(directory.path("state-owner"), [0x29; 32], fixture::CAPACITY)
            .unwrap();
    let binding = fixture::binding(&loaded, &setup, &anchor, key.statement(), object, &quota);
    let depot = JointDepot::open(quota.depot_budget()).unwrap();
    let ingress = depot.ingress();
    let mut history = JointHistory::new(binding.clone(), depot).unwrap();
    let genesis = version_journal::Journal::new(binding.journal_genesis().clone())
        .unwrap()
        .genesis_head();
    let mut initial = fixture::ControlState::empty();
    let boot = fixture::control_block(
        &owner,
        &loaded,
        &binding,
        genesis,
        &mut initial,
        &ingress,
        true,
    );
    let qc = checkpoint(&binding, &history, &boot);
    history.apply(&qc, &boot).unwrap();
    drop(loaded);
    let initial_parent = parent(&history, &binding);
    let mut opening = JointRegistryOpening::from_private_parts(
        &initial_parent,
        initial.registry,
        fixture::CONTROLLERS,
        [fixture::ENROLL_SALT, initial.salt],
    )
    .unwrap();

    for end in [false, true] {
        let before = parent(&history, &binding);
        require_idle_parent(&opening, &before).unwrap();
        let idle_bytes = encode_idle(&opening).unwrap();
        drop(opening);
        let reopened = restore_idle(idle_bytes.as_ref(), &owner, fetched(), &before).unwrap();
        let intent = if end {
            JointControlIntent::end(1, 1, JointEndDisposition::Abort, [0x32; 32]).unwrap()
        } else {
            JointControlIntent::begin(1, 1, [0x31; 32]).unwrap()
        };
        let prepared = owner
            .prepare_joint_control(fetched(), &before, reopened, intent)
            .unwrap();
        let (request, life, kind, candidate) = prepared.into_parts();
        let pair = ingress.retain_public_blob(life.as_bytes()).unwrap();
        let kind_ref = ingress.retain_public_blob(kind.as_bytes()).unwrap();
        let manifest = Manifest::control(
            ss::encode_digest(life.statement().next),
            ss::encode_digest(life.statement().result),
            pair,
            kind_ref,
        )
        .unwrap();
        let control_bytes = encode_control(&candidate).unwrap();
        let request_bytes = request.encode().unwrap();
        drop(candidate);

        // Each mutation has the healthy original as an independent positive
        // control. No filesystem ledger is poisoned by these pure checks.
        assert!(
            restore_control(
                control_bytes.as_ref(),
                idle_bytes.as_ref(),
                &owner,
                fetched(),
                &before,
                &request,
                &manifest
            )
            .is_ok()
        );
        for at in [8, 96, 160, 168, 327, 328, 602, 729, 730] {
            let mut bad = Zeroizing::new(*control_bytes);
            bad[at] ^= 1;
            assert!(
                restore_control(
                    bad.as_ref(),
                    idle_bytes.as_ref(),
                    &owner,
                    fetched(),
                    &before,
                    &request,
                    &manifest
                )
                .is_err(),
                "control byte {at}"
            );
        }
        let mut alias = Zeroizing::new(*control_bytes);
        alias[96..104].copy_from_slice(&Val::ORDER_U64.to_le_bytes());
        assert!(
            restore_control(
                alias.as_ref(),
                idle_bytes.as_ref(),
                &owner,
                fetched(),
                &before,
                &request,
                &manifest
            )
            .is_err()
        );
        let mut old_salt = Zeroizing::new(*idle_bytes);
        old_salt[IDLE_BYTES - 1] ^= 1;
        assert!(
            restore_control(
                control_bytes.as_ref(),
                old_salt.as_ref(),
                &owner,
                fetched(),
                &before,
                &request,
                &manifest
            )
            .is_err()
        );
        assert!(restore_idle(&idle_bytes[..IDLE_BYTES - 1], &owner, fetched(), &before).is_err());
        assert!(
            restore_control(
                &control_bytes[..CONTROL_BYTES - 1],
                idle_bytes.as_ref(),
                &owner,
                fetched(),
                &before,
                &request,
                &manifest
            )
            .is_err()
        );
        let foreign_owner =
            SourceOwner::new([0x21; 16], [0x42; 16], Zeroizing::new([0x62; 32])).unwrap();
        assert!(
            restore_control(
                control_bytes.as_ref(),
                idle_bytes.as_ref(),
                &foreign_owner,
                fetched(),
                &before,
                &request,
                &manifest
            )
            .is_err()
        );
        let app = JointApplication::new(
            binding.application_descriptor().clone(),
            binding.journal_genesis(),
        )
        .unwrap();
        let mut foreign_intent = request.inner().clone();
        foreign_intent.nonce[31] ^= 1;
        foreign_intent.query = registry200_journal::intent_query(
            app.source_spec(),
            foreign_intent.genesis,
            foreign_intent.parent,
            foreign_intent.nonce,
            foreign_intent.enrollment,
            foreign_intent.operation,
        );
        let foreign_request = JointRequest::new(&app, Lane::Control, foreign_intent).unwrap();
        assert!(
            restore_control(
                control_bytes.as_ref(),
                idle_bytes.as_ref(),
                &owner,
                fetched(),
                &before,
                &foreign_request,
                &manifest
            )
            .is_err()
        );

        let restored = restore_control(
            control_bytes.as_ref(),
            idle_bytes.as_ref(),
            &owner,
            fetched(),
            &before,
            &request,
            &manifest,
        )
        .unwrap();
        assert_eq!(restored.request, request_bytes);
        assert_eq!(*encode_control(&restored).unwrap(), *control_bytes);
        let expected = restored
            .expectation(Manifest::decode(&manifest.encode()).unwrap())
            .unwrap();
        let block = fixture::transition(
            &binding,
            before.head(),
            request,
            manifest,
            before.verified.control(),
        );
        let qc = checkpoint(&binding, &history, &block);
        let operation = history.apply_control(&qc, &block, &expected).unwrap();
        let completed = restored.complete(operation).unwrap();
        assert_eq!(
            completed.outcome(),
            if end {
                JointControlOutcome::AbortedRegistry
            } else {
                JointControlOutcome::Begun
            }
        );
        opening = completed.into_opening();
        assert_eq!(opening.registry.transactions.len(), usize::from(!end));
        let after = parent(&history, &binding);
        require_idle_parent(&opening, &after).unwrap();
        assert!(require_idle_parent(&opening, &before).is_err());
        assert!(
            restore_control(
                control_bytes.as_ref(),
                idle_bytes.as_ref(),
                &owner,
                fetched(),
                &after,
                &JointRequest::decode(&request_bytes).unwrap(),
                &Manifest::decode(&expected.manifest().encode()).unwrap()
            )
            .is_err()
        );
    }
    drop(opening);
    drop(history);
    drop(ingress);
    drop(quota);
    drop(directory);
}
