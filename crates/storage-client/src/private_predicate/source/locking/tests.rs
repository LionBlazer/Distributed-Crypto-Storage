//! PUBLIC NONSECRET keys, controllers, rows and opening salts. Real proofs only.
use super::*;
use crate::private_predicate::{BfvContext, FetchedSource, SourceOwner};
use bfv_query_core::{Geometry, KeyScope, Owner, ProofEpochStage};
use compact_query::{PlainRow, ReadHeads, RowIds, TableId};
use ed25519_dalek::SigningKey;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use peer_runtime::RawBundle;
use registry200_journal::{Operation as JournalOperation, RegistryVerifier, intent_query};
use registry200_proof::{
    admission::{CanonicalSource, Expected as LifeExpected},
    coefficient_encoding::{
        self as encoding,
        circuit::Witness as EncodingWitness,
        statement::{BfvBinding, Expected as EncodingExpected},
    },
    lifecycle::{
        circuit::{
            self as life, commitment as lc,
            model::{Command, Operation},
        },
        statement as ls,
    },
    predicate_acquire as link,
    source::{self, commitment as sc, statement as ss},
};
use std::sync::OnceLock;
use version_journal::{
    AuthorizedTransition, Body, Genesis, Header, ProtocolProfile, ShardUpdate, Target,
};

const DB: [u8; 16] = [0x21; 16];
const DOMAIN: [u8; 16] = [0x42; 16];
const AEAD: [u8; 32] = [0x63; 32];
const CONTROLLERS: [[u8; 32]; 2] = [[0x84; 32], [0xa5; 32]];
const ROWS: [PlainRow; 4] = [
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
fn compile(sql: &str) -> CompiledLockingSelect {
    CompiledLockingSelect::compile(sql, Zeroizing::new([0xc6; 32]), [0xe7; 32], [0xf8; 16]).unwrap()
}

#[test]
fn locking_compiler_preserves_three_valued_truth_and_exact_local_windows() {
    for (strength, mode) in [
        ("KEY SHARE", 1),
        ("SHARE", 2),
        ("NO KEY UPDATE", 3),
        ("UPDATE", 4),
    ] {
        for (suffix, wait) in [("", 0), (" NOWAIT", 1), (" SKIP LOCKED", 2)] {
            let c = compile(&format!(
                "SELECT age, amount FROM records WHERE age IN (0, 255, NULL) LIMIT 4 OFFSET 4 FOR {strength}{suffix}"
            ));
            assert_eq!(
                (c.mode, c.wait, c.offset, c.limit, c.projection),
                (mode, wait, 4, 4, 3)
            );
            for age in 0..256 {
                assert_eq!(
                    (c.mask[age / 8] >> (age % 8)) & 1,
                    u8::from(age == 0 || age == 255)
                );
            }
        }
    }
    for (projection, tag) in [("age", 1), ("amount", 2), ("age, amount", 3)] {
        let c = compile(&format!(
            "SELECT {projection} FROM records WHERE NULL LIMIT 0 FOR UPDATE"
        ));
        assert_eq!((c.projection, c.offset, c.limit), (tag, 0, 0));
        assert_eq!(*c.mask, [0; 32]);
    }
    assert_eq!(compile("SELECT age FROM records FOR SHARE").limit, 4);
    assert_eq!(
        *compile("SELECT age FROM records WHERE NOT (age = 1 OR NULL) FOR UPDATE").mask,
        [0; 32]
    );
}

#[test]
fn locking_compiler_rejects_other_plans_ordering_oversized_windows_and_public_blinds() {
    for sql in [
        "SELECT age, amount FROM records",
        "SELECT amount, age FROM records FOR UPDATE",
        "SELECT COUNT(*) FROM records FOR UPDATE",
        "UPDATE records SET amount = amount + 1",
        "SELECT age FROM records LIMIT 5 FOR UPDATE",
        "SELECT age FROM records OFFSET 5 FOR UPDATE",
        "SELECT age FROM records ORDER BY age FOR UPDATE",
        "SELECT age FROM records, records FOR UPDATE",
    ] {
        assert!(
            CompiledLockingSelect::compile(sql, Zeroizing::new([0xc6; 32]), [0xe7; 32], [0xf8; 16])
                .is_err(),
            "{sql}"
        );
    }
    for blind in [[0; 32], [0xe7; 32]] {
        assert!(
            CompiledLockingSelect::compile(
                "SELECT age FROM records FOR UPDATE",
                Zeroizing::new(blind),
                [0xe7; 32],
                [0xf8; 16]
            )
            .is_err()
        );
    }
    let a = compile("SELECT age FROM records FOR UPDATE");
    let b = compile("SELECT  age FROM records FOR UPDATE");
    assert_ne!(a.identity, b.identity);
    assert_eq!(*a.mask, *b.mask);
}

// One actual signed four-body original-app history: Bootstrap, Begin1, Begin2,
// Acquire2(age=0). No root replacement or accepting verifier is used.
struct History {
    bundle: RawBundle,
    heads: ReadHeads,
    object: [u8; 32],
    key_salt: [u64; 4],
    app: Application,
    genesis: Genesis,
    blocks: Vec<(Header, Vec<u8>)>,
    registry: Registry,
    enrollment_salt: [u64; 4],
    registry_salt: [u64; 4],
    unheld: Registry,
    unheld_salt: [u64; 4],
}
fn history() -> &'static History {
    static HISTORY: OnceLock<History> = OnceLock::new();
    HISTORY.get_or_init(|| {
        let owner = SourceOwner::new(DB, DOMAIN, Zeroizing::new(AEAD)).unwrap();
        let table = owner
            .seal_partition(
                &TableId::from_bytes([0x19; 32]).unwrap(),
                &ROWS,
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
        let app = Application::new([0x3a; 32], 7, 8, &loaded.draft).unwrap();
        let signer = SigningKey::from_bytes(&[0x5b; 32]);
        let genesis = Genesis {
            network_id: app.network,
            database: DB,
            owner: signer.verifying_key().to_bytes(),
            application_commitment: app.id(),
            timestamp: 1,
            profile: ProtocolProfile {
                initial_target: Target([255; 32]),
                pow_limit: Target([255; 32]),
                block_spacing_secs: 1,
                retarget_interval: 100,
                max_future_secs: 100,
                confirmation_depth: 1,
                max_headers: 16,
                max_shards: 2,
                max_updates: 1,
                max_body_bytes: 32 * 1024 * 1024,
                max_request_bytes: 4096,
                max_proof_bytes: 32 * 1024 * 1024,
                max_journal_bytes: 256 * 1024 * 1024,
            },
            initial_shards: app.initial_shards(),
        };
        let mut journal = Journal::new(genesis.clone()).unwrap();
        let verifier = RegistryVerifier::new(app.clone(), &genesis).unwrap();
        let enrollment_salt = [11, 12, 13, 14];
        let mut registry_salt = [21, 22, 23, 24];
        let mut registry = Registry::default();
        let mut unheld = Registry::default();
        let mut unheld_salt = [0; 4];
        let mut enrollment = [0; 32];
        let mut other = Command::control(Operation::Acquire, 2, 2, 1);
        other.mask[0] = 1;
        other.mode = 4;
        other.limit = 4;
        other.projection = 3;
        for (ordinal, command) in [
            None,
            Some(Command::control(Operation::Begin, 1, 1, 0)),
            Some(Command::control(Operation::Begin, 2, 2, 0)),
            Some(other),
        ]
        .into_iter()
        .enumerate()
        {
            if ordinal == 3 {
                unheld = registry.clone();
                unheld_salt = registry_salt;
            }
            let parent = journal.best_validated();
            let op = if command.is_none() {
                JournalOperation::Bootstrap
            } else {
                JournalOperation::Transition
            };
            let mut s = loaded.draft.clone();
            let salt = [31 + ordinal as u64, 32, 33, 34];
            // Enrollment's stable prefix is deliberately independent of q/Copen.
            let mut w = life::Witness {
                plain: loaded.plain.as_slice().try_into().unwrap(),
                controllers: CONTROLLERS,
                salts: [[Val::ZERO; 4]; 6],
                old: registry.clone(),
                command,
            };
            w.salts[0] = salt.map(Val::from_u64);
            w.salts[1] = enrollment_salt.map(Val::from_u64);
            w.salts[2] = registry_salt.map(Val::from_u64);
            w.salts[3] = [41 + ordinal as u64, 42, 43, 44].map(Val::from_u64);
            w.salts[4] = [51 + ordinal as u64, 52, 53, 54].map(Val::from_u64);
            w.salts[5] = [61 + ordinal as u64, 62, 63, 64].map(Val::from_u64);
            if ordinal == 0 {
                let draft =
                    ls::Expected::bootstrap(&s, journal.genesis_id(), parent.block, [0; 32])
                        .unwrap();
                enrollment = ss::encode_digest(sc::digest(&lc::enrollment_fields(&draft, &w)));
            }
            let nonce = [71 + ordinal as u8; 32];
            s.request = intent_query(
                &app,
                journal.genesis_id(),
                parent.block,
                nonce,
                enrollment,
                op,
            );
            s.open_commitment = sc::digest(&sc::opening_fields(&s, w.salts[0], &loaded.plain));
            let source = CanonicalSource::checked_claim(&s).unwrap();
            let expected = if let Some(c) = &w.command {
                let old = ls::digest(&lc::registry_fields(
                    &ls::Expected::bootstrap(&s, journal.genesis_id(), parent.block, enrollment)
                        .unwrap(),
                    &w,
                    &registry,
                    w.salts[2],
                ));
                let draft = ls::Expected::transition(
                    &s,
                    journal.genesis_id(),
                    parent.block,
                    enrollment,
                    ss::encode_digest(old),
                    [0; 32],
                )
                .unwrap();
                let cmd = ss::encode_digest(ls::digest(&lc::command_fields(&draft, &w, c)));
                LifeExpected::transition(
                    &source,
                    journal.genesis_id(),
                    parent.block,
                    enrollment,
                    ss::encode_digest(old),
                    cmd,
                )
                .unwrap()
            } else {
                LifeExpected::bootstrap(&source, journal.genesis_id(), parent.block, enrollment)
                    .unwrap()
            };
            let next = w.command.as_ref().map_or_else(Registry::default, |c| {
                registry
                    .step(c, parent.block, ROWS.map(|r| r.age))
                    .unwrap()
                    .next
            });
            let next_salt = w.salts[4].map(|v| v.as_canonical_u64());
            let prepared = lifecycle::PreparedWitness::new(&expected, w).unwrap();
            let source_proof = source::prove(
                &source,
                &owner.source_witness(salt.map(Val::from_u64), &loaded.originals),
            )
            .unwrap();
            let evidence = lifecycle::prove(&expected, &prepared, source_proof.as_bytes()).unwrap();
            let command = match expected.claim().phase {
                ls::Phase::Bootstrap => [0; 32],
                ls::Phase::Transition { command, .. } => ss::encode_digest(command),
            };
            let request = Request {
                operation: op,
                genesis: journal.genesis_id(),
                parent: parent.block,
                application: app.id(),
                nonce,
                query: s.request,
                enrollment,
                opening: ss::encode_digest(s.open_commitment),
                command,
                packets: s.packets.clone(),
            };
            let old = app
                .control(journal.validated_shards(parent).unwrap())
                .unwrap();
            let new = Control::Active {
                enrollment,
                registry: ss::encode_digest(evidence.statement().next),
            }
            .heads(&app);
            let mut tx = AuthorizedTransition {
                parent: parent.block,
                request: request.encode().unwrap(),
                updates: vec![ShardUpdate {
                    id: app.control_id,
                    old,
                    new,
                }],
                proof: evidence.into_parts().1,
                owner_signature: [0; 64],
            };
            tx.sign(journal.genesis_id(), &signer);
            let body = Body::Transition(tx);
            let mut header = journal
                .candidate(parent.block, &body, 2 + ordinal as u64)
                .unwrap();
            header.mine(1).unwrap();
            journal
                .import_block(
                    header,
                    &body.encode(&genesis.profile).unwrap(),
                    100,
                    &verifier,
                )
                .unwrap();
            registry = next;
            registry_salt = next_salt;
        }
        let blocks = journal
            .validated_blocks()
            .into_iter()
            .map(|(h, b)| (h.clone(), b.to_vec()))
            .collect();
        History {
            bundle,
            heads,
            object,
            key_salt: *owner.key_salt,
            app,
            genesis,
            blocks,
            registry,
            enrollment_salt,
            registry_salt,
            unheld,
            unheld_salt,
        }
    })
}
impl History {
    fn owner(&self) -> SourceOwner {
        SourceOwner {
            sealer: compact_store::Owner::from_key(DB, DOMAIN, Zeroizing::new(AEAD)),
            key: Zeroizing::new(AEAD),
            key_salt: Zeroizing::new(self.key_salt),
        }
    }
    fn journal(&self) -> Journal {
        let mut j = Journal::new(self.genesis.clone()).unwrap();
        let v = RegistryVerifier::new(self.app.clone(), &self.genesis).unwrap();
        for (h, b) in &self.blocks {
            j.import_block(h.clone(), b, 100, &v).unwrap();
        }
        j
    }
    fn fetched(&self) -> FetchedSource<'_> {
        FetchedSource {
            object: self.object,
            bundle: &self.bundle,
            heads: &self.heads,
        }
    }
    fn control(&self) -> LockingControl {
        LockingControl::new(
            self.registry.clone(),
            CONTROLLERS,
            [self.enrollment_salt, self.registry_salt],
            LockingActor::new(1, 1, self.registry.revision, 1).unwrap(),
        )
        .unwrap()
    }
}

#[test]
fn actual_parent_and_actor_openings_reject_foreign_domains_before_proving() {
    let h = history();
    let j = h.journal();
    let head = j.best_validated();
    LockingParent::new(&h.app, &j, head).unwrap();
    assert!(LockingParent::new(&h.app, &j, j.genesis_head()).is_err());
    let mut wrong = head;
    wrong.state_root[31] ^= 1;
    assert!(LockingParent::new(&h.app, &j, wrong).is_err());
    let mut app = h.app.clone();
    app.database[15] ^= 1;
    assert!(LockingParent::new(&app, &j, head).is_err());
    for actor in [
        LockingActor::new(1, 2, h.registry.revision, 1).unwrap(),
        LockingActor::new(1, 1, h.registry.revision + 1, 1).unwrap(),
        LockingActor::new(1, 1, h.registry.revision, 2).unwrap(),
        LockingActor::new(3, 1, h.registry.revision, 1).unwrap(),
    ] {
        assert!(
            LockingControl::new(
                h.registry.clone(),
                CONTROLLERS,
                [h.enrollment_salt, h.registry_salt],
                actor
            )
            .is_err()
        );
    }
    let mut failed = h.registry.clone();
    failed.transactions[0].failed = true;
    assert!(
        LockingControl::new(
            failed,
            CONTROLLERS,
            [h.enrollment_salt, h.registry_salt],
            LockingActor::new(1, 1, h.registry.revision, 1).unwrap()
        )
        .is_err()
    );
}

#[test]
fn genuine_joint_preparation_proves_skip_window_limit_zero_and_three_valued_empty() {
    let h = history();
    let source = h.owner();
    let journal = h.journal();
    let parent = LockingParent::new(&h.app, &journal, journal.best_validated()).unwrap();
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let handle = owner
        .key_anchor(
            &setup,
            KeyScope {
                database: DB,
                bfv_key_domain: [0x7c; 16],
                epoch: 1,
            },
        )
        .unwrap();
    let mut epoch = handle.proof_epoch(&setup).unwrap();
    epoch.prove_key().unwrap();
    let mut retained = None;
    for (sql, flags) in [
        (
            "SELECT age, amount FROM records WHERE age IN (0, 128, 255, NULL) LIMIT 1 OFFSET 1 FOR UPDATE SKIP LOCKED",
            [
                [false, false, false, true],
                [true, false, false, false],
                [false, false, true, true],
            ],
        ),
        (
            "SELECT amount FROM records LIMIT 0 FOR UPDATE",
            [[false; 4]; 3],
        ),
        (
            "SELECT age FROM records WHERE NULL FOR UPDATE SKIP LOCKED",
            [[false; 4]; 3],
        ),
        (
            "SELECT age FROM records WHERE age = 0 FOR UPDATE SKIP LOCKED",
            [[false; 4], [true, false, false, false], [false; 4]],
        ),
    ] {
        drop(retained.take());
        let c = compile(sql);
        let result = source
            .prepare_locking(
                BfvContext {
                    owner: &owner,
                    setup: &setup,
                    anchor: handle.public_anchor(),
                },
                &mut epoch,
                h.fetched(),
                &c,
                &parent,
                h.control(),
            )
            .unwrap();
        let LockingPreparation::Prepared(prepared) = result else {
            panic!("actual successful Acquire required")
        };
        assert_eq!(*prepared.completion.flags, flags);
        assert_eq!(*prepared.completion.ordinals, [0, 1, 2, 3]);
        let loaded = source.load(h.fetched()).unwrap();
        assert_eq!(
            prepared.completion.table.as_slice(),
            &loaded.plain[124..156]
        );
        for (i, id) in prepared.completion.row_ids.iter().enumerate() {
            assert_eq!(id.as_slice(), &loaded.plain[2220 + 32 * i..2252 + 32 * i]);
        }
        assert_eq!(
            prepared.request.nonce,
            c.intent(
                prepared.inputs.provenance.encodings()[0]
                    .expected
                    .source_claim(),
                prepared.inputs.provenance.encodings()[0].expected.bfv(),
                h.object,
                &parent,
                &h.control()
            )
            .0
        );
        assert_eq!(
            prepared.request.query,
            intent_query(
                &h.app,
                parent.head.genesis,
                parent.head.block,
                prepared.request.nonce,
                parent.enrollment,
                JournalOperation::Transition
            )
        );
        assert_eq!(
            Request::decode(&prepared.request.encode().unwrap())
                .unwrap()
                .query,
            prepared.inputs.provenance.query()
        );
        assert_eq!(prepared.staged.request, prepared.request.encode().unwrap());
        assert_eq!(
            prepared.staged.provenance,
            prepared.inputs.provenance.encode_claim().unwrap()
        );
        assert_eq!(prepared.staged.encrypted_request, prepared.inputs.request());
        assert_eq!(prepared.staged.parent, parent.head);
        prepared
            .staged
            ._association
            .require_same(prepared.link.expected())
            .unwrap();
        let q = encoding::wire::BorrowedFrame::parse(
            &prepared.inputs.provenance.encodings()[1].expected,
            &prepared.inputs.proofs.encodings[1],
        )
        .unwrap();
        let l = registry200_proof::wire::frame::Frame::parse(
            registry200_proof::wire::frame::Role::Transition,
            prepared.lifecycle.as_bytes(),
        )
        .unwrap();
        assert_eq!(q.source(), l.source);
        prepared
            .inputs
            .provenance
            .verify_inputs(&prepared.inputs.proofs.as_input_evidence())
            .unwrap();
        link::verify(
            prepared.link.expected(),
            &link::Prerequisites {
                query: &prepared.inputs.proofs.encodings[1],
                lifecycle: prepared.lifecycle.as_bytes(),
            },
            prepared.link.as_bytes(),
        )
        .unwrap();
        assert_eq!(epoch.stage(), ProofEpochStage::Ready);
        assert_eq!(journal.best_validated(), parent.head); // No append, authorization or owner-state promotion.
        retained = Some(prepared);
    }
    // Fresh public-only verification after all private producer capabilities drop.
    drop(epoch);
    drop(handle);
    drop(owner);
    drop(source);
    let retained = retained.unwrap();
    retained
        .inputs
        .provenance
        .verify_inputs(&retained.inputs.proofs.as_input_evidence())
        .unwrap();
    link::verify(
        retained.link.expected(),
        &link::Prerequisites {
            query: &retained.inputs.proofs.encodings[1],
            lifecycle: retained.lifecycle.as_bytes(),
        },
        retained.link.as_bytes(),
    )
    .unwrap();
}

#[test]
fn genuine_wait_and_nowait_return_only_nonadmitted_lifecycle_evidence() {
    let h = history();
    let source = h.owner();
    let journal = h.journal();
    let parent = LockingParent::new(&h.app, &journal, journal.best_validated()).unwrap();
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let handle = owner
        .key_anchor(
            &setup,
            KeyScope {
                database: DB,
                bfv_key_domain: [0x7c; 16],
                epoch: 1,
            },
        )
        .unwrap();
    let mut epoch = handle.proof_epoch(&setup).unwrap();
    epoch.prove_key().unwrap();
    for (sql, outcome) in [
        (
            "SELECT age FROM records WHERE age = 0 FOR UPDATE",
            LockingConflict::Wait,
        ),
        (
            "SELECT age FROM records WHERE age = 0 FOR UPDATE NOWAIT",
            LockingConflict::NoWait,
        ),
    ] {
        let c = compile(sql);
        let result = source
            .prepare_locking(
                BfvContext {
                    owner: &owner,
                    setup: &setup,
                    anchor: handle.public_anchor(),
                },
                &mut epoch,
                h.fetched(),
                &c,
                &parent,
                h.control(),
            )
            .unwrap();
        let LockingPreparation::NonAdmitted(blocked) = result else {
            panic!("conflict must not return successful inputs/Link")
        };
        assert_eq!(blocked.outcome(), outcome);
        assert_eq!(
            ss::encode_digest(blocked.lifecycle.statement().next),
            parent.registry
        );
        let expected =
            LifeExpected::checked_claim(&blocked.lifecycle.statement().expected).unwrap();
        let checked =
            registry200_proof::wire::verify(&expected, blocked.lifecycle.as_bytes()).unwrap();
        assert_eq!(checked.next_root(), parent.registry);
        assert_eq!(
            blocked.request.query,
            intent_query(
                &h.app,
                parent.head.genesis,
                parent.head.block,
                blocked.request.nonce,
                parent.enrollment,
                JournalOperation::Transition
            )
        );
        assert_eq!(journal.best_validated(), parent.head);
        assert_eq!(epoch.stage(), ProofEpochStage::Ready);
    }
}

#[test]
fn joint_intent_binds_full_parent_actor_and_query_but_keeps_fresh_key_tail_out_of_q() {
    let h = history();
    let source = h.owner();
    let j = h.journal();
    let parent = LockingParent::new(&h.app, &j, j.best_validated()).unwrap();
    let control = h.control();
    let c = compile("SELECT age, amount FROM records WHERE age = 255 FOR UPDATE SKIP LOCKED");
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let handle = owner
        .key_anchor(
            &setup,
            KeyScope {
                database: DB,
                bfv_key_domain: [0x7c; 16],
                epoch: 1,
            },
        )
        .unwrap();
    let mut first = handle.proof_epoch(&setup).unwrap();
    first.prove_key().unwrap();
    let a = setup
        .verify_key_transform(
            handle.public_anchor(),
            first.key_evidence().unwrap().as_bytes(),
        )
        .unwrap()
        .statement()
        .clone();
    drop(first);
    let mut second = handle.proof_epoch(&setup).unwrap();
    second.prove_key().unwrap();
    let b = setup
        .verify_key_transform(
            handle.public_anchor(),
            second.key_evidence().unwrap().as_bytes(),
        )
        .unwrap()
        .statement()
        .clone();
    assert_eq!(&a.public_values()[..29], &b.public_values()[..29]);
    assert_ne!(a.transformed, b.transformed);
    let ba = BfvBinding::new(handle.public_anchor().full_setup_id(), a);
    let bb = BfvBinding::new(handle.public_anchor().full_setup_id(), b);
    let mut loaded = source.load(h.fetched()).unwrap();
    let (nonce, q) = c.intent(&loaded.draft, &ba, h.object, &parent, &control);
    assert_eq!(
        c.intent(&loaded.draft, &bb, h.object, &parent, &control),
        (nonce, q)
    );
    let mut output_only = loaded.draft.clone();
    output_only.open_commitment = [Val::ONE; 4];
    assert_eq!(
        c.intent(&output_only, &ba, h.object, &parent, &control),
        (nonce, q)
    );
    loaded.draft.request = q;
    loaded.draft.open_commitment = sc::digest(&sc::opening_fields(
        &loaded.draft,
        [Val::ONE; 4],
        &loaded.plain,
    ));
    let canonical = CanonicalSource::checked_claim(&loaded.draft).unwrap();
    let (sa, qa) = c
        .bind(
            &canonical,
            ba.clone(),
            h.object,
            &parent,
            &control,
            [Val::ONE; 4],
        )
        .unwrap();
    let (sb, qb) = c
        .bind(&canonical, bb, h.object, &parent, &control, [Val::ONE; 4])
        .unwrap();
    assert!(sa.require_same(&sb).is_err());
    assert!(qa.require_same(&qb).is_err());
    assert_ne!(qa.encoding_context(), qb.encoding_context()); // ALL33 remain bound after q29.
    for changed in 0..13 {
        let mut p = LockingParent {
            application: parent.application.clone(),
            head: parent.head,
            enrollment: parent.enrollment,
            registry: parent.registry,
        };
        let s = loaded.draft.clone();
        let mut object = h.object;
        let mut ctrl = h.control();
        match changed {
            0 => p.head.height += 1,
            1 => p.head.state_root[31] ^= 1,
            2 => p.head.block[31] ^= 1,
            3 => p.enrollment[0] ^= 1,
            4 => p.registry[0] ^= 1,
            5 => ctrl.actor.sequence += 1,
            6 => ctrl.controllers[0][31] ^= 1,
            7 => object[31] ^= 1,
            8 => p.application.network[31] ^= 1,
            9 => ctrl.actor.transaction ^= 1 << 63,
            10 => ctrl.actor.revision ^= 1 << 63,
            11 => ctrl.actor.sequence ^= 1 << 63,
            12 => ctrl.actor.principal = 2,
            _ => unreachable!(),
        }
        assert_ne!(
            c.intent(&s, &ba, object, &p, &ctrl).1,
            q,
            "context mutation {changed}"
        );
        assert!(
            c.bind(&canonical, ba.clone(), object, &p, &ctrl, [Val::ONE; 4])
                .is_err()
        );
    }
    for other in [
        CompiledLockingSelect::compile(
            "SELECT age, amount FROM records WHERE age = 255 FOR UPDATE SKIP LOCKED",
            Zeroizing::new([0xc7; 32]),
            [0xe7; 32],
            [0xf8; 16],
        )
        .unwrap(),
        CompiledLockingSelect::compile(
            "SELECT age, amount FROM records WHERE age = 255 FOR UPDATE SKIP LOCKED",
            Zeroizing::new([0xc6; 32]),
            [0xe8; 32],
            [0xf8; 16],
        )
        .unwrap(),
        CompiledLockingSelect::compile(
            "SELECT age, amount FROM records WHERE age = 255 FOR UPDATE SKIP LOCKED",
            Zeroizing::new([0xc6; 32]),
            [0xe7; 32],
            [0xf9; 16],
        )
        .unwrap(),
    ] {
        assert_ne!(
            other
                .intent(&loaded.draft, &ba, h.object, &parent, &control)
                .1,
            q
        );
        assert!(
            other
                .bind(
                    &canonical,
                    ba.clone(),
                    h.object,
                    &parent,
                    &control,
                    [Val::ONE; 4]
                )
                .is_err()
        );
    }
    // Actual typed producer rejects altered private roots against the real parent.
    for changed in 0..3 {
        let mut ctrl = h.control();
        match changed {
            0 => ctrl.salts[0][0] += 1,
            1 => ctrl.salts[1][0] += 1,
            2 => ctrl.old.transactions[1].held = [0; 4],
            _ => unreachable!(),
        }
        let result = source.prepare_locking(
            BfvContext {
                owner: &owner,
                setup: &setup,
                anchor: handle.public_anchor(),
            },
            &mut second,
            h.fetched(),
            &c,
            &parent,
            ctrl,
        );
        assert!(
            matches!(result,Err(crate::Error::InvalidInput(message)) if message=="Private control opening differs from the validated parent")
        );
        assert_eq!(second.stage(), ProofEpochStage::Ready);
    }
}

#[test]
fn genuine_same_query_foreign_mask_parent_and_control_pairs_cannot_replay_the_link() {
    let h = history();
    let source_owner = h.owner();
    let mut journal = h.journal();
    let parent = LockingParent::new(&h.app, &journal, journal.best_validated()).unwrap();
    let c = compile("SELECT age, amount FROM records WHERE age = 255 FOR UPDATE SKIP LOCKED");
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let handle = owner
        .key_anchor(
            &setup,
            KeyScope {
                database: DB,
                bfv_key_domain: [0x7c; 16],
                epoch: 1,
            },
        )
        .unwrap();
    let mut epoch = handle.proof_epoch(&setup).unwrap();
    epoch.prove_key().unwrap();
    let key = setup
        .verify_key_transform(
            handle.public_anchor(),
            epoch.key_evidence().unwrap().as_bytes(),
        )
        .unwrap();
    let binding = BfvBinding::new(
        handle.public_anchor().full_setup_id(),
        key.statement().clone(),
    );
    let control = h.control();
    let mut loaded = source_owner.load(h.fetched()).unwrap();
    loaded.draft.request = c
        .intent(&loaded.draft, &binding, h.object, &parent, &control)
        .1;
    let source_salt = [81, 82, 83, 84];
    loaded.draft.open_commitment = sc::digest(&sc::opening_fields(
        &loaded.draft,
        source_salt.map(Val::from_u64),
        &loaded.plain,
    ));
    let canonical = CanonicalSource::checked_claim(&loaded.draft).unwrap();
    let source_proof = source::prove(
        &canonical,
        &source_owner.source_witness(source_salt.map(Val::from_u64), &loaded.originals),
    )
    .unwrap();
    let mask_salt = [91, 92, 93, 94];
    let (_, qa) = c
        .bind(
            &canonical,
            binding.clone(),
            h.object,
            &parent,
            &control,
            mask_salt.map(Val::from_u64),
        )
        .unwrap();
    let wa = EncodingWitness::private_mask(
        &qa,
        Zeroizing::new(*c.mask),
        mask_salt,
        [101, 102, 103, 104],
    )
    .unwrap();
    let pa = encoding::prove(&qa, &wa, source_proof.as_bytes()).unwrap();
    let mut foreign_mask = Zeroizing::new(*c.mask);
    foreign_mask[31] ^= 128;
    foreign_mask[0] ^= 1;
    let draft = EncodingExpected::private_mask(
        &canonical,
        binding.clone(),
        c.identity,
        c.public_nonce,
        [0; 32],
    )
    .unwrap();
    let root = encoding::commitment::command_digest(&encoding::commitment::command_fields(
        &draft,
        *foreign_mask,
        mask_salt.map(Val::from_u64),
    ));
    let qb = EncodingExpected::private_mask(
        &canonical,
        binding,
        c.identity,
        c.public_nonce,
        ss::encode_digest(root),
    )
    .unwrap();
    assert_eq!(qa.source_claim().values(), qb.source_claim().values());
    assert_eq!(qa.sql_identity(), qb.sql_identity());
    assert_eq!(qa.public_nonce(), qb.public_nonce());
    assert_eq!(
        qa.bfv().key().public_values(),
        qb.bfv().key().public_values()
    );
    assert_ne!(qa.command(), qb.command());
    let wb =
        EncodingWitness::private_mask(&qb, foreign_mask, mask_salt, [111, 112, 113, 114]).unwrap();
    let pb = encoding::prove(&qb, &wb, source_proof.as_bytes()).unwrap();
    encoding::wire::verify(&qa, pa.as_bytes()).unwrap();
    encoding::wire::verify(&qb, pb.as_bytes()).unwrap();

    // A real Empty descendant preserves both roots but changes the actual parent.
    let verifier = RegistryVerifier::new(h.app.clone(), &h.genesis).unwrap();
    let mut header = journal
        .candidate(parent.head.block, &Body::Empty, 6)
        .unwrap();
    header.mine(1).unwrap();
    journal
        .import_block(
            header,
            &Body::Empty.encode(&h.genesis.profile).unwrap(),
            100,
            &verifier,
        )
        .unwrap();
    let later = LockingParent::new(&h.app, &journal, journal.best_validated()).unwrap();
    assert_eq!(
        (later.enrollment, later.registry),
        (parent.enrollment, parent.registry)
    );
    assert_ne!(
        c.intent(canonical.claim(), qa.bfv(), h.object, &later, &control)
            .1,
        canonical.claim().request
    );
    assert!(
        c.bind(
            &canonical,
            qa.bfv().clone(),
            h.object,
            &later,
            &control,
            mask_salt.map(Val::from_u64)
        )
        .is_err()
    );

    let make_life = |head: HeadRef, registry: &Registry, registry_salt: [u64; 4], label: u64| {
        let w = life::Witness {
            plain: loaded.plain.as_slice().try_into().unwrap(),
            controllers: CONTROLLERS,
            salts: [
                source_salt,
                h.enrollment_salt,
                registry_salt,
                [label, 122, 123, 124],
                [label + 1, 132, 133, 134],
                [label + 2, 142, 143, 144],
            ]
            .map(|s| s.map(Val::from_u64)),
            old: registry.clone(),
            command: Some(c.command(&control)),
        };
        let heads = h
            .app
            .control(journal.validated_shards(head).unwrap())
            .unwrap();
        let Control::Active {
            enrollment,
            registry: root,
        } = Control::decode(&h.app, heads).unwrap()
        else {
            panic!("active fixture")
        };
        let draft = ls::Expected::transition(
            canonical.claim(),
            head.genesis,
            head.block,
            enrollment,
            root,
            [0; 32],
        )
        .unwrap();
        let command = ls::digest(&lc::command_fields(&draft, &w, w.command.as_ref().unwrap()));
        let expected = LifeExpected::transition(
            &canonical,
            head.genesis,
            head.block,
            enrollment,
            root,
            ss::encode_digest(command),
        )
        .unwrap();
        let step = w
            .old
            .step(w.command.as_ref().unwrap(), head.block, w.ages())
            .unwrap();
        let salts = [
            w.salts[3].map(|v| v.as_canonical_u64()),
            w.salts[5].map(|v| v.as_canonical_u64()),
        ];
        let prepared = lifecycle::PreparedWitness::new(&expected, w).unwrap();
        let p = lifecycle::prove(&expected, &prepared, source_proof.as_bytes()).unwrap();
        registry200_proof::wire::verify(&expected, p.as_bytes()).unwrap();
        (p, [step.returned, step.skipped, step.visit], salts)
    };
    let (life_a, flags, salts) = make_life(parent.head, &h.registry, h.registry_salt, 121);
    let ea = link::Expected::new(pa.statement(), life_a.statement()).unwrap();
    let witness = link::circuit::Witness::new(
        &ea,
        link::circuit::Opening {
            mask: *c.mask,
            transaction: 1,
            principal: 1,
            controller: CONTROLLERS[0],
            revision: h.registry.revision,
            sequence: 1,
            mode: c.mode,
            wait: c.wait,
            offset: c.offset,
            limit: c.limit,
            projection: c.projection,
            flags,
            salts: [mask_salt, salts[0], salts[1]],
        },
    )
    .unwrap();
    let parents_a = link::Prerequisites {
        query: pa.as_bytes(),
        lifecycle: life_a.as_bytes(),
    };
    let proof = link::prove(&ea, &witness, &parents_a).unwrap();
    link::verify(&ea, &parents_a, proof.as_bytes()).unwrap();
    assert!(matches!(
        link::verify(
            &ea,
            &link::Prerequisites {
                query: pb.as_bytes(),
                lifecycle: life_a.as_bytes()
            },
            proof.as_bytes()
        ),
        Err(link::wire::Error::Prerequisite)
    ));

    // The following are genuine standalone mathematical pairs with the SAME q.
    // They are deliberately not claimed to satisfy the original app's outer q
    // request at the foreign parent. Exact joint association must still reject.
    let before = (*journal.validated_blocks()[2].0).clone();
    let before_head = HeadRef {
        genesis: parent.head.genesis,
        database: DB,
        block: before.id(),
        height: before.height,
        state_root: before.state_root,
    };
    let (foreign_control, _, _) = make_life(before_head, &h.unheld, h.unheld_salt, 151);
    let ec = link::Expected::new(pa.statement(), foreign_control.statement()).unwrap();
    assert_ne!(
        ec.lifecycle().expected.context(),
        ea.lifecycle().expected.context()
    );
    assert!(
        link::verify(
            &ec,
            &link::Prerequisites {
                query: pa.as_bytes(),
                lifecycle: foreign_control.as_bytes()
            },
            proof.as_bytes()
        )
        .is_err()
    );
    let (foreign_parent, _, _) = make_life(later.head, &h.registry, h.registry_salt, 161);
    let ep = link::Expected::new(pa.statement(), foreign_parent.statement()).unwrap();
    assert_ne!(
        ep.lifecycle().expected.parent,
        ea.lifecycle().expected.parent
    );
    assert!(
        link::verify(
            &ep,
            &link::Prerequisites {
                query: pa.as_bytes(),
                lifecycle: foreign_parent.as_bytes()
            },
            proof.as_bytes()
        )
        .is_err()
    );
}

#[test]
fn staged_actual_next_opening_builds_a_conditional_end_witness_without_promoting_state() {
    let h = history();
    let source = h.owner();
    let journal = h.journal();
    let parent = LockingParent::new(&h.app, &journal, journal.best_validated()).unwrap();
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let handle = owner
        .key_anchor(
            &setup,
            KeyScope {
                database: DB,
                bfv_key_domain: [0x7c; 16],
                epoch: 1,
            },
        )
        .unwrap();
    let mut epoch = handle.proof_epoch(&setup).unwrap();
    epoch.prove_key().unwrap();
    let c =
        compile("SELECT age, amount FROM records WHERE age >= 128 FOR NO KEY UPDATE SKIP LOCKED");
    let result = source
        .prepare_locking(
            BfvContext {
                owner: &owner,
                setup: &setup,
                anchor: handle.public_anchor(),
            },
            &mut epoch,
            h.fetched(),
            &c,
            &parent,
            h.control(),
        )
        .unwrap();
    let LockingPreparation::Prepared(prepared) = result else {
        panic!("successful actual proof chain required")
    };
    let staged = &prepared.staged;
    assert_eq!(staged.next.revision, h.registry.revision + 1);
    assert_eq!(staged.controllers.as_slice(), CONTROLLERS.as_slice());
    assert_eq!(staged.salts[0], h.enrollment_salt);
    let actor = staged
        .next
        .transactions
        .iter()
        .find(|tx| tx.id == 1)
        .unwrap();
    assert_eq!(
        (actor.principal, actor.sequence, actor.held),
        (1, 2, [0, 0, 3, 3])
    );
    assert_eq!(staged.next.transactions[1], h.registry.transactions[1]);
    assert_eq!(journal.best_validated(), parent.head); // No Acquire was installed.

    // CONDITIONAL mathematical End only. A real End needs a newly finalized
    // joint Acquire parent and its new Source proof; neither exists in this test.
    // This uses a fresh Source opening and the preserved new Registry salt to
    // demonstrate that the actual staged Cnext preimage was not discarded.
    let mut loaded = source.load(h.fetched()).unwrap();
    let enrollment = ss::encode_digest(prepared.lifecycle.statement().expected.enrollment);
    loaded.draft.request = intent_query(
        &h.app,
        parent.head.genesis,
        parent.head.block,
        [0xda; 32],
        enrollment,
        JournalOperation::Transition,
    );
    let source_salt = [211, 212, 213, 214].map(Val::from_u64);
    loaded.draft.open_commitment = sc::digest(&sc::opening_fields(
        &loaded.draft,
        source_salt,
        &loaded.plain,
    ));
    let canonical = CanonicalSource::checked_claim(&loaded.draft).unwrap();
    let w = life::Witness {
        plain: loaded.plain.as_slice().try_into().unwrap(),
        controllers: *staged.controllers,
        salts: [
            source_salt,
            staged.salts[0].map(Val::from_u64),
            staged.salts[1].map(Val::from_u64),
            [221, 222, 223, 224].map(Val::from_u64),
            [231, 232, 233, 234].map(Val::from_u64),
            [241, 242, 243, 244].map(Val::from_u64),
        ],
        old: (*staged.next).clone(),
        command: Some(Command::control(Operation::End, 1, 1, actor.sequence)),
    };
    let cold = ss::encode_digest(prepared.lifecycle.statement().next);
    let draft = ls::Expected::transition(
        canonical.claim(),
        parent.head.genesis,
        parent.head.block,
        enrollment,
        cold,
        [0; 32],
    )
    .unwrap();
    assert_eq!(
        ss::encode_digest(ls::digest(&lc::registry_fields(
            &draft, &w, &w.old, w.salts[2]
        ))),
        cold
    );
    let command = ss::encode_digest(ls::digest(&lc::command_fields(
        &draft,
        &w,
        w.command.as_ref().unwrap(),
    )));
    let expected = LifeExpected::transition(
        &canonical,
        parent.head.genesis,
        parent.head.block,
        enrollment,
        cold,
        command,
    )
    .unwrap();
    let statement = w.statement(expected.claim()).unwrap();
    assert_ne!(statement.next, prepared.lifecycle.statement().next);
    for changed in 0..3 {
        let mut wrong = w.clone();
        match changed {
            0 => wrong.controllers[0][31] ^= 1,
            1 => wrong.salts[2][3] += Val::ONE,
            2 => wrong.old.transactions[0].held[3] = 0,
            _ => unreachable!(),
        }
        assert!(lifecycle::PreparedWitness::new(&expected, wrong).is_err());
    }
    let captured = lifecycle::PreparedWitness::new(&expected, w).unwrap();
    drop(captured);
    assert_eq!(journal.best_validated(), parent.head); // Constructor is not admission.
}
