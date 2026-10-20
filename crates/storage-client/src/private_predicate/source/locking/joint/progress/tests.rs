//! PUBLIC NONSECRET fixtures. Fast codec/WAL tests grant no proof authority.
//! The explicit ignored gate uses one real remote FHE worker and local genuine
//! weighted QCs; it is not four-validator agreement or full WAIT acceptance.
use super::*;
use super::{
    host::{Bootstrap, ControlOutcome},
    state::{Bank, Kind, RawCall},
    wal::{Fault, Wal},
};
use crate::private_predicate::source::locking::joint::tests::{
    full_acquire_fixture as fixture, os_process,
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use protocol_storage::ByteBudget;
use registry200_proof::{
    Val,
    lifecycle::circuit::model::{Command, Operation as CoreOperation},
    registry_progress::circuit::{ProgressOpening, State, StatementOpening},
};
use std::fs::OpenOptions;

fn authority() -> Authority {
    Authority::new(Zeroizing::new([0x91; 32]))
}
fn bank() -> Bank {
    Bank {
        state: Zeroizing::new(State::default()),
        controllers: Zeroizing::new([[0x41; 32], [0x42; 32]]),
        enroll_salt: Zeroizing::new([1; 4]),
        registry_salt: Zeroizing::new([2; 4]),
    }
}
#[test]
fn private_bank_codec_has_exact_extents_canonical_salts_and_absence_padding() {
    let b = bank();
    let bytes = b.encode().unwrap();
    assert_eq!(bytes.len(), 1228);
    assert_eq!(state::STATE_BYTES, 1092);
    assert_eq!(state::BOOK_BYTES, 512);
    assert_eq!(state::STATEMENT_BYTES, 342);
    assert_eq!(state::PROGRESS_BYTES, 408);
    assert_eq!(
        Bank::decode(bytes.as_ref())
            .unwrap()
            .encode()
            .unwrap()
            .as_ref(),
        bytes.as_ref()
    );
    for n in [0, 7, bytes.len() - 1, bytes.len() + 1] {
        let mut wrong = bytes.to_vec();
        wrong.resize(n, 0);
        assert!(Bank::decode(&wrong).is_err());
    }
    let mut wrong = bytes.to_vec();
    wrong[8 + state::STATE_BYTES + 64..8 + state::STATE_BYTES + 72]
        .copy_from_slice(&Val::ORDER_U64.to_le_bytes());
    assert!(Bank::decode(&wrong).is_err());
    for at in [
        8 + super::super::private_state_codec::REGISTRY,
        8 + super::super::private_state_codec::REGISTRY + 1,
    ] {
        let mut wrong = bytes.to_vec();
        wrong[at] = 2;
        assert!(Bank::decode(&wrong).is_err());
    }
}
#[test]
fn private_parked_opening_round_trip_follows_stable_transaction_after_compaction() {
    let mut b = bank();
    b.state = Zeroizing::new(
        b.state
            .control(&Command::control(CoreOperation::Begin, 1, 1, 0), [0x31; 32])
            .unwrap(),
    );
    b.state = Zeroizing::new(
        b.state
            .control(&Command::control(CoreOperation::Begin, 2, 2, 0), [0x32; 32])
            .unwrap(),
    );
    let original = StatementOpening {
        scope: [0x51; 64],
        enrollment: [1; 4],
        client: [0x52; 32],
        call: 1,
        transaction: 2,
        principal: 2,
        controller: [0x42; 32],
        invocation: [0x53; 32],
        sql_identity: [0x54; 32],
        snapshot: [0x32; 32],
        mask: [255; 32],
        mode: 4,
        wait: 0,
        offset: 0,
        limit: 4,
        projection: 3,
        salt: [3; 4],
    };
    b.state.registry.revision = 3;
    b.state.registry.transactions[0].held[1] = 4;
    b.state.registry.transactions[1].held[0] = 4;
    b.state.progress[1] = Some(ProgressOpening {
        statement: original.clone(),
        microstep: 1,
        cursor: 1,
        visited: [true, false, false, false],
        selected: [true, false, false, false],
        holder: 1,
        holder_mode: 4,
        blocked_revision: 2,
        salt: [4; 4],
    });
    let encoded = b.encode().unwrap();
    let restored = Bank::decode(encoded.as_ref()).unwrap();
    assert!(restored.state.progress[1].as_ref().unwrap().statement == original);
    let next = restored
        .state
        .control(&Command::control(CoreOperation::End, 1, 1, 1), [0x33; 32])
        .unwrap();
    assert_eq!(next.registry.transactions[0].id, 2);
    assert!(next.progress[0].as_ref().unwrap().statement == original);
    assert!(next.progress[1].is_none());
}
#[test]
fn logical_call_codec_rejects_aliases_and_sql_options_are_explicit() {
    let c = RawCall {
        slot: 1,
        kind: Kind::Acquire,
        sequence: 2,
        digest: [0x71; 32],
        transaction: 5,
    };
    assert!(RawCall::decode(c.encode().as_ref()).unwrap() == Some(c));
    for at in [0, 1, 2, 3, 7] {
        let mut wrong = c.encode();
        wrong[at] = 255;
        assert!(RawCall::decode(wrong.as_ref()).is_err());
    }
    assert!(RawCall::decode(&[0; state::CALL_BYTES]).unwrap().is_none());
    for sql in [
        "BEGIN ISOLATION LEVEL SERIALIZABLE",
        "COMMIT AND CHAIN",
        "SELECT age FROM records",
    ] {
        assert!(
            Call::sql([1; 32], 1, sql).is_err(),
            "unsupported owner syntax: {sql}"
        );
    }
    for sql in [
        "BEGIN",
        "COMMIT",
        "ROLLBACK",
        "SELECT age, amount FROM records WHERE age >= 128 FOR UPDATE",
        "SELECT age FROM records WHERE age = 255 FOR UPDATE NOWAIT",
        "SELECT amount FROM records WHERE age > 0 FOR UPDATE SKIP LOCKED",
    ] {
        assert!(
            Call::sql([1; 32], 1, sql).is_ok(),
            "supported owner syntax: {sql}"
        );
    }
}
#[test]
fn parked_call_allows_other_client_to_end_but_terminal_delivery_requires_exact_ack() {
    use super::state::{Book, Client};

    // This is a private ledger test, not a proof-positive owner fixture.
    let clients = core::array::from_fn(|slot| Client {
        binding: ClientBinding::new([0x61 + slot as u8; 32], 1 + slot as u8).unwrap(),
        active: 1 + slot as u64,
        last: 1,
        digest: [0x71; 32],
        record: 4 + slot as u64,
    });
    let book = Book {
        clients,
        flight: None,
        parked: [None, None],
    };
    let waiting = RawCall {
        slot: 1,
        kind: Kind::Acquire,
        sequence: 2,
        digest: [0x81; 32],
        transaction: 2,
    };
    let book = book.start(waiting, false).unwrap();
    let book = book.park(waiting, [0x31; 32], [0x32; 32], 8).unwrap();
    assert!(book.flight.is_none());
    assert_eq!(book.clients[1].last, 1);
    assert!(book.parked[1].unwrap().call == waiting);
    assert_eq!(book.parked[1].unwrap().record, 8);
    let before = book.encode();
    assert!(matches!(book.acknowledge(waiting), Err(Error::Cas)));
    assert!(matches!(book.start(waiting, false), Err(Error::Cas)));
    for changed in [
        RawCall {
            digest: [0x82; 32],
            ..waiting
        },
        RawCall {
            sequence: 3,
            ..waiting
        },
        RawCall {
            transaction: 3,
            ..waiting
        },
    ] {
        assert!(matches!(book.start(changed, true), Err(Error::Cas)));
    }
    assert_eq!(book.encode().as_ref(), before.as_ref());

    let ending = RawCall {
        slot: 0,
        kind: Kind::EndClose,
        sequence: 2,
        digest: [0x83; 32],
        transaction: 1,
    };
    let book = book
        .start(ending, false)
        .unwrap()
        .terminal(ending, 9)
        .unwrap();
    assert_eq!(book.clients[0].active, 0);
    assert!(book.parked[1].unwrap().call == waiting);
    assert!(matches!(book.start(waiting, true), Err(Error::Cas)));
    assert!(matches!(
        book.acknowledge(RawCall {
            digest: [0x84; 32],
            ..ending
        }),
        Err(Error::Cas)
    ));
    let book = book.acknowledge(ending).unwrap();
    let book = book
        .start(waiting, true)
        .unwrap()
        .terminal(waiting, 10)
        .unwrap();
    assert!(book.parked[1].is_none());
    assert_eq!(book.clients[1].last, 2);
    assert!(book.flight == Some(waiting));

    let next_begin = RawCall {
        slot: 0,
        kind: Kind::Begin,
        sequence: 3,
        digest: [0x85; 32],
        transaction: 3,
    };
    assert!(matches!(book.start(next_begin, false), Err(Error::Cas)));
    let book = book.acknowledge(waiting).unwrap();
    assert!(matches!(book.acknowledge(waiting), Err(Error::Cas)));
    assert!(matches!(book.start(waiting, true), Err(Error::Cas)));
    assert!(book.start(next_begin, false).is_ok());
}

#[test]
fn actual_aead_wal_rejects_wrong_authority_truncation_and_unsynced_tail() {
    let dir = fixture::Directory::new();
    let path = dir.path("public-private-wal");
    let header = [0x81; 104];
    let budget = ByteBudget::new(MAX_FILE_BYTES).unwrap();
    let mut wal = Wal::create_bound(&path, budget, header, authority()).unwrap();
    let mut lease = wal.reserve(2, 1024).unwrap();
    wal.append(b"PUBLIC NONSECRET phase one", &mut lease)
        .unwrap();
    wal.append(b"PUBLIC NONSECRET phase two", &mut lease)
        .unwrap();
    drop(lease);
    drop(wal);
    assert!(
        Wal::open_bound(
            &path,
            ByteBudget::new(MAX_FILE_BYTES).unwrap(),
            header,
            Authority::new(Zeroizing::new([0x92; 32]))
        )
        .is_err()
    );
    let (wal, records) = Wal::open_bound(
        &path,
        ByteBudget::new(MAX_FILE_BYTES).unwrap(),
        header,
        authority(),
    )
    .unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].as_slice(), b"PUBLIC NONSECRET phase one");
    assert_eq!(records[1].as_slice(), b"PUBLIC NONSECRET phase two");
    drop(wal);
    let file = OpenOptions::new().write(true).open(&path).unwrap();
    file.set_len(file.metadata().unwrap().len() - 1).unwrap();
    drop(file);
    assert!(
        Wal::open_bound(
            &path,
            ByteBudget::new(MAX_FILE_BYTES).unwrap(),
            header,
            authority()
        )
        .is_err()
    );
}
#[test]
fn ambiguous_write_poison_and_cold_replay_distinguish_actual_sync() {
    use protocol_storage::{ControlFile, ParticipantQuota};

    for (i, fault) in [Fault::BeforeWrite, Fault::PartialWrite, Fault::AfterSync]
        .into_iter()
        .enumerate()
    {
        let dir = fixture::Directory::new();
        let quota_root = dir.path(&format!("public-fault-{i}"));
        let quota = ParticipantQuota::create_new(&quota_root, [0x86; 32], MAX_FILE_BYTES).unwrap();
        let baseline = quota.usage().unwrap().control_bytes();
        let path = quota.control_file([0x87; 32], ControlFile::Wal);
        let sibling_budget = quota.control_budget();
        let header = [0x82; 104];
        let mut w = Wal::create_bound(&path, quota.control_budget(), header, authority()).unwrap();
        let mut lease = w.reserve(2, 1024).unwrap();
        w.append(b"PUBLIC NONSECRET durable prefix", &mut lease)
            .unwrap();
        w.fault = Some(fault);
        assert!(
            w.append(b"PUBLIC NONSECRET atomic phase", &mut lease)
                .is_err()
        );
        assert!(matches!(w.live(), Err(Error::Poisoned)));
        assert!(sibling_budget.require_live().is_err());
        drop(lease);
        drop(w);
        drop(sibling_budget);
        drop(quota);
        let quota =
            ParticipantQuota::open_existing(&quota_root, [0x86; 32], MAX_FILE_BYTES).unwrap();
        assert_eq!(
            quota.usage().unwrap().control_bytes(),
            baseline + std::fs::metadata(&path).unwrap().len()
        );
        let opened = Wal::open_bound(&path, quota.control_budget(), header, authority());
        if i == 1 {
            assert!(opened.is_err());
        } else {
            let (_, records) = opened.unwrap();
            assert_eq!(records.len(), if i == 2 { 2 } else { 1 });
            assert_eq!(records[0].as_slice(), b"PUBLIC NONSECRET durable prefix");
            if i == 2 {
                assert_eq!(records[1].as_slice(), b"PUBLIC NONSECRET atomic phase");
            }
        }
    }
}

pub(super) fn checkpoint(
    binding: &Binding,
    context: &work_finality::consensus::Context,
    block: &registry200_finality::CandidateBlock,
) -> Checkpoint {
    use work_finality::{QuorumCertificate, SignedVote, Step, VoteContext};
    let candidate = registry200_finality::progress::Candidate::for_context(
        binding,
        context,
        block.header().clone(),
    )
    .unwrap();
    let mut h = Sha256::new();
    h.update(b"dcs/work-finality/consensus-vote-instance/v1");
    h.update(work_finality::profile_digest());
    h.update(context.id());
    let vote = VoteContext::new(
        context.set(),
        h.finalize().into(),
        context.slot(),
        0,
        Step::Precommit,
        Some(context.value_id(&candidate.encode()).unwrap()),
    )
    .unwrap();
    let votes: Vec<_> = fixture::signers()
        .iter()
        .take(3)
        .map(|k| SignedVote::sign(vote, k).unwrap())
        .collect();
    Checkpoint::new(
        candidate,
        0,
        QuorumCertificate::assemble(context.set(), &vote, &votes)
            .unwrap()
            .encode()
            .unwrap(),
    )
    .unwrap()
}
#[test]
#[ignore = "One actual OS FHE input16/output118, new Progress/Core896, local genuine weighted QCs, owner fsync and strict cold replay; requires DCS_PEER_EXE; no four-validator or WAIT-continuation credit"]
fn actual_remote_product_qc_result160_sync_reopen_ack_and_end() {
    use bfv_query_core::{Geometry, KeyScope, Owner as BfvOwner};
    use compact_query::{PlainRow, RowIds, TableId};
    use ed25519_dalek::SigningKey;
    use peer_runtime::{
        Bootstrap as PeerBootstrap, Connector, RawBundle, RemotePeer, Request as PeerRequest,
        Response,
    };
    use registry200_joint::progress::{Lane, Manifest, ProgressDepot, Request};
    use registry200_journal::{
        Application as SourceSpec, ApplicationDescriptor, Control, Operation, intent_query,
    };
    use registry200_proof::{
        admission::CanonicalSource,
        registry_progress::{self as core, BootstrapWitness},
        source::{self, statement as ss},
    };
    use version_journal::{
        AuthorizedTransition, Body, Genesis, ProtocolProfile, ShardUpdate, Target,
    };
    use work_finality::{
        Genesis as WorkGenesis, Limits as WorkLimits, NetworkSeed, WorkTicket,
        consensus::{MAX_RECORD_BYTES, Rules},
    };
    let started = std::time::Instant::now();
    let phase = |name: &str| {
        eprintln!(
            "progress_owner_gate phase={name} elapsed_ms={}",
            started.elapsed().as_millis()
        )
    };
    let executable = std::path::PathBuf::from(
        std::env::var_os("DCS_PEER_EXE").expect("actual dcs-peer binary required"),
    );
    assert!(executable.is_absolute() && executable.is_file());
    let source_owner =
        SourceOwner::new([0x21; 16], [0x42; 16], Zeroizing::new([0x63; 32])).unwrap();
    let table = source_owner
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
    let loaded = source_owner.load(fetched()).unwrap();
    let (owner, setup) = BfvOwner::generate(Geometry::Rows16).unwrap();
    let owner_authority = OwnerStateAuthority::new(Zeroizing::new([0xa2; 32]));
    let (anchor, key, owner_identity, owner_record, anchor_record, ready_record) = {
        let handle = owner
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
        let id = OwnerStateIdentity {
            scope: anchor.scope().clone(),
            record_id: [0xa1; 32],
        };
        let mut epoch = handle.proof_epoch(&setup).unwrap();
        epoch.prove_key().unwrap();
        let key = setup
            .verify_key_transform(&anchor, epoch.key_evidence().unwrap().as_bytes())
            .unwrap()
            .statement()
            .clone();
        let records = (
            owner
                .backup_private_state(&setup, &id, &owner_authority)
                .unwrap(),
            handle
                .backup_private_state(&setup, &id, &owner_authority)
                .unwrap(),
            epoch
                .backup_ready_state(&setup, &id, &owner_authority)
                .unwrap(),
        );
        (anchor, key, id, records.0, records.1, records.2)
    };
    let source_identity =
        SourceStateIdentity::new([0xa3; 32], ss::encode_digest(loaded.draft.key_commitment))
            .unwrap();
    let source_authority = SourceStateAuthority::new(Zeroizing::new([0xa4; 32]));
    let source_record = source_owner
        .backup_private_state(&source_identity, fetched(), &source_authority)
        .unwrap();
    let material = Material {
        setup: &setup,
        anchor: &anchor,
        key: &key,
        owner_identity: &owner_identity,
        owner_authority: &owner_authority,
        owner_record: &owner_record,
        anchor_record: &anchor_record,
        ready_record: &ready_record,
        source_identity: &source_identity,
        source_authority: &source_authority,
        source_record: &source_record,
    };
    drop(owner);
    phase("original-Source-BFV-custody-fixture-ready");
    let dir = fixture::Directory::new();
    let quota = protocol_storage::ParticipantQuota::create_new(
        dir.path("participant"),
        [0x29; 32],
        10_000_000_000,
    )
    .unwrap();
    let spec = SourceSpec::new([0x3a; 32], 7, 8, &loaded.draft).unwrap();
    let descriptor = Descriptor::checked(
        ApplicationDescriptor::from_application(&spec).unwrap(),
        object,
        &setup,
        &anchor,
        &key,
    )
    .unwrap();
    let depot = ProgressDepot::open(quota.depot_budget(), &descriptor).unwrap();
    let claim = depot.retain_setup(&setup).unwrap();
    let signer = SigningKey::from_bytes(&[0x5b; 32]);
    let g = Genesis {
        network_id: spec.network,
        database: spec.database,
        owner: signer.verifying_key().to_bytes(),
        application_commitment: descriptor.id(),
        timestamp: 1000,
        profile: ProtocolProfile {
            initial_target: Target([255; 32]),
            pow_limit: Target([255; 32]),
            block_spacing_secs: 10,
            retarget_interval: 100,
            max_future_secs: 60,
            confirmation_depth: 1,
            max_headers: 32,
            max_shards: 2,
            max_updates: 1,
            max_body_bytes: version_journal::MAX_BODY_BYTES as u32,
            max_request_bytes: registry200_joint::progress::REQUEST_BYTES as u32,
            max_proof_bytes: registry200_joint::progress::MANIFEST_BYTES as u32,
            max_journal_bytes: version_journal::MAX_JOURNAL_BYTES,
        },
        initial_shards: spec.initial_shards(),
    };
    let rules = Rules::multi_slot(
        registry200_finality::progress::durable_profile_digest(),
        registry200_finality::progress::CANDIDATE_BYTES as u32,
        32,
        [180_000; 3],
        1_000,
        MAX_RECORD_BYTES as u64,
    )
    .unwrap();
    let seed = NetworkSeed::new(
        rules.seed_domain(spec.network),
        [10; 32],
        [255; 32],
        WorkLimits::new(16, 4).unwrap(),
    )
    .unwrap();
    let tickets = fixture::signers()
        .iter()
        .map(|k| WorkTicket::sign(&seed.bootstrap_election(), k, 0).unwrap())
        .collect();
    let binding = Binding::for_durable(
        spec.network,
        rules,
        WorkGenesis::from_bootstrap(seed, tickets).unwrap(),
        g,
        descriptor,
        claim,
    )
    .unwrap();
    let app = app(&binding).unwrap();
    let ingress = depot.ingress();
    let history = registry200_finality::progress::History::new(binding.clone(), depot).unwrap();
    let clients = [
        ClientBinding::new([0x61; 32], 1).unwrap(),
        ClientBinding::new([0x62; 32], 2).unwrap(),
    ];
    let controllers = [[0x41; 32], [0x42; 32]];
    let pins = || {
        Pins::new(
            binding.clone(),
            [0x63; 32],
            clients,
            Zeroizing::new(controllers),
        )
        .unwrap()
    };
    let salts = [[11, 12, 13, 14], [21, 22, 23, 24]];
    let empty = Bank {
        state: Zeroizing::new(State::default()),
        controllers: Zeroizing::new(controllers),
        enroll_salt: Zeroizing::new(salts[0]),
        registry_salt: Zeroizing::new(salts[1]),
    };
    let parent = history.bootstrap_parent().unwrap().head();
    let (enrollment, _) = empty
        .root(
            &pins(),
            parent.block,
            &loaded.draft,
            &loaded.plain.as_slice().try_into().unwrap(),
        )
        .unwrap();
    let nonce = [0xb1; 32];
    let mut source = loaded.draft.clone();
    source.request = intent_query(
        app.source_spec(),
        app.genesis(),
        parent.block,
        nonce,
        enrollment,
        Operation::Bootstrap,
    );
    source.open_commitment = source::commitment::digest(&source::commitment::opening_fields(
        &source,
        [Val::from_u64(31); 4],
        &loaded.plain,
    ));
    let canonical = CanonicalSource::checked_claim(&source).unwrap();
    let source_proof = source::prove(
        &canonical,
        &source_owner.source_witness([Val::from_u64(31); 4], &loaded.originals),
    )
    .unwrap();
    let expected =
        core::BootstrapExpected::new(&canonical, app.genesis(), parent.block, enrollment).unwrap();
    let witness = BootstrapWitness::new(
        &expected,
        Zeroizing::new(loaded.plain.as_slice().try_into().unwrap()),
        Zeroizing::new(controllers),
        Zeroizing::new([[31; 4], salts[0], salts[1]]),
    )
    .unwrap();
    let proof = core::prove_bootstrap(&expected, &witness, source_proof.as_bytes()).unwrap();
    let manifest = Manifest::bootstrap(
        proof.statement().next(),
        ingress.retain_public_blob(source_proof.as_bytes()).unwrap(),
        ingress.retain_public_blob(&proof.into_parts().1).unwrap(),
    )
    .unwrap();
    let request = Request::new(
        &app,
        Lane::Bootstrap,
        registry200_journal::Request {
            operation: Operation::Bootstrap,
            genesis: app.genesis(),
            parent: parent.block,
            application: app.source_spec().id(),
            nonce,
            query: source.request,
            enrollment,
            opening: ss::encode_digest(source.open_commitment),
            command: [0; 32],
            packets: source.packets,
        },
    )
    .unwrap();
    let mut t = AuthorizedTransition {
        parent: parent.block,
        request: request.encode().unwrap(),
        proof: manifest.encode(),
        updates: vec![ShardUpdate {
            id: app.source_spec().control_id,
            old: Control::Pending.heads(app.source_spec()),
            new: Control::Active {
                enrollment,
                registry: manifest.next_root(),
            }
            .heads(app.source_spec()),
        }],
        owner_signature: [0; 64],
    };
    t.sign(app.genesis(), &signer);
    let body = Body::Transition(t);
    let mut header = history.candidate_header(&body, 1001, 2000).unwrap();
    header.mine(16).unwrap();
    let boot = registry200_finality::CandidateBlock::new(
        header,
        body.encode(&binding.journal_genesis().profile).unwrap(),
    )
    .unwrap();
    let boot_qc = checkpoint(&binding, history.context().unwrap(), &boot);
    drop(history);
    drop(ingress);
    phase("genuine-Bootstrap803-and-local-weighted-QC-ready");
    let gate = peer_runtime::ProofGate::new();
    let mut host = Owner::create_new(
        pins(),
        authority(),
        &quota,
        gate.clone(),
        &material,
        fetched(),
        Bootstrap {
            replay: &[Replay {
                checkpoint: &boot_qc,
                block: &boot,
            }],
            salts: Zeroizing::new(salts),
        },
    )
    .unwrap();
    phase("custody-bootstrap-owner-created");
    let cursor = host.cursor().unwrap();
    host.prepare(
        cursor,
        &Call::sql(clients[0].id, 1, "BEGIN").unwrap(),
        &material,
        fetched(),
    )
    .unwrap();
    let prepared_cursor = host.cursor().unwrap();
    assert!(host.outcome(prepared_cursor).unwrap().is_none());
    assert!(matches!(host.work(cursor, &material), Err(Error::Cas)));
    assert!(
        host.submit(
            prepared_cursor,
            None,
            &SigningKey::from_bytes(&[0x6b; 32]),
            1002,
            16
        )
        .is_err()
    );
    assert!(host.cursor().unwrap() == prepared_cursor);
    let s = host
        .submit(prepared_cursor, None, &signer, 1002, 16)
        .unwrap();
    let q = host.test_checkpoint(s.block());
    assert!(matches!(
        host.complete(s.cursor(), &q, &material, fetched()).unwrap(),
        Outcome::Control(ControlOutcome::Begun)
    ));
    host.acknowledge(host.cursor().unwrap()).unwrap();
    phase("actual-Begin815-QC-fsync-ACK");
    let peer_identity = fixture::identity();
    let config = PeerBootstrap {
        identity: fixture::identity(),
        authority: vec![],
        owner: peer_identity.fingerprint(),
        node_id: 207,
        quota_bytes: 16 * 1024 * 1024,
        listen: "127.0.0.1:0".parse().unwrap(),
    };
    let process =
        os_process::Process::start_storage(&executable, &dir.path("actual-fhe-peer"), &config)
            .unwrap();
    assert_ne!(process.pid(), std::process::id());
    let remote = RemotePeer::new(
        process.endpoint().clone(),
        Connector::permissionless(&peer_identity).unwrap(),
    );
    assert!(
        matches!(remote.call(PeerRequest::Store(bundle.clone())).unwrap(),Response::Stored(info)if info.id==object)
    );
    assert!(matches!(
        remote
            .call(PeerRequest::InstallSetup(setup.to_bytes().unwrap()))
            .unwrap(),
        Response::Setup(_)
    ));
    phase("independent-OS-peer-original-setup-installed");
    host.prepare(
        host.cursor().unwrap(),
        &Call::sql(
            clients[0].id,
            2,
            "SELECT age, amount FROM records WHERE age >= 128 FOR UPDATE SKIP LOCKED",
        )
        .unwrap(),
        &material,
        fetched(),
    )
    .unwrap();
    phase("original-Ready-restoration-Source-input16-Core896-prepared");
    assert!(host.outcome(host.cursor().unwrap()).unwrap().is_none());
    let work = host
        .work(host.cursor().unwrap(), &material)
        .unwrap()
        .unwrap();
    let computed = work.compute(&remote).unwrap();
    phase("actual-remote-FHE-product118-verified-recorded");
    let s = host
        .submit(host.cursor().unwrap(), Some(computed), &signer, 1003, 16)
        .unwrap();
    let q = host.test_checkpoint(s.block());
    host.test_fault(Fault::AfterSync);
    assert!(host.complete(s.cursor(), &q, &material, fetched()).is_err());
    assert!(matches!(host.cursor(), Err(Error::Poisoned)));
    drop(s);
    drop(host);
    drop(quota);
    phase("actual-QC-result160-fsync-acknowledgement-lost");
    let quota = protocol_storage::ParticipantQuota::open_existing(
        dir.path("participant"),
        [0x29; 32],
        10_000_000_000,
    )
    .unwrap();
    let mut host =
        Owner::open_existing(pins(), authority(), &quota, gate, &material, fetched()).unwrap();
    let Some(Outcome::Done(reply)) = host.outcome(host.cursor().unwrap()).unwrap() else {
        panic!("cold genuine replay must deliver Done")
    };
    assert_eq!(reply.rows().len(), 2);
    assert_eq!(
        (reply.rows()[0].age, reply.rows()[0].amount),
        (Some(128), Some(255))
    );
    assert_eq!(
        (reply.rows()[1].age, reply.rows()[1].amount),
        (Some(255), Some(65534))
    );
    host.acknowledge(host.cursor().unwrap()).unwrap();
    phase("cold-proof-QC-replay-decrypt-ACK");
    host.prepare(
        host.cursor().unwrap(),
        &Call::sql(clients[0].id, 3, "COMMIT").unwrap(),
        &material,
        fetched(),
    )
    .unwrap();
    let s = host
        .submit(host.cursor().unwrap(), None, &signer, 1004, 16)
        .unwrap();
    let q = host.test_checkpoint(s.block());
    assert!(matches!(
        host.complete(s.cursor(), &q, &material, fetched()).unwrap(),
        Outcome::Control(ControlOutcome::Closed)
    ));
    host.acknowledge(host.cursor().unwrap()).unwrap();
    process.finish().unwrap();
    phase("actual-End815-QC-fsync");
}
