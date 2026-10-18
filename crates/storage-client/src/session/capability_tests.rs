//! Actual TLS, signatures and arithmetic at the rejected SQL admission boundary.
use super::*;
use peer_runtime::{Bootstrap, Connector, Identity, PeerServer, RemoteError, RunningServer};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use std::{
    fs,
    io::Write,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

fn identity() -> Identity {
    let mut params = CertificateParams::new(vec!["dcs-peer".into()]).unwrap();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let key = KeyPair::generate().unwrap();
    let certificate = params.self_signed(&key).unwrap();
    Identity {
        certificate: certificate.der().to_vec(),
        private_key_pkcs8: key.serialize_der(),
    }
}
fn profile() -> ProtocolProfile {
    ProtocolProfile {
        initial_target: version_journal::Target([0x0f; 32]),
        pow_limit: version_journal::Target([0x0f; 32]),
        block_spacing_secs: 1,
        retarget_interval: 1024,
        max_future_secs: 30,
        confirmation_depth: 1,
        max_headers: 256,
        max_shards: 16,
        max_updates: 16,
        max_body_bytes: 32 * 1024 * 1024,
        max_request_bytes: 32 * 1024 * 1024,
        max_proof_bytes: 32 * 1024 * 1024,
        max_journal_bytes: 256 * 1024 * 1024,
    }
}
struct Network {
    parent: PathBuf,
    name: std::ffi::OsString,
    directory: PathBuf,
    server: RunningServer,
    participant: Participant,
    events: Arc<Mutex<Vec<String>>>,
}
impl Network {
    fn new() -> Self {
        let parent =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.local/sql-capability-tests");
        fs::create_dir_all(&parent).unwrap();
        let parent = parent.canonicalize().unwrap();
        let name = std::ffi::OsString::from(format!(
            "{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let directory = parent.join(&name);
        fs::create_dir(&directory).unwrap();
        let directory = directory.canonicalize().unwrap();
        assert_eq!(directory.parent(), Some(parent.as_path()));
        assert_eq!(directory.file_name(), Some(name.as_os_str()));
        let owner = identity();
        let connector = Connector::permissionless(&owner).unwrap();
        let server = PeerServer::bind(
            Bootstrap {
                identity: identity(),
                authority: vec![],
                owner: owner.fingerprint(),
                node_id: 1,
                quota_bytes: 256 * 1024 * 1024,
                listen: "127.0.0.1:0".parse().unwrap(),
            },
            &directory.join("peer"),
        )
        .unwrap()
        .spawn()
        .unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let observed = events.clone();
        let participant = Participant {
            id: 1,
            remote: RemotePeer::new(server.endpoint.clone(), connector).with_trace(Arc::new(
                move |event| observed.lock().unwrap().push(event.operation),
            )),
        };
        Self {
            parent,
            name,
            directory,
            server,
            participant,
            events,
        }
    }
}
impl Drop for Network {
    fn drop(&mut self) {
        self.server.stop();
        if let Ok(current) = self.directory.canonicalize()
            && current == self.directory
            && current.parent() == Some(self.parent.as_path())
            && current.file_name() == Some(self.name.as_os_str())
        {
            let _ = fs::remove_dir_all(current);
        }
    }
}
fn capability(error: Error) {
    assert!(
        matches!(error, Error::InvalidInput(ref reason) if reason.contains("encrypted SQL execution is unavailable")),
        "{error}"
    );
}

#[test]
fn both_pending_mutation_kinds_remain_exact_and_unpublished_on_resume_or_new_sql() {
    let network = Network::new();
    let mut session = Session::create(
        "pending-guard".into(),
        &[PlainRow { age: 42, amount: 7 }],
        vec![network.participant.clone()],
        profile(),
    )
    .unwrap();
    let initial = session.version();
    let original_heads = heads(&session.data.shards[0].info);
    for outcome in [
        MutationOutcome::Inserted { count: 1 },
        MutationOutcome::Updated { affected_rows: 1 },
    ] {
        let inserted = matches!(outcome, MutationOutcome::Inserted { .. });
        // Deliberately unproved retained bytes: the public resume must reject
        // before reading or authenticating them. They are not a proof fixture.
        let transition = AuthorizedTransition {
            parent: initial.block,
            request: vec![1, 2, 3],
            updates: vec![],
            proof: vec![4, 5],
            owner_signature: [6; 64],
        };
        session.pending_mutation = Some(PendingMutation {
            sql_digest: version_journal::hash(b"INSERT INTO records VALUES(18,20)"),
            query_binding: [8; 32],
            transition: transition.clone(),
            submitted: Some(initial),
            outcome,
            stored: vec![StoredMutation {
                slot: 0,
                object: session.data.shards[0].info.object,
                heads: original_heads,
                holders: vec![network.participant.clone()],
            }],
        });
        let before = network.participant.remote.status().unwrap();
        network.events.lock().unwrap().clear();
        capability(session.resume_pending().unwrap_err());
        capability(
            session
                .execute("INSERT INTO records VALUES(18,20)")
                .unwrap_err(),
        );
        capability(session.execute("SELECT * FROM records").unwrap_err());
        assert!(network.events.lock().unwrap().is_empty());
        let retained = session.pending_mutation.as_ref().unwrap();
        assert_eq!(retained.transition, transition);
        assert_eq!(retained.submitted, Some(initial));
        assert_eq!(retained.query_binding, [8; 32]);
        assert_eq!(
            retained.sql_digest,
            version_journal::hash(b"INSERT INTO records VALUES(18,20)")
        );
        assert_eq!(retained.stored[0].heads, original_heads);
        assert_eq!(
            retained.stored[0].object,
            session.data.shards[0].info.object
        );
        assert_eq!(retained.stored[0].holders[0].id, network.participant.id);
        assert!(matches!(
            (&retained.outcome, inserted),
            (MutationOutcome::Inserted { count: 1 }, true)
                | (MutationOutcome::Updated { affected_rows: 1 }, false)
        ));
        assert!(session.pending_publication.is_none());
        assert_eq!(session.version(), initial);
        let after = network.participant.remote.status().unwrap();
        assert_eq!(after.journal_bytes, before.journal_bytes);
        assert_eq!(after.objects.len(), before.objects.len());
    }
}

#[test]
fn typed_select_capability_rejects_before_synchronization_or_source_io() {
    let network = Network::new();
    let database = relational_types::import_database_dump(
        "CREATE TABLE items(id INT NOT NULL, label NVARCHAR(20) NULL); INSERT INTO items VALUES(1,'public'),(2,NULL);",
        relational_types::ImportLimits::default(),
    ).unwrap();
    let mut session = crate::relational::RelationalSession::import(
        database,
        vec![network.participant.clone()],
        profile(),
    )
    .unwrap();
    let initial = session.version();
    let before = network.participant.remote.status().unwrap();
    for sql in [
        "SELECT * FROM items",
        "SELECT label FROM items WHERE id=1",
        "SELECT label FROM items WHERE id<0 LIMIT 0",
        "SELECT label FROM items ORDER BY label DESC NULLS LAST OFFSET 1 LIMIT 1",
        "SELECT label FROM items ORDER BY label FETCH FIRST 1 ROW WITH TIES",
    ] {
        network.events.lock().unwrap().clear();
        capability(session.select(sql).unwrap_err());
        assert!(network.events.lock().unwrap().is_empty(), "{sql}");
        assert_eq!(session.version(), initial);
    }
    let after = network.participant.remote.status().unwrap();
    assert_eq!(after.journal_bytes, before.journal_bytes);
    assert_eq!(after.objects.len(), before.objects.len());
}

#[test]
fn genuine_arithmetic_and_owner_signatures_cannot_mine_publish_or_reopen_jobs_mutations() {
    let network = Network::new();
    let database = [87; 16];
    let storage = compact_store::Owner::generate(database).unwrap();
    let limits = Limits::default();
    let data = storage
        .seal(
            compact_store::Layout {
                schema: [1; 16],
                row_width: 3,
                rows_per_page: 16,
                row_count: 1,
            },
            &[18, 20, 0],
            limits,
        )
        .unwrap();
    let index = storage
        .seal(
            compact_store::Layout {
                schema: [2; 16],
                row_width: 1,
                rows_per_page: 16,
                row_count: 1,
            },
            &[0],
            limits,
        )
        .unwrap();
    let old = HeadPair {
        data: data.commitment().encode(),
        index: index.commitment().encode(),
    };
    let bundle = RawBundle::from_snapshots(&data, &index).unwrap();
    let object = *bundle.target_version().unwrap().object();
    assert!(
        matches!(network.participant.remote.call(Request::Store(bundle)).unwrap(), Response::Stored(info) if info.id == object)
    );
    let (owner, setup) =
        bfv_query_core::Owner::generate(bfv_query_core::Geometry::Rows256).unwrap();
    let verifier = JobVerifier::new(setup.update_parameters().unwrap()).unwrap();
    let Response::Setup(setup_id) = network
        .participant
        .remote
        .call(Request::InstallSetup(setup.to_bytes().unwrap()))
        .unwrap()
    else {
        panic!("setup")
    };
    // This explicitly public signing fixture is not an operational owner key.
    let signer = SigningKey::from_bytes(&[91; 32]);
    let genesis = Genesis {
        network_id: [92; 32],
        database,
        owner: signer.verifying_key().to_bytes(),
        application_commitment: verifier.application_commitment(),
        timestamp: agreement::now().saturating_sub(1),
        profile: profile(),
        initial_shards: vec![ShardState { id: 7, heads: old }],
    };
    let journal = Journal::new(genesis.clone()).unwrap();
    let network_id = journal.genesis_id();
    assert!(
        matches!(network.participant.remote.call(Request::InitJournal { genesis: genesis.encode().unwrap(), setup: setup_id }).unwrap(), Response::JournalReady(id) if id == network_id)
    );
    for operation in [Operation::Insert, Operation::Update] {
        let context = bfv_query_core::QueryContext::new([93; 16], old.data, old.index);
        let original = [bfv_query_core::SelectedField {
            age: 18,
            amount: 20,
            active: true,
        }];
        let request = match operation {
            Operation::Insert => {
                owner
                    .prepare_indexed_insert_for_experiment(
                        context,
                        &original,
                        &[bfv_query_core::SelectedField {
                            age: 42,
                            amount: 30,
                            active: true,
                        }],
                    )
                    .unwrap()
                    .request
            }
            Operation::Update => {
                owner
                    .prepare_indexed_update_for_experiment(context, &original, 5)
                    .unwrap()
                    .request
            }
            _ => unreachable!(),
        };
        let Response::Proved(reply) = network
            .participant
            .remote
            .call(Request::Prove {
                object,
                setup: setup_id,
                operation,
                ciphertext: request.clone(),
            })
            .unwrap()
        else {
            panic!("genuine arithmetic")
        };
        verifier.check_job(operation, &request, &reply).unwrap();
        let mut next_data = data.clone();
        let mut next_index = index.clone();
        if operation == Operation::Insert {
            next_data = storage
                .grow_from_checked_plaintext(
                    &data,
                    data.commitment(),
                    2,
                    &[18, 20, 0, 42, 30, 0],
                    limits,
                )
                .unwrap();
            next_index = storage
                .grow_from_checked_plaintext(&index, index.commitment(), 2, &[0, 1], limits)
                .unwrap();
        } else {
            storage
                .replace_page(&mut next_data, data.commitment(), 0, &[18, 25, 0], limits)
                .unwrap();
            storage
                .replace_page(&mut next_index, index.commitment(), 0, &[1], limits)
                .unwrap();
        }
        let manifest = MutationManifest {
            query_binding: [94; 32],
            operation,
            previous_shards: genesis.initial_shards.clone(),
            jobs: vec![MutationJob { shard: 7, request }],
        };
        let mut transition = AuthorizedTransition {
            parent: network_id,
            request: manifest.encode().unwrap(),
            updates: vec![ShardUpdate {
                id: 7,
                old,
                new: HeadPair {
                    data: next_data.commitment().encode(),
                    index: next_index.commitment().encode(),
                },
            }],
            proof: MutationEvidence { jobs: vec![reply] }.encode().unwrap(),
            owner_signature: [0; 64],
        };
        transition.sign(network_id, &signer);
        signer
            .verifying_key()
            .verify_strict(
                &transition.signing_message(network_id),
                &ed25519_dalek::Signature::from_bytes(&transition.owner_signature),
            )
            .unwrap();
        let body = Body::Transition(transition);
        let wire = body.encode(journal.profile()).unwrap();
        let timestamp = agreement::now();
        let mut header = journal.candidate(network_id, &body, timestamp).unwrap();
        header.mine(100_000).unwrap();
        let before = network.participant.remote.status().unwrap();
        for request in [
            Request::MineBlock {
                network: network_id,
                parent: network_id,
                body: wire.clone(),
                timestamp,
                attempts: 100_000,
            },
            Request::PublishBlock {
                network: network_id,
                header: header.encode().to_vec(),
                body: wire.clone(),
            },
        ] {
            let error = network
                .participant
                .remote
                .call(request)
                .err()
                .expect("a signature and arithmetic are insufficient");
            assert!(
                matches!(error.get_ref().and_then(|e|e.downcast_ref::<RemoteError>()), Some(RemoteError::Cryptography(reason)) if reason.contains("RejectedComputationProof")),
                "{error}"
            );
        }
        assert_eq!(
            network.participant.remote.status().unwrap().journal_bytes,
            before.journal_bytes
        );
        assert!(
            matches!(network.participant.remote.call(Request::JournalBlocks { network:network_id, known:vec![network_id] }).unwrap(), Response::JournalBlocks(blocks) if blocks.is_empty())
        );
        let path = network
            .directory
            .join(format!("historical-{operation:?}.journal"));
        drop(
            version_journal::DurableJournal::create(
                &path,
                genesis.clone(),
                peer_runtime::OBJECT_PROFILE_ID,
            )
            .unwrap(),
        );
        // Untrusted disk input models an old Jobs record. No permissive verifier
        // creates authority for it: fresh reopen must reverify and reject it.
        let mut frame = header.encode().to_vec();
        frame.extend_from_slice(&wire);
        let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&(frame.len() as u32).to_le_bytes()).unwrap();
        file.write_all(&frame).unwrap();
        file.write_all(&version_journal::hash(&frame)).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let bytes = fs::read(&path).unwrap();
        assert!(matches!(
            version_journal::DurableJournal::open(
                &path,
                genesis.clone(),
                peer_runtime::OBJECT_PROFILE_ID,
                timestamp,
                &verifier
            ),
            Err(version_journal::Error::RejectedComputationProof)
        ));
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
}
