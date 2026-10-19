use super::*;
#[test]
fn one_body_lease_spans_fetch_queue_and_send_until_actual_owner_drop() {
    let gate = BodyGate::new();
    let next_connection = gate.clone();
    let first = gate.acquire().unwrap();
    assert_eq!(
        next_connection.acquire().err().unwrap().kind(),
        io::ErrorKind::WouldBlock
    );
    let thread = std::thread::spawn(move || {
        assert!(next_connection.acquire().is_err());
        drop(first);
    });
    thread.join().unwrap();
    assert!(gate.acquire().is_ok());
}
#[test]
fn small_command_accounting_checks_full_aggregate_and_releases_on_rejected_queue() {
    let ledger = InboxBytes(Arc::new(AtomicUsize::new(0)));
    let commands: Vec<_> = (0..MAX_COMMANDS)
        .map(|_| ledger.acquire(2 * 1024 * 1024).unwrap())
        .collect();
    assert!(ledger.acquire(1).is_err());
    assert!(ledger.acquire(usize::MAX).is_err());
    drop(commands);
    assert!(ledger.acquire(MAX_QUEUED_BYTES).is_ok());
    assert_eq!(ledger.0.load(Ordering::Acquire), 0);
}
#[test]
fn independent_profile_binding_and_declared_control_limit_precede_payload_decode() {
    let packet = wire::encode([1; 32], wire::GET_CHECKPOINT, &7u64.to_le_bytes()).unwrap();
    let (tag, data) = wire::decode([1; 32], &packet).unwrap();
    assert_eq!(tag, wire::GET_CHECKPOINT);
    assert_eq!(wire::word(data).unwrap(), 7);
    assert!(wire::decode([2; 32], &packet).is_err());
    for n in [0, 7, 39, 71, 72] {
        assert!(wire::decode([1; 32], &packet[..n]).is_err());
    }
    let mut changed = packet.clone();
    changed[8] ^= 1;
    assert!(wire::decode([1; 32], &changed).is_err());
    let mut tail = data.to_vec();
    tail.push(0);
    assert!(wire::word(&tail).is_err());
    assert!(
        wire::encode(
            [1; 32],
            wire::INPUT,
            &vec![0; work_finality::consensus::MAX_INPUT_BYTES + 1]
        )
        .is_err()
    );
}

// Real TLS actors in ONE process. This is deliberately not the independently
// launched four-OS-peer deployment gate. Keys/data below are PUBLIC NONSECRET
// fixtures; an Empty Body has actual Journal work/QC semantics, not SQL/FHE.
fn identity() -> peer_transport::Identity {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut p = rcgen::CertificateParams::new(vec!["dcs-peer".into()]).unwrap();
    p.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let certificate = p.self_signed(&key).unwrap();
    peer_transport::Identity {
        certificate: certificate.der().to_vec(),
        private_key_pkcs8: key.serialize_der(),
    }
}
struct Files {
    root: std::path::PathBuf,
    parent: std::path::PathBuf,
    name: std::ffi::OsString,
}
impl Files {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let parent = std::env::temp_dir().canonicalize().unwrap();
        for _ in 0..64 {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let name = std::ffi::OsString::from(format!(
                "dcs-public-finality-TLS-{}-{stamp}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let raw = parent.join(&name);
            match std::fs::create_dir(&raw) {
                Ok(()) => {
                    let root = raw.canonicalize().unwrap();
                    assert_eq!(root.parent(), Some(parent.as_path()));
                    assert_eq!(root.file_name(), Some(name.as_os_str()));
                    return Self { root, parent, name };
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
                Err(e) => panic!("create public test directory: {e}"),
            }
        }
        panic!("bounded unique public directory");
    }
}
impl Drop for Files {
    fn drop(&mut self) {
        if let Ok(path) = self.root.canonicalize()
            && path == self.root
            && path.parent() == Some(self.parent.as_path())
            && path.file_name() == Some(self.name.as_os_str())
        {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}
fn binding() -> (
    registry200_finality::Binding,
    Vec<ed25519_dalek::SigningKey>,
) {
    use registry200_proof::source;
    let owner =
        compact_store::Owner::from_key([0x42; 16], [0x73; 16], zeroize::Zeroizing::new([0x71; 32]));
    let stored = owner
        .seal(
            compact_store::Layout {
                schema: source::DATA_SCHEMA,
                row_width: 3,
                rows_per_page: 256,
                row_count: 4,
            },
            &[255, 0, 0, 0, 255, 255, 255, 0, 1, 128, 255, 0],
            source::statement::limits(),
        )
        .unwrap();
    let suffix: Vec<u8> =
        include_str!("../../../compact-query/tests/fixtures/index-v3-four-row-suffix.hex")
            .lines()
            .filter(|l| !l.starts_with('#'))
            .flat_map(str::split_whitespace)
            .map(|x| u8::from_str_radix(x, 16).unwrap())
            .collect();
    let mut index = stored.commitment().encode().to_vec();
    index.extend(suffix);
    let indexed = owner
        .seal(
            compact_store::Layout {
                schema: source::INDEX_SCHEMA,
                row_width: 1,
                rows_per_page: 4096,
                row_count: 2336,
            },
            &index,
            source::statement::limits(),
        )
        .unwrap();
    // Public canonical geometry only. These zero commitments are unproved and
    // cannot admit Bootstrap/Acquire; this owning TLS test uses ONLY real Empty.
    let source = source::Statement::checked_relation(
        source::Relation::CanonicalIndex,
        [&stored.encode(), &indexed.encode()],
        [stored.commitment(), indexed.commitment()],
        [0; 32],
        [0; 32],
        [0; 32],
    )
    .unwrap();
    let app = registry200_journal::Application::new([9; 32], 7, 8, &source).unwrap();
    let rules = work_finality::consensus::Rules::multi_slot(
        registry200_finality::profile_digest(),
        registry200_finality::DESCRIPTOR_BYTES as u32,
        100,
        [1000, 1500, 2000],
        1000,
        work_finality::consensus::MAX_RECORD_BYTES as u64,
    )
    .unwrap();
    let mut keys: Vec<_> = (1..=4)
        .map(|n| ed25519_dalek::SigningKey::from_bytes(&[n; 32]))
        .collect();
    keys.sort_by_key(|k| k.verifying_key().to_bytes());
    let seed = work_finality::NetworkSeed::new(
        rules.seed_domain([9; 32]),
        [10; 32],
        [255; 32],
        work_finality::Limits::new(16, 4).unwrap(),
    )
    .unwrap();
    let work = work_finality::Genesis::from_bootstrap(
        seed.clone(),
        keys.iter()
            .map(|k| work_finality::WorkTicket::sign(&seed.bootstrap_election(), k, 0).unwrap())
            .collect(),
    )
    .unwrap();
    let genesis = version_journal::Genesis {
        network_id: [9; 32],
        database: app.database,
        owner: ed25519_dalek::SigningKey::from_bytes(&[0x55; 32])
            .verifying_key()
            .to_bytes(),
        application_commitment: app.id(),
        timestamp: 1000,
        profile: version_journal::ProtocolProfile {
            initial_target: version_journal::Target([255; 32]),
            pow_limit: version_journal::Target([255; 32]),
            block_spacing_secs: 10,
            retarget_interval: 100,
            max_future_secs: 60,
            confirmation_depth: 1,
            max_headers: 32,
            max_shards: 2,
            max_updates: 1,
            max_body_bytes: version_journal::MAX_BODY_BYTES as u32,
            max_request_bytes: registry200_journal::REQUEST_BYTES as u32,
            max_proof_bytes: version_journal::MAX_BODY_BYTES as u32,
            max_journal_bytes: version_journal::MAX_JOURNAL_BYTES,
        },
        initial_shards: app.initial_shards(),
    };
    (
        registry200_finality::Binding::new(
            [9; 32],
            rules,
            work,
            genesis,
            registry200_journal::ApplicationDescriptor::from_application(&app).unwrap(),
        )
        .unwrap(),
        keys,
    )
}
fn until(mut condition: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        if condition() {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "observable TLS condition timed out"
        );
        std::thread::park_timeout(Duration::from_millis(20));
    }
}
fn empty(
    journal: &mut version_journal::Journal,
    binding: &registry200_finality::Binding,
) -> CandidateBlock {
    let body = version_journal::Body::Empty;
    let parent = journal.best_validated();
    let mut header = journal
        .candidate(parent.block, &body, 1001 + parent.height)
        .unwrap();
    header.mine(1000).unwrap();
    let bytes = body.encode(&binding.journal_genesis().profile).unwrap();
    let verifier = registry200_journal::RegistryVerifier::new(
        binding.application_descriptor().application().unwrap(),
        binding.journal_genesis(),
    )
    .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    journal
        .import_block(header.clone(), &bytes, now, &verifier)
        .unwrap();
    CandidateBlock::new(header, bytes).unwrap()
}

#[test]
fn real_tls_empty_actors_wait_in_two_partitions_then_heal_and_catch_up_an_offline_signer() {
    let (binding, keys) = binding();
    let files = Files::new();
    let owner = identity();
    let nodes: Vec<_> = (0..4).map(|_| identity()).collect();
    let gate = crate::ProofGate::new();
    let connector = peer_transport::Connector::permissionless(&owner).unwrap();
    let mut servers = Vec::new();
    for (i, node) in nodes.iter().enumerate() {
        let directory = files.root.join(i.to_string());
        std::fs::create_dir(&directory).unwrap();
        let owned = registry200_finality::RegistryFinality::create_new(
            &directory,
            binding.clone(),
            keys[i].clone(),
            &protocol_storage::ByteBudget::new(version_journal::MAX_JOURNAL_BYTES).unwrap(),
        )
        .unwrap();
        servers.push(
            FinalityServer::bind(
                ListenerConfig {
                    listen: "127.0.0.1:0".parse().unwrap(),
                    identity: node.fingerprint(),
                    owner: owner.fingerprint(),
                    acceptor: peer_transport::Acceptor::permissionless(node).unwrap(),
                    connector: peer_transport::Connector::permissionless(node).unwrap(),
                    neighbors: Vec::new(),
                },
                owned,
                gate.clone(),
            )
            .unwrap(),
        );
    }
    let endpoints: Vec<_> = servers.iter().map(|s| s.endpoint().clone()).collect();
    for (i, server) in servers.iter_mut().enumerate() {
        server
            .set_neighbors(
                endpoints
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i && *j / 2 == i / 2)
                    .map(|(_, p)| p.clone())
                    .collect(),
            )
            .unwrap();
    }
    let clients: Vec<_> = endpoints
        .iter()
        .map(|p| FinalityClient::new(connector.clone(), p.clone(), &binding))
        .collect();
    let mut running: Vec<_> = servers.into_iter().map(|s| s.spawn().unwrap()).collect();
    let mut journal = version_journal::Journal::new(binding.journal_genesis().clone()).unwrap();
    let first = empty(&mut journal, &binding);
    // Remote local-control tags are rejected by the actual consensus decoder;
    // TLS authentication is not permission to advance our local clock.
    let mut wire_connection = connector.connect(&endpoints[0]).unwrap();
    peer_transport::write_frame(
        &mut wire_connection,
        &wire::encode(binding.id(), wire::INPUT, &[5]).unwrap(),
        wire::MAX_CONTROL,
    )
    .unwrap();
    let rejection = peer_transport::read_frame(&mut wire_connection, wire::MAX_CONTROL).unwrap();
    assert_eq!(
        wire::decode(binding.id(), &rejection).unwrap().0,
        wire::REJECT
    );
    drop(wire_connection);
    assert_eq!(clients[0].observed_slot().unwrap(), 1);
    // Unauthorized TLS identity cannot even trigger a Body upload.
    let stranger = identity();
    let stranger = FinalityClient::new(
        peer_transport::Connector::permissionless(&stranger).unwrap(),
        endpoints[0].clone(),
        &binding,
    );
    assert!(stranger.submit(&first).is_err());
    for client in &clients {
        until(|| client.submit(&first).is_ok());
    }
    // Observe a bounded no-quorum interval across actual RPCs, not an arbitrary
    // sleep followed by a guessed local-manager state.
    let end = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < end {
        for client in &clients {
            assert_eq!(client.observed_slot().unwrap(), 1);
        }
        std::thread::park_timeout(Duration::from_millis(20));
    }
    for server in &mut running {
        server.stop().unwrap();
    }
    drop(running);
    let mut running = Vec::new();
    for (i, node) in nodes.iter().enumerate() {
        let owned = registry200_finality::RegistryFinality::open_existing(
            &files.root.join(i.to_string()),
            binding.clone(),
            keys[i].clone(),
            &protocol_storage::ByteBudget::new(version_journal::MAX_JOURNAL_BYTES).unwrap(),
        )
        .unwrap();
        let server = FinalityServer::bind(
            ListenerConfig {
                listen: endpoints[i].address,
                identity: node.fingerprint(),
                owner: owner.fingerprint(),
                acceptor: peer_transport::Acceptor::permissionless(node).unwrap(),
                connector: peer_transport::Connector::permissionless(node).unwrap(),
                neighbors: endpoints
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .map(|(_, p)| p.clone())
                    .collect(),
            },
            owned,
            gate.clone(),
        )
        .unwrap();
        running.push(server.spawn().unwrap());
    }
    for client in &clients {
        until(|| client.submit(&first).is_ok() || client.observed_slot().is_ok_and(|s| s >= 2));
    }
    until(|| {
        clients
            .iter()
            .all(|c| c.observed_slot().is_ok_and(|s| s == 2))
    });
    running[3].stop().unwrap();
    let second = empty(&mut journal, &binding);
    for client in &clients[..3] {
        until(|| client.submit(&second).is_ok());
    }
    until(|| {
        clients[..3]
            .iter()
            .all(|c| c.observed_slot().is_ok_and(|s| s == 3))
    });
    let offline = registry200_finality::RegistryFinality::open_existing(
        &files.root.join("3"),
        binding.clone(),
        keys[3].clone(),
        &protocol_storage::ByteBudget::new(version_journal::MAX_JOURNAL_BYTES).unwrap(),
    )
    .unwrap();
    running[3] = FinalityServer::bind(
        ListenerConfig {
            listen: endpoints[3].address,
            identity: nodes[3].fingerprint(),
            owner: owner.fingerprint(),
            acceptor: peer_transport::Acceptor::permissionless(&nodes[3]).unwrap(),
            connector: peer_transport::Connector::permissionless(&nodes[3]).unwrap(),
            neighbors: endpoints[..3].to_vec(),
        },
        offline,
        gate.clone(),
    )
    .unwrap()
    .spawn()
    .unwrap();
    until(|| clients[3].observed_slot().is_ok_and(|s| s == 3));
    let mut follower = registry200_finality::Follower::new(binding.clone()).unwrap();
    until(|| {
        clients[3]
            .follow_next(&mut follower, &gate)
            .is_ok_and(|h| h.is_some())
    });
    until(|| {
        clients[3]
            .follow_next(&mut follower, &gate)
            .is_ok_and(|h| h.is_some())
    });
    assert_eq!(
        follower.checked_head().unwrap().head().block,
        second.header().id()
    );
    let genuine = clients[3].checkpoint_after(0).unwrap().unwrap();
    let mut broken = genuine.certificate().to_vec();
    *broken.last_mut().unwrap() ^= 1;
    let forged = registry200_finality::Checkpoint::new(
        genuine.descriptor().clone(),
        genuine.round(),
        broken,
    )
    .unwrap();
    let mut fresh = registry200_finality::Follower::new(binding).unwrap();
    assert!(fresh.apply(&forged, &first).is_err());
    assert_eq!(fresh.context().slot(), 1);
    assert!(clients[3].submit(&first).is_err());
    assert_eq!(clients[3].observed_slot().unwrap(), 3);
    for server in &mut running {
        server.stop().unwrap();
    }
}

#[test]
fn simultaneous_tls_relays_leave_checkpoint_transfer_to_the_lagging_peer() {
    use sha2::{Digest, Sha256};
    use work_finality::{QuorumCertificate, SignedVote, Step, VoteContext, consensus::Input};
    let (binding, keys) = binding();
    let files = Files::new();
    let owner = identity();
    let nodes = [identity(), identity()];
    let gate = crate::ProofGate::new();
    let mut journal = version_journal::Journal::new(binding.journal_genesis().clone()).unwrap();
    let first = empty(&mut journal, &binding);
    let mut owned = Vec::new();
    for (i, key) in keys.iter().take(2).enumerate() {
        let directory = files.root.join(i.to_string());
        std::fs::create_dir(&directory).unwrap();
        owned.push(
            registry200_finality::RegistryFinality::create_new(
                &directory,
                binding.clone(),
                key.clone(),
                &protocol_storage::ByteBudget::new(version_journal::MAX_JOURNAL_BYTES).unwrap(),
            )
            .unwrap(),
        );
    }
    // Install an actual checked Empty Body and genuine three-of-four commit,
    // rather than setting a slot/head marker. The lagging peer has neither.
    let descriptor = owned[0]
        .import_candidate(first.header().clone(), first.body())
        .unwrap();
    let value = descriptor.encode().to_vec();
    let context = owned[0].context();
    // Construct public fixture votes under the exact independently pinned
    // protocol domain; the production Context keeps its signing helper private.
    let mut instance = Sha256::new();
    instance.update(b"dcs/work-finality/consensus-vote-instance/v1");
    instance.update(work_finality::profile_digest());
    instance.update(context.id());
    let expected = VoteContext::new(
        context.set(),
        instance.finalize().into(),
        context.slot(),
        0,
        Step::Precommit,
        Some(context.value_id(&value).unwrap()),
    )
    .unwrap();
    let votes: Vec<_> = keys
        .iter()
        .take(3)
        .map(|key| SignedVote::sign(expected, key).unwrap())
        .collect();
    let certificate = QuorumCertificate::assemble(context.set(), &expected, &votes).unwrap();
    owned[0]
        .receive(&Input::Certificate { value, certificate }.encode().unwrap())
        .unwrap();
    assert_eq!(owned[0].context().slot(), 2);
    assert_eq!(owned[1].context().slot(), 1);

    let bodies = [BodyGate::new(), BodyGate::new()];
    let mut running: Vec<_> = owned
        .into_iter()
        .enumerate()
        .map(|(i, owned)| {
            FinalityServer::bind(
                ListenerConfig {
                    listen: "127.0.0.1:0".parse().unwrap(),
                    identity: nodes[i].fingerprint(),
                    owner: owner.fingerprint(),
                    acceptor: peer_transport::Acceptor::permissionless(&nodes[i]).unwrap(),
                    connector: peer_transport::Connector::permissionless(&nodes[i]).unwrap(),
                    neighbors: Vec::new(),
                },
                owned,
                gate.clone(),
            )
            .unwrap()
            .spawn_with_body_gate_for_test(bodies[i].clone())
            .unwrap()
        })
        .collect();
    let connector = peer_transport::Connector::permissionless(&owner).unwrap();
    let clients: Vec<_> = running
        .iter()
        .map(|server| FinalityClient::new(connector.clone(), server.endpoint().clone(), &binding))
        .collect();
    let handles: Vec<_> = running
        .iter()
        .map(|server| server.relay_handle_for_test())
        .collect();
    // A real export may occupy the ahead peer's single lease. Force that state
    // and start both directions together; the ahead pass must not try to push
    // or acquire a second Body. No scheduling luck or owner resubmission helps.
    let occupied = bodies[0].acquire().unwrap();
    let start = Arc::new(std::sync::Barrier::new(3));
    let passes: Vec<_> = (0..2)
        .map(|i| {
            let client = clients[1 - i].clone();
            let handle = handles[i].clone();
            let body = bodies[i].clone();
            let start = start.clone();
            std::thread::spawn(move || {
                start.wait();
                super::client::synchronize(&client, &handle, &body)
            })
        })
        .collect();
    start.wait();
    let mut results = passes.into_iter().map(|pass| pass.join().unwrap());
    assert!(
        results.next().unwrap().is_ok(),
        "ahead peer must leave the transfer to the lagging relay"
    );
    assert_eq!(
        results.next().unwrap().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(clients[1].observed_slot().unwrap(), 1);
    drop(occupied);
    until(|| super::client::synchronize(&clients[0], &handles[1], &bodies[1]).is_ok());
    assert_eq!(clients[1].observed_slot().unwrap(), 2);
    let mut follower = registry200_finality::Follower::new(binding).unwrap();
    let checked = clients[1]
        .follow_next(&mut follower, &gate)
        .unwrap()
        .unwrap();
    assert_eq!(checked.head().block, first.header().id());
    for server in &mut running {
        server.stop().unwrap();
    }
}
