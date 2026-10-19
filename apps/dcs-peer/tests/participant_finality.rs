//! Actual four OS peers. PUBLIC NONSECRET fixtures, actual Source/Lifecycle
//! proofs and actual durable weighted votes. This is not a SQL acceptance test.
#[path = "support/participant_finality.rs"]
mod support;
use peer_runtime::{
    Connector, Endpoint, Identity,
    finality::{FinalityClient, profile_digest},
    participant::{ParticipantReady, participant_host_profile_digest},
};
use registry200_finality::{Binding, CandidateBlock, Checkpoint, Follower};
use registry200_proof::lifecycle::circuit::model::Operation;
use std::{
    io::{self, BufRead, BufReader, Read},
    net::TcpListener,
    path::PathBuf,
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::{History, Prepared};

fn identity() -> Identity {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut p = rcgen::CertificateParams::new(vec!["dcs-peer".into()]).unwrap();
    p.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];
    Identity {
        certificate: p.self_signed(&key).unwrap().der().to_vec(),
        private_key_pkcs8: key.serialize_der(),
    }
}
struct ProcessFixture {
    binding: Binding,
    identities: Vec<Identity>,
    signers: Vec<[u8; 32]>,
    owner: [u8; 32],
    endpoints: Vec<Endpoint>,
}
struct ProcessOwner {
    child: Child,
    input: Option<ChildStdin>,
}
impl Drop for ProcessOwner {
    fn drop(&mut self) {
        drop(self.input.take());
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}
struct Node {
    owned: ProcessOwner,
    pub ready: ParticipantReady,
}
impl Node {
    fn start(
        root: &std::path::Path,
        new: bool,
        fixture: &ProcessFixture,
        index: usize,
        partition: bool,
    ) -> Self {
        let binding = &fixture.binding;
        let tls = &fixture.identities[index];
        let endpoints = &fixture.endpoints;
        let mut command = Command::new(env!("CARGO_BIN_EXE_dcs-peer"));
        command
            .args([
                "--participant-finality",
                if new { "new" } else { "existing" },
                root.to_str().unwrap(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .env("RAYON_NUM_THREADS", "2");
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let mut child = command.spawn().unwrap();
        let input = child.stdin.take().unwrap();
        let mut owned = ProcessOwner {
            child,
            input: Some(input),
        };
        let neighbors: Vec<_> = endpoints
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != index && (!partition || *i / 2 == index / 2))
            .map(|(_, e)| e.clone())
            .collect();
        let namespace = [index as u8 + 0x91; 32];
        let bytes=zeroize::Zeroizing::new(serde_json::to_vec(&serde_json::json!({
            "version":1,"kind":"registry200-participant-finality-v1","identity":tls,"authority":[],"owner":fixture.owner,
            "listen":endpoints[index].address,"neighbors":neighbors,"namespace":namespace,"capacity":10_000_000_000u64,
            "work_genesis":binding.work_genesis().id(),"journal_genesis":binding.journal_genesis().id().unwrap(),"binding":binding.id(),
            "rules":{"max_round":1000,"timeouts_ms":[3000,4000,5000],"timeout_delta_ms":1000,"wal_bytes":work_finality::consensus::MAX_RECORD_BYTES},
            "signer":fixture.signers[index]
        })).unwrap());
        let input = owned.input.as_mut().unwrap();
        peer_transport::write_frame(input, &bytes, peer_runtime::PARTICIPANT_BOOTSTRAP_BYTES)
            .unwrap();
        drop(bytes);
        peer_transport::write_frame(
            input,
            &binding.work_genesis().encode().unwrap(),
            work_finality::MAX_GENESIS_BYTES,
        )
        .unwrap();
        peer_transport::write_frame(input, &binding.journal_genesis().encode().unwrap(), 716)
            .unwrap();
        peer_transport::write_frame(input, &binding.application_descriptor().encode(), 312)
            .unwrap();
        let stdout = owned.child.stdout.take().unwrap();
        let (sent, received) = mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || {
            let mut line = String::new();
            let r = BufReader::new(stdout).read_line(&mut line).map(|_| line);
            let _ = sent.send(r);
        });
        let line = match received.recv_timeout(Duration::from_secs(240)) {
            Ok(Ok(line)) => line,
            other => {
                drop(owned.input.take());
                let _ = owned.child.kill();
                let _ = owned.child.wait();
                let _ = reader.join();
                panic!("actual participant startup failed: {other:?}");
            }
        };
        reader.join().unwrap();
        let ready: ParticipantReady = match serde_json::from_str(&line) {
            Ok(ready) => ready,
            Err(e) => panic!("invalid actual participant Ready: {e}"),
        };
        // Construct the lifecycle owner before assertions so every failed Ready
        // pin also closes stdin and joins/kills the actual child.
        let node = Self { owned, ready };
        let ready = &node.ready;
        assert_eq!(ready.version, 1);
        assert_eq!(ready.profile, participant_host_profile_digest());
        assert_eq!(ready.binding, binding.id());
        assert_eq!(ready.namespace, namespace);
        assert_eq!(ready.endpoint, endpoints[index]);
        assert_eq!(ready.pid, node.owned.child.id());
        assert_ne!(ready.pid, std::process::id());
        println!("participant_peer_pid={}", ready.pid);
        node
    }
    fn stop(&mut self) {
        drop(self.owned.input.take());
        let end = Instant::now() + Duration::from_secs(240);
        loop {
            if let Some(status) = self.owned.child.try_wait().unwrap() {
                assert!(status.success());
                return;
            }
            assert!(
                Instant::now() < end,
                "joined participant shutdown did not finish"
            );
            std::thread::park_timeout(Duration::from_millis(20));
        }
    }
}
fn until(mut condition: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(240);
    loop {
        if condition() {
            return;
        }
        assert!(Instant::now() < end, "actual OS/TLS condition timed out");
        std::thread::park_timeout(Duration::from_millis(30));
    }
}
fn reject(client: &FinalityClient, block: &CandidateBlock) {
    until(|| match client.submit(block) {
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => false,
        Err(e) => {
            assert_eq!(
                e.kind(),
                io::ErrorKind::InvalidData,
                "expected an actual remote rejection"
            );
            true
        }
        Ok(()) => panic!("nonappendable/stale body admitted"),
    });
}
// Owning protocol decoder only. Reuses the exported profile, actual Header and
// public caps; Follower below still performs every genuine application/QC check.
fn fetch(
    connector: &Connector,
    endpoint: &Endpoint,
    binding: &Binding,
    id: [u8; 32],
) -> io::Result<CandidateBlock> {
    let mut stream = connector.connect_cancellable(endpoint, None)?;
    stream.set_io_timeout(Duration::from_secs(180))?;
    let _deadline = stream.deadline(Duration::from_secs(180))?;
    let mut request = b"DCSRFN01".to_vec();
    request.extend_from_slice(&profile_digest());
    request.extend_from_slice(&binding.id());
    request.push(2);
    request.extend_from_slice(&id);
    peer_transport::write_frame(
        &mut stream,
        &request,
        work_finality::consensus::MAX_INPUT_BYTES + 73,
    )?;
    let bytes = peer_transport::read_frame(&mut stream, 73 + version_journal::HEADER_BYTES + 4)?;
    assert!(bytes.len() >= 73);
    assert_eq!(&bytes[..8], b"DCSRFN01");
    assert_eq!(bytes[8..40], profile_digest());
    assert_eq!(bytes[40..72], binding.id());
    if bytes[72] == 17 {
        assert_eq!(bytes.len(), 73);
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "actual Body lease Busy",
        ));
    }
    assert_eq!(bytes[72], 20);
    assert_eq!(bytes.len(), 73 + version_journal::HEADER_BYTES + 4);
    let header =
        version_journal::Header::decode(&bytes[73..73 + version_journal::HEADER_BYTES]).unwrap();
    assert_eq!(header.id(), id);
    let n = u32::from_le_bytes(
        bytes[73 + version_journal::HEADER_BYTES..]
            .try_into()
            .unwrap(),
    ) as usize;
    assert!((1..=version_journal::MAX_BODY_BYTES).contains(&n));
    let body = peer_transport::read_frame(&mut stream, n)?;
    assert_eq!(body.len(), n);
    if stream.read(&mut [0; 1])? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Trailing GetBlock bytes",
        ));
    }
    Ok(CandidateBlock::new(header, body).unwrap())
}
fn catch_up(
    follower: &mut Follower,
    client: &FinalityClient,
    connector: &Connector,
    endpoint: &Endpoint,
    binding: &Binding,
    slot: u64,
) {
    while follower.context().slot() <= slot {
        let mut record: Option<Checkpoint> = None;
        until(
            || match client.checkpoint_after(follower.context().slot() - 1) {
                Ok(Some(c)) => {
                    record = Some(c);
                    true
                }
                _ => false,
            },
        );
        let record = record.unwrap();
        assert_eq!(record.descriptor().slot(), follower.context().slot());
        // Only this helper does native verification in the parent process, one
        // at a time. No dummy PeerServer or fabricated scheduling gate exists.
        let mut block = None;
        until(|| {
            match fetch(
                connector,
                endpoint,
                binding,
                record.descriptor().header().id(),
            ) {
                Ok(actual) => {
                    block = Some(actual);
                    true
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => false,
                Err(e) => panic!("actual GetBlock failed: {e}"),
            }
        });
        follower.apply(&record, &block.unwrap()).unwrap();
    }
}
fn roots() -> PathBuf {
    let parent = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.local/network-tests");
    std::fs::create_dir_all(&parent).unwrap();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = parent.join(format!(
        "participant-finality-{}-{stamp}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    println!("participant_public_test_root={}", root.display());
    root
}

#[test]
fn four_os_source_lifecycle_peers_certify_one_competing_acquire_and_recover_without_quorum_shortcuts()
 {
    let mut history = History::new();
    let binding = history.binding.clone();
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let mut initial = Vec::new();
    for (op, id) in [
        (None, 1),
        (Some(Operation::Begin), 1),
        (Some(Operation::Begin), 2),
    ] {
        let prepared = history.prepare(op, id, 0);
        initial.push(history.adopt(prepared));
    }
    let a = history.prepare(Some(Operation::Acquire), 1, 0);
    let b = history.prepare(Some(Operation::Acquire), 2, 0);
    assert_eq!(a.block.header().parent, b.block.header().parent);
    assert_ne!(a.block.header().id(), b.block.header().id());
    assert_eq!(a.outcome, 0);
    assert_eq!(b.outcome, 0);
    let tls: Vec<_> = (0..4).map(|_| identity()).collect();
    let reservations: Vec<_> = (0..4)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let endpoints: Vec<_> = reservations
        .iter()
        .zip(&tls)
        .map(|(socket, id)| Endpoint {
            address: socket.local_addr().unwrap(),
            identity: id.fingerprint(),
        })
        .collect();
    drop(reservations);
    let root = roots();
    let clients: Vec<_> = endpoints
        .iter()
        .map(|p| FinalityClient::new(connector.clone(), p.clone(), &binding))
        .collect();
    let processes = ProcessFixture {
        binding: binding.clone(),
        identities: tls,
        signers: history.keys.iter().map(|k| k.to_bytes()).collect(),
        owner: owner.fingerprint(),
        endpoints: endpoints.clone(),
    };
    let mut nodes: Vec<_> = (0..4)
        .map(|i| Node::start(&root.join(i.to_string()), true, &processes, i, false))
        .collect();
    assert_eq!(
        nodes
            .iter()
            .map(|n| n.ready.pid)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        4
    );
    for (i, block) in initial.iter().enumerate() {
        for client in &clients {
            until(|| {
                client.submit(block).is_ok()
                    || client.observed_slot().is_ok_and(|s| s >= i as u64 + 2)
            });
        }
        until(|| {
            clients
                .iter()
                .all(|c| c.observed_slot().is_ok_and(|s| s == i as u64 + 2))
        });
    }
    for n in &mut nodes {
        n.stop();
    }
    drop(nodes);
    let mut nodes: Vec<_> = (0..4)
        .map(|i| Node::start(&root.join(i.to_string()), false, &processes, i, true))
        .collect();
    for (i, c) in clients.iter().enumerate() {
        let block = if i < 2 { &a.block } else { &b.block };
        until(|| c.submit(block).is_ok());
    }
    let no_quorum = Instant::now() + Duration::from_secs(8);
    while Instant::now() < no_quorum {
        for c in &clients {
            assert_eq!(c.observed_slot().unwrap(), 4);
        }
        std::thread::park_timeout(Duration::from_millis(30));
    }
    for n in &mut nodes {
        n.stop();
    }
    drop(nodes);
    let mut nodes: Vec<_> = (0..4)
        .map(|i| Node::start(&root.join(i.to_string()), false, &processes, i, false))
        .collect();
    for c in &clients {
        until(|| c.submit(&a.block).is_ok() || c.observed_slot().is_ok_and(|s| s >= 5));
    }
    until(|| {
        clients
            .iter()
            .all(|c| c.observed_slot().is_ok_and(|s| s == 5))
    });
    let mut follower = Follower::new(binding.clone()).unwrap();
    catch_up(
        &mut follower,
        &clients[0],
        &connector,
        &endpoints[0],
        &binding,
        4,
    );
    let winner = follower.checked_head().unwrap().head().block;
    let (winning, losing, winner_id, loser_id): (Prepared, Prepared, u64, u64) =
        if winner == a.block.header().id() {
            (a, b, 1, 2)
        } else {
            assert_eq!(winner, b.block.header().id());
            (b, a, 2, 1)
        };
    let winning = history.adopt(winning);
    let losing = losing.block;
    // Every other independent follower must verify the SAME actual QC/body.
    for (i, c) in clients.iter().enumerate().skip(1) {
        let mut f = Follower::new(binding.clone()).unwrap();
        catch_up(&mut f, c, &connector, &endpoints[i], &binding, 4);
        assert_eq!(f.checked_head().unwrap().head().block, winner);
    }
    for c in &clients {
        reject(c, &losing);
        assert_eq!(c.observed_slot().unwrap(), 5);
    }
    for wait in [0, 1] {
        let blocked = history.prepare(Some(Operation::Acquire), loser_id, wait);
        assert_eq!(blocked.outcome, wait + 1);
        for c in &clients {
            reject(c, &blocked.block);
            assert_eq!(c.observed_slot().unwrap(), 5);
        }
    }
    nodes[3].stop();
    let end = history.prepare(Some(Operation::End), winner_id, 0);
    let end = history.adopt(end);
    for c in &clients[..3] {
        until(|| c.submit(&end).is_ok() || c.observed_slot().is_ok_and(|s| s >= 6));
    }
    until(|| {
        clients[..3]
            .iter()
            .all(|c| c.observed_slot().is_ok_and(|s| s == 6))
    });
    let reacquire = history.prepare(Some(Operation::Acquire), loser_id, 0);
    let reacquire = history.adopt(reacquire);
    for c in &clients[..3] {
        until(|| c.submit(&reacquire).is_ok() || c.observed_slot().is_ok_and(|s| s >= 7));
    }
    until(|| {
        clients[..3]
            .iter()
            .all(|c| c.observed_slot().is_ok_and(|s| s == 7))
    });
    nodes[3] = Node::start(&root.join("3"), false, &processes, 3, false);
    until(|| clients[3].observed_slot().is_ok_and(|s| s == 7));
    catch_up(
        &mut follower,
        &clients[3],
        &connector,
        &endpoints[3],
        &binding,
        6,
    );
    assert_eq!(
        follower.checked_head().unwrap().head().block,
        reacquire.header().id()
    );
    reject(&clients[3], &winning);
    assert_eq!(clients[3].observed_slot().unwrap(), 7);
    for n in &mut nodes {
        n.stop();
    }
    for i in 0..4 {
        let quota = protocol_storage::ParticipantQuota::open_existing(
            root.join(i.to_string()),
            [i as u8 + 0x91; 32],
            10_000_000_000,
        )
        .unwrap();
        let usage = quota.usage().unwrap();
        assert_eq!(usage.total_bytes(), usage.control_bytes());
        assert!(usage.control_bytes() <= version_journal::MAX_JOURNAL_BYTES);
        assert_eq!(
            std::fs::read_dir(root.join(i.to_string()).join("control"))
                .unwrap()
                .count(),
            4
        );
    }
}
