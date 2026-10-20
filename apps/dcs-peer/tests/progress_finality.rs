//! Real four-process Progress validators. PUBLIC NONSECRET owner fixtures build
//! genuine Source/Bootstrap803/Control815 proofs; no Predicate or SQL answer is simulated.
#[path = "support/progress_finality.rs"]
mod fixture;
#[path = "support/joint_process.rs"]
#[expect(
    dead_code,
    reason = "The shared supervisor also defines the separately tested Joint wrapper"
)]
mod process;
use fixture::{History, until};
use peer_runtime::{
    Connector, Endpoint, Identity,
    finality::{ProgressFinalityClient, ProgressProofBlobSelector},
    participant::ParticipantInstall,
    progress_participant::progress_participant_host_profile_digest,
};
use process::ProgressProcess as Process;
use protocol_storage::BlobId;
use registry200_finality::{
    CandidateBlock,
    progress::{Candidate, Checkpoint},
};
use registry200_joint::progress::Manifest;
use sha2::{Digest, Sha256};
use std::{
    io,
    net::TcpListener,
    path::Path,
    time::{Duration, Instant},
};
use version_journal::Body;
use work_finality::consensus::Context;

fn start(
    history: &History,
    root: &Path,
    tls: &[Identity],
    endpoints: &[Endpoint],
    owner: [u8; 32],
    new: bool,
    partition: bool,
) -> Vec<Process> {
    (0..4)
        .map(|i| {
            let neighbors: Vec<_> = endpoints
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i && (!partition || *j / 2 == i / 2))
                .map(|(_, e)| e.clone())
                .collect();
            let namespace = [0x91 + i as u8; 32];
            let frames = fixture::bootstrap_frames(
                history,
                fixture::Network {
                    tls: &tls[i],
                    owner,
                    listen: endpoints[i].clone(),
                    neighbors: &neighbors,
                    namespace,
                    index: i,
                },
                new,
            );
            let borrowed: Vec<_> = frames.iter().map(|f| f.as_slice()).collect();
            let node = Process::start(
                Path::new(env!("CARGO_BIN_EXE_dcs-peer")),
                &root.join(format!("validator{i}")),
                if new {
                    ParticipantInstall::New
                } else {
                    ParticipantInstall::Existing
                },
                &borrowed,
            )
            .unwrap();
            assert_eq!(node.ready().version, 2);
            assert_eq!(
                node.ready().profile,
                progress_participant_host_profile_digest()
            );
            assert_eq!(node.ready().binding, history.binding.id());
            assert_eq!(node.ready().namespace, namespace);
            assert_eq!(node.endpoint(), &endpoints[i]);
            println!("progress_validator_pid={}", node.pid());
            node
        })
        .collect()
}
fn clients(
    history: &History,
    connector: &Connector,
    endpoints: &[Endpoint],
) -> Vec<ProgressFinalityClient> {
    endpoints
        .iter()
        .map(|e| ProgressFinalityClient::new(connector.clone(), e.clone(), &history.binding))
        .collect()
}
fn submit(client: &ProgressFinalityClient, block: &CandidateBlock) {
    until(|| match client.submit(block) {
        Ok(()) => true,
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => false,
        Err(e) => panic!("Actual signed candidate rejected: {e}"),
    })
}
fn reject(mut action: impl FnMut() -> io::Result<()>) {
    until(|| match action() {
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => false,
        Err(e) => {
            assert_eq!(
                e.kind(),
                io::ErrorKind::InvalidData,
                "Expected protocol rejection, not transport timeout"
            );
            true
        }
        Ok(()) => panic!("Host accepted an unauthorized/invalid operation"),
    })
}
fn checkpoint(client: &ProgressFinalityClient, after: u64) -> Checkpoint {
    let mut result = None;
    until(|| match client.checkpoint_after(after) {
        Ok(Some(c)) => {
            result = Some(c);
            true
        }
        Ok(None) => false,
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => false,
        Err(e) => panic!("Actual checkpoint fetch failed: {e}"),
    });
    result.unwrap()
}
fn checked_decision(
    history: &History,
    context: &Context,
    checkpoint: &Checkpoint,
    block: &CandidateBlock,
) -> [u8; 32] {
    let candidate =
        Candidate::for_context(&history.binding, context, block.header().clone()).unwrap();
    assert_eq!(checkpoint.candidate(), &candidate);
    context
        .verify_commit(
            &candidate.encode(),
            checkpoint.round(),
            checkpoint.certificate(),
        )
        .unwrap()
        .semantic_id()
}
fn stop(nodes: Vec<Process>) {
    for node in nodes {
        node.finish().unwrap();
    }
}
fn put(
    client: &ProgressFinalityClient,
    block: &CandidateBlock,
    ordinal: u16,
    id: BlobId,
    bytes: &[u8],
) {
    until(|| {
        match client.put_proof_blob(
            block,
            ProgressProofBlobSelector::manifest(ordinal).unwrap(),
            id,
            bytes,
        ) {
            Ok(()) => true,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => false,
            Err(e) => panic!("Authorized public proof upload: {e}"),
        }
    })
}
fn drop_ack(
    connector: &Connector,
    endpoint: &Endpoint,
    history: &History,
    block: &CandidateBlock,
) -> io::Result<()> {
    let mut stream = connector.connect_cancellable(endpoint, None)?;
    stream.set_io_timeout(Duration::from_secs(180))?;
    let _deadline = stream.deadline(peer_runtime::finality::PROGRESS_OPERATION_BUDGET)?;
    let mut packet = b"DCSPFN02".to_vec();
    packet.extend_from_slice(&peer_runtime::finality::progress_profile_digest());
    packet.extend_from_slice(&history.binding.id());
    packet.push(6);
    packet.extend_from_slice(&block.header().encode());
    packet.extend_from_slice(&(block.body().len() as u32).to_le_bytes());
    peer_transport::write_frame(
        &mut stream,
        &packet,
        73 + work_finality::consensus::MAX_INPUT_BYTES,
    )?;
    let ready = peer_transport::read_frame(&mut stream, 73)?;
    assert_eq!(ready.len(), 73);
    if ready[72] == 17 {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "Actual Body lease Busy",
        ));
    }
    assert_eq!(ready[72], 16);
    peer_transport::write_frame(&mut stream, block.body(), version_journal::MAX_BODY_BYTES)?;
    // Intentional actual lost ACK: no synthetic success, no checkpoint receipt.
    // Only a later real four-process QC can establish that this body committed.
    drop(stream);
    Ok(())
}

#[test]
#[ignore = "actual four OS validators, genuine Source/Bootstrap803/Control815, partition/heal/reopen"]
fn four_os_progress_peers_prefetch_genuine_bootstrap_control_wait_for_quorum_and_reopen_exact_decisions()
 {
    let root = fixture::directory();
    println!("progress_public_test_root={}", root.display());
    let mut history = History::new(&root.join("owner-public-premises"));
    let bootstrap = history.prepare(true);
    let owner = fixture::identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let foreign = Connector::permissionless(&fixture::identity()).unwrap();
    let tls: Vec<_> = (0..4).map(|_| fixture::identity()).collect();
    let endpoints: Vec<_> = tls
        .iter()
        .map(|identity| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            Endpoint {
                address: listener.local_addr().unwrap(),
                identity: identity.fingerprint(),
            }
        })
        .collect();
    let nodes = start(
        &history,
        &root,
        &tls,
        &endpoints,
        owner.fingerprint(),
        true,
        true,
    );
    let first_pids: Vec<_> = nodes.iter().map(Process::pid).collect();
    assert_eq!(
        first_pids
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        4
    );
    let clients = clients(&history, &connector, &endpoints);
    // Each partition has a genuine proof seed. Its other member must fetch all
    // immutable evidence through actual TLS before its real native admission.
    history.upload(&clients[0], &bootstrap);
    history.upload(&clients[2], &bootstrap);
    for client in &clients {
        submit(client, &bootstrap.block);
    }
    // Observe reachable real TLS peers throughout one configured proposal+
    // prevote window. Two equal-weight participants cannot form the strict QC.
    let window = Instant::now() + Duration::from_secs(7);
    while Instant::now() < window {
        for client in &clients {
            assert_eq!(client.observed_slot().unwrap(), 1);
            assert!(client.checkpoint_after(0).unwrap().is_none());
        }
    }
    println!("Progress control phase finished: two real two-node partitions have no QC");
    stop(nodes);
    let nodes = start(
        &history,
        &root,
        &tls,
        &endpoints,
        owner.fingerprint(),
        false,
        false,
    );
    let second_pids: Vec<_> = nodes.iter().map(Process::pid).collect();
    for (a, b) in first_pids.iter().zip(&second_pids) {
        assert_ne!(a, b);
    }
    for client in &clients {
        submit(client, &bootstrap.block);
    }
    let boot_qc = checkpoint(&clients[0], 0);
    assert_eq!(boot_qc.candidate().header(), bootstrap.block.header());
    for client in &clients {
        until(|| client.observed_slot().is_ok_and(|slot| slot == 2));
    }
    history.adopt(bootstrap, &boot_qc);
    println!("Progress control phase finished: healed four-node Bootstrap QC and owner replay");
    let begin = history.prepare(false);
    let Body::Transition(body) = Body::decode(
        begin.block.body(),
        &history.binding.journal_genesis().profile,
    )
    .unwrap() else {
        panic!("Expected begin")
    };
    let manifest = Manifest::decode(&body.proof).unwrap();
    let refs: Vec<_> = manifest.references().collect();
    assert_eq!(refs.len(), 2);
    let pair = refs[0].blob_id();
    let kind = begin.child;
    assert_eq!(refs[1].blob_id(), kind);
    let kind_bytes = history
        .ingress
        .read_public_blob(kind, refs[1].byte_cap())
        .unwrap();
    let unauthorized = ProgressFinalityClient::new(foreign, endpoints[0].clone(), &history.binding);
    reject(|| {
        unauthorized.put_proof_blob(
            &begin.block,
            ProgressProofBlobSelector::manifest(1).unwrap(),
            kind,
            &kind_bytes,
        )
    });
    let missing = BlobId::new([0x97; 32], kind.bytes()).unwrap();
    let missing_block = history.tamper(&begin.block, |b| {
        b.proof = Manifest::control(manifest.next_root(), manifest.result_root(), pair, missing)
            .unwrap()
            .encode();
    });
    reject(|| clients[0].submit(&missing_block));
    let wrong_q = history.tamper(&begin.block, |b| b.request[48 + 16 + 4 * 32] ^= 1);
    reject(|| clients[0].submit(&wrong_q));
    let wrong_parent = history.tamper(&begin.block, |b| b.request[48 + 16 + 32] ^= 1);
    reject(|| clients[0].submit(&wrong_parent));
    let mut bad_kind = kind_bytes.clone();
    bad_kind[0] ^= 1;
    let bad_id = BlobId::new(Sha256::digest(&bad_kind).into(), bad_kind.len() as u64).unwrap();
    let bad_block = history.tamper(&begin.block, |b| {
        b.proof = Manifest::control(manifest.next_root(), manifest.result_root(), pair, bad_id)
            .unwrap()
            .encode()
    });
    // Matching public hash is deliberately retained; it is NOT proof authority.
    put(
        &clients[0],
        &bad_block,
        0,
        pair,
        &history
            .ingress
            .read_public_blob(pair, refs[0].byte_cap())
            .unwrap(),
    );
    put(&clients[0], &bad_block, 1, bad_id, &bad_kind);
    reject(|| clients[0].submit(&bad_block));
    for client in &clients {
        assert_eq!(client.observed_slot().unwrap(), 2);
    }
    // A hash-valid but mathematically invalid Source is tested with the SAME
    // genuinely valid Control815 child, own signed Body and current parent.
    // It must not pass merely because the transition child verifies.
    let source_bytes = history
        .ingress
        .read_public_blob(pair, refs[0].byte_cap())
        .unwrap();
    let mut bad_source = source_bytes.clone();
    bad_source[0] ^= 1;
    let bad_source_id =
        BlobId::new(Sha256::digest(&bad_source).into(), bad_source.len() as u64).unwrap();
    let source_block = history.tamper(&begin.block, |b| {
        b.proof = Manifest::control(
            manifest.next_root(),
            manifest.result_root(),
            bad_source_id,
            kind,
        )
        .unwrap()
        .encode();
    });
    put(&clients[0], &source_block, 0, bad_source_id, &bad_source);
    put(&clients[0], &source_block, 1, kind, &kind_bytes);
    reject(|| clients[0].submit(&source_block));
    assert_eq!(clients[0].observed_slot().unwrap(), 2);
    drop(source_bytes);
    drop(bad_source);
    drop(bad_kind);
    drop(kind_bytes);
    history.upload(&clients[0], &begin);
    until(
        || match drop_ack(&connector, &endpoints[0], &history, &begin.block) {
            Ok(()) => true,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => false,
            Err(e) => panic!("Actual lost-ACK upload failed: {e}"),
        },
    );
    let begin_qc = checkpoint(&clients[0], 1);
    assert_eq!(begin_qc.candidate().header(), begin.block.header());
    let begin_context = history.context().clone();
    let begin_decision = checked_decision(&history, &begin_context, &begin_qc, &begin.block);
    let mut altered = begin_qc.certificate().to_vec();
    altered[work_finality::CERTIFICATE_HEADER_BYTES + 32] ^= 1;
    assert!(matches!(
        begin_context.verify_commit(&begin_qc.candidate().encode(), begin_qc.round(), &altered),
        Err(work_finality::consensus::Error::Evidence(
            work_finality::Error::InvalidSignature
        ))
    ));
    let bad_qc = Checkpoint::new(begin_qc.candidate().clone(), begin_qc.round(), altered).unwrap();
    assert_eq!(
        Checkpoint::decode(&bad_qc.encode()).unwrap().encode(),
        bad_qc.encode()
    );
    reject(|| clients[0].submit_checkpoint(&bad_qc));
    assert_eq!(clients[0].observed_slot().unwrap(), 3);

    for client in &clients {
        until(|| client.observed_slot().is_ok_and(|slot| slot == 3));
    }
    let duplicate =
        CandidateBlock::new(begin.block.header().clone(), begin.block.body().to_vec()).unwrap();
    history.adopt(begin, &begin_qc);
    let mut selected_begin = Vec::with_capacity(4);
    for client in &clients {
        submit(client, &duplicate);
        until(|| match client.submit_checkpoint(&begin_qc) {
            Ok(()) => true,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => false,
            Err(e) => panic!("Actual duplicate QC rejected: {e}"),
        });
        assert_eq!(client.observed_slot().unwrap(), 3);
        let selected = checkpoint(client, 1);
        assert_eq!(
            checked_decision(&history, &begin_context, &selected, &duplicate),
            begin_decision
        );
        selected_begin.push(selected.encode());
    }
    println!(
        "Progress control phase finished: invalid proofs refused; lost ACK and latest retries retain one Begin decision"
    );
    // Legitimate Empty has no blobs; the actual new-lane prefetch/PoW/QC path
    // still runs. It must not be mistaken for a signed transition manifest.
    let empty = history.empty();
    submit(&clients[0], &empty);
    let empty_qc = checkpoint(&clients[0], 2);
    assert_eq!(empty_qc.candidate().header(), empty.header());
    let empty_context = history.context().clone();
    let empty_decision = checked_decision(&history, &empty_context, &empty_qc, &empty);
    let mut selected_empty = Vec::with_capacity(4);
    for client in &clients {
        until(|| client.observed_slot().is_ok_and(|slot| slot == 4));
        let selected = checkpoint(client, 2);
        assert_eq!(
            checked_decision(&history, &empty_context, &selected, &empty),
            empty_decision
        );
        selected_empty.push(selected.encode());
    }
    println!(
        "Progress control phase finished: each node retains a genuine QC for the same Empty decision"
    );
    stop(nodes);
    let reopened = start(
        &history,
        &root,
        &tls,
        &endpoints,
        owner.fingerprint(),
        false,
        false,
    );
    for (i, ((old, node), client)) in second_pids.iter().zip(&reopened).zip(&clients).enumerate() {
        assert_ne!(*old, node.pid());
        assert_eq!(client.observed_slot().unwrap(), 4);
        let replayed = checkpoint(client, 1);
        assert_eq!(
            checked_decision(&history, &begin_context, &replayed, &duplicate),
            begin_decision
        );
        // Quorum subsets can differ between nodes; the exact certificate selected
        // by THIS node must survive its own durable restart byte for byte.
        assert_eq!(replayed.encode(), selected_begin[i]);
        assert_eq!(replayed.candidate().header(), duplicate.header());
        let replayed_empty = checkpoint(client, 2);
        assert_eq!(
            checked_decision(&history, &empty_context, &replayed_empty, &empty),
            empty_decision
        );
        assert_eq!(replayed_empty.encode(), selected_empty[i]);
    }
    stop(reopened);
    println!(
        "Progress control phase finished: all four restarted nodes replay their exact own QCs and common semantic decisions"
    );
}
