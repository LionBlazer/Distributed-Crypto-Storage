//! Four NEW scratch public-fixture validators only. No FHE child or owner bank.
use crate::{
    capture::{self, Archive, Prefix, Target, Upload},
    process::ProgressProcess,
};
use capture::{checked, deadline, invalid, require};
use ed25519_dalek::SigningKey;
use peer_runtime::{
    Connector, Endpoint, Identity, finality::ProgressFinalityClient,
    participant::ParticipantInstall,
    progress_participant::progress_participant_host_profile_digest,
};
use registry200_finality::progress::{Binding, Candidate, Checkpoint};
use std::{
    collections::{BTreeSet, VecDeque},
    fs, io,
    net::TcpListener,
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

pub(crate) struct Directory {
    root: PathBuf,
    parent: PathBuf,
    cleaned: bool,
}
impl Directory {
    pub(crate) fn new() -> io::Result<Self> {
        let parent = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.local/network-tests");
        fs::create_dir_all(&parent)?;
        let parent = fs::canonicalize(parent)?;
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let root = parent.join(format!(
            "public-progress-replay-{}-{stamp}",
            std::process::id()
        ));
        fs::create_dir(&root)?;
        let root = fs::canonicalize(root)?;
        require(
            root.parent() == Some(parent.as_path()),
            "Owned directory escaped parent",
        )?;
        Ok(Self {
            root,
            parent,
            cleaned: false,
        })
    }
    pub(crate) fn path(&self) -> &Path {
        &self.root
    }
    fn cleanup(&mut self) -> io::Result<()> {
        if self.cleaned {
            return Ok(());
        }
        let actual = fs::canonicalize(&self.root)?;
        let metadata = fs::symlink_metadata(&self.root)?;
        require(
            actual == self.root
                && actual.parent() == Some(self.parent.as_path())
                && metadata.is_dir()
                && !metadata.file_type().is_symlink(),
            "Refuse cleanup of changed/unowned target",
        )?;
        fs::remove_dir_all(&actual)?;
        self.cleaned = true;
        Ok(())
    }
    pub(crate) fn finish(mut self) -> io::Result<()> {
        self.cleanup()
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.cleanup();
        }
    }
}

fn identity() -> io::Result<Identity> {
    let key = checked(rcgen::KeyPair::generate())?;
    let mut parameters = checked(rcgen::CertificateParams::new(vec!["dcs-peer".into()]))?;
    parameters.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    parameters.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];
    Ok(Identity {
        certificate: checked(parameters.self_signed(&key))?.der().to_vec(),
        private_key_pkcs8: key.serialize_der(),
    })
}
fn endpoints(identities: &[Identity]) -> io::Result<Vec<Endpoint>> {
    let listeners: Vec<_> = (0..identities.len())
        .map(|_| TcpListener::bind("127.0.0.1:0"))
        .collect::<io::Result<_>>()?;
    identities
        .iter()
        .zip(&listeners)
        .map(|(identity, listener)| {
            Ok(Endpoint {
                address: listener.local_addr()?,
                identity: peer_transport::fingerprint(&identity.certificate),
            })
        })
        .collect()
}
fn clients(
    binding: &Binding,
    connector: &Connector,
    endpoints: &[Endpoint],
) -> Vec<ProgressFinalityClient> {
    endpoints
        .iter()
        .map(|e| ProgressFinalityClient::new(connector.clone(), e.clone(), binding))
        .collect()
}
fn retryable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock
            | io::ErrorKind::Interrupted
            | io::ErrorKind::TimedOut
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
    )
}
fn wait_retry(expires: Instant) -> io::Result<()> {
    deadline(expires)?;
    std::thread::park_timeout(
        Duration::from_millis(20).min(expires.saturating_duration_since(Instant::now())),
    );
    deadline(expires)
}
fn retry(
    mut f: impl FnMut() -> io::Result<()>,
    expires: Instant,
    stop: &AtomicBool,
) -> io::Result<()> {
    loop {
        deadline(expires)?;
        if stop.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "Replay cancelled",
            ));
        }
        let value = f();
        if let Err(error) = &value
            && !retryable(error)
        {
            // A racing cancellation cannot erase an observed invalid reply.
            return value;
        }
        if stop.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "Replay cancelled",
            ));
        }
        deadline(expires)?;
        match value {
            Ok(()) => return Ok(()),
            Err(e) if retryable(&e) => wait_retry(expires)?,
            Err(e) => return Err(e),
        }
    }
}
fn send_target_outcome(
    outcome: io::Result<Option<Checkpoint>>,
    stop: &AtomicBool,
    sender: &mpsc::SyncSender<io::Result<Option<Checkpoint>>>,
) -> io::Result<()> {
    let public = match outcome {
        Err(error) if stop.load(Ordering::Acquire) && retryable(&error) => Ok(None),
        Err(error) => {
            // Wake the coordinator and retain the original failure for join,
            // even when another worker has already selected a genuine QC.
            let _ = sender.send(Err(io::Error::new(
                error.kind(),
                "Actual replay worker failed; original error retained by join",
            )));
            return Err(error);
        }
        value => value,
    };
    sender
        .send(public)
        .map_err(|_| invalid("Live QC receiver closed"))
}
// One queued turn per peer, one bounded blob per turn, no lock during read/RPC.
// At most THREE role buffers exist; each comes from a fresh hash+EOF reread.
fn upload_all(
    archive: &Archive,
    clients: &[ProgressFinalityClient],
    block: &registry200_finality::CandidateBlock,
    uploads: &[Upload],
    expires: Instant,
    slot: u64,
    began: Instant,
) -> io::Result<()> {
    require(
        clients.len() == 4 && !uploads.is_empty(),
        "Exact four upload targets",
    )?;
    let jobs = Mutex::new((0..4).map(|i| (i, 0_usize)).collect::<VecDeque<_>>());
    let stop = AtomicBool::new(false);
    let result = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..3 {
            handles.push(scope.spawn(||->io::Result<()>{
                let result=(|| {
                    loop {
                        if stop.load(Ordering::Acquire){return Ok(());}
                        deadline(expires)?;
                        let job=jobs.lock().map_err(|_|invalid("Upload queue poisoned"))?.pop_front();
                        let Some((peer,ordinal))=job else{return Ok(());};
                        if ordinal==0{println!("public_replay phase=upload_start slot={slot} peer={peer} elapsed_ms={}",began.elapsed().as_millis());}
                        let upload=uploads.get(ordinal).ok_or_else(||invalid("Upload ordinal"))?;
                        let bytes=archive.read_blob(upload.id,upload.cap)?;
                        retry(||clients[peer].put_proof_blob(block,upload.selector,upload.id,&bytes),expires,&stop)?;
                        drop(bytes);
                        if ordinal+1<uploads.len(){
                            jobs.lock().map_err(|_|invalid("Upload queue poisoned"))?
                                .push_back((peer,ordinal+1));
                        }else{println!("public_replay phase=upload_end slot={slot} peer={peer} roles={} elapsed_ms={}",uploads.len(),began.elapsed().as_millis());}
                    }
                })();
                if result.is_err(){
                    stop.store(true,Ordering::Release);
                    for client in clients {client.cancel();}
                }
                result
            }));
        }
        let mut first = None;
        for handle in handles {
            let result = handle
                .join()
                .map_err(|_| invalid("Upload worker panicked"))
                .and_then(|r| r);
            if let Err(e) = result
                && first.is_none()
            {
                first = Some(e);
            }
        }
        if let Some(e) = first {
            return Err(e);
        }
        require(
            jobs.lock()
                .map_err(|_| invalid("Upload queue poisoned"))?
                .is_empty(),
            "Upload turns unfinished",
        )
    });
    result?;
    deadline(expires)
}
fn verify(
    binding: &Binding,
    context: &work_finality::consensus::Context,
    block: &registry200_finality::CandidateBlock,
    qc: &Checkpoint,
    semantic: [u8; 32],
) -> io::Result<()> {
    let expected = checked(Candidate::for_context(
        binding,
        context,
        block.header().clone(),
    ))?;
    require(
        qc.candidate() == &expected,
        "Whole live Candidate differs from independent target",
    )?;
    let decision =
        checked(context.verify_commit(&expected.encode(), qc.round(), qc.certificate()))?;
    require(
        decision.semantic_id() == semantic,
        "Wrong live semantic decision",
    )
}
fn seed_prefix(
    archive: &Archive,
    connector: &Connector,
    endpoints: &[Endpoint],
    frame: &Prefix,
) -> io::Result<()> {
    let began = Instant::now();
    let expires = began + peer_runtime::finality::PROGRESS_OPERATION_BUDGET;
    let clients = clients(&archive.binding, connector, endpoints);
    upload_all(
        archive,
        &clients,
        &frame.block,
        &frame.uploads,
        expires,
        frame.context.slot(),
        began,
    )?;
    let stop = AtomicBool::new(false);
    let result = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for (peer, client) in clients.iter().enumerate() {
            let peers = &clients;
            let stop = &stop;
            handles.push(scope.spawn(move ||->io::Result<()>{
                let result=(|| {
                    let submit_began=Instant::now();
                    println!("public_replay phase=submit_start slot={} peer={peer} elapsed_ms={}",frame.context.slot(),began.elapsed().as_millis());
                    retry(||client.submit(&frame.block),expires,stop)?;
                    println!("public_replay phase=submit_ack slot={} peer={peer} rpc_ms={} elapsed_ms={}",frame.context.slot(),submit_began.elapsed().as_millis(),began.elapsed().as_millis());
                    // This field exists ONLY on Prefix, a fixed array of slots1..3.
                    require(frame.context.slot()<=3,"Target certificate must never be seeded")?;
                    let prefix_began=Instant::now();
                    retry(||client.submit_checkpoint(&frame.checkpoint),expires,stop)?;
                    println!("public_replay phase=prefix_qc_ack slot={} peer={peer} rpc_ms={} elapsed_ms={}",frame.context.slot(),prefix_began.elapsed().as_millis(),began.elapsed().as_millis());
                    loop {
                        if stop.load(Ordering::Acquire){return Err(io::Error::new(io::ErrorKind::Interrupted,"Prefix cancelled"));}
                        deadline(expires)?;
                        let observed=client.checkpoint_after(frame.context.slot()-1);
                        deadline(expires)?;
                        match observed {
                            Ok(Some(qc))=>{
                                verify(&archive.binding,&frame.context,&frame.block,&qc,frame.decision)?;
                                return Ok(());
                            }
                            Ok(None)=>wait_retry(expires)?,
                            Err(e) if retryable(&e)=>wait_retry(expires)?,
                            Err(e)=>return Err(e),
                        }
                    }
                })();
                if result.is_err(){stop.store(true,Ordering::Release);for client in peers{client.cancel();}}
                result
            }));
        }
        let mut first = None;
        for handle in handles {
            let result = handle
                .join()
                .map_err(|_| invalid("Prefix worker panicked"))
                .and_then(|r| r);
            if let Err(e) = result
                && first.is_none()
            {
                first = Some(e);
            }
        }
        first.map_or(Ok(()), Err)
    });
    for client in &clients {
        client.cancel();
    }
    result?;
    deadline(expires)?;
    println!(
        "public_replay_cold_prefix_slot={} peers=4",
        frame.context.slot()
    );
    Ok(())
}
fn target(
    archive: &Archive,
    connector: &Connector,
    endpoints: &[Endpoint],
    frame: &Target,
) -> io::Result<()> {
    let began = Instant::now();
    let expires = began + peer_runtime::finality::PROGRESS_OPERATION_BUDGET;
    let clients = clients(&archive.binding, connector, endpoints);
    let proposer = checked(frame.context.proposer(0))?;
    let leader = frame
        .context
        .set()
        .validators()
        .iter()
        .position(|v| v.public_key() == proposer)
        .ok_or_else(|| invalid("Actual proposer absent from current weighted roster"))?;
    println!(
        "public_replay phase=target_start slot=4 proposer_round0_peer={leader} context={}",
        capture::hex(&frame.context.id())
    );
    // There has been no target Body/QC submission before this fresh operation.
    upload_all(
        archive,
        &clients,
        &frame.block,
        &frame.uploads,
        expires,
        frame.context.slot(),
        began,
    )?;
    let stop = AtomicBool::new(false);
    let (sender, receiver) = mpsc::sync_channel(4);
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for (peer, client) in clients.iter().enumerate() {
            let sender = sender.clone();
            let stop = &stop;
            handles.push(scope.spawn(move ||->io::Result<()>{
                let outcome=(||{
                    let submit_began=Instant::now();
                    println!("public_replay phase=submit_start slot={} peer={peer} elapsed_ms={}",frame.context.slot(),began.elapsed().as_millis());
                    retry(||client.submit(&frame.block),expires,stop)?;
                    println!("public_replay phase=submit_ack slot={} peer={peer} rpc_ms={} elapsed_ms={}",frame.context.slot(),submit_began.elapsed().as_millis(),began.elapsed().as_millis());
                    loop {
                        if stop.load(Ordering::Acquire){return Ok(None);}
                        deadline(expires)?;
                        let observed=match client.checkpoint_after(frame.context.slot()-1) {
                            Ok(Some(qc))=>{
                                // Inspect every actual success before a cancellation tail.
                                verify(&archive.binding,&frame.context,&frame.block,&qc,frame.decision)?;
                                Ok(Some(qc))
                            }
                            Err(error) if !retryable(&error)=>return Err(error),
                            value=>value,
                        };
                        if stop.load(Ordering::Acquire){return Ok(None);}
                        deadline(expires)?;
                        match observed {
                            Ok(Some(qc))=>{
                                return Ok(Some(qc));
                            }
                            Ok(None)=>wait_retry(expires)?,
                            Err(e) if retryable(&e)=>wait_retry(expires)?,
                            Err(e)=>return Err(e),
                        }
                    }
                })();
                send_target_outcome(outcome,stop,&sender)
            }));
        }
        drop(sender);
        let selected = (|| -> io::Result<()> {
            loop {
                deadline(expires)?;
                let value = receiver
                    .recv_timeout(expires.saturating_duration_since(Instant::now()))
                    .map_err(|e| {
                        io::Error::new(io::ErrorKind::TimedOut, format!("Live QC wait: {e}"))
                    })?;
                deadline(expires)?;
                match value? {
                    Some(qc) => {
                        verify(
                            &archive.binding,
                            &frame.context,
                            &frame.block,
                            &qc,
                            frame.decision,
                        )?;
                        println!(
                            "public_replay phase=first_valid_qc slot=4 elapsed_ms={}",
                            began.elapsed().as_millis()
                        );
                        return Ok(());
                    }
                    None => continue,
                }
            }
        })();
        let join_began = Instant::now();
        stop.store(true, Ordering::Release);
        for client in &clients {
            client.cancel();
        }
        // No detached workers. A valid QC does not hide a panicking/unjoined thread.
        let mut join_error = None;
        for handle in handles {
            let result = handle
                .join()
                .map_err(|_| invalid("Live QC worker panicked"))
                .and_then(|r| r);
            if let Err(e) = result
                && join_error.is_none()
            {
                join_error = Some(e);
            }
        }
        if let Some(e) = join_error {
            return Err(e);
        }
        selected?;
        println!(
            "public_replay phase=rpc_workers_joined slot=4 join_ms={} elapsed_ms={}",
            join_began.elapsed().as_millis(),
            began.elapsed().as_millis()
        );
        deadline(expires)
    })?;
    println!("public_replay_new_process_qc_slot=4 original_body_exact=true");
    Ok(())
}

pub(crate) fn run(archive: &Archive, root: &Path) -> io::Result<()> {
    let owner = identity()?;
    let connector = Connector::permissionless(&owner)?;
    let tls: Vec<_> = (0..4).map(|_| identity()).collect::<io::Result<_>>()?;
    let endpoints = endpoints(&tls)?;
    require(
        endpoints
            .iter()
            .map(|e| e.address)
            .collect::<BTreeSet<_>>()
            .len()
            == 4,
        "Repeated OS endpoint",
    )?;
    let mut signers: Vec<_> = (1..=4).map(|n| SigningKey::from_bytes(&[n; 32])).collect();
    signers.sort_by_key(|s| s.verifying_key().to_bytes());
    let mut nodes = Vec::new();
    for i in 0..4 {
        let neighbors: Vec<_> = endpoints
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, e)| e.clone())
            .collect();
        let namespace = [0xb0 + i as u8; 32];
        let binding = &archive.binding;
        // Only known PUBLIC NONSECRET Work-fixture seeds; never the DB owner key.
        let config = serde_json::to_vec(&serde_json::json!({"version":2,
            "kind":"registry208-progress-participant-finality-v2","identity":&tls[i],
            "authority":[],"owner":peer_transport::fingerprint(&owner.certificate),
            "listen":endpoints[i].address,"neighbors":neighbors,"namespace":namespace,
            "capacity":10_000_000_000_u64,"work_genesis":binding.work_genesis().id(),
            "journal_genesis":checked(binding.journal_genesis().id())?,"binding":binding.id(),
            "rules":{"max_round":32,"timeouts_ms":[180000,180000,180000],"timeout_delta_ms":1000,
                "wal_bytes":work_finality::consensus::MAX_RECORD_BYTES},
            "signer":signers[i].to_bytes()}))
        .map_err(io::Error::other)?;
        let mut frames = vec![
            Zeroizing::new(config),
            Zeroizing::new(checked(binding.work_genesis().encode())?),
            Zeroizing::new(checked(binding.journal_genesis().encode())?),
            Zeroizing::new(binding.application_descriptor().encode()),
            Zeroizing::new(binding.setup_claim().encode()),
        ];
        for part in archive.setup_parts()? {
            frames.push(Zeroizing::new(part));
        }
        let slices: Vec<_> = frames.iter().map(|f| f.as_slice()).collect();
        let node = ProgressProcess::start(
            Path::new(env!("CARGO_BIN_EXE_dcs-peer")),
            &root.join(format!("validator{i}")),
            ParticipantInstall::New,
            &slices,
        )?;
        require(
            node.ready().version == 2
                && node.ready().namespace == namespace
                && node.ready().binding == binding.id()
                && node.ready().profile == progress_participant_host_profile_digest()
                && node.endpoint() == &endpoints[i],
            "Actual Ready/profile/Binding mismatch",
        )?;
        require(
            nodes
                .iter()
                .all(|p: &ProgressProcess| p.pid() != node.pid()),
            "Repeated actual child PID",
        )?;
        println!("public_replay_validator_pid={}", node.pid());
        nodes.push(node);
        drop(frames);
    }
    require(
        nodes.len() == 4,
        "Exactly four independently running validators",
    )?;
    let result = (|| {
        for frame in &archive.prefix {
            seed_prefix(archive, &connector, &endpoints, frame)?;
        }
        target(archive, &connector, &endpoints, &archive.target)
    })();
    let mut joined = None;
    for node in nodes {
        if let Err(e) = node.finish()
            && joined.is_none()
        {
            joined = Some(e);
        }
    }
    result?;
    if let Some(e) = joined {
        return Err(e);
    }
    println!("public_replay_all_four_children_joined=true fhe_children=0");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_racing_a_hard_rpc_error_preserves_the_original_error() {
        let stop = AtomicBool::new(false);
        let mut calls = 0;
        let error = retry(
            || {
                calls += 1;
                stop.store(true, Ordering::Release);
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid public frame",
                ))
            },
            Instant::now() + Duration::from_secs(1),
            &stop,
        )
        .unwrap_err();
        assert_eq!(calls, 1);
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "invalid public frame");
    }

    #[test]
    fn a_stopped_worker_keeps_hard_errors_for_join_and_ignores_only_transport_tail() {
        let stop = AtomicBool::new(true);
        let (sender, receiver) = mpsc::sync_channel(1);
        let error = send_target_outcome(
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid public reply",
            )),
            &stop,
            &sender,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "invalid public reply");
        assert_eq!(
            receiver.try_recv().unwrap().err().unwrap().kind(),
            io::ErrorKind::InvalidData
        );
        send_target_outcome(
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "cancelled transport",
            )),
            &stop,
            &sender,
        )
        .unwrap();
        assert!(receiver.try_recv().unwrap().unwrap().is_none());
    }
}
