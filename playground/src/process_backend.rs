//! OS process supervision and view adaptation. No protocol or FHE evaluator here.
use fhe_playground::{
    DatabaseDraft, LabError, LabSnapshot, LogicalShardInfo, NetworkLink, NetworkLog, NetworkNode,
    NetworkPacket, NetworkSnapshot, NodeId, NodeRole, PacketKind, PeerConfig, PeerInfo,
    ReplicaLocation, ReplicationInfo,
};
use peer_runtime::{Bootstrap, Connector, Endpoint, Identity, RemotePeer, Request, Status, Trace};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use std::{
    collections::{BTreeMap, VecDeque},
    io::{self, BufRead, BufReader, Read},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use storage_client::{Participant, Session, VerifiedResult};
use version_journal::{ProtocolProfile, Target};

/// Local defaults include room for real durable proof journals. Explicit caller
/// quotas remain unchanged; historical LabEngine fixtures retain their own defaults.
pub(super) fn default_peer_config(id: usize) -> PeerConfig {
    PeerConfig {
        storage_limit_bytes: 64 * 1024 * 1024,
        ..PeerConfig::numbered(id)
    }
}

fn identity() -> io::Result<Identity> {
    let mut params = CertificateParams::new(vec!["dcs-peer".into()]).map_err(io::Error::other)?;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let key = KeyPair::generate().map_err(io::Error::other)?;
    let cert = params.self_signed(&key).map_err(io::Error::other)?;
    Ok(Identity {
        certificate: cert.der().to_vec(),
        private_key_pkcs8: key.serialize_der(),
    })
}

/// Explicit local playground contract. Easy work and one confirmation have no
/// validated production attack budget; the core intentionally supplies no default.
fn playground_profile() -> ProtocolProfile {
    ProtocolProfile {
        initial_target: Target([0x0f; 32]),
        pow_limit: Target([0x0f; 32]),
        block_spacing_secs: 1,
        retarget_interval: 1024,
        max_future_secs: 30,
        confirmation_depth: 1,
        max_headers: 4096,
        max_shards: 16,
        max_updates: 16,
        max_body_bytes: 32 * 1024 * 1024,
        max_request_bytes: 32 * 1024 * 1024,
        max_proof_bytes: 32 * 1024 * 1024,
        max_journal_bytes: 256 * 1024 * 1024,
    }
}
struct OwnedPeer {
    child: Option<Child>,
    bootstrap: Bootstrap,
    directory: PathBuf,
    endpoint: Option<Endpoint>,
}
impl OwnedPeer {
    fn start(&mut self) -> io::Result<Endpoint> {
        self.stop();
        let executable = if let Some(path) = std::env::var_os("DCS_PEER_BIN") {
            PathBuf::from(path)
        } else {
            std::env::current_exe()?.with_file_name(if cfg!(windows) {
                "dcs-peer.exe"
            } else {
                "dcs-peer"
            })
        };
        let mut command = Command::new(executable);
        command
            .arg("--state-dir")
            .arg(&self.directory)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env("RAYON_NUM_THREADS", "2");
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let mut child = command.spawn().map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "Cannot launch dcs-peer: {e}. Build it beside the GUI or set DCS_PEER_BIN."
                ),
            )
        })?;
        let result = (|| {
            let secret = zeroize::Zeroizing::new(
                serde_json::to_vec(&self.bootstrap).map_err(io::Error::other)?,
            );
            peer_transport::write_frame(
                &mut child
                    .stdin
                    .take()
                    .ok_or_else(|| io::Error::other("Missing bootstrap pipe"))?,
                &secret,
                64 * 1024,
            )?;
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| io::Error::other("Missing readiness pipe"))?;
            let (tx, rx) = mpsc::sync_channel(1);
            std::thread::spawn(move || {
                let mut line = String::new();
                let result = BufReader::new(stdout)
                    .take(64 * 1024)
                    .read_line(&mut line)
                    .map(|_| line);
                let _ = tx.send(result);
            });
            let line = rx
                .recv_timeout(Duration::from_secs(10))
                .map_err(io::Error::other)??;
            let endpoint: Endpoint = serde_json::from_str(&line).map_err(io::Error::other)?;
            if endpoint.identity != self.bootstrap.identity.fingerprint() {
                return Err(io::Error::other("Readiness identity mismatch"));
            }
            Ok(endpoint)
        })();
        match result {
            Ok(endpoint) => {
                self.endpoint = Some(endpoint.clone());
                self.child = Some(child);
                Ok(endpoint)
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                Err(error)
            }
        }
    }
    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
    fn running(&mut self) -> bool {
        self.child
            .as_mut()
            .is_some_and(|child| matches!(child.try_wait(), Ok(None)))
    }
    fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }
}
impl Drop for OwnedPeer {
    fn drop(&mut self) {
        self.stop();
    }
}
struct Peer {
    node: NodeId,
    config: PeerConfig,
    process: OwnedPeer,
    remote: RemotePeer,
    status: Option<Status>,
    last_status: Option<Status>,
    seen: u64,
}
pub(super) struct ProcessBackend {
    owner: Identity,
    connector: Connector,
    root: PathBuf,
    peers: BTreeMap<usize, Peer>,
    clients: BTreeMap<NodeId, String>,
    next_peer: usize,
    next_node: NodeId,
    database: Option<Session>,
    retained_databases: Vec<Session>,
    owner_rows: Vec<compact_query::PlainRow>,
    desired: usize,
    started: Instant,
    traces: Receiver<Trace>,
    trace_sender: SyncSender<Trace>,
    session: Arc<AtomicU64>,
    logs: VecDeque<NetworkLog>,
    packets: VecDeque<(Instant, NetworkPacket)>,
    next_packet: u64,
}
fn error(e: impl std::fmt::Display) -> LabError {
    LabError::InvalidInput(e.to_string())
}
impl ProcessBackend {
    pub fn new() -> io::Result<Self> {
        let owner = identity()?;
        let connector = Connector::permissionless(&owner)?;
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../.local/peer-processes")
            .join(format!(
                "{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(io::Error::other)?
                    .as_nanos()
            ));
        let (trace_sender, traces) = mpsc::sync_channel(1024);
        Ok(Self {
            owner,
            connector,
            root,
            peers: BTreeMap::new(),
            clients: BTreeMap::from([(1, "Client 01".into())]),
            next_peer: 1,
            next_node: 2,
            database: None,
            retained_databases: Vec::new(),
            owner_rows: vec![],
            desired: 1,
            started: Instant::now(),
            traces,
            trace_sender,
            session: Arc::new(AtomicU64::new(1)),
            logs: VecDeque::new(),
            packets: VecDeque::new(),
            next_packet: 1,
        })
    }
    fn remote(&self, endpoint: Endpoint) -> RemotePeer {
        let sender = self.trace_sender.clone();
        RemotePeer::new(endpoint, self.connector.clone()).with_trace(Arc::new(move |trace| {
            let _ = sender.try_send(trace);
        }))
    }
    pub fn add_peer(&mut self, config: PeerConfig) -> Result<NodeId, LabError> {
        config.validate()?;
        if config.delay_ms != 0 {
            return Err(error(
                "Artificial delays are unavailable with real peer processes",
            ));
        }
        if self.peers.len() >= 16 {
            return Err(error("Use at most 16 locally managed peer processes"));
        }
        let id = self.next_peer;
        self.next_peer = self
            .next_peer
            .checked_add(1)
            .ok_or_else(|| error("Peer ID exhausted"))?;
        let node = self.next_node;
        self.next_node = self
            .next_node
            .checked_add(1)
            .ok_or_else(|| error("Node ID exhausted"))?;
        let mut process = OwnedPeer {
            child: None,
            bootstrap: Bootstrap {
                identity: identity().map_err(error)?,
                authority: Vec::new(),
                owner: self.owner.fingerprint(),
                node_id: node,
                quota_bytes: config.storage_limit_bytes as u64,
                listen: "127.0.0.1:0".parse().unwrap(),
            },
            directory: self.root.join(format!("peer-{id}")),
            endpoint: None,
        };
        let endpoint = process.start().map_err(error)?;
        let remote = self.remote(endpoint);
        let status = Some(remote.status().map_err(error)?);
        self.peers.insert(
            id,
            Peer {
                node,
                config,
                process,
                remote,
                last_status: status.clone(),
                status,
                seen: 0,
            },
        );
        self.mesh();
        Ok(node)
    }
    fn mesh(&mut self) {
        let endpoints: Vec<_> = self
            .peers
            .values_mut()
            .filter_map(|p| p.process.running().then(|| p.remote.endpoint().clone()))
            .collect();
        for peer in self.peers.values_mut() {
            if peer.process.running() {
                let others = endpoints
                    .iter()
                    .filter(|e| e.identity != peer.remote.endpoint().identity)
                    .cloned()
                    .collect();
                let _ = peer.remote.call(Request::Neighbors(others));
            }
        }
    }
    pub fn create(&mut self, draft: DatabaseDraft) -> Result<(), LabError> {
        if draft.rows.len() > 128 {
            return Err(error(
                "The interactive fixture editor permits at most 128 rows",
            ));
        }
        if !self.retained_databases.is_empty() {
            return Err(error(
                "Two owner database states are already retained in this session; no encrypted data or previous keys were removed.",
            ));
        }
        if self.peers.is_empty() {
            for config in draft.peers {
                self.add_peer(config)?;
            }
        }
        let participants = self
            .peers
            .iter_mut()
            .filter_map(|(id, p)| {
                p.process.running().then(|| Participant {
                    id: *id as u64,
                    remote: p.remote.clone(),
                })
            })
            .collect();
        let database = Session::create(draft.name, &draft.rows, participants, playground_profile())
            .map_err(error)?;
        self.owner_rows = database.inspect_rows().map_err(error)?;
        self.desired = if database.shards().len() > 1 { 2 } else { 1 };
        if let Some(previous) = self.database.replace(database) {
            self.retained_databases.push(previous);
        }
        self.refresh();
        Ok(())
    }
    pub fn query(&mut self, client: NodeId, sql: &str) -> Result<VerifiedResult, LabError> {
        if !self.clients.contains_key(&client) {
            return Err(error("Requesting client session was removed"));
        }
        self.session.store(client, Ordering::Release);
        let database = self.database.as_mut().ok_or(LabError::NoDatabase)?;
        let result = database.execute(sql).map_err(error)?;
        if matches!(
            result,
            VerifiedResult::Updated { .. } | VerifiedResult::Inserted { .. }
        ) {
            self.owner_rows = database.inspect_rows().map_err(|e| {
                error(format!(
                    "SQL committed at version {}; owner data view refresh failed: {e}",
                    database.version().height
                ))
            })?;
        }
        Ok(result)
    }
    pub fn add_client(&mut self, name: String) -> Result<NodeId, LabError> {
        if self.clients.len() >= 8
            || name.trim().is_empty()
            || name.len() > 48
            || name.chars().any(char::is_control)
        {
            return Err(error("Use a name and at most 8 owner-client sessions"));
        }
        let id = self.next_node;
        self.next_node = self
            .next_node
            .checked_add(1)
            .ok_or_else(|| error("Node ID exhausted"))?;
        self.clients.insert(id, name);
        Ok(id)
    }
    pub fn remove(&mut self, id: NodeId) -> Result<(), LabError> {
        if self.clients.remove(&id).is_some() {
            return Ok(());
        }
        let key = self
            .peers
            .iter()
            .find(|(_, p)| p.node == id)
            .map(|(id, _)| *id)
            .ok_or_else(|| error("Unknown node"))?;
        self.peers.remove(&key);
        self.mesh();
        Ok(())
    }
    pub fn online(&mut self, id: usize, online: bool) -> Result<(), LabError> {
        if !online {
            self.peers
                .get_mut(&id)
                .ok_or_else(|| error("Unknown peer"))?
                .process
                .stop();
        } else {
            let endpoint = self
                .peers
                .get_mut(&id)
                .ok_or_else(|| error("Unknown peer"))?
                .process
                .start()
                .map_err(error)?;
            let remote = self.remote(endpoint);
            self.peers.get_mut(&id).unwrap().remote = remote.clone();
            if let Some(db) = &mut self.database {
                db.replace_participant(Participant {
                    id: id as u64,
                    remote,
                })
                .map_err(error)?;
            }
        }
        self.mesh();
        self.refresh();
        Ok(())
    }
    pub fn configure(&mut self, id: usize, config: PeerConfig) -> Result<(), LabError> {
        config.validate()?;
        if config.delay_ms != 0 {
            return Err(error("Real transport does not emulate packet delay"));
        }
        let peer = self
            .peers
            .get_mut(&id)
            .ok_or_else(|| error("Unknown peer"))?;
        peer.remote
            .call(Request::Quota(config.storage_limit_bytes as u64))
            .map_err(error)?;
        peer.process.bootstrap.quota_bytes = config.storage_limit_bytes as u64;
        peer.config = config;
        Ok(())
    }
    pub fn copies(&mut self, copies: usize) -> Result<(usize, usize), LabError> {
        if !(1..=3).contains(&copies) {
            return Err(error("Use 1..3 owner-requested physical copies"));
        }
        let result = self.repair_to(copies)?;
        self.desired = copies;
        Ok(result)
    }
    pub fn repair(&mut self) -> Result<(usize, usize), LabError> {
        self.repair_to(self.desired)
    }
    fn repair_to(&mut self, copies: usize) -> Result<(usize, usize), LabError> {
        let db = self.database.as_mut().ok_or(LabError::NoDatabase)?;
        let mut total = 0;
        for shard in db.shards() {
            let mut live: Vec<u64> = shard
                .holders
                .iter()
                .copied()
                .filter(|id| {
                    self.peers.get(&(*id as usize)).is_some_and(|peer| {
                        peer.status.as_ref().is_some_and(|status| {
                            status
                                .objects
                                .iter()
                                .any(|object| object.id == shard.object && object.available)
                        })
                    })
                })
                .collect();
            for (id, peer) in &mut self.peers {
                if live.len() >= copies {
                    break;
                }
                if !live.contains(&(*id as u64)) && peer.process.running() {
                    if db
                        .copy_shard(
                            shard.id,
                            Participant {
                                id: *id as u64,
                                remote: peer.remote.clone(),
                            },
                        )
                        .is_err()
                    {
                        continue;
                    }
                    peer.status = Some(peer.remote.status().map_err(error)?);
                    if !peer
                        .status
                        .as_ref()
                        .unwrap()
                        .objects
                        .iter()
                        .any(|object| object.id == shard.object && object.available)
                    {
                        return Err(error("Target did not report the copied object"));
                    }
                    live.push(*id as u64);
                }
            }
            if live.len() < copies {
                return Err(error(
                    "Insufficient live targets for the requested physical copies",
                ));
            }
            total += live.len();
        }
        Ok((total, 0))
    }
    pub fn refresh(&mut self) {
        let mut observed = Vec::new();
        for peer in self.peers.values_mut() {
            peer.status = if peer.process.running() {
                peer.remote.status().ok()
            } else {
                None
            };
            if let Some(status) = &peer.status {
                peer.last_status = Some(status.clone());
                for event in &status.recent {
                    if event.sequence > peer.seen {
                        observed.push((peer.node, event.clone()));
                    }
                }
                peer.seen = status
                    .recent
                    .last()
                    .map_or(peer.seen, |event| event.sequence);
            }
        }
        for (target, event) in observed {
            if let Some(source) = self
                .peers
                .values()
                .find(|peer| peer.remote.endpoint().identity == event.remote)
                .map(|peer| peer.node)
            {
                self.next_packet = self.next_packet.saturating_add(1);
                self.packets.push_back((
                    Instant::now(),
                    NetworkPacket {
                        id: self.next_packet,
                        from: source,
                        to: target,
                        kind: if event.operation == "probe" {
                            PacketKind::Ping
                        } else {
                            PacketKind::Request
                        },
                        progress: 1.0,
                        request_id: None,
                    },
                ));
                self.logs.push_back(NetworkLog{time_ms:self.started.elapsed().as_secs_f64()*1000.0,message:format!("Peer node {source} → {target}: {} / {} received application bytes / {} sent reply bytes",event.operation,event.received_bytes,event.sent_bytes)});
            }
        }
        self.drain_observations();
    }
    fn drain_observations(&mut self) {
        while let Ok(trace) = self.traces.try_recv() {
            let target = self
                .peers
                .values()
                .find(|p| p.remote.endpoint().identity == trace.peer)
                .map(|p| p.node);
            if let Some(target) = target {
                let source = self.session.load(Ordering::Acquire);
                if trace.request_bytes > 0 {
                    self.next_packet = self.next_packet.saturating_add(1);
                    self.packets.push_back((
                        Instant::now(),
                        NetworkPacket {
                            id: self.next_packet,
                            from: source,
                            to: target,
                            kind: PacketKind::Request,
                            progress: 1.0,
                            request_id: Some(trace.request_id),
                        },
                    ));
                }
                if trace.response_bytes > 0 {
                    self.next_packet = self.next_packet.saturating_add(1);
                    self.packets.push_back((
                        Instant::now(),
                        NetworkPacket {
                            id: self.next_packet,
                            from: target,
                            to: source,
                            kind: PacketKind::Response,
                            progress: 1.0,
                            request_id: Some(trace.request_id),
                        },
                    ));
                }
                self.logs.push_back(NetworkLog {
                    time_ms: self.started.elapsed().as_secs_f64() * 1000.0,
                    message: format!(
                        "{} → node {target}: {} application bytes / {} reply bytes / {:.1} ms / {}",
                        trace.operation,
                        trace.request_bytes,
                        trace.response_bytes,
                        trace.elapsed_ms,
                        if trace.succeeded {
                            "completed"
                        } else {
                            "failed"
                        }
                    ),
                });
            }
        }
        while self.logs.len() > 40 {
            self.logs.pop_front();
        }
        while self
            .packets
            .front()
            .is_some_and(|(time, _)| time.elapsed() > Duration::from_secs(1))
        {
            self.packets.pop_front();
        }
        while self.packets.len() > 1024 {
            self.packets.pop_front();
        }
    }
    pub fn snapshot(&self) -> Option<LabSnapshot> {
        let db = self.database.as_ref()?;
        let shards = db.shards();
        let peers = self
            .peers
            .iter()
            .map(|(id, p)| {
                let observed = p.status.as_ref().or(p.last_status.as_ref());
                let journal_bytes = observed.map_or(0, |status| status.journal_bytes as usize);
                let public_setup_bytes =
                    observed.map_or(0, |status| status.public_setup_bytes as usize);
                let objects = observed.map(|s| s.objects.as_slice()).unwrap_or(&[]);
                let mut indices = Vec::new();
                let mut offset = 0;
                for shard in &shards {
                    if objects
                        .iter()
                        .any(|object| object.id == shard.object && object.available)
                    {
                        indices.extend(offset..offset + shard.rows);
                    }
                    offset += shard.rows;
                }
                PeerInfo {
                    id: *id,
                    config: p.config.clone(),
                    online: p.status.is_some(),
                    rows: objects.iter().map(|o| o.rows as usize).sum(),
                    logical_bytes: objects.iter().map(|o| o.logical_bytes as usize).sum(),
                    data_bytes: objects.iter().map(|o| o.data_bytes as usize).sum(),
                    index_bytes: objects.iter().map(|o| o.index_bytes as usize).sum(),
                    stored_bytes: objects
                        .iter()
                        .map(|o| o.stored_bytes as usize)
                        .sum::<usize>()
                        + journal_bytes,
                    journal_bytes,
                    public_setup_bytes,
                    owner_row_indices: indices,
                }
            })
            .collect();
        let logical: Vec<_> = shards
            .iter()
            .map(|s| {
                let replicas = s
                    .holders
                    .iter()
                    .filter_map(|id| {
                        self.peers.get(&(*id as usize)).map(|peer| {
                            let object = peer.status.as_ref().and_then(|status| {
                                status
                                    .objects
                                    .iter()
                                    .find(|object| object.id == s.object && object.available)
                            });
                            ReplicaLocation {
                                peer_id: *id as usize,
                                failure_domain: 1,
                                online: peer.status.is_some(),
                                current: object.is_some(),
                                data_bytes: object.map_or(0, |o| o.data_bytes as usize),
                                index_bytes: object.map_or(0, |o| o.index_bytes as usize),
                            }
                        })
                    })
                    .collect::<Vec<_>>();
                let executor = replicas
                    .iter()
                    .find(|r| r.online && r.current)
                    .map(|r| r.peer_id);
                LogicalShardInfo {
                    id: s.id as usize,
                    rows: s.rows,
                    data_head: s.data_head.clone(),
                    index_head: s.index_head.clone(),
                    replicas,
                    executor,
                }
            })
            .collect();
        let unavailable = logical
            .iter()
            .filter(|s| s.executor.is_none())
            .map(|s| s.id)
            .collect();
        let read = logical
            .iter()
            .filter_map(|s| s.executor)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let write = logical
            .iter()
            .flat_map(|s| {
                s.replicas
                    .iter()
                    .filter(|r| r.online && r.current)
                    .map(|r| r.peer_id)
            })
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        Some(LabSnapshot {
            name: db.name().into(),
            revision: db.version().height,
            owner_rows: self.owner_rows.clone(),
            peers,
            replication: Some(ReplicationInfo {
                desired_copies: self.desired,
                shards: logical,
                failure_domains: self.peers.keys().map(|id| (*id, 1)).collect(),
                read_peers: read,
                write_peers: write,
                unavailable_shards: unavailable,
            }),
        })
    }
    pub fn network(&mut self) -> NetworkSnapshot {
        self.drain_observations();
        let mut nodes = self
            .clients
            .iter()
            .map(|(id, name)| NetworkNode {
                id: *id,
                name: name.clone(),
                role: NodeRole::Client,
                peer_id: None,
                online: true,
                process_id: Some(std::process::id()),
            })
            .collect::<Vec<_>>();
        nodes.extend(self.peers.iter().map(|(id, p)| NetworkNode {
            id: p.node,
            name: p.config.name.clone(),
            role: NodeRole::Peer,
            peer_id: Some(*id),
            online: p.status.is_some(),
            process_id: p.process.pid(),
        }));
        let mut links = Vec::new();
        for peer in self.peers.values() {
            if let Some(status) = &peer.status {
                let client = self.session.load(Ordering::Acquire);
                if self.clients.contains_key(&client) {
                    links.push(NetworkLink {
                        from: client,
                        to: peer.node,
                    });
                }
                for neighbor in &status.neighbors {
                    if neighbor.reachable
                        && let Some(other) = self
                            .peers
                            .values()
                            .find(|p| p.remote.endpoint() == &neighbor.endpoint)
                    {
                        links.push(NetworkLink {
                            from: peer.node,
                            to: other.node,
                        });
                    }
                }
            }
        }
        NetworkSnapshot {
            time_ms: self.started.elapsed().as_secs_f64() * 1000.0,
            speed: 1.0,
            paused: false,
            nodes,
            links,
            packets: self.packets.iter().map(|(_, p)| p.clone()).collect(),
            recent: self.logs.iter().cloned().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "starts owned peer daemons; build dcs-peer and set DCS_PEER_BIN"]
    fn real_process_views_follow_verified_sql_copies_failover_and_restart() {
        let mut backend = ProcessBackend::new().unwrap();
        backend
            .create(DatabaseDraft {
                name: "network-view".into(),
                rows: vec![
                    compact_query::PlainRow {
                        age: 18,
                        amount: 20,
                    },
                    compact_query::PlainRow {
                        age: 42,
                        amount: 30,
                    },
                ],
                peers: vec![default_peer_config(1), default_peer_config(2)],
            })
            .unwrap();
        assert!(
            backend
                .peers
                .values()
                .all(|peer| peer.process.bootstrap.authority.is_empty())
        );
        assert_eq!(
            backend.database.as_ref().unwrap().genesis().profile,
            playground_profile()
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            backend.refresh();
            if backend
                .network()
                .links
                .iter()
                .filter(|link| link.from != 1)
                .count()
                >= 2
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "Actual mutual-TLS probes must establish observed reachability"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let pids: std::collections::BTreeSet<_> = backend
            .network()
            .nodes
            .iter()
            .filter(|node| node.role == NodeRole::Peer)
            .map(|node| node.process_id.unwrap())
            .collect();
        assert_eq!(pids.len(), 2);
        assert!(!pids.contains(&std::process::id()));
        assert_eq!(backend.copies(2).unwrap().0, 4);
        backend.refresh();

        let VerifiedResult::Selected {
            columns,
            mut rows,
            version: initial,
        } = backend.query(1, "SELECT * FROM records").unwrap()
        else {
            panic!("Expected verified SELECT");
        };
        rows.sort();
        assert_eq!(
            columns,
            vec![sql_plan::Column::Age, sql_plan::Column::Amount]
        );
        assert_eq!(rows, vec![vec![18, 20], vec![42, 30]]);
        assert!(
            backend
                .network()
                .recent
                .iter()
                .any(|event| event.message.starts_with("fhe-proof"))
        );

        // Losing one local process leaves genuine copies and another journal participant.
        backend.online(1, false).unwrap();
        let VerifiedResult::Selected { rows, .. } = backend
            .query(1, "SELECT amount FROM records WHERE age = 18")
            .unwrap()
        else {
            panic!("Expected verified failover read");
        };
        assert_eq!(rows, vec![vec![20]]);
        backend.add_peer(default_peer_config(3)).unwrap();
        assert_eq!(backend.repair().unwrap().0, 4);
        assert!(
            backend
                .database
                .as_ref()
                .unwrap()
                .shards()
                .iter()
                .all(|shard| shard.holders.contains(&3))
        );
        backend.online(1, true).unwrap();
        assert!(!pids.contains(&backend.peers[&1].process.pid().unwrap()));

        let VerifiedResult::Updated {
            changed_rows,
            version: updated,
        } = backend
            .query(1, "UPDATE records SET amount = amount + 5 WHERE age = 18")
            .unwrap()
        else {
            panic!("Expected verified UPDATE");
        };
        assert_eq!(changed_rows, 1);
        assert!(updated.height > initial.height);
        assert!(
            backend
                .owner_rows
                .iter()
                .any(|row| row.age == 18 && row.amount == 25)
        );
        let VerifiedResult::Inserted {
            count,
            version: inserted,
        } = backend
            .query(1, "INSERT INTO records (age, amount) VALUES (7, 9)")
            .unwrap()
        else {
            panic!("Expected verified INSERT");
        };
        assert_eq!(count, 1);
        assert!(inserted.height > updated.height);
        assert_eq!(backend.owner_rows.len(), 3);
        assert!(
            backend
                .owner_rows
                .iter()
                .any(|row| row.age == 7 && row.amount == 9)
        );
        let VerifiedResult::Selected { rows, version, .. } = backend
            .query(1, "SELECT * FROM records WHERE age = 7")
            .unwrap()
        else {
            panic!("Expected read-after-write SELECT");
        };
        assert_eq!(rows, vec![vec![7, 9]]);
        assert!(version.height >= inserted.height);
        assert_eq!(backend.snapshot().unwrap().revision, version.height);
        assert!(
            backend
                .snapshot()
                .unwrap()
                .replication
                .unwrap()
                .failure_domains
                .iter()
                .all(|(_, domain)| *domain == 1)
        );
        backend.remove(1).unwrap();
        assert!(backend.query(1, "SELECT * FROM records").is_err());
    }
    #[test]
    #[ignore = "starts owned peer daemons; build dcs-peer and set DCS_PEER_BIN"]
    fn dropping_the_manager_stops_its_owned_processes_and_never_leaves_a_simulated_fallback() {
        let remote = {
            let mut backend = ProcessBackend::new().unwrap();
            backend.add_peer(PeerConfig::numbered(1)).unwrap();
            let remote = backend.peers[&1].remote.clone();
            assert!(remote.status().is_ok());
            remote
        };
        assert!(remote.status().is_err());
    }
}
