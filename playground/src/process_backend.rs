//! OS process supervision and view adaptation. No protocol or FHE evaluator here.
use crate::traffic::{LiveTraffic, MAX_OBSERVATIONS, Observation};
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
            .arg("--exit-on-stdin-close")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env(
                "RAYON_NUM_THREADS",
                crate::resources::cpu_workers().to_string(),
            );
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
            // Retain Child::stdin after bootstrap. Its OS pipe is the lifetime
            // lease: a killed/crashed GUI closes it without needing Drop to run.
            peer_transport::write_frame(
                child
                    .stdin
                    .as_mut()
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
/// Manager-owned process settings, available before any database exists.
#[derive(Clone, Debug)]
pub(crate) struct PeerProfile {
    pub node: NodeId,
    pub id: usize,
    pub config: PeerConfig,
}
type TopologyObserver = Arc<dyn Fn(Vec<PeerProfile>, NetworkSnapshot) + Send + Sync>;
pub(super) struct ProcessBackend {
    owner: Identity,
    connector: Connector,
    pub(super) request_control: peer_runtime::RequestControl,
    root: PathBuf,
    peers: BTreeMap<usize, Peer>,
    clients: BTreeMap<NodeId, String>,
    next_peer: usize,
    next_node: NodeId,
    database: Option<Session>,
    relational: Option<storage_client::relational::RelationalSession>,
    retained_databases: Vec<Session>,
    owner_rows: Vec<compact_query::PlainRow>,
    desired: usize,
    started: Instant,
    traces: Receiver<Trace>,
    trace_sender: SyncSender<Trace>,
    session: Arc<AtomicU64>,
    logs: VecDeque<NetworkLog>,
    packets: VecDeque<(Instant, NetworkPacket)>,
    next_packet: Arc<AtomicU64>,
    pub(super) traffic: LiveTraffic,
    pub(super) wake_traffic: Option<Arc<dyn Fn() + Send + Sync>>,
    pub(super) observe_traffic: Option<Arc<dyn Fn(Observation) + Send + Sync>>,
    pub(super) observe_topology: Option<TopologyObserver>,
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
            request_control: peer_runtime::RequestControl::default(),
            root,
            peers: BTreeMap::new(),
            clients: BTreeMap::from([(1, "Client 01".into())]),
            next_peer: 1,
            next_node: 2,
            database: None,
            relational: None,
            retained_databases: Vec::new(),
            owner_rows: vec![],
            desired: 1,
            started: Instant::now(),
            traces,
            trace_sender,
            session: Arc::new(AtomicU64::new(1)),
            logs: VecDeque::new(),
            packets: VecDeque::new(),
            next_packet: Arc::new(AtomicU64::new(1)),
            traffic: Arc::default(),
            wake_traffic: None,
            observe_traffic: None,
            observe_topology: None,
        })
    }
    fn remote(&self, endpoint: Endpoint, node: NodeId) -> RemotePeer {
        let sender = self.trace_sender.clone();
        let traffic = self.traffic.clone();
        let session = self.session.clone();
        let sequence = self.next_packet.clone();
        let wake = self.wake_traffic.clone();
        let observe = self.observe_traffic.clone();
        RemotePeer::new(endpoint, self.connector.clone())
            .with_control(self.request_control.clone())
            .with_activity(Arc::new(move |activity| {
                let source = session.load(Ordering::Acquire);
                let reply = activity.phase == peer_runtime::ActivityPhase::ReplyReceived;
                let health = matches!(
                    activity.operation.as_str(),
                    "probe" | "status" | "neighbors" | "quota" | "shutdown"
                );
                let Ok(id) = sequence
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
                else {
                    return;
                };
                let packet = NetworkPacket {
                    id,
                    from: if reply { node } else { source },
                    to: if reply { source } else { node },
                    kind: match (health, reply) {
                        (true, false) => PacketKind::Ping,
                        (true, true) => PacketKind::Pong,
                        (false, false) => PacketKind::Request,
                        (false, true) => PacketKind::Response,
                    },
                    progress: 1.0,
                    request_id: Some(activity.request_id),
                };
                let observation = Observation {
                    packet,
                    operation: activity.operation,
                    bytes: activity.bytes,
                };
                if let Some(observe) = &observe {
                    observe(observation);
                } else if let Ok(mut pending) = traffic.lock() {
                    if pending.len() == MAX_OBSERVATIONS {
                        pending.pop_front();
                    }
                    pending.push_back(observation);
                }
                if let Some(wake) = &wake {
                    wake();
                }
            }))
            .with_trace(Arc::new(move |trace| {
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
        let remote = self.remote(endpoint, node);
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
        if let Some(observe) = self.observe_topology.clone() {
            observe(self.peer_profiles(), self.network());
        }
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
        if self.relational.is_some() {
            return Err(error(
                "An imported typed catalog already exists; it was not replaced",
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
    #[cfg(test)]
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
    #[cfg(test)]
    pub fn import(&mut self, draft: DatabaseDraft) -> Result<(), LabError> {
        if self.database.is_some() || self.relational.is_some() {
            return Err(error(
                "A database already exists. Import requires a new empty workspace; existing encrypted data was not replaced.",
            ));
        }
        self.create(draft)
    }
    pub fn import_relational(
        &mut self,
        database: relational_types::ImportedDatabase,
    ) -> Result<(), LabError> {
        if self.database.is_some() || self.relational.is_some() {
            return Err(error(
                "Import requires an empty workspace; existing encrypted data was not replaced",
            ));
        }
        if self.peers.is_empty() {
            for id in 1..=3 {
                self.add_peer(default_peer_config(id))?;
            }
        }
        let participants = self
            .peers
            .iter_mut()
            .filter_map(|(id, peer)| {
                peer.process.running().then(|| Participant {
                    id: *id as u64,
                    remote: peer.remote.clone(),
                })
            })
            .collect();
        let session = storage_client::relational::RelationalSession::import(
            database,
            participants,
            playground_profile(),
        )
        .map_err(error)?;
        self.desired = if self.peers.len() > 1 { 2 } else { 1 };
        self.relational = Some(session);
        self.owner_rows.clear();
        self.refresh();
        Ok(())
    }
    pub fn catalog(&self) -> Vec<(relational_types::TableSchema, usize)> {
        self.relational
            .as_ref()
            .map(|db| {
                db.schemas()
                    .into_iter()
                    .zip(db.shards().iter().map(|s| s.rows))
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn has_relational(&self) -> bool {
        self.relational.is_some()
    }
    pub fn execute_typed(
        &mut self,
        client: NodeId,
        sql: &str,
    ) -> Result<storage_client::relational::Selected, LabError> {
        if !self.clients.contains_key(&client) {
            return Err(error("Requesting client session was removed"));
        }
        self.session.store(client, Ordering::Release);
        self.relational
            .as_mut()
            .ok_or(LabError::NoDatabase)?
            .select(sql)
            .map_err(error)
    }
    fn shards(&self) -> Vec<storage_client::ShardInfo> {
        self.relational
            .as_ref()
            .map(|db| db.shards())
            .or_else(|| self.database.as_ref().map(|db| db.shards()))
            .unwrap_or_default()
    }
    pub fn execute_sql(
        &mut self,
        client: NodeId,
        sql: &str,
    ) -> Result<storage_client::ScriptResult, LabError> {
        if self.relational.is_some() {
            return Err(error(
                "Use the typed SQL execution path for the imported catalog",
            ));
        }
        if !self.clients.contains_key(&client) {
            return Err(error("Requesting client session was removed"));
        }
        let script = storage_client::SqlScript::parse(sql).map_err(error)?;
        self.session.store(client, Ordering::Release);
        let had_database = self.database.is_some();
        let mut database = self.database.take();
        let result = script.execute(&mut database, || {
            if self.peers.is_empty() {
                for id in 1..=3 {
                    self.add_peer(default_peer_config(id))
                        .map_err(|e| storage_client::Error::InvalidInput(e.to_string()))?;
                }
            }
            let participants = self
                .peers
                .iter_mut()
                .filter_map(|(id, peer)| {
                    peer.process.running().then(|| Participant {
                        id: *id as u64,
                        remote: peer.remote.clone(),
                    })
                })
                .collect();
            Session::create("database".into(), &[], participants, playground_profile())
        });
        // Runtime failures may follow committed statements; retain the actual
        // session and head. SQL scripts are deliberately not transactions.
        self.database = database;
        let completed = match &result {
            Ok(result) => &result.statements,
            Err(error) => &error.completed,
        };
        let changed = !had_database
            || completed.iter().any(|statement| {
                matches!(
                    statement.result,
                    storage_client::StatementResult::Executed(
                        VerifiedResult::Updated { .. } | VerifiedResult::Inserted { .. }
                    )
                )
            });
        if let Some(database) = &self.database
            && changed
        {
            if !had_database {
                self.desired = if database.shards().len() > 1 { 2 } else { 1 };
            }
            self.owner_rows = database.inspect_rows().map_err(|e| error(format!("SQL finished at confirmed version {}, but refreshing the owner view failed: {e}", database.version().height)))?;
        }
        result.map_err(error)
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
            let node = self.peers[&id].node;
            let remote = self.remote(endpoint, node);
            let peer = self.peers.get_mut(&id).unwrap();
            peer.remote = remote.clone();
            peer.seen = 0;
            peer.status = None;
            if let Some(db) = &mut self.database {
                db.replace_participant(Participant {
                    id: id as u64,
                    remote: remote.clone(),
                })
                .map_err(error)?;
            }
            if let Some(db) = &mut self.relational {
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
        if self.database.is_none() && self.relational.is_none() {
            return Err(LabError::NoDatabase);
        }
        let shards = self.shards();
        let mut total = 0;
        for shard in shards {
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
                    let target = Participant {
                        id: *id as u64,
                        remote: peer.remote.clone(),
                    };
                    let copied = if let Some(db) = &mut self.relational {
                        db.copy_shard(shard.id, target)
                    } else {
                        self.database
                            .as_mut()
                            .expect("checked database")
                            .copy_shard(shard.id, target)
                    };
                    if copied.is_err() {
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
                let Ok(id) =
                    self.next_packet
                        .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
                else {
                    continue;
                };
                let packet = NetworkPacket {
                    id,
                    from: source,
                    to: target,
                    kind: if matches!(
                        event.operation.as_str(),
                        "probe" | "status" | "neighbors" | "journal-sync"
                    ) {
                        PacketKind::Ping
                    } else {
                        PacketKind::Request
                    },
                    progress: 1.0,
                    request_id: None,
                };
                self.packets.push_back((Instant::now(), packet.clone()));
                if let Some(observe) = &self.observe_traffic {
                    observe(Observation {
                        packet,
                        operation: format!("Peer reported completed {}", event.operation),
                        bytes: event.received_bytes,
                    });
                }
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
        let (name, revision) = if let Some(db) = &self.relational {
            (db.name(), db.version().height)
        } else {
            let db = self.database.as_ref()?;
            (db.name(), db.version().height)
        };
        let shards = self.shards();
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
                    rows: if self.relational.is_some() {
                        shards
                            .iter()
                            .filter(|s| objects.iter().any(|o| o.id == s.object && o.available))
                            .map(|s| s.rows)
                            .sum()
                    } else {
                        objects.iter().map(|o| o.rows as usize).sum()
                    },
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
            name: name.into(),
            revision,
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
    pub fn peer_profiles(&self) -> Vec<PeerProfile> {
        self.peers
            .iter()
            .map(|(id, peer)| PeerProfile {
                node: peer.node,
                id: *id,
                config: peer.config.clone(),
            })
            .collect()
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
    fn real_peer_inventory_and_configuration_exist_before_database_creation() {
        let mut backend = ProcessBackend::new().unwrap();
        let first = backend.add_peer(default_peer_config(1)).unwrap();
        let second = backend.add_peer(default_peer_config(2)).unwrap();
        assert!(backend.snapshot().is_none());
        let profiles = backend.peer_profiles();
        assert_eq!(
            profiles
                .iter()
                .map(|peer| (peer.node, peer.config.name.as_str()))
                .collect::<Vec<_>>(),
            vec![(first, "Peer 01"), (second, "Peer 02")]
        );
        let config = PeerConfig {
            name: "Configured before storage".into(),
            storage_limit_bytes: 32 * 1024 * 1024,
            ..profiles[1].config.clone()
        };

        backend.configure(2, config.clone()).unwrap();

        assert!(backend.snapshot().is_none());
        assert_eq!(backend.peer_profiles()[1].config, config);
        let network = backend.network();
        let configured = network.nodes.iter().find(|node| node.id == second).unwrap();
        assert_eq!(configured.name, "Configured before storage");
        assert!(
            configured
                .process_id
                .is_some_and(|pid| pid != std::process::id())
        );
        backend.remove(first).unwrap();
        assert_eq!(backend.peer_profiles().len(), 1);
    }
    #[test]
    #[ignore = "starts owned peer daemons; build dcs-peer and set DCS_PEER_BIN"]
    fn real_process_views_follow_verified_sql_copies_failover_and_restart() {
        let rows = vec![
            compact_query::PlainRow {
                age: 18,
                amount: 20,
            },
            compact_query::PlainRow {
                age: 42,
                amount: 30,
            },
        ];
        let mut backend = ProcessBackend::new().unwrap();
        backend
            .create(DatabaseDraft {
                name: "network-view".into(),
                rows,
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

        backend.traffic.lock().unwrap().clear();
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
        let observed = backend.traffic.lock().unwrap();
        assert!(observed.iter().any(|event| event.operation == "fhe-proof"
            && event.packet.kind == PacketKind::Request
            && event.packet.from == 1
            && event.bytes > 0));
        assert!(observed.iter().any(|event| event.operation == "fhe-proof"
            && event.packet.kind == PacketKind::Response
            && event.packet.to == 1
            && event.bytes > 0));
        drop(observed);
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
    fn sql_bootstrap_from_an_empty_workspace_returns_a_proved_empty_table_and_preserves_later_writes()
     {
        let startup = format!(
            "{} SELECT * FROM records;",
            crate::samples::SUPPORTED_SCHEMA.replace("CREATE TABLE", "CREATE TABLE IF NOT EXISTS")
        );
        let mut backend = ProcessBackend::new().unwrap();

        let missing = backend.execute_sql(1, "SELECT * FROM records").unwrap_err();

        assert!(missing.to_string().contains("No database/table exists"));
        assert!(backend.database.is_none());
        assert!(backend.peers.is_empty());

        let created = backend.execute_sql(1, &startup).unwrap();

        assert!(matches!(
            created.statements[0].result,
            storage_client::StatementResult::Created { created: true, .. }
        ));
        let storage_client::StatementResult::Executed(VerifiedResult::Selected {
            ref rows,
            ref columns,
            version: initial,
        }) = created.statements[1].result
        else {
            panic!("Bootstrap must return a verified SELECT, not an owner-built empty answer");
        };
        assert!(rows.is_empty());
        assert_eq!(columns, &[sql_plan::Column::Age, sql_plan::Column::Amount]);
        let genesis = backend.database.as_ref().unwrap().genesis().clone();
        let pids: std::collections::BTreeSet<_> = backend
            .peers
            .values()
            .map(|peer| peer.process.pid().unwrap())
            .collect();
        assert_eq!(pids.len(), 3);
        assert!(!pids.contains(&std::process::id()));
        assert!(backend.traffic.lock().unwrap().iter().any(|event| {
            event.operation == "fhe-proof" && event.packet.kind == PacketKind::Response
        }));

        let changed = backend
            .execute_sql(
                1,
                "INSERT INTO records VALUES (18,20),(42,30); UPDATE records SET amount = amount + 5 WHERE age = 18; SELECT * FROM records;",
            )
            .unwrap();

        assert_eq!(changed.statements.len(), 4);
        for outcome in &changed.statements[..2] {
            assert!(matches!(
                outcome.result,
                storage_client::StatementResult::Executed(VerifiedResult::Inserted { count: 1, version })
                    if version.height > initial.height
            ));
        }
        assert!(matches!(
            changed.statements[2].result,
            storage_client::StatementResult::Executed(VerifiedResult::Updated {
                changed_rows: 1,
                ..
            })
        ));
        let storage_client::StatementResult::Executed(VerifiedResult::Selected {
            ref rows,
            version: written,
            ..
        }) = changed.statements[3].result
        else {
            panic!("The final script statement must return verified updated rows");
        };
        let mut actual = rows.clone();
        actual.sort();
        assert_eq!(actual, [vec![18, 25], vec![42, 30]]);

        let repeated = backend.execute_sql(1, &startup).unwrap();

        assert!(matches!(
            repeated.statements[0].result,
            storage_client::StatementResult::Created { created: false, .. }
        ));
        let storage_client::StatementResult::Executed(VerifiedResult::Selected {
            ref rows,
            version,
            ..
        }) = repeated.statements[1].result
        else {
            panic!("Repeated IF NOT EXISTS must preserve the actual table");
        };
        let mut actual = rows.clone();
        actual.sort();
        assert_eq!(actual, [vec![18, 25], vec![42, 30]]);
        assert!(version.height >= written.height);
        assert_eq!(backend.database.as_ref().unwrap().genesis(), &genesis);
    }

    #[test]
    #[ignore = "starts owned peer daemons; build dcs-peer and set DCS_PEER_BIN"]
    fn sql_script_preflight_rejects_unsupported_locks_and_runtime_failure_retains_preceding_commits()
     {
        let mut backend = ProcessBackend::new().unwrap();
        backend
            .import(DatabaseDraft {
                name: "partial-script".into(),
                rows: vec![compact_query::PlainRow {
                    age: 18,
                    amount: 65_534,
                }],
                peers: vec![default_peer_config(1)],
            })
            .unwrap();
        let initial = backend.database.as_ref().unwrap().version();
        let heads: Vec<_> = backend
            .database
            .as_ref()
            .unwrap()
            .shards()
            .into_iter()
            .map(|shard| (shard.object, shard.data_head, shard.index_head))
            .collect();

        let unsupported = backend
            .execute_sql(
                1,
                "UPDATE records SET amount = amount + 1; SELECT * FROM records FOR UPDATE;",
            )
            .unwrap_err();

        assert!(unsupported.to_string().contains("row locking"));
        assert_eq!(backend.database.as_ref().unwrap().version(), initial);
        assert_eq!(
            backend
                .database
                .as_ref()
                .unwrap()
                .shards()
                .into_iter()
                .map(|shard| (shard.object, shard.data_head, shard.index_head))
                .collect::<Vec<_>>(),
            heads
        );

        let failed = backend
            .execute_sql(
                1,
                "UPDATE records SET amount = amount + 1; UPDATE records SET amount = amount + 1; SELECT * FROM records;",
            )
            .unwrap_err();

        let message = failed.to_string();
        assert!(message.contains("Statement 2"), "{message}");
        assert!(message.contains("overflowed"), "{message}");
        assert!(
            message.contains("1 preceding operation(s) completed"),
            "{message}"
        );
        assert!(message.contains("not a transaction"), "{message}");
        assert!(backend.database.as_ref().unwrap().version().height > initial.height);
        assert_eq!(
            backend.owner_rows,
            [compact_query::PlainRow {
                age: 18,
                amount: 65_535
            }]
        );
        let actual = backend.execute_sql(1, "SELECT * FROM records;").unwrap();
        let storage_client::StatementResult::Executed(VerifiedResult::Selected {
            ref rows, ..
        }) = actual.statements[0].result
        else {
            panic!("Expected a verified read of the committed first UPDATE");
        };
        assert_eq!(rows, &[vec![18, 65_535]]);
    }

    #[test]
    #[ignore = "starts owned peer daemons; build dcs-peer and set DCS_PEER_BIN"]
    fn validated_import_creates_real_ciphertext_and_never_replaces_an_existing_database() {
        let mut backend = ProcessBackend::new().unwrap();

        backend
            .import(DatabaseDraft {
                name: "imported".into(),
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

        let genesis = backend.database.as_ref().unwrap().genesis().clone();
        let selected = backend.execute_sql(1, "SELECT * FROM records;").unwrap();
        let storage_client::StatementResult::Executed(VerifiedResult::Selected {
            ref rows,
            version,
            ..
        }) = selected.statements[0].result
        else {
            panic!("Imported owner input must be read back through the verified peer path");
        };
        let mut actual = rows.clone();
        actual.sort();
        assert_eq!(actual, [vec![18, 20], vec![42, 30]]);
        assert!(
            backend
                .database
                .as_ref()
                .unwrap()
                .shards()
                .iter()
                .all(|shard| shard.holders.len() == 2)
        );

        let rejected = backend
            .import(DatabaseDraft {
                name: "replacement".into(),
                rows: vec![compact_query::PlainRow { age: 7, amount: 99 }],
                peers: vec![],
            })
            .unwrap_err();

        assert!(rejected.to_string().contains("already exists"));
        assert_eq!(backend.database.as_ref().unwrap().name(), "imported");
        assert_eq!(backend.database.as_ref().unwrap().genesis(), &genesis);
        assert_eq!(backend.database.as_ref().unwrap().version(), version);
        assert_eq!(backend.owner_rows.len(), 2);
    }

    #[test]
    #[ignore = "starts owned peer daemons; build dcs-peer and set DCS_PEER_BIN"]
    fn official_northwind_import_and_typed_select_use_independent_peer_processes() {
        if let Some(directory) = std::env::var_os("DCS_TEST_PROOF_KERNEL_DIR") {
            let backend =
                bfv_query_proof::initialize_backend(&std::path::PathBuf::from(directory)).unwrap();
            eprintln!("Client proof backend: {backend:?}");
        }
        let path = std::env::var("DCS_NORTHWIND_SQL")
            .expect("set the path of the official downloaded Microsoft instnwnd.sql");
        let sql = std::fs::read_to_string(path).unwrap();
        let prepared = crate::samples::prepare_import(&sql).expect("complete official dump");
        assert_eq!(prepared.database.tables.len(), 13);
        assert_eq!(prepared.database.row_count(), 3308);
        let detail_schema = prepared
            .database
            .table("Order Details")
            .unwrap()
            .schema
            .clone();
        let expected_details = prepared
            .database
            .table("Order Details")
            .unwrap()
            .rows
            .clone();
        let mut backend = ProcessBackend::new().unwrap();
        let imported = Instant::now();
        backend.import_relational(prepared.database).unwrap();
        eprintln!("Northwind encrypted import: {:?}", imported.elapsed());
        let pids: std::collections::BTreeSet<_> = backend
            .peers
            .values()
            .map(|p| p.process.pid().unwrap())
            .collect();
        assert_eq!(pids.len(), 3);
        assert!(!pids.contains(&std::process::id()));
        assert_eq!(
            backend
                .catalog()
                .iter()
                .map(|(_, rows)| rows)
                .sum::<usize>(),
            3308
        );
        assert!(
            backend.owner_rows.is_empty(),
            "no plaintext imported answer cache"
        );

        let answer=backend.execute_typed(1,"SELECT CustomerID, CompanyName FROM Customers WHERE Country = 'Germany' ORDER BY CustomerID;").unwrap();
        eprintln!(
            "German customers: {:?}, {} proof blocks",
            answer.elapsed, answer.proof_blocks
        );
        assert_eq!(answer.rows.len(), 11);
        assert_eq!(
            answer.rows[0][0],
            relational_types::Value::Text("ALFKI".into())
        );
        assert_eq!(answer.columns, ["CustomerID", "CompanyName"]);

        let answer = backend
            .execute_typed(1, "SELECT * FROM [Order Details];")
            .unwrap();
        eprintln!(
            "All order details: {:?}, {} rows, {} proof blocks",
            answer.elapsed,
            answer.rows.len(),
            answer.proof_blocks
        );
        assert_eq!(answer.rows, expected_details);
        assert_eq!(answer.rows.len(), 2155);
        assert!(answer.proof_blocks > 1);
        assert_eq!(
            answer.columns,
            detail_schema
                .columns
                .iter()
                .map(|c| c.name.clone())
                .collect::<Vec<_>>()
        );
        assert!(
            backend
                .snapshot()
                .unwrap()
                .peers
                .iter()
                .map(|p| p.rows)
                .sum::<usize>()
                >= 3308
        );

        let answer=backend.execute_typed(1,"SELECT ProductID, ProductName, UnitPrice FROM Products WHERE UnitPrice >= 50 ORDER BY UnitPrice DESC;").unwrap();
        assert!(!answer.rows.is_empty());
        assert_eq!(
            answer.rows[0][1],
            relational_types::Value::Text("Côte de Blaye".into())
        );
        assert!(
            backend
                .execute_typed(1, "UPDATE Products SET UnitPrice = 1;")
                .is_err()
        );
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
