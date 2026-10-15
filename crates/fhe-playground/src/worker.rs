use std::collections::{BTreeMap, BTreeSet};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui;
use fhe_playground::{
    DatabaseDraft, Delivery, DemoNetwork, LabEngine, LabError, LabProgress, LabSnapshot,
    NetworkSnapshot, NodeId, NodeRole, PeerConfig, QueryOutcome,
};

pub enum Command {
    Create(DatabaseDraft),
    Query { client_id: NodeId, sql: String },
    AddPeer(PeerConfig),
    AddClient { name: String },
    RemoveNode { id: NodeId },
    SetPeer { id: usize, online: bool },
    ConfigurePeer { id: usize, config: PeerConfig },
    SetSimulation { speed: f64, paused: bool },
    SetReplication { copies: usize },
    SetFailureDomain { id: usize, domain: u64 },
    RepairReplicas,
}

#[derive(Debug)]
pub enum Outcome {
    Created,
    PeerChanged,
    NodeAdded { id: NodeId },
    NodeRemoved { id: NodeId },
    ReplicasRepaired { current: usize, stale: usize },
    Query(QueryOutcome),
}

pub enum Event {
    Network(NetworkSnapshot),
    Progress(String),
    PeerProgress(LabProgress),
    Finished {
        snapshot: Option<LabSnapshot>,
        outcome: Result<Outcome, LabError>,
        elapsed_ms: f64,
        client_id: Option<NodeId>,
    },
    ControlFinished {
        snapshot: Option<LabSnapshot>,
        outcome: Result<Outcome, LabError>,
    },
    MaintenanceFinished {
        snapshot: Option<LabSnapshot>,
        outcome: Result<Outcome, LabError>,
    },
}

pub struct Worker {
    sender: SyncSender<Command>,
    receiver: Receiver<Event>,
    latest_network: Arc<Mutex<Option<NetworkSnapshot>>>,
}

impl Worker {
    #[cfg(test)]
    pub fn test_channel() -> (Self, Receiver<Command>, mpsc::Sender<Event>) {
        let (sender, commands) = mpsc::sync_channel(32);
        let (events, receiver) = mpsc::channel();
        (
            Self {
                sender,
                receiver,
                latest_network: Arc::default(),
            },
            commands,
            events,
        )
    }
    pub fn start(context: egui::Context) -> std::io::Result<Self> {
        let (sender, commands) = mpsc::sync_channel(32);
        let (events, receiver) = mpsc::channel();
        let latest_network = Arc::new(Mutex::new(None));
        let snapshots = Arc::clone(&latest_network);
        std::thread::Builder::new()
            .name("fhe-lab-network".into())
            .spawn(move || run(commands, events, snapshots, context))?;
        Ok(Self {
            sender,
            receiver,
            latest_network,
        })
    }
    pub fn send(&self, command: Command) -> Result<(), String> {
        self.sender
            .try_send(command)
            .map_err(|error| format!("Cannot submit operation: {error}"))
    }
    pub fn poll(&self) -> Result<Option<Event>, String> {
        match self.receiver.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(TryRecvError::Empty) => Ok(self
                .latest_network
                .lock()
                .map_err(|_| "Network snapshot lock failed.".to_owned())?
                .take()
                .map(Event::Network)),
            Err(TryRecvError::Disconnected) => {
                Err("The FHE worker stopped. Restart the playground.".into())
            }
        }
    }
}

enum ComputeCommand {
    Create {
        draft: DatabaseDraft,
        ids: Vec<usize>,
        offline: Vec<usize>,
    },
    Control(EngineControl),
    Prepare {
        id: u64,
        sql: String,
    },
    Commit {
        id: u64,
        permit: Arc<Mutex<CommitState>>,
    },
    Abort,
}
enum EngineControl {
    Repartition(Vec<(usize, PeerConfig, bool)>),
    SetPeer { id: usize, online: bool },
    Configure { id: usize, config: PeerConfig },
    SetReplication { copies: usize },
    SetFailureDomain { id: usize, domain: u64 },
    RepairReplicas,
}
enum ComputeEvent {
    Created {
        snapshot: Option<LabSnapshot>,
        result: Result<(), LabError>,
    },
    Controlled {
        snapshot: Option<LabSnapshot>,
        result: Result<(), LabError>,
    },
    Prepared {
        id: u64,
        result: Result<QueryOutcome, LabError>,
    },
    Committed {
        id: u64,
        snapshot: Option<LabSnapshot>,
    },
    Progress {
        id: u64,
        message: LabProgress,
    },
}
#[derive(Clone)]
enum NetworkControl {
    AddPeer { id: usize, config: PeerConfig },
    Remove { id: NodeId },
    SetPeer { id: usize, online: bool },
    Configure { id: usize, config: PeerConfig },
    SetReplication { copies: usize },
    SetFailureDomain { id: usize, domain: u64 },
    RepairReplicas { automatic: bool },
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Requests,
    Computing,
    Responses,
    Committing,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommitState {
    Pending,
    Cancelled,
    Committed,
}
struct PendingQuery {
    id: u64,
    client: NodeId,
    sql: String,
    peers: BTreeSet<usize>,
    received: BTreeSet<usize>,
    phase: Phase,
    outcome: Option<QueryOutcome>,
    start: Instant,
    route_start: f64,
    permit: Arc<Mutex<CommitState>>,
}
struct Runtime {
    network: DemoNetwork,
    snapshot: Option<LabSnapshot>,
    profiles: BTreeMap<usize, (PeerConfig, bool)>,
    next_peer: usize,
    next_request: u64,
    query: Option<PendingQuery>,
    control: Option<NetworkControl>,
    creating: Option<Instant>,
    repair_pending: bool,
    compute: SyncSender<ComputeCommand>,
    events: mpsc::Sender<Event>,
}

fn run(
    commands: Receiver<Command>,
    events: mpsc::Sender<Event>,
    snapshots: Arc<Mutex<Option<NetworkSnapshot>>>,
    context: egui::Context,
) {
    let (compute, jobs) = mpsc::sync_channel(8);
    let (answers, results) = mpsc::channel();
    let spawn = std::thread::Builder::new()
        .name("fhe-lab-compute".into())
        .spawn(move || compute_loop(jobs, answers));
    if let Err(error) = spawn {
        let _ = events.send(Event::Finished {
            snapshot: None,
            outcome: Err(LabError::InvalidInput(format!(
                "Cannot start FHE worker: {error}"
            ))),
            elapsed_ms: 0.0,
            client_id: None,
        });
        return;
    }
    let mut runtime = Runtime {
        network: DemoNetwork::default(),
        snapshot: None,
        profiles: BTreeMap::new(),
        next_peer: 4,
        next_request: 1,
        query: None,
        control: None,
        creating: None,
        repair_pending: false,
        compute,
        events,
    };
    let _ = runtime.network.add_client("Client 01".into());
    for id in 1..=3 {
        let config = PeerConfig::numbered(id);
        let _ = runtime.network.add_peer(id, &config, true);
        runtime.profiles.insert(id, (config, true));
    }
    let mut tick = Instant::now();
    loop {
        match commands.recv_timeout(Duration::from_millis(25)) {
            Ok(command) => runtime.command(command),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                runtime.cancel_query("Application closed before response delivery.");
                break;
            }
        }
        loop {
            match results.try_recv() {
                Ok(answer) => runtime.answer(answer),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    runtime
                        .cancel_query("The FHE compute worker stopped before response delivery.");
                    if runtime.creating.take().is_some() {
                        runtime.finish(
                            Err(LabError::InvalidInput(
                                "The FHE compute worker stopped.".into(),
                            )),
                            None,
                            0.0,
                        );
                    }
                    if let Some(control) = runtime.control.take() {
                        runtime.control_result(
                            matches!(control, NetworkControl::RepairReplicas { automatic: true }),
                            Err(LabError::InvalidInput(
                                "The FHE compute worker stopped.".into(),
                            )),
                        );
                    }
                    return;
                }
            }
        }
        let elapsed = tick.elapsed().as_secs_f64();
        tick = Instant::now();
        for delivery in runtime.network.advance(elapsed) {
            runtime.delivered(delivery);
        }
        if runtime.query.as_ref().is_some_and(|query| {
            matches!(query.phase, Phase::Requests | Phase::Responses)
                && runtime.network.snapshot().time_ms - query.route_start > 30_000.0
        }) {
            runtime.cancel_query(
                "Required messages were not delivered before the virtual transport deadline.",
            );
        }
        runtime.maybe_repair();
        if let Ok(mut latest) = snapshots.lock() {
            *latest = Some(runtime.network.snapshot());
        }
        context.request_repaint();
    }
}

fn compute_loop(commands: Receiver<ComputeCommand>, answers: mpsc::Sender<ComputeEvent>) {
    let mut engine = LabEngine::default();
    let mut prepared_id = None;
    while let Ok(command) = commands.recv() {
        let event = match command {
            ComputeCommand::Create {
                draft,
                ids,
                offline,
            } => {
                let result = engine.create_with_peer_ids(draft, ids).and_then(|_| {
                    for id in offline {
                        engine.set_peer_online(id, false)?;
                    }
                    Ok(())
                });
                ComputeEvent::Created {
                    snapshot: engine.snapshot(),
                    result,
                }
            }
            ComputeCommand::Control(control) => {
                engine.discard_prepared();
                prepared_id = None;
                let result = match control {
                    EngineControl::Repartition(profiles) => engine.repartition(profiles),
                    EngineControl::SetPeer { id, online } => engine.set_peer_online(id, online),
                    EngineControl::Configure { id, config } => engine.set_peer_config(id, config),
                    EngineControl::SetReplication { copies } => engine.set_replication(copies),
                    EngineControl::SetFailureDomain { id, domain } => {
                        engine.set_failure_domain(id, domain)
                    }
                    EngineControl::RepairReplicas => engine.repair_replicas(),
                };
                ComputeEvent::Controlled {
                    snapshot: engine.snapshot(),
                    result,
                }
            }
            ComputeCommand::Prepare { id, sql } => {
                let result = engine.prepare_query(&sql, |message| {
                    let _ = answers.send(ComputeEvent::Progress { id, message });
                });
                prepared_id = result.is_ok().then_some(id);
                ComputeEvent::Prepared { id, result }
            }
            ComputeCommand::Commit { id, permit } => {
                if let Ok(mut state) = permit.lock()
                    && *state == CommitState::Pending
                    && prepared_id == Some(id)
                {
                    engine.commit_prepared();
                    prepared_id = None;
                    *state = CommitState::Committed;
                }
                ComputeEvent::Committed {
                    id,
                    snapshot: engine.snapshot(),
                }
            }
            ComputeCommand::Abort => {
                engine.discard_prepared();
                prepared_id = None;
                continue;
            }
        };
        if answers.send(event).is_err() {
            break;
        }
    }
}

impl Runtime {
    fn finish(
        &self,
        outcome: Result<Outcome, LabError>,
        client_id: Option<NodeId>,
        elapsed_ms: f64,
    ) {
        let _ = self.events.send(Event::Finished {
            snapshot: self.snapshot.clone(),
            outcome,
            elapsed_ms,
            client_id,
        });
    }
    fn control_finished(&self, outcome: Result<Outcome, LabError>) {
        let _ = self.events.send(Event::ControlFinished {
            snapshot: self.snapshot.clone(),
            outcome,
        });
    }
    fn control_result(&self, automatic: bool, outcome: Result<Outcome, LabError>) {
        if automatic {
            let _ = self.events.send(Event::MaintenanceFinished {
                snapshot: self.snapshot.clone(),
                outcome,
            });
        } else {
            self.control_finished(outcome);
        }
    }
    fn busy_error() -> LabError {
        LabError::InvalidInput("Another database or topology operation is still running.".into())
    }
    fn command(&mut self, command: Command) {
        match command {
            Command::SetSimulation { speed, paused } => {
                if let Err(error) = self.network.set_simulation(speed, paused) {
                    self.control_finished(Err(error));
                }
            }
            Command::AddClient { name } => {
                let result = self
                    .network
                    .add_client(name)
                    .map(|id| Outcome::NodeAdded { id });
                self.control_finished(result);
            }
            Command::Query { client_id, sql } => {
                if self.query.is_some() || self.creating.is_some() || self.control.is_some() {
                    self.finish(Err(Self::busy_error()), Some(client_id), 0.0);
                    return;
                }
                let result = self.begin_query(client_id, sql);
                if let Err(error) = result {
                    self.finish(Err(error), Some(client_id), 0.0);
                }
            }
            Command::Create(mut draft) => {
                if self.query.is_some() || self.creating.is_some() || self.control.is_some() {
                    self.finish(Err(Self::busy_error()), None, 0.0);
                    return;
                }
                // Topology is owned by node controls, never recreated by owner-data editing.
                draft.peers = self
                    .profiles
                    .values()
                    .map(|(config, _)| config.clone())
                    .collect();
                let ids = self.profiles.keys().copied().collect();
                let offline = self
                    .profiles
                    .iter()
                    .filter(|(_, (_, online))| !online)
                    .map(|(id, _)| *id)
                    .collect();
                self.creating = Some(Instant::now());
                let _ = self.events.send(Event::Progress(
                    "Encrypting owner data into the current peer layout...".into(),
                ));
                if self
                    .compute
                    .try_send(ComputeCommand::Create {
                        draft,
                        ids,
                        offline,
                    })
                    .is_err()
                {
                    self.creating = None;
                    self.finish(Err(Self::busy_error()), None, 0.0);
                }
            }
            Command::RemoveNode { id } => {
                let Some(node) = self.network.node(id) else {
                    self.control_finished(Err(LabError::InvalidInput("Unknown node.".into())));
                    return;
                };
                if node.role == NodeRole::Client {
                    if self.query.as_ref().is_some_and(|query| query.client == id) {
                        self.cancel_query(
                            "Requesting client was deleted; no result or update was accepted.",
                        );
                    }
                    let result = self.network.remove(id).map(|_| Outcome::NodeRemoved { id });
                    self.control_finished(result);
                } else {
                    let peer = node.peer_id.expect("peer mapping");
                    let profiles = self
                        .profiles
                        .iter()
                        .filter(|(other, _)| **other != peer)
                        .map(|(id, (config, online))| (*id, config.clone(), *online))
                        .collect();
                    self.start_control(
                        NetworkControl::Remove { id },
                        EngineControl::Repartition(profiles),
                    );
                }
            }
            Command::AddPeer(config) => {
                if let Err(error) = config.validate() {
                    self.control_finished(Err(error));
                    return;
                }
                if self.profiles.len() >= fhe_playground::MAX_PEERS {
                    self.control_finished(Err(LabError::InvalidInput(
                        "Use at most 16 local peers.".into(),
                    )));
                    return;
                }
                let id = self.next_peer;
                self.next_peer += 1;
                let mut profiles: Vec<_> = self
                    .profiles
                    .iter()
                    .map(|(id, (config, online))| (*id, config.clone(), *online))
                    .collect();
                profiles.push((id, config.clone(), true));
                self.start_control(
                    NetworkControl::AddPeer { id, config },
                    EngineControl::Repartition(profiles),
                );
            }
            Command::SetPeer { id, online } => {
                self.start_control(
                    NetworkControl::SetPeer { id, online },
                    EngineControl::SetPeer { id, online },
                );
            }
            Command::ConfigurePeer { id, config } => {
                if let Err(error) = config.validate() {
                    self.control_finished(Err(error));
                    return;
                }
                self.start_control(
                    NetworkControl::Configure {
                        id,
                        config: config.clone(),
                    },
                    EngineControl::Configure { id, config },
                );
            }
            Command::SetReplication { copies } => {
                if !(1..=3).contains(&copies) {
                    self.control_finished(Err(LabError::InvalidInput(
                        "Choose 1, 2 or 3 minimum copies.".into(),
                    )));
                    return;
                }
                if self.snapshot.is_none() {
                    self.control_finished(Err(LabError::NoDatabase));
                    return;
                }
                if self.query.is_some() {
                    self.control_finished(Err(Self::busy_error()));
                    return;
                }
                self.start_control(
                    NetworkControl::SetReplication { copies },
                    EngineControl::SetReplication { copies },
                );
            }
            Command::SetFailureDomain { id, domain } => {
                if self.snapshot.is_none() {
                    self.control_finished(Err(LabError::NoDatabase));
                    return;
                }
                self.start_control(
                    NetworkControl::SetFailureDomain { id, domain },
                    EngineControl::SetFailureDomain { id, domain },
                );
            }
            Command::RepairReplicas => self.start_repair(false),
        }
    }
    fn repair_gate(&self) -> Result<(), LabError> {
        if self.query.is_some() || self.creating.is_some() || self.control.is_some() {
            return Err(Self::busy_error());
        }
        if self.network.snapshot().paused {
            return Err(LabError::InvalidInput(
                "Local replica repair is deferred while simulation is paused.".into(),
            ));
        }
        if self
            .snapshot
            .as_ref()
            .ok_or(LabError::NoDatabase)?
            .replication
            .is_none()
        {
            return Err(LabError::InvalidInput(
                "Enable a replicated layout before local repair.".into(),
            ));
        }
        let online: Vec<_> = self
            .profiles
            .iter()
            .filter(|(_, (_, online))| *online)
            .map(|(id, _)| *id)
            .collect();
        for (index, from) in online.iter().enumerate() {
            for to in online.iter().skip(index + 1) {
                let route = self
                    .network
                    .peer_node(*from)
                    .zip(self.network.peer_node(*to));
                if !route.is_some_and(|(a, b)| self.network.connected(a, b)) {
                    return Err(LabError::InvalidInput("Local replica repair is deferred until actual peer routes are established.".into()));
                }
            }
        }
        Ok(())
    }
    fn start_repair(&mut self, automatic: bool) {
        if let Err(error) = self.repair_gate() {
            if !automatic {
                self.control_finished(Err(error));
            }
            return;
        }
        self.repair_pending = false;
        self.start_control(
            NetworkControl::RepairReplicas { automatic },
            EngineControl::RepairReplicas,
        );
    }
    fn maybe_repair(&mut self) {
        if !self.repair_pending {
            return;
        }
        let Some(replication) = self
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.replication.as_ref())
        else {
            self.repair_pending = false;
            return;
        };
        let needed = replication.shards.iter().any(|shard| {
            let domains: BTreeSet<_> = shard
                .replicas
                .iter()
                .filter(|copy| copy.online && copy.current)
                .map(|copy| copy.failure_domain)
                .collect();
            domains.len() < replication.desired_copies
                || shard
                    .replicas
                    .iter()
                    .any(|copy| copy.online && !copy.current)
        });
        if !needed {
            self.repair_pending = false;
            return;
        }
        self.start_repair(true);
    }
    fn start_control(&mut self, network: NetworkControl, engine: EngineControl) {
        let automatic = matches!(&network, NetworkControl::RepairReplicas { automatic: true });
        if self.creating.is_some() || self.control.is_some() {
            self.control_result(automatic, Err(Self::busy_error()));
            return;
        }
        self.cancel_query("Peer layout or availability changed while the query was in flight. Staged changes were discarded.");
        // Revoke a removed peer's routes immediately, even if the current FHE
        // operation has not reached its next cancellable boundary yet. A failed
        // manager repartition restores this same stable node and rediscovers it.
        if let NetworkControl::Remove { id } = &network
            && let Some(peer_id) = self.network.node(*id).and_then(|node| node.peer_id)
            && let Some((config, _)) = self.profiles.get(&peer_id)
        {
            let _ = self.network.configure_peer(peer_id, config, false);
        }
        if self.snapshot.is_none() {
            let result = self.apply_control(network);
            self.control_result(automatic, result);
        } else {
            self.control = Some(network);
            if self
                .compute
                .try_send(ComputeCommand::Control(engine))
                .is_err()
            {
                if let Some(control) = self.control.take() {
                    self.restore_failed_control(&control);
                }
                self.control_result(automatic, Err(Self::busy_error()));
            }
        }
    }
    fn restore_failed_control(&mut self, control: &NetworkControl) {
        if let NetworkControl::Remove { id } = control
            && let Some(peer_id) = self.network.node(*id).and_then(|node| node.peer_id)
            && let Some((config, online)) = self.profiles.get(&peer_id)
        {
            let _ = self.network.configure_peer(peer_id, config, *online);
        }
    }
    fn apply_control(&mut self, control: NetworkControl) -> Result<Outcome, LabError> {
        match control {
            NetworkControl::AddPeer { id, config } => {
                let node = self.network.add_peer(id, &config, true)?;
                self.profiles.insert(id, (config, true));
                Ok(Outcome::NodeAdded { id: node })
            }
            NetworkControl::Remove { id } => {
                let node = self.network.remove(id)?;
                if let Some(peer) = node.peer_id {
                    self.profiles.remove(&peer);
                }
                Ok(Outcome::NodeRemoved { id })
            }
            NetworkControl::SetPeer { id, online } => {
                let (config, _) = self
                    .profiles
                    .get(&id)
                    .ok_or_else(|| LabError::InvalidInput("Unknown peer.".into()))?
                    .clone();
                self.network.configure_peer(id, &config, online)?;
                self.profiles.insert(id, (config, online));
                Ok(Outcome::PeerChanged)
            }
            NetworkControl::Configure { id, config } => {
                let online = self
                    .profiles
                    .get(&id)
                    .ok_or_else(|| LabError::InvalidInput("Unknown peer.".into()))?
                    .1;
                self.network.configure_peer(id, &config, online)?;
                self.profiles.insert(id, (config, online));
                Ok(Outcome::PeerChanged)
            }
            NetworkControl::SetReplication { copies } => {
                self.network.record_local_maintenance(format!("Minimum copies set to {copies}; extra placement waits for local repair after discovery"));
                Ok(Outcome::PeerChanged)
            }
            NetworkControl::SetFailureDomain { id, domain } => {
                self.network.record_local_maintenance(format!(
                    "Peer {id} failure domain set to {domain}; placement checked by local repair"
                ));
                Ok(Outcome::PeerChanged)
            }
            NetworkControl::RepairReplicas { .. } => {
                let copies = self
                    .snapshot
                    .as_ref()
                    .and_then(|snapshot| snapshot.replication.as_ref())
                    .ok_or(LabError::NoDatabase)?;
                let current = copies
                    .shards
                    .iter()
                    .flat_map(|shard| &shard.replicas)
                    .filter(|copy| copy.current)
                    .count();
                let stale = copies
                    .shards
                    .iter()
                    .flat_map(|shard| &shard.replicas)
                    .filter(|copy| !copy.current)
                    .count();
                Ok(Outcome::ReplicasRepaired { current, stale })
            }
        }
    }
    fn begin_query(&mut self, client: NodeId, sql: String) -> Result<(), LabError> {
        let plan = fhe_playground::parse_sql(&sql)?;
        let node = self.network.node(client).ok_or_else(|| {
            LabError::InvalidInput("Select a surviving client before running SQL.".into())
        })?;
        if node.role != NodeRole::Client || !node.online {
            return Err(LabError::InvalidInput(
                "SQL must originate from an online client.".into(),
            ));
        }
        let snapshot = self.snapshot.as_ref().ok_or(LabError::NoDatabase)?;
        if snapshot.peers.is_empty() && snapshot.replication.is_none() {
            return Err(LabError::InvalidInput(
                "No storage peers are available. Add a peer to rebuild encrypted shards.".into(),
            ));
        }
        let mut peers: BTreeSet<_> = if let Some(replication) = &snapshot.replication {
            if !replication.unavailable_shards.is_empty() {
                return Err(LabError::UnavailableShards(
                    replication.unavailable_shards.clone(),
                ));
            }
            match plan {
                fhe_playground::QueryPlan::Aggregate { .. } => {
                    replication.read_peers.iter().copied().collect()
                }
                fhe_playground::QueryPlan::AddAmount { .. } => {
                    replication.write_peers.iter().copied().collect()
                }
            }
        } else {
            let missing: Vec<_> = snapshot
                .peers
                .iter()
                .filter(|peer| !peer.online && peer.rows > 0)
                .map(|peer| peer.id)
                .collect();
            if !missing.is_empty() {
                return Err(LabError::Unavailable(missing));
            }
            snapshot
                .peers
                .iter()
                .filter(|peer| peer.rows > 0)
                .map(|peer| peer.id)
                .collect()
        };
        // Even an empty database has to reach a real storage peer.
        if peers.is_empty() {
            let first = snapshot
                .peers
                .iter()
                .find(|peer| peer.online)
                .ok_or_else(|| {
                    LabError::InvalidInput("No online storage peer can receive the query.".into())
                })?;
            peers.insert(first.id);
        }
        let id = self.next_request;
        self.next_request += 1;
        for peer in &peers {
            if let Err(error) = self.network.request(client, *peer, id) {
                self.network.cancel_request(id);
                return Err(error);
            }
        }
        self.query = Some(PendingQuery {
            id,
            client,
            sql,
            peers,
            received: BTreeSet::new(),
            phase: Phase::Requests,
            outcome: None,
            start: Instant::now(),
            route_start: self.network.snapshot().time_ms,
            permit: Arc::new(Mutex::new(CommitState::Pending)),
        });
        let _ = self.events.send(Event::Progress(
            "Delivering query requests through established routes...".into(),
        ));
        Ok(())
    }
    fn cancel_query(&mut self, reason: &str) {
        // Commit and cancellation share a lock. A removal after all responses
        // were accepted and commit completed cannot retroactively roll it back.
        if let Some(query) = &self.query
            && let Ok(mut state) = query.permit.lock()
        {
            if *state == CommitState::Committed {
                return;
            }
            *state = CommitState::Cancelled;
        }
        if let Some(query) = self.query.take() {
            self.network.cancel_request(query.id);
            let _ = self.compute.try_send(ComputeCommand::Abort);
            self.finish(
                Err(LabError::InvalidInput(reason.into())),
                Some(query.client),
                query.start.elapsed().as_secs_f64() * 1000.0,
            );
        }
    }
    fn delivered(&mut self, delivery: Delivery) {
        let Some(query) = self.query.as_mut() else {
            return;
        };
        let (client, peer, id, phase) = match delivery {
            Delivery::Request {
                client_id,
                peer_id,
                request_id,
            } => (client_id, peer_id, request_id, Phase::Requests),
            Delivery::Response {
                client_id,
                peer_id,
                request_id,
            } => (client_id, peer_id, request_id, Phase::Responses),
        };
        if query.id != id
            || query.client != client
            || query.phase != phase
            || !query.peers.contains(&peer)
        {
            return;
        }
        query.received.insert(peer);
        if query.received != query.peers {
            return;
        }
        match query.phase {
            Phase::Requests => {
                query.phase = Phase::Computing;
                if self
                    .compute
                    .try_send(ComputeCommand::Prepare {
                        id: query.id,
                        sql: query.sql.clone(),
                    })
                    .is_err()
                {
                    self.cancel_query("FHE compute queue is unavailable.");
                }
            }
            Phase::Responses => {
                query.phase = Phase::Committing;
                if self
                    .compute
                    .try_send(ComputeCommand::Commit {
                        id: query.id,
                        permit: Arc::clone(&query.permit),
                    })
                    .is_err()
                {
                    self.cancel_query("FHE commit queue is unavailable.");
                }
            }
            _ => {}
        }
    }
    fn answer(&mut self, answer: ComputeEvent) {
        match answer {
            ComputeEvent::Progress { id, message } => {
                if self
                    .query
                    .as_ref()
                    .is_some_and(|query| query.id == id && query.phase == Phase::Computing)
                {
                    let _ = self.events.send(Event::PeerProgress(message));
                }
            }
            ComputeEvent::Created { snapshot, result } => {
                self.snapshot = snapshot;
                self.repair_pending = self
                    .snapshot
                    .as_ref()
                    .is_some_and(|snapshot| snapshot.replication.is_some());
                let elapsed = self
                    .creating
                    .take()
                    .map(|start| start.elapsed().as_secs_f64() * 1000.0)
                    .unwrap_or(0.0);
                self.finish(result.map(|_| Outcome::Created), None, elapsed);
            }
            ComputeEvent::Controlled { snapshot, result } => {
                self.snapshot = snapshot;
                if let Some(control) = self.control.take() {
                    let automatic =
                        matches!(&control, NetworkControl::RepairReplicas { automatic: true });
                    let repair = matches!(&control, NetworkControl::RepairReplicas { .. });
                    if result.is_err() {
                        self.restore_failed_control(&control);
                    }
                    let outcome = result.and_then(|_| self.apply_control(control));
                    if repair {
                        let message = match &outcome {
                            Ok(Outcome::ReplicasRepaired { current, stale }) => format!(
                                "Replica repair completed: {current} current / {stale} stale copies. Local copy after established routes; no full wire transfer modeled."
                            ),
                            Err(error) => format!("Replica repair failed: {error}"),
                            _ => unreachable!("repair returns its own outcome"),
                        };
                        self.network.record_local_maintenance(message);
                    } else if outcome.is_ok() {
                        self.repair_pending = self
                            .snapshot
                            .as_ref()
                            .is_some_and(|snapshot| snapshot.replication.is_some());
                    }
                    self.control_result(automatic, outcome);
                }
            }
            ComputeEvent::Prepared { id, result } => {
                // Cancellation already queued Abort in order. A stale completion
                // must not append another Abort behind a newer query's Prepare.
                if self
                    .query
                    .as_ref()
                    .is_none_or(|query| query.id != id || query.phase != Phase::Computing)
                {
                    return;
                }
                match result {
                    Err(error) => {
                        let query = self.query.take().expect("known query");
                        self.network.cancel_request(query.id);
                        self.finish(
                            Err(error),
                            Some(query.client),
                            query.start.elapsed().as_secs_f64() * 1000.0,
                        );
                    }
                    Ok(outcome) => {
                        let query = self.query.as_mut().expect("known query");
                        query.outcome = Some(outcome);
                        query.phase = Phase::Responses;
                        query.received.clear();
                        query.route_start = self.network.snapshot().time_ms;
                        let peers: Vec<_> = query.peers.iter().copied().collect();
                        let client = query.client;
                        for peer in peers {
                            if let Err(error) = self.network.respond(peer, client, id) {
                                self.cancel_query(&error.to_string());
                                break;
                            }
                        }
                        let _ = self.events.send(Event::Progress(
                            "Returning computed ciphertext results to the requesting client..."
                                .into(),
                        ));
                    }
                }
            }
            ComputeEvent::Committed { id, snapshot } => {
                self.snapshot = snapshot;
                if self
                    .query
                    .as_ref()
                    .is_some_and(|query| query.id == id && query.phase == Phase::Committing)
                {
                    let query = self.query.take().expect("known query");
                    let accepted = query
                        .permit
                        .lock()
                        .is_ok_and(|state| *state == CommitState::Committed);
                    let outcome = if accepted {
                        Ok(Outcome::Query(query.outcome.expect("computed outcome")))
                    } else {
                        Err(LabError::InvalidInput(
                            "The operation's commit permit was revoked; no update was accepted."
                                .into(),
                        ))
                    };
                    if matches!(
                        &outcome,
                        Ok(Outcome::Query(QueryOutcome::Updated { committed: true }))
                    ) {
                        self.repair_pending = self
                            .snapshot
                            .as_ref()
                            .is_some_and(|snapshot| snapshot.replication.is_some());
                    }
                    self.finish(
                        outcome,
                        Some(query.client),
                        query.start.elapsed().as_secs_f64() * 1000.0,
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhe_playground::PeerInfo;
    use fhe_playground::PlainRow;

    fn runtime() -> (
        Runtime,
        Receiver<ComputeCommand>,
        Receiver<Event>,
        NodeId,
        NodeId,
    ) {
        let (compute, jobs) = mpsc::sync_channel(8);
        let (events, outputs) = mpsc::channel();
        let mut network = DemoNetwork::default();
        let client = network.add_client("Client".into()).unwrap();
        let config = PeerConfig::numbered(7);
        let peer = network.add_peer(7, &config, true).unwrap();
        for _ in 0..6 {
            network.advance(0.4);
        }
        let snapshot = LabSnapshot {
            name: "public test fixture".into(),
            revision: 0,
            owner_rows: vec![PlainRow {
                age: 18,
                amount: 10,
            }],
            peers: vec![PeerInfo {
                id: 7,
                config: config.clone(),
                online: true,
                rows: 1,
                data_bytes: 163,
                index_bytes: 2332,
                stored_bytes: 2495,
                owner_row_indices: vec![0],
            }],
            replication: None,
        };
        let runtime = Runtime {
            network,
            snapshot: Some(snapshot),
            profiles: BTreeMap::from([(7, (config, true))]),
            next_peer: 8,
            next_request: 1,
            query: None,
            control: None,
            creating: None,
            repair_pending: false,
            compute,
            events,
        };
        (runtime, jobs, outputs, client, peer)
    }
    fn deliver(runtime: &mut Runtime, seconds: f64) {
        let messages = runtime.network.advance(seconds);
        for message in messages {
            runtime.delivered(message);
        }
    }
    fn replicated(runtime: &mut Runtime, discover_routes: bool) {
        use fhe_playground::{LogicalShardInfo, ReplicaLocation, ReplicationInfo};
        let config = PeerConfig::numbered(8);
        runtime.network.add_peer(8, &config, true).unwrap();
        runtime.profiles.insert(8, (config.clone(), true));
        runtime.next_peer = 9;
        let state = runtime.snapshot.as_mut().unwrap();
        let mut extra = state.peers[0].clone();
        extra.id = 8;
        extra.config = config;
        state.peers.push(extra);
        // Public synthetic head only: these tests own worker routing/scheduling,
        // not engine cryptography. Real owner/replica behavior is tested below.
        let owner = compact_store::Owner::generate([71; 16]).unwrap();
        let head = owner
            .seal(
                compact_store::Layout {
                    schema: [3; 16],
                    row_width: 3,
                    rows_per_page: 256,
                    row_count: 1,
                },
                &[18, 10, 0],
                compact_store::Limits::default(),
            )
            .unwrap()
            .commitment()
            .clone();
        state.replication = Some(ReplicationInfo {
            desired_copies: 2,
            shards: vec![LogicalShardInfo {
                id: 7,
                rows: 1,
                data_head: head.clone(),
                index_head: head,
                replicas: [7, 8]
                    .into_iter()
                    .map(|peer_id| ReplicaLocation {
                        peer_id,
                        failure_domain: peer_id as u64,
                        online: true,
                        current: true,
                        data_bytes: 163,
                        index_bytes: 2332,
                    })
                    .collect(),
                executor: Some(7),
            }],
            failure_domains: vec![(7, 7), (8, 8)],
            read_peers: vec![7],
            write_peers: vec![7, 8],
            unavailable_shards: vec![],
        });
        if discover_routes {
            for _ in 0..6 {
                deliver(runtime, 0.4);
            }
        }
    }

    #[test]
    fn replicated_read_uses_the_surviving_executor_without_requiring_an_offline_copy() {
        let (mut runtime, jobs, _, client, _) = runtime();
        replicated(&mut runtime, true);
        let config = runtime.profiles[&7].0.clone();
        runtime.network.configure_peer(7, &config, false).unwrap();
        runtime.profiles.get_mut(&7).unwrap().1 = false;
        let state = runtime.snapshot.as_mut().unwrap();
        state.peers[0].online = false;
        let info = state.replication.as_mut().unwrap();
        info.shards[0].replicas[0].online = false;
        info.shards[0].executor = Some(8);
        info.read_peers = vec![8];
        info.write_peers = vec![8];

        runtime.command(Command::Query {
            client_id: client,
            sql: "SELECT COUNT(*), SUM(amount) FROM records".into(),
        });
        assert_eq!(runtime.query.as_ref().unwrap().peers, BTreeSet::from([8]));
        deliver(&mut runtime, 0.4);
        assert!(matches!(
            jobs.try_recv().unwrap(),
            ComputeCommand::Prepare { id: 1, .. }
        ));
    }

    #[test]
    fn replicated_update_waits_for_all_current_write_holders_without_double_counting_reads() {
        let (mut runtime, jobs, _, client, _) = runtime();
        replicated(&mut runtime, true);
        runtime.command(Command::Query {
            client_id: client,
            sql: "UPDATE records SET amount = amount + 1".into(),
        });
        assert_eq!(
            runtime.query.as_ref().unwrap().peers,
            BTreeSet::from([7, 8])
        );
        let mut delivered = runtime.network.advance(0.4);
        assert_eq!(delivered.len(), 2);
        runtime.delivered(delivered.remove(0));
        assert!(jobs.try_recv().is_err());
        runtime.delivered(delivered.remove(0));
        assert!(matches!(
            jobs.try_recv().unwrap(),
            ComputeCommand::Prepare { id: 1, .. }
        ));
    }

    #[test]
    fn a_missing_logical_shard_refuses_the_query_even_with_other_online_copies() {
        let (mut runtime, jobs, outputs, client, _) = runtime();
        replicated(&mut runtime, true);
        runtime
            .snapshot
            .as_mut()
            .unwrap()
            .replication
            .as_mut()
            .unwrap()
            .unavailable_shards = vec![7];
        runtime.command(Command::Query {
            client_id: client,
            sql: "SELECT COUNT(*), SUM(amount) FROM records".into(),
        });
        assert!(jobs.try_recv().is_err());
        assert!(runtime.query.is_none());
        assert!(outputs.try_iter().any(|event| matches!(event, Event::Finished { outcome: Err(LabError::UnavailableShards(ids)), .. } if ids == vec![7])));
    }

    #[test]
    fn automatic_repair_waits_for_unpaused_actual_peer_discovery_and_emits_no_fake_packets() {
        let (mut runtime, jobs, _, _, _) = runtime();
        replicated(&mut runtime, false);
        runtime
            .snapshot
            .as_mut()
            .unwrap()
            .replication
            .as_mut()
            .unwrap()
            .shards[0]
            .replicas[1]
            .current = false;
        runtime.repair_pending = true;
        runtime.network.set_simulation(1.0, true).unwrap();
        runtime.maybe_repair();
        assert!(jobs.try_recv().is_err());
        runtime.network.set_simulation(1.0, false).unwrap();
        runtime.maybe_repair();
        assert!(jobs.try_recv().is_err());
        for _ in 0..6 {
            deliver(&mut runtime, 0.4);
            runtime.maybe_repair();
            if runtime.control.is_some() {
                break;
            }
        }
        assert!(matches!(
            jobs.try_recv().unwrap(),
            ComputeCommand::Control(EngineControl::RepairReplicas)
        ));
        assert!(
            runtime
                .network
                .snapshot()
                .packets
                .iter()
                .all(|packet| !matches!(
                    packet.kind,
                    fhe_playground::PacketKind::Request | fhe_playground::PacketKind::Response
                ))
        );
        assert!(!runtime.repair_pending);
    }

    #[test]
    fn copy_policy_can_change_while_paused_but_materialization_remains_deferred() {
        let (mut runtime, jobs, outputs, _, _) = runtime();
        runtime.network.set_simulation(1.0, true).unwrap();
        runtime.command(Command::SetReplication { copies: 2 });
        assert!(matches!(
            jobs.try_recv().unwrap(),
            ComputeCommand::Control(EngineControl::SetReplication { copies: 2 })
        ));
        replicated(&mut runtime, false);
        runtime
            .snapshot
            .as_mut()
            .unwrap()
            .replication
            .as_mut()
            .unwrap()
            .shards[0]
            .replicas
            .pop();
        runtime.answer(ComputeEvent::Controlled {
            snapshot: runtime.snapshot.clone(),
            result: Ok(()),
        });
        runtime.maybe_repair();
        assert!(runtime.repair_pending);
        assert!(jobs.try_recv().is_err());
        runtime.command(Command::RepairReplicas);
        assert!(outputs.try_iter().any(|event| matches!(
            event,
            Event::ControlFinished {
                outcome: Err(_),
                ..
            }
        )));
        assert!(jobs.try_recv().is_err());
    }

    #[test]
    fn failed_automatic_repair_is_reported_separately_and_does_not_retry_forever() {
        let (mut runtime, jobs, outputs, _, _) = runtime();
        replicated(&mut runtime, true);
        runtime
            .snapshot
            .as_mut()
            .unwrap()
            .replication
            .as_mut()
            .unwrap()
            .shards[0]
            .replicas[1]
            .current = false;
        runtime.repair_pending = true;
        runtime.maybe_repair();
        let _ = jobs.try_recv().unwrap();
        runtime.answer(ComputeEvent::Controlled {
            snapshot: runtime.snapshot.clone(),
            result: Err(LabError::InvalidInput("public quota rejection".into())),
        });
        assert!(outputs.try_iter().any(|event| matches!(
            event,
            Event::MaintenanceFinished {
                outcome: Err(_),
                ..
            }
        )));
        runtime.maybe_repair();
        assert!(jobs.try_recv().is_err());
        assert!(
            runtime
                .network
                .snapshot()
                .recent
                .iter()
                .any(|entry| entry.message.contains("repair failed"))
        );
    }

    #[test]
    fn update_repair_waits_until_response_delivery_and_commit_have_finished() {
        let (mut runtime, jobs, _, client, _) = runtime();
        replicated(&mut runtime, true);
        let info = runtime
            .snapshot
            .as_mut()
            .unwrap()
            .replication
            .as_mut()
            .unwrap();
        info.shards[0].replicas[1].current = false;
        info.write_peers = vec![7];
        runtime.repair_pending = true;
        runtime.command(Command::Query {
            client_id: client,
            sql: "UPDATE records SET amount = amount + 1".into(),
        });
        runtime.maybe_repair();
        assert!(jobs.try_recv().is_err());
        deliver(&mut runtime, 0.4);
        let _ = jobs.try_recv().unwrap();
        runtime.answer(ComputeEvent::Prepared {
            id: 1,
            result: Ok(QueryOutcome::Updated { committed: true }),
        });
        runtime.maybe_repair();
        assert!(jobs.try_recv().is_err());
        deliver(&mut runtime, 0.4);
        let ComputeCommand::Commit { permit, .. } = jobs.try_recv().unwrap() else {
            panic!("expected actual commit gate");
        };
        runtime.maybe_repair();
        assert!(jobs.try_recv().is_err());
        *permit.lock().unwrap() = CommitState::Committed;
        runtime.answer(ComputeEvent::Committed {
            id: 1,
            snapshot: runtime.snapshot.clone(),
        });
        runtime.maybe_repair();
        assert!(matches!(
            jobs.try_recv().unwrap(),
            ComputeCommand::Control(EngineControl::RepairReplicas)
        ));
    }
    #[test]
    fn compute_waits_for_request_delivery_and_commit_waits_for_response_delivery() {
        let (mut runtime, jobs, _, client, _) = runtime();
        runtime.command(Command::Query {
            client_id: client,
            sql: "SELECT COUNT(*), SUM(amount) FROM records".into(),
        });
        assert!(jobs.try_recv().is_err());
        deliver(&mut runtime, 0.4);
        assert!(matches!(
            jobs.try_recv().unwrap(),
            ComputeCommand::Prepare { id: 1, .. }
        ));
        runtime.answer(ComputeEvent::Prepared {
            id: 1,
            result: Ok(QueryOutcome::Aggregate {
                count: 1,
                sum: 10,
                peers: vec![],
            }),
        });
        assert!(jobs.try_recv().is_err());
        deliver(&mut runtime, 0.4);
        assert!(matches!(
            jobs.try_recv().unwrap(),
            ComputeCommand::Commit { id: 1, .. }
        ));
    }
    #[test]
    fn repeated_compute_failures_release_transport_work_before_the_next_query() {
        let (mut runtime, jobs, outputs, client, _) = runtime();
        for id in 1..=128 {
            runtime.command(Command::Query {
                client_id: client,
                sql: "SELECT COUNT(*), SUM(amount) FROM records".into(),
            });
            deliver(&mut runtime, 0.4);
            assert!(matches!(
                jobs.try_recv().unwrap(),
                ComputeCommand::Prepare { id: received, .. } if received == id
            ));

            runtime.answer(ComputeEvent::Prepared {
                id,
                result: Err(LabError::Cryptography("public injected failure".into())),
            });

            assert!(runtime.query.is_none());
            assert!(runtime.network.snapshot().packets.iter().all(|packet| {
                !matches!(
                    packet.kind,
                    fhe_playground::PacketKind::Request | fhe_playground::PacketKind::Response
                )
            }));
            let finished: Vec<_> = outputs
                .try_iter()
                .filter(|event| {
                    matches!(
                        event,
                        Event::Finished {
                            outcome: Err(_),
                            ..
                        }
                    )
                })
                .collect();
            assert_eq!(finished.len(), 1);
        }

        runtime.command(Command::Query {
            client_id: client,
            sql: "SELECT COUNT(*), SUM(amount) FROM records".into(),
        });
        deliver(&mut runtime, 0.4);
        assert!(matches!(
            jobs.try_recv().unwrap(),
            ComputeCommand::Prepare { id: 129, .. }
        ));
        runtime.answer(ComputeEvent::Prepared {
            id: 129,
            result: Ok(QueryOutcome::Aggregate {
                count: 1,
                sum: 10,
                peers: vec![],
            }),
        });
        deliver(&mut runtime, 0.4);
        assert!(matches!(
            jobs.try_recv().unwrap(),
            ComputeCommand::Commit { id: 129, .. }
        ));
    }
    #[test]
    fn deleting_requesting_client_cancels_query_without_delivering_to_replacement() {
        let (mut runtime, jobs, outputs, client, _) = runtime();
        runtime.command(Command::Query {
            client_id: client,
            sql: "UPDATE records SET amount = amount + 1".into(),
        });
        runtime.command(Command::RemoveNode { id: client });
        assert!(runtime.query.is_none());
        assert!(matches!(jobs.try_recv().unwrap(), ComputeCommand::Abort));
        let replacement = runtime.network.add_client("Replacement".into()).unwrap();
        assert_ne!(replacement, client);
        let finishes: Vec<_> = outputs
            .try_iter()
            .filter_map(|event| match event {
                Event::Finished {
                    outcome, client_id, ..
                } => Some((outcome, client_id)),
                _ => None,
            })
            .collect();
        assert_eq!(finishes.len(), 1);
        assert_eq!(finishes[0].1, Some(client));
        assert!(finishes[0].0.is_err());
        deliver(&mut runtime, 1.0);
        assert!(jobs.try_recv().is_err());
    }
    #[test]
    fn stale_compute_completion_cannot_append_abort_behind_newer_prepare() {
        let (mut runtime, jobs, _, client, _) = runtime();
        runtime.command(Command::Query {
            client_id: client,
            sql: "SELECT COUNT(*), SUM(amount) FROM records".into(),
        });
        deliver(&mut runtime, 0.4);
        let _ = jobs.try_recv().unwrap();
        runtime.cancel_query("test cancellation");
        assert!(matches!(jobs.try_recv().unwrap(), ComputeCommand::Abort));
        runtime.command(Command::Query {
            client_id: client,
            sql: "SELECT COUNT(*), SUM(amount) FROM records".into(),
        });
        deliver(&mut runtime, 0.4);
        assert!(matches!(
            jobs.try_recv().unwrap(),
            ComputeCommand::Prepare { id: 2, .. }
        ));
        runtime.answer(ComputeEvent::Prepared {
            id: 1,
            result: Ok(QueryOutcome::Updated { committed: true }),
        });
        assert!(jobs.try_recv().is_err());
        assert_eq!(runtime.query.as_ref().unwrap().id, 2);
    }
    #[test]
    fn cancellation_before_commit_revokes_commit_permit() {
        let (mut runtime, jobs, _, client, _) = runtime();
        runtime.command(Command::Query {
            client_id: client,
            sql: "UPDATE records SET amount = amount + 1".into(),
        });
        deliver(&mut runtime, 0.4);
        let _ = jobs.try_recv().unwrap();
        runtime.answer(ComputeEvent::Prepared {
            id: 1,
            result: Ok(QueryOutcome::Updated { committed: true }),
        });
        deliver(&mut runtime, 0.4);
        let permit = match jobs.try_recv().unwrap() {
            ComputeCommand::Commit { permit, .. } => permit,
            _ => panic!("expected commit"),
        };
        runtime.command(Command::RemoveNode { id: client });
        assert_eq!(*permit.lock().unwrap(), CommitState::Cancelled);
        assert!(runtime.query.is_none());
    }
    #[test]
    fn zero_clients_or_zero_peers_cannot_run_sql() {
        let (mut runtime, _, outputs, client, _) = runtime();
        runtime.network.remove(client).unwrap();
        runtime.command(Command::Query {
            client_id: client,
            sql: "SELECT COUNT(*), SUM(amount) FROM records".into(),
        });
        assert!(outputs.try_iter().any(|event| matches!(
            event,
            Event::Finished {
                outcome: Err(_),
                ..
            }
        )));
        let replacement = runtime.network.add_client("Replacement".into()).unwrap();
        runtime.snapshot.as_mut().unwrap().peers.clear();
        runtime.command(Command::Query {
            client_id: replacement,
            sql: "SELECT COUNT(*), SUM(amount) FROM records".into(),
        });
        assert!(outputs.try_iter().any(|event| matches!(
            event,
            Event::Finished {
                outcome: Err(_),
                ..
            }
        )));
    }

    #[test]
    fn failed_peer_removal_restores_same_identity_but_requires_new_handshake() {
        let (mut runtime, jobs, outputs, client, peer) = runtime();
        runtime.command(Command::RemoveNode { id: peer });
        assert!(!runtime.network.connected(client, peer));
        assert!(matches!(
            jobs.try_recv().unwrap(),
            ComputeCommand::Control(EngineControl::Repartition(_))
        ));
        runtime.answer(ComputeEvent::Controlled {
            snapshot: runtime.snapshot.clone(),
            result: Err(LabError::InvalidInput("quota exceeded".into())),
        });
        assert_eq!(runtime.network.node(peer).unwrap().peer_id, Some(7));
        assert!(runtime.network.node(peer).unwrap().online);
        assert!(!runtime.network.connected(client, peer));
        assert!(outputs.try_iter().any(|event| matches!(
            event,
            Event::ControlFinished {
                outcome: Err(_),
                ..
            }
        )));
        for _ in 0..6 {
            deliver(&mut runtime, 0.4);
        }
        assert!(runtime.network.connected(client, peer));
    }
}

#[cfg(test)]
mod live_worker_tests {
    use super::*;
    use fhe_playground::PlainRow;

    fn until(worker: &Worker, condition: impl Fn(&Event) -> bool) -> Event {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(event) = worker.poll().expect("worker remains alive")
                && condition(&event)
            {
                return event;
            }
            assert!(
                Instant::now() < deadline,
                "timed out awaiting observable worker event"
            );
            std::thread::park_timeout(Duration::from_millis(2));
        }
    }
    #[test]
    fn real_replica_repair_waits_for_resume_and_keeps_queries_exact_through_failover() {
        let worker = Worker::start(egui::Context::default()).unwrap();
        worker
            .send(Command::SetSimulation {
                speed: 8.0,
                paused: true,
            })
            .unwrap();
        worker
            .send(Command::Create(DatabaseDraft {
                name: "public replica worker fixture".into(),
                rows: vec![
                    PlainRow { age: 18, amount: 7 },
                    PlainRow {
                        age: 42,
                        amount: 11,
                    },
                    PlainRow {
                        age: 18,
                        amount: 13,
                    },
                ],
                peers: vec![],
            }))
            .unwrap();
        until(&worker, |event| {
            matches!(
                event,
                Event::Finished {
                    outcome: Ok(Outcome::Created),
                    ..
                }
            )
        });
        worker.send(Command::SetReplication { copies: 2 }).unwrap();
        let configured = until(&worker, |event| {
            matches!(event, Event::ControlFinished { .. })
        });
        let Event::ControlFinished {
            snapshot: Some(snapshot),
            outcome: Ok(_),
            ..
        } = configured
        else {
            panic!("copy policy must configure while paused");
        };
        let info = snapshot.replication.unwrap();
        assert_eq!(info.desired_copies, 2);
        assert!(info.shards.iter().all(|shard| shard.replicas.len() == 1));
        worker.send(Command::RepairReplicas).unwrap();
        assert!(matches!(
            until(&worker, |event| matches!(
                event,
                Event::ControlFinished { .. }
            )),
            Event::ControlFinished {
                outcome: Err(_),
                ..
            }
        ));

        worker
            .send(Command::SetSimulation {
                speed: 8.0,
                paused: false,
            })
            .unwrap();
        let repaired = until(&worker, |event| {
            matches!(event, Event::MaintenanceFinished { .. })
        });
        let Event::MaintenanceFinished {
            snapshot: Some(snapshot),
            outcome: Ok(Outcome::ReplicasRepaired { .. }),
        } = repaired
        else {
            panic!("automatic repair must complete after actual discovery");
        };
        assert!(
            snapshot
                .replication
                .as_ref()
                .unwrap()
                .shards
                .iter()
                .all(|shard| shard
                    .replicas
                    .iter()
                    .filter(|copy| copy.current && copy.online)
                    .count()
                    >= 2)
        );
        let primary = snapshot.replication.as_ref().unwrap().shards[0]
            .executor
            .unwrap();
        worker
            .send(Command::SetPeer {
                id: primary,
                online: false,
            })
            .unwrap();
        until(&worker, |event| {
            matches!(event, Event::ControlFinished { .. })
        });
        // The availability change may schedule one local repair; wait for its
        // own acknowledgment before submitting SQL, without replacing SQL results.
        until(&worker, |event| {
            matches!(event, Event::MaintenanceFinished { .. })
        });
        worker
            .send(Command::Query {
                client_id: 1,
                sql: "SELECT COUNT(*), SUM(amount) FROM records".into(),
            })
            .unwrap();
        assert!(matches!(
            until(&worker, |event| matches!(event, Event::Finished { .. })),
            Event::Finished {
                outcome: Ok(Outcome::Query(QueryOutcome::Aggregate {
                    count: 3,
                    sum: 31,
                    ..
                })),
                ..
            }
        ));
        worker
            .send(Command::Query {
                client_id: 1,
                sql: "UPDATE records SET amount = amount + 1 WHERE age = 18".into(),
            })
            .unwrap();
        let updated = until(&worker, |event| matches!(event, Event::Finished { .. }));
        let Event::Finished {
            snapshot: Some(snapshot),
            outcome: Ok(Outcome::Query(QueryOutcome::Updated { committed: true })),
            ..
        } = updated
        else {
            panic!("replicated update must commit");
        };
        assert!(
            snapshot
                .replication
                .as_ref()
                .unwrap()
                .shards
                .iter()
                .flat_map(|shard| &shard.replicas)
                .any(|copy| !copy.online && !copy.current)
        );
        worker
            .send(Command::SetSimulation {
                speed: 8.0,
                paused: true,
            })
            .unwrap();
        worker
            .send(Command::SetPeer {
                id: primary,
                online: true,
            })
            .unwrap();
        let returned = until(&worker, |event| {
            matches!(event, Event::ControlFinished { .. })
        });
        let Event::ControlFinished {
            snapshot: Some(snapshot),
            outcome: Ok(_),
        } = returned
        else {
            panic!("peer must return without hidden repair");
        };
        assert!(
            snapshot
                .replication
                .as_ref()
                .unwrap()
                .shards
                .iter()
                .flat_map(|shard| &shard.replicas)
                .any(|copy| copy.peer_id == primary && !copy.current)
        );
        worker
            .send(Command::SetSimulation {
                speed: 8.0,
                paused: false,
            })
            .unwrap();
        let repaired = until(&worker, |event| {
            matches!(event, Event::MaintenanceFinished { .. })
        });
        let Event::MaintenanceFinished {
            snapshot: Some(snapshot),
            outcome: Ok(Outcome::ReplicasRepaired { .. }),
        } = repaired
        else {
            panic!("returned-peer maintenance must complete");
        };
        assert!(
            snapshot
                .replication
                .as_ref()
                .unwrap()
                .shards
                .iter()
                .all(|shard| {
                    shard
                        .replicas
                        .iter()
                        .filter(|copy| copy.current && copy.online)
                        .map(|copy| copy.failure_domain)
                        .collect::<BTreeSet<_>>()
                        .len()
                        >= 2
                })
        );
        worker
            .send(Command::Query {
                client_id: 1,
                sql: "SELECT COUNT(*), SUM(amount) FROM records".into(),
            })
            .unwrap();
        assert!(matches!(
            until(&worker, |event| matches!(event, Event::Finished { .. })),
            Event::Finished {
                outcome: Ok(Outcome::Query(QueryOutcome::Aggregate {
                    count: 3,
                    sum: 33,
                    ..
                })),
                ..
            }
        ));
    }
    #[test]
    fn removing_client_during_real_fhe_update_preserves_data_for_a_new_client() {
        let _ = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build_global();
        let worker = Worker::start(egui::Context::default()).unwrap();
        worker
            .send(Command::SetSimulation {
                speed: 4.0,
                paused: false,
            })
            .unwrap();
        worker
            .send(Command::Create(DatabaseDraft {
                name: "public cancellation fixture".into(),
                rows: vec![PlainRow { age: 18, amount: 7 }],
                peers: vec![],
            }))
            .unwrap();
        let created = until(&worker, |event| matches!(event, Event::Finished { .. }));
        assert!(matches!(
            created,
            Event::Finished {
                outcome: Ok(Outcome::Created),
                ..
            }
        ));
        until(
            &worker,
            |event| matches!(event,Event::Network(network) if network.links.iter().any(|link| link.from==1&&link.to==2)),
        );
        worker
            .send(Command::Query {
                client_id: 1,
                sql: "UPDATE records SET amount = amount + 1".into(),
            })
            .unwrap();
        until(&worker, |event| matches!(event, Event::PeerProgress(_)));
        worker.send(Command::RemoveNode { id: 1 }).unwrap();
        let cancelled = until(&worker, |event| matches!(event, Event::Finished { .. }));
        assert!(matches!(
            cancelled,
            Event::Finished {
                outcome: Err(_),
                client_id: Some(1),
                ..
            }
        ));
        worker
            .send(Command::AddClient {
                name: "Replacement".into(),
            })
            .unwrap();
        let added = until(&worker, |event| {
            matches!(
                event,
                Event::ControlFinished {
                    outcome: Ok(Outcome::NodeAdded { .. }),
                    ..
                }
            )
        });
        let client = match added {
            Event::ControlFinished {
                outcome: Ok(Outcome::NodeAdded { id }),
                ..
            } => id,
            _ => unreachable!(),
        };
        assert_ne!(client, 1);
        until(
            &worker,
            |event| matches!(event,Event::Network(network) if network.links.iter().any(|link| link.from==2&&link.to==client)),
        );
        worker
            .send(Command::Query {
                client_id: client,
                sql: "SELECT COUNT(*), SUM(amount) FROM records".into(),
            })
            .unwrap();
        let result = until(&worker, |event| matches!(event, Event::Finished { .. }));
        assert!(
            matches!(result,Event::Finished { outcome:Ok(Outcome::Query(QueryOutcome::Aggregate { count:1,sum:7,.. })),client_id:Some(id),.. } if id==client)
        );
    }
}
