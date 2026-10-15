//! The GUI supervises actual child processes. It never executes a peer FHE job.
use crate::process_backend::ProcessBackend;
use crate::traffic::{LiveTraffic, Observation};
use eframe::egui;
use fhe_playground::{
    DatabaseDraft, LabError, LabSnapshot, NetworkSnapshot, NodeId, PeerConfig, QueryOutcome,
};
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TryRecvError},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

pub enum Command {
    Create(DatabaseDraft),
    Query { client_id: NodeId, sql: String },
    AddPeer(PeerConfig),
    AddClient { name: String },
    RemoveNode { id: NodeId },
    SetPeer { id: usize, online: bool },
    ConfigurePeer { id: usize, config: PeerConfig },
    SetReplication { copies: usize },
    RepairReplicas,
}

#[derive(Debug)]
pub enum Outcome {
    Created,
    PeerChanged,
    NodeAdded {
        id: NodeId,
    },
    NodeRemoved {
        id: NodeId,
    },
    ReplicasRepaired {
        current: usize,
        stale: usize,
    },
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Only explicit public-fixture renderer tests supply this variant; live results require a computation proof"
        )
    )]
    Query(QueryOutcome),
    /// Only the actual Session proof/version acceptance path creates live results.
    VerifiedQuery {
        outcome: QueryOutcome,
        version: version_journal::HeadRef,
        changed_rows: Option<usize>,
    },
}

impl Outcome {
    pub fn query(&self) -> Option<&QueryOutcome> {
        match self {
            Self::Query(outcome) | Self::VerifiedQuery { outcome, .. } => Some(outcome),
            _ => None,
        }
    }
    fn verified(result: storage_client::VerifiedResult) -> Self {
        use storage_client::VerifiedResult;
        let (outcome, version, changed_rows) = match result {
            VerifiedResult::Selected {
                columns,
                rows,
                version,
            } => (QueryOutcome::Selected { columns, rows }, version, None),
            VerifiedResult::Updated {
                changed_rows,
                version,
            } => (
                QueryOutcome::Updated { committed: true },
                version,
                Some(changed_rows),
            ),
            VerifiedResult::Inserted { count, version } => (
                QueryOutcome::Inserted {
                    count: count as u32,
                },
                version,
                None,
            ),
        };
        Self::VerifiedQuery {
            outcome,
            version,
            changed_rows,
        }
    }
}

pub enum Event {
    Traffic(Observation),
    Network(NetworkSnapshot),
    Snapshot(LabSnapshot),
    Progress(String),
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
}

pub struct Worker {
    sender: Option<SyncSender<Command>>,
    receiver: Receiver<Event>,
    latest: Arc<Mutex<VecDeque<Event>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    traffic: LiveTraffic,
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.sender.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
impl Worker {
    #[cfg(test)]
    pub fn test_channel() -> (Self, Receiver<Command>, mpsc::Sender<Event>) {
        let (sender, commands) = mpsc::sync_channel(32);
        let (events, receiver) = mpsc::channel();
        (
            Self {
                sender: Some(sender),
                receiver,
                latest: Arc::default(),
                stop: Arc::default(),
                thread: None,
                traffic: Arc::default(),
            },
            commands,
            events,
        )
    }
    pub fn start(context: egui::Context) -> std::io::Result<Self> {
        let (sender, commands) = mpsc::sync_channel(32);
        let (events, receiver) = mpsc::channel();
        let latest = Arc::new(Mutex::new(VecDeque::new()));
        let views = latest.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let traffic = LiveTraffic::default();
        let observing = traffic.clone();
        let thread = std::thread::Builder::new()
            .name("dcs-process-manager".into())
            .spawn(move || run(commands, events, views, context, stopping, observing))?;
        Ok(Self {
            sender: Some(sender),
            receiver,
            latest,
            stop,
            thread: Some(thread),
            traffic,
        })
    }
    pub fn send(&self, command: Command) -> Result<(), String> {
        self.sender
            .as_ref()
            .ok_or_else(|| "Peer manager is stopping".to_string())?
            .try_send(command)
            .map_err(|e| format!("Cannot submit operation: {e}"))
    }
    pub fn discard_traffic_tail(&self) {
        // Only visual observations, never commands, SQL completions or snapshots.
        if let Ok(mut pending) = self.traffic.lock() {
            pending.clear();
        }
    }
    pub fn poll(&self) -> Result<Option<Event>, String> {
        // Real command outcomes take priority over optional visual playback.
        match self.receiver.try_recv() {
            Ok(event) => return Ok(Some(event)),
            Err(TryRecvError::Disconnected) => {
                return Err("Peer manager stopped; child processes were closed".into());
            }
            Err(TryRecvError::Empty) => {}
        }
        if let Some(observation) = self
            .traffic
            .lock()
            .map_err(|_| "Traffic view lock failed".to_string())?
            .pop_front()
        {
            return Ok(Some(Event::Traffic(observation)));
        }
        self.latest
            .lock()
            .map_err(|_| "Process view lock failed".to_string())
            .map(|mut events| events.pop_front())
    }
}
fn run(
    commands: Receiver<Command>,
    events: mpsc::Sender<Event>,
    latest: Arc<Mutex<VecDeque<Event>>>,
    context: egui::Context,
    stop: Arc<AtomicBool>,
    traffic: LiveTraffic,
) {
    let mut backend = match ProcessBackend::new() {
        Ok(backend) => backend,
        Err(error) => {
            let _ = events.send(Event::Finished {
                snapshot: None,
                outcome: Err(LabError::InvalidInput(error.to_string())),
                elapsed_ms: 0.0,
                client_id: None,
            });
            return;
        }
    };
    backend.traffic = traffic;
    let repaint = context.clone();
    backend.wake_traffic = Some(Arc::new(move || repaint.request_repaint()));
    while !stop.load(Ordering::Acquire) {
        match commands.recv_timeout(Duration::from_millis(500)) {
            Ok(command) => {
                if stop.load(Ordering::Acquire) {
                    return;
                }
                let _ = events.send(Event::Progress(
                    "Communicating with authenticated peer processes…".into(),
                ));
                context.request_repaint();
                let started = Instant::now();
                let query = match &command {
                    Command::Query { client_id, .. } => Some(*client_id),
                    _ => None,
                };
                let finished = matches!(&command, Command::Create(_) | Command::Query { .. });
                let outcome = match command {
                    Command::Create(draft) => backend.create(draft).map(|_| Outcome::Created),
                    Command::Query { client_id, sql } => {
                        backend.query(client_id, &sql).map(Outcome::verified)
                    }
                    Command::AddPeer(config) => {
                        backend.add_peer(config).map(|id| Outcome::NodeAdded { id })
                    }
                    Command::AddClient { name } => {
                        backend.add_client(name).map(|id| Outcome::NodeAdded { id })
                    }
                    Command::RemoveNode { id } => {
                        backend.remove(id).map(|_| Outcome::NodeRemoved { id })
                    }
                    Command::SetPeer { id, online } => {
                        backend.online(id, online).map(|_| Outcome::PeerChanged)
                    }
                    Command::ConfigurePeer { id, config } => {
                        backend.configure(id, config).map(|_| Outcome::PeerChanged)
                    }
                    Command::SetReplication { copies } => {
                        backend.copies(copies).map(|_| Outcome::PeerChanged)
                    }
                    Command::RepairReplicas => backend
                        .repair()
                        .map(|(current, stale)| Outcome::ReplicasRepaired { current, stale }),
                };
                backend.refresh();
                let snapshot = backend.snapshot();
                let event = if finished {
                    Event::Finished {
                        snapshot,
                        outcome,
                        elapsed_ms: started.elapsed().as_secs_f64() * 1000.0,
                        client_id: query,
                    }
                } else {
                    Event::ControlFinished { snapshot, outcome }
                };
                if events.send(event).is_err() {
                    return;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => backend.refresh(),
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
        if let Ok(mut views) = latest.lock() {
            views.clear();
            if let Some(snapshot) = backend.snapshot() {
                views.push_back(Event::Snapshot(snapshot));
            }
            views.push_back(Event::Network(backend.network()));
        }
        context.request_repaint();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn live_sync_discards_visual_tail_without_erasing_a_waiting_sql_completion() {
        let (worker, _commands, events) = Worker::test_channel();
        worker.traffic.lock().unwrap().push_back(Observation {
            packet: fhe_playground::NetworkPacket {
                id: 1,
                from: 1,
                to: 2,
                kind: fhe_playground::PacketKind::Request,
                progress: 1.0,
                request_id: Some(9),
            },
            operation: "public telemetry fixture".into(),
            bytes: 123,
        });
        events
            .send(Event::Finished {
                snapshot: None,
                outcome: Err(LabError::InvalidInput("public failure fixture".into())),
                elapsed_ms: 1.0,
                client_id: Some(1),
            })
            .unwrap();

        worker.discard_traffic_tail();

        assert!(matches!(
            worker.poll().unwrap(),
            Some(Event::Finished {
                client_id: Some(1),
                ..
            })
        ));
        assert!(worker.poll().unwrap().is_none());
    }

    fn public_version(height: u64) -> version_journal::HeadRef {
        version_journal::HeadRef {
            genesis: [1; 32],
            database: [2; 16],
            block: [3; 32],
            height,
            state_root: [4; 32],
        }
    }

    #[test]
    fn accepted_network_results_preserve_cells_confirmed_version_and_mutation_counts() {
        // Adapter-only public values; this test does not claim to create a valid proof.
        let selected = Outcome::verified(storage_client::VerifiedResult::Selected {
            columns: vec![sql_plan::Column::Amount],
            rows: vec![vec![65535]],
            version: public_version(7),
        });
        assert!(matches!(selected, Outcome::VerifiedQuery {
            outcome: QueryOutcome::Selected { ref columns, ref rows }, version,
            changed_rows: None,
        } if columns == &[sql_plan::Column::Amount] && rows == &[vec![65535]] && version == public_version(7)));
        let updated = Outcome::verified(storage_client::VerifiedResult::Updated {
            changed_rows: 2,
            version: public_version(9),
        });
        assert!(matches!(updated, Outcome::VerifiedQuery {
            outcome: QueryOutcome::Updated { committed: true }, version,
            changed_rows: Some(2),
        } if version == public_version(9)));
        let inserted = Outcome::verified(storage_client::VerifiedResult::Inserted {
            count: 1,
            version: public_version(11),
        });
        assert!(matches!(inserted, Outcome::VerifiedQuery {
            outcome: QueryOutcome::Inserted { count: 1 }, version, ..
        } if version == public_version(11)));
    }

    #[test]
    fn historical_query_output_has_no_network_verification_metadata() {
        let historical = Outcome::Query(QueryOutcome::Selected {
            columns: vec![sql_plan::Column::Age],
            rows: vec![vec![18]],
        });
        assert!(historical.query().is_some());
        assert!(matches!(historical, Outcome::Query(_)));
    }

    #[test]
    fn closing_the_gui_waits_until_manager_owned_resources_are_released() {
        let (sender, commands) = mpsc::sync_channel::<Command>(1);
        let (_events, receiver) = mpsc::channel();
        let released = Arc::new(AtomicBool::new(false));
        let resource = released.clone();
        let thread = std::thread::spawn(move || {
            assert!(commands.recv().is_err());
            // Represents the manager's RAII resources, including owned children.
            resource.store(true, Ordering::Release);
        });
        let worker = Worker {
            sender: Some(sender),
            receiver,
            latest: Arc::default(),
            stop: Arc::default(),
            thread: Some(thread),
            traffic: Arc::default(),
        };
        drop(worker);
        assert!(released.load(Ordering::Acquire));
    }
}
