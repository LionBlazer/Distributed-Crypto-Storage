//! The GUI supervises actual child processes. It never executes a peer FHE job.
use crate::process_backend::ProcessBackend;
use crate::traffic::Observation;
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
    ImportRelational(relational_types::ImportedDatabase),
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
    TypedSelected(storage_client::relational::Selected),
    Created,
    TableReady {
        created: bool,
        version: version_journal::HeadRef,
    },
    Script {
        completed: usize,
        created: bool,
        changed: bool,
        last: Box<Outcome>,
    },
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
    pub fn terminal(&self) -> &Self {
        match self {
            Self::Script { last, .. } => last.terminal(),
            _ => self,
        }
    }
    pub fn created(&self) -> bool {
        matches!(
            self,
            Self::Created
                | Self::Script { created: true, .. }
                | Self::TableReady { created: true, .. }
        )
    }
    pub fn changed(&self) -> bool {
        matches!(self, Self::Script { changed: true, .. })
            || matches!(
                self.query(),
                Some(QueryOutcome::Updated { committed: true } | QueryOutcome::Inserted { .. })
            )
    }
    pub fn query(&self) -> Option<&QueryOutcome> {
        match self.terminal() {
            Self::Query(outcome) | Self::VerifiedQuery { outcome, .. } => Some(outcome),
            _ => None,
        }
    }
    fn script(result: storage_client::ScriptResult) -> Self {
        use storage_client::{StatementResult, VerifiedResult};
        let completed = result.statements.len();
        let created = result
            .statements
            .iter()
            .any(|s| matches!(s.result, StatementResult::Created { created: true, .. }));
        let changed = result.statements.iter().any(|s| {
            matches!(
                s.result,
                StatementResult::Executed(
                    VerifiedResult::Updated { .. } | VerifiedResult::Inserted { .. }
                )
            )
        });
        let last = match result
            .statements
            .into_iter()
            .last()
            .expect("nonempty validated SQL script")
            .result
        {
            StatementResult::Created { created, version } => Self::TableReady { created, version },
            StatementResult::Executed(result) => Self::verified(result),
        };
        if completed == 1 {
            last
        } else {
            Self::Script {
                completed,
                created,
                changed,
                last: Box::new(last),
            }
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
    /// Timestamped at the actual observation producer, before display queuing.
    Stamped {
        at: Instant,
        event: Box<Event>,
    },
    DisplayGap(usize),
    Stopped(String),
    Traffic(Observation),
    Network(NetworkSnapshot),
    Peers(Vec<crate::process_backend::PeerProfile>),
    Catalog(Vec<(relational_types::TableSchema, usize)>),
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

/// All live producers share this queue and stamp while holding its lock. A
/// completion therefore cannot overtake the I/O observations that preceded it.
#[derive(Clone, Default)]
struct EventBus(Arc<Mutex<VecDeque<(Instant, Event)>>>);
impl EventBus {
    fn send(&self, event: Event) {
        if let Ok(mut queue) = self.0.lock() {
            // The GUI is optional observation. Bound telemetry without blocking
            // a real RPC callback or dropping an accepted SQL result.
            if queue.len() >= 4096
                && let Some(index) = queue
                    .iter()
                    .position(|(_, event)| {
                        matches!(
                            event,
                            Event::Snapshot(_)
                                | Event::Network(_)
                                | Event::Peers(_)
                                | Event::Progress(_)
                        )
                    })
                    .or_else(|| {
                        queue
                            .iter()
                            .position(|(_, event)| matches!(event, Event::Traffic(_)))
                    })
            {
                queue.remove(index);
                if let Some((_, Event::DisplayGap(count))) = queue
                    .iter_mut()
                    .find(|(_, e)| matches!(e, Event::DisplayGap(_)))
                {
                    *count += 1;
                } else {
                    queue.push_back((Instant::now(), Event::DisplayGap(1)));
                }
            }
            queue.push_back((Instant::now(), event));
        }
    }
    fn pop(&self) -> Option<Event> {
        self.0
            .lock()
            .ok()?
            .pop_front()
            .map(|(at, event)| Event::Stamped {
                at,
                event: Box::new(event),
            })
    }
}

pub struct Worker {
    sender: Option<SyncSender<Command>>,
    receiver: Receiver<Event>,
    bus: EventBus,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    _events: Option<mpsc::Sender<Event>>,
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
                bus: EventBus::default(),
                stop: Arc::default(),
                thread: None,
                _events: None,
            },
            commands,
            events,
        )
    }
    pub fn start(context: egui::Context) -> std::io::Result<Self> {
        let (sender, commands) = mpsc::sync_channel(32);
        let (events, receiver) = mpsc::channel();
        let bus = EventBus::default();
        let views = bus.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let thread = std::thread::Builder::new()
            .name("dcs-process-manager".into())
            .spawn(move || run(commands, views, context, stopping))?;
        Ok(Self {
            sender: Some(sender),
            receiver,
            bus,
            stop,
            thread: Some(thread),
            _events: Some(events),
        })
    }
    pub fn send(&self, command: Command) -> Result<(), String> {
        self.sender
            .as_ref()
            .ok_or_else(|| "Peer manager is stopping".to_string())?
            .try_send(command)
            .map_err(|e| format!("Cannot submit operation: {e}"))
    }
    pub fn poll(&self) -> Result<Option<Event>, String> {
        // Bare events are retained only for the explicit public test channel.
        match self.receiver.try_recv() {
            Ok(event) => return Ok(Some(event)),
            Err(TryRecvError::Disconnected) => {
                return Err("Peer manager stopped; child processes were closed".into());
            }
            Err(TryRecvError::Empty) => {}
        }
        if let Some(event) = self.bus.pop() {
            return Ok(Some(event));
        }
        if self
            .thread
            .as_ref()
            .is_some_and(|thread| thread.is_finished())
        {
            return Err("Peer manager stopped; child processes were closed".into());
        }
        Ok(None)
    }
}
fn run(
    commands: Receiver<Command>,
    events: EventBus,
    context: egui::Context,
    stop: Arc<AtomicBool>,
) {
    let mut backend = match ProcessBackend::new() {
        Ok(backend) => backend,
        Err(error) => {
            events.send(Event::Finished {
                snapshot: None,
                outcome: Err(LabError::InvalidInput(error.to_string())),
                elapsed_ms: 0.0,
                client_id: None,
            });
            return;
        }
    };
    let repaint = context.clone();
    let observations = events.clone();
    backend.observe_traffic = Some(Arc::new(move |observation| {
        observations.send(Event::Traffic(observation));
        repaint.request_repaint();
    }));
    let topology = events.clone();
    let repaint = context.clone();
    backend.observe_topology = Some(Arc::new(move |peers, network| {
        topology.send(Event::Peers(peers));
        topology.send(Event::Network(network));
        repaint.request_repaint();
    }));
    while !stop.load(Ordering::Acquire) {
        match commands.recv_timeout(Duration::from_millis(500)) {
            Ok(command) => {
                if stop.load(Ordering::Acquire) {
                    return;
                }
                events.send(Event::Progress(
                    "Communicating with authenticated peer processes…".into(),
                ));
                context.request_repaint();
                let started = Instant::now();
                let query = match &command {
                    Command::Query { client_id, .. } => Some(*client_id),
                    _ => None,
                };
                let finished = matches!(
                    &command,
                    Command::Create(_) | Command::ImportRelational(_) | Command::Query { .. }
                );
                let outcome = match command {
                    Command::Create(draft) => backend.create(draft).map(|_| Outcome::Created),
                    Command::ImportRelational(database) => backend
                        .import_relational(database)
                        .map(|_| Outcome::Created),
                    Command::Query { client_id, sql } => {
                        if backend.has_relational() {
                            backend
                                .execute_typed(client_id, &sql)
                                .map(Outcome::TypedSelected)
                        } else {
                            backend.execute_sql(client_id, &sql).map(Outcome::script)
                        }
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
                events.send(Event::Peers(backend.peer_profiles()));
                events.send(Event::Catalog(backend.catalog()));
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
                events.send(event);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => backend.refresh(),
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
        if let Some(snapshot) = backend.snapshot() {
            events.send(Event::Snapshot(snapshot));
        }
        events.send(Event::Peers(backend.peer_profiles()));
        events.send(Event::Network(backend.network()));
        context.request_repaint();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_observation_backlog_retains_the_command_result_and_reports_a_gap() {
        let events = EventBus::default();
        events.send(Event::Finished {
            snapshot: None,
            outcome: Err(LabError::InvalidInput("public rejected result".into())),
            elapsed_ms: 1.0,
            client_id: Some(1),
        });
        for _ in 0..5000 {
            events.send(Event::Progress("public status fixture".into()));
        }
        let mut result_seen = false;
        let mut gap = 0;
        let mut observations = 0;
        let mut previous = None;
        while let Some(Event::Stamped { at, event }) = events.pop() {
            assert!(previous.is_none_or(|previous| previous <= at));
            previous = Some(at);
            observations += 1;
            match *event {
                Event::Finished { .. } => result_seen = true,
                Event::DisplayGap(count) => gap += count,
                _ => {}
            }
        }
        assert!(result_seen);
        assert!(gap > 0);
        assert!(observations <= 4097);
    }
    #[test]
    fn actual_frame_observations_precede_the_sql_completion_in_the_display_stream() {
        let events = EventBus::default();
        events.send(Event::Traffic(Observation {
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
        }));
        events.send(Event::Finished {
            snapshot: None,
            outcome: Err(LabError::InvalidInput("public failure fixture".into())),
            elapsed_ms: 1.0,
            client_id: Some(1),
        });
        let Some(Event::Stamped { at: sent, event }) = events.pop() else {
            panic!("missing sent event")
        };
        assert!(matches!(*event, Event::Traffic(_)));
        let Some(Event::Stamped {
            at: finished,
            event,
        }) = events.pop()
        else {
            panic!("missing result")
        };
        assert!(matches!(
            *event,
            Event::Finished {
                client_id: Some(1),
                ..
            }
        ));
        assert!(sent <= finished);
        assert!(events.pop().is_none());
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
            bus: EventBus::default(),
            stop: Arc::default(),
            thread: Some(thread),
            _events: None,
        };
        drop(worker);
        assert!(released.load(Ordering::Acquire));
    }
}
