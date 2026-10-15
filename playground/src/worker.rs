//! The GUI supervises actual child processes. It never executes a peer FHE job.
use crate::process_backend::ProcessBackend;
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
}

pub enum Event {
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
        let thread = std::thread::Builder::new()
            .name("dcs-process-manager".into())
            .spawn(move || run(commands, events, views, context, stopping))?;
        Ok(Self {
            sender: Some(sender),
            receiver,
            latest,
            stop,
            thread: Some(thread),
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
        match self.receiver.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(TryRecvError::Empty) => self
                .latest
                .lock()
                .map_err(|_| "Process view lock failed".to_string())
                .map(|mut events| events.pop_front()),
            Err(TryRecvError::Disconnected) => {
                Err("Peer manager stopped; child processes were closed".into())
            }
        }
    }
}
fn run(
    commands: Receiver<Command>,
    events: mpsc::Sender<Event>,
    latest: Arc<Mutex<VecDeque<Event>>>,
    context: egui::Context,
    stop: Arc<AtomicBool>,
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
                    Command::Query { client_id, sql } => match backend.query(client_id, &sql) {
                        Ok(accepted) => match accepted {},
                        Err(error) => Err(error),
                    },
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
        };
        drop(worker);
        assert!(released.load(Ordering::Acquire));
    }
}
