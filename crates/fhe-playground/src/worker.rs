use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::time::Instant;

use eframe::egui;
use fhe_playground::{
    DatabaseDraft, LabEngine, LabError, LabProgress, LabSnapshot, PeerConfig, QueryOutcome,
};

pub enum Command {
    Create(DatabaseDraft),
    Query(String),
    SetPeer { id: usize, online: bool },
    ConfigurePeers(Vec<PeerConfig>),
    ConfigurePeer { id: usize, config: PeerConfig },
}

pub enum Outcome {
    Created,
    PeerChanged,
    LayoutChanged,
    Query(QueryOutcome),
}

pub enum Event {
    Progress(String),
    PeerProgress(LabProgress),
    Finished {
        snapshot: Option<LabSnapshot>,
        outcome: Result<Outcome, LabError>,
        elapsed_ms: f64,
    },
}

pub struct Worker {
    sender: SyncSender<Command>,
    receiver: Receiver<Event>,
}

impl Worker {
    #[cfg(test)]
    pub fn test_channel() -> (Self, Receiver<Command>, mpsc::Sender<Event>) {
        let (sender, commands) = mpsc::sync_channel(1);
        let (events, receiver) = mpsc::channel();
        (Self { sender, receiver }, commands, events)
    }

    pub fn start(context: egui::Context) -> std::io::Result<Self> {
        let (sender, commands) = mpsc::sync_channel(1);
        let (events, receiver) = mpsc::channel();
        // Dropping the command sender ends the worker after its current operation.
        // No secret keys or owner fixtures are persisted on application shutdown.
        std::thread::Builder::new()
            .name("fhe-lab-worker".into())
            .spawn(move || {
                let mut engine = LabEngine::default();
                while let Ok(command) = commands.recv() {
                    let start = Instant::now();
                    let outcome = match command {
                        Command::Create(draft) => {
                            let _ = events.send(Event::Progress(
                                "Generating keys and encrypting shards...".into(),
                            ));
                            context.request_repaint();
                            engine.create(draft).map(|_| Outcome::Created)
                        }
                        Command::Query(sql) => engine
                            .execute_with_progress(&sql, |message| {
                                let _ = events.send(Event::PeerProgress(message));
                                context.request_repaint();
                            })
                            .map(Outcome::Query),
                        Command::SetPeer { id, online } => engine
                            .set_peer_online(id, online)
                            .map(|_| Outcome::PeerChanged),
                        Command::ConfigurePeers(configs) => {
                            let _ = events
                                .send(Event::Progress("Repartitioning encrypted shards...".into()));
                            context.request_repaint();
                            engine
                                .configure_peers(configs)
                                .map(|_| Outcome::LayoutChanged)
                        }
                        Command::ConfigurePeer { id, config } => engine
                            .set_peer_config(id, config)
                            .map(|_| Outcome::PeerChanged),
                    };
                    if events
                        .send(Event::Finished {
                            snapshot: engine.snapshot(),
                            outcome,
                            elapsed_ms: start.elapsed().as_secs_f64() * 1000.0,
                        })
                        .is_err()
                    {
                        break;
                    }
                    context.request_repaint();
                }
            })?;
        Ok(Self { sender, receiver })
    }

    pub fn send(&self, command: Command) -> Result<(), String> {
        self.sender
            .try_send(command)
            .map_err(|error| format!("Cannot submit operation: {error}"))
    }

    pub fn poll(&self) -> Result<Option<Event>, String> {
        match self.receiver.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => {
                Err("The FHE worker stopped. Restart the playground.".into())
            }
        }
    }
}
