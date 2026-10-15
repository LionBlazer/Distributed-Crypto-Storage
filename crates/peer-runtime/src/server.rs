use crate::{RemotePeer, store::Store, wire::*};
use bfv_query_core::{PeerEvaluator, PublicSetup};
use peer_transport::{Acceptor, Connector, Endpoint, MAX_FRAME_BYTES, read_frame, write_frame};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    net::{TcpListener, TcpStream},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
mod network;

struct Setup {
    public: PublicSetup,
    legacy: Mutex<Option<Arc<PeerEvaluator>>>,
    verifier: Arc<crate::JobVerifier>,
    bytes: usize,
}
struct State {
    store: Store,
    setups: BTreeMap<[u8; 32], Arc<Setup>>,
    journals: BTreeMap<[u8; 32], Arc<Mutex<network::Network>>>,
    neighbors: Vec<Neighbor>,
    recent: VecDeque<Observation>,
    sequence: u64,
    received: u64,
    sent: u64,
}
struct Shared {
    state: Mutex<State>,
    owner: [u8; 32],
    node_id: u64,
    connector: Connector,
    stop: AtomicBool,
    active: AtomicUsize,
    proof_busy: AtomicBool,
}
/// Owns a bound socket and the peer's ciphertext directory lock, never owner keys.
pub struct PeerServer {
    listener: TcpListener,
    endpoint: Endpoint,
    acceptor: Acceptor,
    shared: Arc<Shared>,
}
pub struct RunningServer {
    pub endpoint: Endpoint,
    shared: Arc<Shared>,
    thread: Option<JoinHandle<io::Result<()>>>,
}
impl RunningServer {
    pub fn stop(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
impl Drop for RunningServer {
    fn drop(&mut self) {
        self.stop();
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}
fn io_error(e: impl std::fmt::Display) -> RemoteError {
    RemoteError::Io(e.to_string())
}
impl PeerServer {
    pub fn bind(config: Bootstrap, directory: &Path) -> io::Result<Self> {
        let (acceptor, connector) = if config.authority.is_empty() {
            (
                Acceptor::permissionless(&config.identity)?,
                Connector::permissionless(&config.identity)?,
            )
        } else {
            (
                Acceptor::new(&config.identity, &config.authority)?,
                Connector::new(&config.identity, &config.authority)?,
            )
        };
        let listener = TcpListener::bind(config.listen)?;
        listener.set_nonblocking(true)?;
        let endpoint = Endpoint {
            address: listener.local_addr()?,
            identity: config.identity.fingerprint(),
        };
        let store = Store::open(directory, config.quota_bytes)?;
        Ok(Self {
            listener,
            endpoint,
            acceptor,
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    store,
                    setups: BTreeMap::new(),
                    journals: BTreeMap::new(),
                    neighbors: vec![],
                    recent: VecDeque::new(),
                    sequence: 0,
                    received: 0,
                    sent: 0,
                }),
                owner: config.owner,
                node_id: config.node_id,
                connector,
                stop: AtomicBool::new(false),
                active: AtomicUsize::new(0),
                proof_busy: AtomicBool::new(false),
            }),
        })
    }
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
    pub fn spawn(self) -> io::Result<RunningServer> {
        let endpoint = self.endpoint.clone();
        let shared = self.shared.clone();
        let thread = thread::Builder::new()
            .name("dcs-peer-listener".into())
            .spawn(move || self.run())?;
        Ok(RunningServer {
            endpoint,
            shared,
            thread: Some(thread),
        })
    }
    pub fn run(self) -> io::Result<()> {
        let heartbeat = self.shared.clone();
        let heartbeat_thread = thread::Builder::new()
            .name("dcs-peer-heartbeat".into())
            .spawn(move || heartbeat_loop(heartbeat))?;
        let mut workers: Vec<JoinHandle<()>> = Vec::new();
        while !self.shared.stop.load(Ordering::Acquire) {
            let mut remaining = Vec::new();
            for worker in workers.drain(..) {
                if worker.is_finished() {
                    let _ = worker.join();
                } else {
                    remaining.push(worker);
                }
            }
            workers = remaining;
            match self.listener.accept() {
                Ok((socket, _)) => {
                    // Reserve before TLS or frame allocation. Never an unbounded thread pool.
                    if self
                        .shared
                        .active
                        .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                            (n < 8).then_some(n + 1)
                        })
                        .is_err()
                    {
                        drop(socket);
                        continue;
                    }
                    let shared = self.shared.clone();
                    let acceptor = self.acceptor.clone();
                    match thread::Builder::new()
                        .name("dcs-peer-connection".into())
                        .spawn(move || {
                            struct Permit(Arc<Shared>);
                            impl Drop for Permit {
                                fn drop(&mut self) {
                                    self.0.active.fetch_sub(1, Ordering::Release);
                                }
                            }
                            let _permit = Permit(shared.clone());
                            if let Err(error) = serve(socket, acceptor, shared) {
                                eprintln!("peer connection rejected: {error}");
                            }
                        }) {
                        Ok(worker) => workers.push(worker),
                        Err(error) => {
                            self.shared.active.fetch_sub(1, Ordering::Release);
                            self.shared.stop.store(true, Ordering::Release);
                            return Err(error);
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10))
                }
                Err(error) => {
                    self.shared.stop.store(true, Ordering::Release);
                    return Err(error);
                }
            }
        }
        for worker in workers {
            let _ = worker.join();
        }
        let _ = heartbeat_thread.join();
        Ok(())
    }
}
fn serve(socket: TcpStream, acceptor: Acceptor, shared: Arc<Shared>) -> io::Result<()> {
    let (remote, mut stream) = acceptor.accept(socket)?;
    let bytes = read_frame(&mut stream, MAX_FRAME_BYTES)?;
    let wire: WireRequest = decode(&bytes)?;
    if wire.version != 1 {
        return Err(io::Error::other("Unsupported RPC version"));
    }
    let operation = wire.request.name().to_owned();
    let result = dispatch(&shared, remote, wire.request);
    let succeeded = result.is_ok();
    let payload = encode(&WireResponse {
        version: 1,
        id: wire.id,
        result,
    })?;
    let delivery = write_frame(&mut stream, &payload, MAX_FRAME_BYTES);
    if let Ok(mut state) = shared.state.lock() {
        state.received = state.received.saturating_add(bytes.len() as u64);
        state.sent = state.sent.saturating_add(if delivery.is_ok() {
            payload.len() as u64
        } else {
            0
        });
        state.sequence = state.sequence.saturating_add(1);
        let sequence = state.sequence;
        state.recent.push_back(Observation {
            sequence,
            time_ms: now(),
            remote,
            operation,
            received_bytes: bytes.len() as u64,
            sent_bytes: if delivery.is_ok() {
                payload.len() as u64
            } else {
                0
            },
            succeeded: succeeded && delivery.is_ok(),
        });
        while state.recent.len() > 128 {
            state.recent.pop_front();
        }
    }
    delivery
}
fn dispatch(
    shared: &Arc<Shared>,
    remote: [u8; 32],
    request: Request,
) -> Result<Response, RemoteError> {
    let privileged = matches!(
        &request,
        Request::Store(_)
            | Request::InstallSetup(_)
            | Request::Neighbors(_)
            | Request::Quota(_)
            | Request::Shutdown
            | Request::Copy { .. }
            | Request::InitJournal { .. }
            | Request::CollectJournal { .. }
    );
    if privileged && remote != shared.owner {
        return Err(RemoteError::Unauthorized);
    }
    if let Request::Prove {
        object,
        setup,
        operation,
        ciphertext,
    } = request
    {
        return network::prove(shared, object, setup, operation, ciphertext);
    }
    if matches!(
        &request,
        Request::InstallSetup(_)
            | Request::Evaluate { .. }
            | Request::Prove { .. }
            | Request::InitJournal { .. }
            | Request::JournalBlocks { .. }
            | Request::PublishBlock { .. }
            | Request::MineBlock { .. }
            | Request::CollectJournal { .. }
    ) {
        return network::dispatch(shared, request);
    }
    // Copy reads from another authenticated peer; the owner never supplies source plaintext.
    if let Request::Copy { source, object } = &request {
        let source = RemotePeer::new(source.clone(), shared.connector.clone());
        let Response::Bundle(bundle) = source
            .call(Request::Fetch { object: *object })
            .map_err(io_error)?
        else {
            return Err(RemoteError::InvalidRequest);
        };
        if bundle.id() != *object {
            return Err(RemoteError::Integrity);
        }
        return shared
            .state
            .lock()
            .map_err(io_error)?
            .store
            .put(bundle)
            .map(Response::Stored);
    }
    let mut state = shared.state.lock().map_err(io_error)?;
    match request {
        Request::Probe => Ok(Response::Alive {
            node_id: shared.node_id,
            pid: std::process::id(),
        }),
        Request::Status => Ok(Response::Status(Status {
            node_id: shared.node_id,
            pid: std::process::id(),
            quota_bytes: state.store.quota(),
            objects: state.store.objects(),
            public_setup_bytes: state.setups.values().map(|s| s.bytes as u64).sum(),
            journal_bytes: state.store.journal_bytes(),
            received_bytes: state.received,
            sent_bytes: state.sent,
            neighbors: state.neighbors.clone(),
            recent: state.recent.iter().cloned().collect(),
        })),
        Request::Store(bundle) => state.store.put(bundle).map(Response::Stored),
        Request::Fetch { object } => state.store.get(&object).map(Response::Bundle),
        Request::FetchVersion {
            data_head,
            index_head,
        } => state
            .store
            .get_version(&data_head, &index_head)
            .map(Response::Bundle),
        Request::Neighbors(endpoints) => {
            if endpoints.len() > 32
                || endpoints
                    .iter()
                    .map(|e| e.identity)
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != endpoints.len()
            {
                return Err(RemoteError::ResourceLimit);
            }
            state.neighbors = endpoints
                .into_iter()
                .map(|endpoint| Neighbor {
                    endpoint,
                    reachable: false,
                    last_success_ms: None,
                })
                .collect();
            Ok(Response::Done)
        }
        Request::Quota(quota) => {
            state.store.configure(quota)?;
            Ok(Response::Done)
        }
        Request::Shutdown => {
            shared.stop.store(true, Ordering::Release);
            Ok(Response::Done)
        }
        Request::Copy { .. } => unreachable!("copy handled without the local store lock"),
        Request::InstallSetup(_)
        | Request::Evaluate { .. }
        | Request::Prove { .. }
        | Request::InitJournal { .. }
        | Request::JournalBlocks { .. }
        | Request::PublishBlock { .. }
        | Request::MineBlock { .. }
        | Request::CollectJournal { .. } => {
            unreachable!("heavy work has its own permit and no state lock")
        }
    }
}
fn heartbeat_loop(shared: Arc<Shared>) {
    while !shared.stop.load(Ordering::Acquire) {
        let endpoints = match shared.state.lock() {
            Ok(state) => state
                .neighbors
                .iter()
                .map(|n| n.endpoint.clone())
                .collect::<Vec<_>>(),
            Err(_) => return,
        };
        for endpoint in endpoints {
            if shared.stop.load(Ordering::Acquire) {
                return;
            }
            let reachable = matches!(
                RemotePeer::new(endpoint.clone(), shared.connector.clone()).call(Request::Probe),
                Ok(Response::Alive { .. })
            );
            if reachable {
                network::synchronize_neighbor(&shared, &endpoint);
            }
            if let Ok(mut state) = shared.state.lock()
                && let Some(neighbor) = state.neighbors.iter_mut().find(|n| n.endpoint == endpoint)
            {
                neighbor.reachable = reachable;
                if reachable {
                    neighbor.last_success_ms = Some(now());
                }
            }
        }
        // Only heartbeat scheduling uses wall time. No virtual delivery or fake ack.
        for _ in 0..10 {
            if shared.stop.load(Ordering::Acquire) {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
}
