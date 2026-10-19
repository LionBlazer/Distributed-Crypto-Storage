use crate::{Bootstrap, CheckedObject, RemotePeer, store::Store, wire::*};
use bfv_query_core::{PeerEvaluator, PublicSetup};
use mio::{Events, Interest, Poll, Token, Waker};
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
mod private_product;

const LISTENER: Token = Token(0);
const STOP: Token = Token(1);
const MAX_CONNECTIONS: usize = 8;

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
    listener_waker: Waker,
    active: AtomicUsize,
    proof_busy: crate::ProofGate,
}
impl Shared {
    fn request_stop(&self) {
        self.stop.store(true, Ordering::Release);
        // If the listener has already exited, the stop flag remains sufficient.
        let _ = self.listener_waker.wake();
    }
}
/// Owns a bound socket and the peer's ciphertext directory lock, never owner keys.
pub struct PeerServer {
    listener: mio::net::TcpListener,
    poll: Poll,
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
        self.shared.request_stop();
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
        let mut listener = mio::net::TcpListener::from_std(listener);
        let poll = Poll::new()?;
        poll.registry()
            .register(&mut listener, LISTENER, Interest::READABLE)?;
        let listener_waker = Waker::new(poll.registry(), STOP)?;
        let store = Store::open(directory, config.quota_bytes)?;
        Ok(Self {
            listener,
            poll,
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
                listener_waker,
                active: AtomicUsize::new(0),
                proof_busy: crate::ProofGate::new(),
            }),
        })
    }
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
    /// The actual process gate, shared with custody/FHE and closed finality.
    /// A clone is scheduling state, never a successful-verification token.
    pub fn proof_gate(&self) -> crate::ProofGate {
        self.shared.proof_busy.clone()
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
    pub fn run(mut self) -> io::Result<()> {
        let heartbeat = self.shared.clone();
        let heartbeat_thread = thread::Builder::new()
            .name("dcs-peer-heartbeat".into())
            .spawn(move || heartbeat_loop(heartbeat))?;
        let mut workers: Vec<JoinHandle<()>> = Vec::new();
        let result = self.accept_connections(&mut workers);
        self.shared.request_stop();
        for worker in workers {
            let _ = worker.join();
        }
        let _ = heartbeat_thread.join();
        result
    }

    fn accept_connections(&mut self, workers: &mut Vec<JoinHandle<()>>) -> io::Result<()> {
        let mut events = Events::with_capacity(2);
        while !self.shared.stop.load(Ordering::Acquire) {
            for worker in workers.extract_if(.., |worker| worker.is_finished()) {
                let _ = worker.join();
            }
            match self.poll.poll(&mut events, None) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
            for event in &events {
                if event.token() != LISTENER {
                    continue;
                }
                // Drain readiness to WouldBlock, as required for edge-triggered
                // pollers. Check stop even under a continuous connection flood.
                while !self.shared.stop.load(Ordering::Acquire) {
                    match self.listener.accept() {
                        Ok((socket, _)) => self.start_connection(socket.into(), workers)?,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) => return Err(error),
                    }
                }
            }
        }
        Ok(())
    }

    fn start_connection(
        &self,
        socket: TcpStream,
        workers: &mut Vec<JoinHandle<()>>,
    ) -> io::Result<()> {
        // A continuously readable listener must also reap completed workers:
        // readiness draining cannot retain a handle for every past connection.
        for worker in workers.extract_if(.., |worker| worker.is_finished()) {
            let _ = worker.join();
        }
        // The active permit can drop before thread-local destructors finish.
        // Bound retained OS threads as well as connections currently serving I/O.
        if workers.len() >= MAX_CONNECTIONS {
            return Ok(());
        }
        // Reserve before TLS or frame allocation. Never an unbounded thread pool.
        if self
            .shared
            .active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_CONNECTIONS).then_some(n + 1)
            })
            .is_err()
        {
            return Ok(());
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
                return Err(error);
            }
        }
        Ok(())
    }
}
fn serve(socket: TcpStream, acceptor: Acceptor, shared: Arc<Shared>) -> io::Result<()> {
    let (remote, mut stream) = acceptor.accept(socket)?;
    let initial_deadline =
        peer_transport::ConnectionDeadline::new(&stream.sock, crate::private_product::IO_BUDGET)?;
    let bytes = read_frame(&mut stream, MAX_FRAME_BYTES)?;
    let wire = decode_request(&bytes)?;
    drop(initial_deadline);
    if wire.version != 2 {
        return Err(io::Error::other("Unsupported RPC version"));
    }
    if let Request::PrivateProduct(request) = wire.request {
        return private_product::serve(&shared, remote, wire.id, request, bytes.len(), &mut stream);
    }
    let response_limit = match &wire.request {
        Request::FetchPages(_) => crate::MAX_PAGE_BATCH_RESPONSE_BYTES,
        Request::FetchReadImage(_) => crate::MAX_READ_IMAGE_RESPONSE_BYTES,
        Request::StoreDelta(_) => crate::MAX_STORE_DELTA_RESPONSE_BYTES,
        _ => MAX_FRAME_BYTES,
    };
    let operation = wire.request.name().to_owned();
    let result = dispatch(&shared, remote, wire.request);
    let succeeded = result.is_ok();
    let payload = encode(&WireResponse {
        version: 2,
        id: wire.id,
        result,
    })?;
    let delivery = write_frame(&mut stream, &payload, response_limit);
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
            | Request::StoreDelta(_)
            | Request::InstallSetup(_)
            | Request::Neighbors(_)
            | Request::Quota(_)
            | Request::Shutdown
            | Request::Copy { .. }
            | Request::InitJournal { .. }
            | Request::InitRegistryJournal { .. }
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
            | Request::InitRegistryJournal { .. }
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
        let Response::RawBundle(bundle) = source
            .call(Request::Fetch { object: *object })
            .map_err(io_error)?
        else {
            return Err(RemoteError::InvalidRequest);
        };
        let checked = CheckedObject::audit(bundle)?;
        if checked.version().object() != object {
            return Err(RemoteError::Integrity);
        }
        return shared
            .state
            .lock()
            .map_err(io_error)?
            .store
            .put_checked(checked)
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
        Request::StoreDelta(delta) => state.store.put_delta(delta).map(Response::Stored),
        Request::Fetch { object } => state.store.get(&object).map(Response::RawBundle),
        Request::FetchPages(request) => state.store.get_pages(request).map(Response::Pages),
        Request::FetchReadImage(request) => {
            state.store.get_read_image(request).map(Response::ReadImage)
        }
        Request::FetchVersion {
            data_head,
            index_head,
        } => state
            .store
            .get_version(&data_head, &index_head)
            .map(Response::RawBundle),
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
            shared.request_stop();
            Ok(Response::Done)
        }
        Request::Copy { .. } => unreachable!("copy handled without the local store lock"),
        Request::PrivateProduct(_) => Err(RemoteError::InvalidRequest),
        Request::InstallSetup(_)
        | Request::Evaluate { .. }
        | Request::Prove { .. }
        | Request::InitJournal { .. }
        | Request::InitRegistryJournal { .. }
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
