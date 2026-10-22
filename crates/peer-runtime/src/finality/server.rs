//! Passive source definitions; no I/O occurs until the trusted owner binds/spawns.
//! Only public canonical ciphertext/proof Bodies and signed consensus messages
//! cross TLS. The service never accepts an opening, signing key or SQL grant.
use super::{
    actor::{self, Command, Handle, Reply},
    wire::*,
    *,
};
use peer_transport::{
    AcceptedConnection, Acceptor, Cancellation, Connector, Endpoint, read_frame, write_frame,
};
use registry200_finality::{Binding, Checkpoint, RegistryFinality};
use std::{
    io::Write,
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::Mutex,
    thread::{self, JoinHandle},
};
use version_journal::{HEADER_BYTES, Header as BlockHeader, MAX_BODY_BYTES};

/// Trusted public network composition. The caller has already created/opened
/// the concrete finality handle with independent pins and actual file quota.
pub struct ListenerConfig {
    pub listen: SocketAddr,
    pub identity: [u8; 32],
    pub owner: [u8; 32],
    pub acceptor: Acceptor,
    pub connector: Connector,
    pub neighbors: Vec<Endpoint>,
}
pub struct FinalityServer {
    listener: TcpListener,
    endpoint: Endpoint,
    config: ListenerConfig,
    owned: RegistryFinality,
    binding: Binding,
    gate: crate::ProofGate,
}
pub struct RunningFinality {
    endpoint: Endpoint,
    handle: Handle,
    sockets: Arc<Mutex<Vec<Arc<TcpStream>>>>,
    cancellation: Cancellation,
    thread: Option<JoinHandle<io::Result<()>>>,
}
impl RunningFinality {
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
    #[cfg(test)]
    pub(super) fn relay_handle_for_test(&self) -> Handle {
        self.handle.clone()
    }
    /// Stop sockets and join the owner, including any current nonpreemptible
    /// actual proof verification. Cancellation cannot erase a lock or vote.
    pub fn stop(&mut self) -> io::Result<()> {
        self.handle.stop.store(true, Ordering::Release);
        self.cancellation.cancel();
        close_sockets(&self.sockets);
        match self.thread.take() {
            Some(t) => t.join().map_err(|_| error("Finality thread panicked"))?,
            None => Ok(()),
        }
    }
}
impl Drop for RunningFinality {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
impl FinalityServer {
    /// No workspace creation, bootstrap decoding, key import or alternate gate.
    /// Use the exact gate cloned from the owning PeerServer before it is spawned.
    pub fn bind(
        config: ListenerConfig,
        owned: RegistryFinality,
        gate: crate::ProofGate,
    ) -> io::Result<Self> {
        if config.neighbors.len() > MAX_PEERS {
            return Err(invalid());
        }
        for (i, peer) in config.neighbors.iter().enumerate() {
            if config.neighbors[..i].iter().any(|p| p == peer) {
                return Err(invalid());
            }
        }
        let binding = owned.binding().map_err(error)?;
        let listener = TcpListener::bind(config.listen)?;
        listener.set_nonblocking(true)?;
        let endpoint = Endpoint {
            address: listener.local_addr()?,
            identity: config.identity,
        };
        Ok(Self {
            listener,
            endpoint,
            config,
            owned,
            binding,
            gate,
        })
    }
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
    /// Trusted pre-launch composition after ephemeral listener addresses are
    /// known. No remote command can change the pinned peer list or work roster.
    pub fn set_neighbors(&mut self, neighbors: Vec<Endpoint>) -> io::Result<()> {
        if neighbors.len() > MAX_PEERS
            || neighbors
                .iter()
                .enumerate()
                .any(|(i, p)| neighbors[..i].contains(p))
        {
            return Err(invalid());
        }
        self.config.neighbors = neighbors;
        Ok(())
    }
    pub fn spawn(self) -> io::Result<RunningFinality> {
        self.spawn_with_body_gate(BodyGate::new())
    }
    #[cfg(test)]
    pub(super) fn spawn_with_body_gate_for_test(
        self,
        bodies: BodyGate,
    ) -> io::Result<RunningFinality> {
        self.spawn_with_body_gate(bodies)
    }
    fn spawn_with_body_gate(self, bodies: BodyGate) -> io::Result<RunningFinality> {
        let endpoint = self.endpoint.clone();
        let sockets = Arc::new(Mutex::new(Vec::new()));
        let cancellation = Cancellation::default();
        let (handle, actor) = actor::spawn(self.owned, self.gate)?;
        let actor = Arc::new(Mutex::new(Some(actor)));
        let actor_on_exit = actor.clone();
        let owner = handle.clone();
        let resources = sockets.clone();
        let cancel = cancellation.clone();
        let join = thread::Builder::new()
            .name("dcs-registry-finality-TLS".into())
            .spawn(move || {
                let result = listen(
                    self.listener,
                    self.config,
                    self.binding,
                    owner.clone(),
                    bodies,
                    resources.clone(),
                    cancel.clone(),
                );
                owner.stop.store(true, Ordering::Release);
                cancel.cancel();
                close_sockets(&resources);
                let joined = actor_on_exit
                    .lock()
                    .map_err(error)?
                    .take()
                    .ok_or_else(closed)?
                    .join()
                    .map_err(|_| error("Finality owner panicked"))?;
                result.and(joined)
            });
        // A failed supervisor spawn must still stop AND join the key owner.
        match join {
            Ok(thread) => Ok(RunningFinality {
                endpoint,
                handle,
                sockets,
                cancellation,
                thread: Some(thread),
            }),
            Err(e) => {
                handle.stop.store(true, Ordering::Release);
                if let Some(actor) = actor.lock().map_err(error)?.take() {
                    let _ = actor.join();
                }
                Err(e)
            }
        }
    }
}
fn close_sockets(sockets: &Mutex<Vec<Arc<TcpStream>>>) {
    if let Ok(sockets) = sockets.lock() {
        for socket in sockets.iter() {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }
}
struct SocketRegistration {
    socket: Arc<TcpStream>,
    sockets: Arc<Mutex<Vec<Arc<TcpStream>>>>,
}
impl Drop for SocketRegistration {
    fn drop(&mut self) {
        if let Ok(mut sockets) = self.sockets.lock() {
            sockets.retain(|s| !Arc::ptr_eq(s, &self.socket));
        }
    }
}
fn listen(
    listener: TcpListener,
    config: ListenerConfig,
    binding: Binding,
    handle: Handle,
    bodies: BodyGate,
    sockets: Arc<Mutex<Vec<Arc<TcpStream>>>>,
    cancellation: Cancellation,
) -> io::Result<()> {
    let relay_handle = handle.clone();
    let relay_bodies = bodies.clone();
    let relay_cancel = cancellation.clone();
    let relay_binding = binding.clone();
    let neighbors = config.neighbors;
    let connector = config.connector;
    let relay = thread::Builder::new()
        .name("dcs-registry-finality-relay".into())
        .spawn(move || {
            while !relay_handle.stop.load(Ordering::Acquire) {
                for endpoint in &neighbors {
                    if relay_handle.stop.load(Ordering::Acquire) {
                        break;
                    }
                    let client = super::FinalityClient::new(
                        connector.clone(),
                        endpoint.clone(),
                        &relay_binding,
                    )
                    .with_cancellation(relay_cancel.clone());
                    // Unavailable/Byzantine peers can delay only one bounded pass.
                    // Failure is never converted into quorum or a local timeout.
                    let _ = super::client::synchronize(&client, &relay_handle, &relay_bodies);
                }
                thread::park_timeout(Duration::from_millis(100));
            }
        })?;
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    let result = (|| {
        while !handle.stop.load(Ordering::Acquire) {
            let mut i = 0;
            while i < workers.len() {
                if workers[i].is_finished() {
                    let _ = workers.swap_remove(i).join();
                } else {
                    i += 1;
                }
            }
            match listener.accept() {
                Ok((socket, _)) => {
                    if workers.len() >= MAX_CONNECTIONS {
                        drop(socket);
                        continue;
                    }
                    let copy = Arc::new(socket.try_clone()?);
                    sockets.lock().map_err(error)?.push(copy.clone());
                    let registered = SocketRegistration {
                        socket: copy,
                        sockets: sockets.clone(),
                    };
                    let acceptor = config.acceptor.clone();
                    let owner = config.owner;
                    let request = handle.clone();
                    let bodies = bodies.clone();
                    let id = binding.id();
                    workers.push(
                        thread::Builder::new()
                            .name("dcs-registry-finality-connection".into())
                            .spawn(move || {
                                let _registered = registered;
                                let _ = serve(socket, &acceptor, owner, id, &request, &bodies);
                            })?,
                    );
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::park_timeout(Duration::from_millis(20))
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    })();
    handle.stop.store(true, Ordering::Release);
    cancellation.cancel();
    close_sockets(&sockets);
    for worker in workers {
        let _ = worker.join();
    }
    relay.join().map_err(|_| error("Finality relay panicked"))?;
    result
}
fn send(
    stream: &mut AcceptedConnection,
    binding: [u8; 32],
    tag: u8,
    bytes: &[u8],
) -> io::Result<()> {
    write_frame(stream, &encode(binding, tag, bytes)?, MAX_CONTROL)
}
fn finish(stream: &mut AcceptedConnection) -> io::Result<()> {
    stream.conn.send_close_notify();
    stream.flush()
}
fn terminal(
    stream: &mut AcceptedConnection,
    binding: [u8; 32],
    tag: u8,
    bytes: &[u8],
) -> io::Result<()> {
    send(stream, binding, tag, bytes)?;
    finish(stream)
}
fn serve(
    socket: TcpStream,
    acceptor: &Acceptor,
    owner: [u8; 32],
    binding: [u8; 32],
    handle: &Handle,
    bodies: &BodyGate,
) -> io::Result<()> {
    let (identity, mut stream) = acceptor.accept(socket)?;
    let _deadline = peer_transport::ConnectionDeadline::new(&stream.sock, RPC_BUDGET)?;
    stream.sock.set_read_timeout(Some(RPC_BUDGET))?;
    stream.sock.set_write_timeout(Some(RPC_BUDGET))?;
    // Precharge BEFORE announced length allocation, including queue waiting and
    // response ownership. Oversized/control EOF is checked before DTO allocation.
    let lease = match handle.reserve_control() {
        Ok(lease) => lease,
        Err(_) => return terminal(&mut stream, binding, BUSY, &[]),
    };
    let mut packet = read_frame(&mut stream, MAX_CONTROL)?;
    let (tag, data) = decode(binding, &packet)?;
    let command = match tag {
        STATUS if data.is_empty() => Command::Status,
        INPUT => {
            packet.drain(..HEADER);
            Command::Input(packet)
        }
        GET_BLOCK => {
            let id = hash(data)?;
            let lease = match bodies.acquire() {
                Ok(lease) => lease,
                Err(_) => return terminal(&mut stream, binding, BUSY, &[]),
            };
            Command::GetBlock(id, lease)
        }
        GET_CHECKPOINT => Command::GetCheckpoint(word(data)?),
        CHECKPOINT => Command::Checkpoint(Checkpoint::decode(data).map_err(error)?),
        PUT_BLOCK | SUBMIT => {
            if tag == SUBMIT && identity != owner {
                return terminal(&mut stream, binding, REJECT, &[]);
            }
            if data.len() != HEADER_BYTES + 4 {
                return Err(invalid());
            }
            let header = BlockHeader::decode(&data[..HEADER_BYTES]).map_err(error)?;
            let n = u32::from_le_bytes(data[HEADER_BYTES..].try_into().map_err(|_| invalid())?)
                as usize;
            if n == 0 || n > MAX_BODY_BYTES {
                return Err(invalid());
            }
            let body = match bodies.acquire() {
                Ok(lease) => lease,
                Err(_) => return terminal(&mut stream, binding, BUSY, &[]),
            };
            send(&mut stream, binding, OK, &[])?;
            let bytes = read_frame(&mut stream, n)?;
            if bytes.len() != n {
                return Err(invalid());
            }
            Command::Block(
                OwnedBlock {
                    block: CandidateBlock::new(header, bytes).map_err(error)?,
                    _lease: body,
                },
                tag == SUBMIT,
            )
        }
        _ => return Err(invalid()),
    };
    let result = match handle.call_reserved(command, lease) {
        Ok((reply, _lease)) => match reply {
            Reply::Ok => send(&mut stream, binding, OK, &[]),
            Reply::Status { slot, context } => {
                let mut bytes = slot.to_le_bytes().to_vec();
                bytes.extend_from_slice(&context);
                send(&mut stream, binding, OK, &bytes)
            }
            Reply::NeedBlock(id) => send(&mut stream, binding, NEED_BLOCK, &id),
            Reply::Checkpoint(Some(c)) => send(&mut stream, binding, RECORD, &c.encode()),
            Reply::Checkpoint(None) => send(&mut stream, binding, NONE, &[]),
            Reply::Block(block) => {
                let mut header = block.block.header().encode().to_vec();
                header.extend_from_slice(&(block.block.body().len() as u32).to_le_bytes());
                send(&mut stream, binding, BLOCK, &header)?;
                write_frame(&mut stream, block.block.body(), MAX_BODY_BYTES)
            }
            Reply::Outbound(_)
            | Reply::JointSnapshot(_)
            | Reply::JointCheckpoint(_)
            | Reply::WordPending(_) => Err(invalid()),
        },
        Err(e) => send(
            &mut stream,
            binding,
            if e.kind() == io::ErrorKind::WouldBlock {
                BUSY
            } else {
                REJECT
            },
            &[],
        ),
    };
    result?;
    finish(&mut stream)
}
