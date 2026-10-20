//! Joint-only typed TLS service. Prefetch is outside owner/state/proof locks;
//! the actual durable owner then rechecks every proof and the current snapshot.
use super::{
    actor::{self, Command, Handle, Reply},
    joint_client::{decode_id, encode_id},
    joint_prefetch::{self, BlobGate, ProofBlobSelector},
    joint_wire as joint,
    wire::*,
    *,
};
use peer_transport::{
    AcceptedConnection, Acceptor, Cancellation, Connector, Endpoint, read_frame, write_frame,
};
use registry200_finality::joint::{DurableJointFinality, JointBinding, JointCheckpoint};
use registry200_joint::JointEvidenceIngress;
use std::{
    io::Write,
    net::{Shutdown, TcpListener, TcpStream},
    sync::Mutex,
    thread::{self, JoinHandle},
    time::Instant,
};
use version_journal::{HEADER_BYTES, Header as BlockHeader, MAX_BODY_BYTES};

mod relay;

pub struct JointFinalityServer {
    listener: TcpListener,
    endpoint: Endpoint,
    config: ListenerConfig,
    owned: DurableJointFinality,
    binding: JointBinding,
    ingress: JointEvidenceIngress,
    gate: crate::ProofGate,
}
pub struct RunningJointFinality {
    endpoint: Endpoint,
    handle: Handle,
    sockets: Arc<Mutex<Vec<Arc<TcpStream>>>>,
    cancellation: Cancellation,
    thread: Option<JoinHandle<io::Result<()>>>,
}
impl super::FinalityServer {
    /// Distinct durable Joint entry. No legacy mode, depot, gate or signer is
    /// created here; trusted composition supplies the SAME actual owners.
    pub fn bind_joint(
        config: ListenerConfig,
        owned: DurableJointFinality,
        gate: crate::ProofGate,
    ) -> io::Result<JointFinalityServer> {
        if config.neighbors.len() > MAX_PEERS
            || config
                .neighbors
                .iter()
                .enumerate()
                .any(|(i, p)| config.neighbors[..i].contains(p))
        {
            return Err(invalid());
        }
        let binding = owned.binding().map_err(error)?;
        let ingress = owned.evidence_ingress().map_err(error)?;
        let listener = TcpListener::bind(config.listen)?;
        listener.set_nonblocking(true)?;
        let endpoint = Endpoint {
            address: listener.local_addr()?,
            identity: config.identity,
        };
        Ok(JointFinalityServer {
            listener,
            endpoint,
            config,
            owned,
            binding,
            ingress,
            gate,
        })
    }
}
impl JointFinalityServer {
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
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
    pub fn spawn(self) -> io::Result<RunningJointFinality> {
        let endpoint = self.endpoint.clone();
        let sockets = Arc::new(Mutex::new(Vec::new()));
        let cancellation = Cancellation::default();
        let (handle, owner) = actor::spawn_joint(self.owned, self.gate)?;
        let owner = Arc::new(Mutex::new(Some(owner)));
        let owner_on_exit = owner.clone();
        let request = handle.clone();
        let resources = sockets.clone();
        let cancel = cancellation.clone();
        let join = thread::Builder::new()
            .name("dcs-joint-finality-TLS".into())
            .spawn(move || {
                let result = listen(
                    self.listener,
                    self.config,
                    self.binding,
                    self.ingress,
                    request.clone(),
                    resources.clone(),
                    cancel.clone(),
                );
                request.stop.store(true, Ordering::Release);
                cancel.cancel();
                close_sockets(&resources);
                let joined = owner_on_exit
                    .lock()
                    .map_err(error)?
                    .take()
                    .ok_or_else(closed)?
                    .join()
                    .map_err(|_| error("Joint owner panicked"))?;
                result.and(joined)
            });
        match join {
            Ok(thread) => Ok(RunningJointFinality {
                endpoint,
                handle,
                sockets,
                cancellation,
                thread: Some(thread),
            }),
            Err(e) => {
                handle.stop.store(true, Ordering::Release);
                if let Some(owner) = owner.lock().map_err(error)?.take() {
                    let _ = owner.join();
                }
                Err(e)
            }
        }
    }
}
impl RunningJointFinality {
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
    pub fn stop(&mut self) -> io::Result<()> {
        self.handle.stop.store(true, Ordering::Release);
        self.cancellation.cancel();
        close_sockets(&self.sockets);
        match self.thread.take() {
            Some(t) => t
                .join()
                .map_err(|_| error("Joint TLS supervisor panicked"))?,
            None => Ok(()),
        }
    }
}
impl Drop for RunningJointFinality {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
fn close_sockets(sockets: &Mutex<Vec<Arc<TcpStream>>>) {
    if let Ok(sockets) = sockets.lock() {
        for s in sockets.iter() {
            let _ = s.shutdown(Shutdown::Both);
        }
    }
}
struct Registration {
    socket: Arc<TcpStream>,
    sockets: Arc<Mutex<Vec<Arc<TcpStream>>>>,
}
impl Drop for Registration {
    fn drop(&mut self) {
        if let Ok(mut sockets) = self.sockets.lock() {
            sockets.retain(|s| !Arc::ptr_eq(s, &self.socket));
        }
    }
}
#[derive(Clone)]
struct Service {
    acceptor: Acceptor,
    owner: [u8; 32],
    binding: JointBinding,
    ingress: JointEvidenceIngress,
    handle: Handle,
    bodies: BodyGate,
    blobs: BlobGate,
    connector: Connector,
    neighbors: Vec<Endpoint>,
    cancellation: Cancellation,
}
fn snapshot(handle: &Handle, expires: Instant) -> io::Result<super::owner::Snapshot> {
    match handle.call_joint(Command::JointSnapshot, expires)? {
        Reply::JointSnapshot(s) => Ok(s),
        _ => Err(invalid()),
    }
}
impl Service {
    fn prepare(
        &self,
        block: &CandidateBlock,
        expires: Instant,
    ) -> io::Result<super::owner::Snapshot> {
        let Self {
            binding,
            ingress,
            blobs,
            handle,
            connector,
            neighbors,
            cancellation,
            ..
        } = self;
        let current = snapshot(handle, expires)?;
        if block.header().id() == current.parent {
            // Latest selected-body retry: no new-parent prefetch rule. The owner
            // must route it through the actual last QC/context/full-proof replay.
            return Ok(current);
        }
        match joint_prefetch::prefetch_local(binding, ingress, blobs, block, current, expires) {
            Ok(()) => return Ok(current),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }
        let mut last = io::Error::new(
            io::ErrorKind::NotFound,
            "No source has the required Joint premises",
        );
        for endpoint in neighbors {
            cancellation.check()?;
            let client =
                super::JointFinalityClient::new(connector.clone(), endpoint.clone(), binding)
                    .with_cancellation(cancellation.clone());
            match joint_prefetch::prefetch(
                &client, binding, ingress, blobs, block, current, expires,
            ) {
                Ok(()) => return Ok(current),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Err(e),
                Err(e) => last = e,
            }
        }
        Err(last)
    }
}
fn listen(
    listener: TcpListener,
    config: ListenerConfig,
    binding: JointBinding,
    ingress: JointEvidenceIngress,
    handle: Handle,
    sockets: Arc<Mutex<Vec<Arc<TcpStream>>>>,
    cancellation: Cancellation,
) -> io::Result<()> {
    let bodies = BodyGate::new();
    let blobs = BlobGate::new();
    let service = Service {
        acceptor: config.acceptor,
        owner: config.owner,
        binding,
        ingress,
        handle: handle.clone(),
        bodies,
        blobs,
        connector: config.connector,
        neighbors: config.neighbors,
        cancellation: cancellation.clone(),
    };
    let mut relay = relay::Workers::spawn(service.clone(), sockets.clone())?;
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    let result = (|| {
        while !handle.stop.load(Ordering::Acquire) {
            let mut i = 0;
            while i < workers.len() {
                if workers[i].is_finished() {
                    let _ = workers.swap_remove(i).join();
                } else {
                    i += 1
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
                    let registration = Registration {
                        socket: copy,
                        sockets: sockets.clone(),
                    };
                    let service = service.clone();
                    workers.push(
                        thread::Builder::new()
                            .name("dcs-joint-finality-connection".into())
                            .spawn(move || {
                                let _registration = registration;
                                let _ = serve(socket, &service);
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
    relay.shutdown_and_join()?;
    result
}
fn send(
    stream: &mut AcceptedConnection,
    binding: [u8; 32],
    tag: u8,
    bytes: &[u8],
) -> io::Result<()> {
    write_frame(stream, &joint::encode(binding, tag, bytes)?, MAX_CONTROL)
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
fn result_tag(e: &io::Error) -> u8 {
    if e.kind() == io::ErrorKind::WouldBlock {
        BUSY
    } else {
        REJECT
    }
}
fn serve(socket: TcpStream, service: &Service) -> io::Result<()> {
    let Service {
        acceptor,
        owner,
        binding,
        ingress,
        handle,
        bodies,
        blobs,
        cancellation,
        ..
    } = service;
    let (identity, mut stream) = acceptor.accept(socket)?;
    let id = binding.id();
    let expires = super::JointFinalityClient::expires()?;
    let _deadline = peer_transport::ConnectionDeadline::new(&stream.sock, joint::OPERATION_BUDGET)?;
    stream.sock.set_read_timeout(Some(joint::IO_BUDGET))?;
    stream.sock.set_write_timeout(Some(joint::IO_BUDGET))?;
    let lease = match handle.reserve_control() {
        Ok(l) => l,
        Err(_) => return terminal(&mut stream, id, BUSY, &[]),
    };
    let mut packet = read_frame(&mut stream, MAX_CONTROL)?;
    let (tag, data) = joint::decode(id, &packet)?;
    if tag == joint::GET_BLOB {
        if data.len() != 44 {
            return Err(invalid());
        }
        let blob = decode_id(&data[..40])?;
        let cap = u32::from_le_bytes(data[40..].try_into().map_err(|_| invalid())?) as usize;
        if cap == 0 || cap > protocol_storage::MAX_BLOB_BYTES as usize || blob.bytes() > cap as u64
        {
            return Err(invalid());
        }
        let _export = match blobs.export() {
            Ok(l) => l,
            Err(_) => return terminal(&mut stream, id, BUSY, &[]),
        };
        let bytes = match ingress.read_public_blob(blob, cap) {
            Ok(b) => b,
            Err(_) => return terminal(&mut stream, id, REJECT, &[]),
        };
        let mut head = Vec::with_capacity(40);
        encode_id(blob, &mut head);
        send(&mut stream, id, joint::BLOB, &head)?;
        write_frame(&mut stream, &bytes, cap)?;
        return finish(&mut stream);
    }
    if tag == joint::PUT_BLOB {
        // Both owner TLS and ACTUAL canonical owner signature/membership are
        // checked before acquiring/allocating any announced blob payload.
        if identity != *owner {
            return terminal(&mut stream, id, REJECT, &[]);
        }
        let fixed = 8 + 40 + HEADER_BYTES + 4;
        if data.len() < fixed {
            return Err(invalid());
        }
        let selector = ProofBlobSelector::decode(&data[..8])?;
        let claimed = decode_id(&data[8..48])?;
        let header = BlockHeader::decode(&data[48..48 + HEADER_BYTES]).map_err(error)?;
        let n = u32::from_le_bytes(
            data[48 + HEADER_BYTES..fixed]
                .try_into()
                .map_err(|_| invalid())?,
        ) as usize;
        if n == 0 || data.len() != fixed + n {
            return Err(invalid());
        }
        packet.drain(..HEADER + fixed);
        let block = CandidateBlock::new(header, packet).map_err(error)?;
        let current = snapshot(handle, expires)?;
        let parent = if block.header().id() == current.parent {
            None
        } else {
            Some(current.parent)
        };
        let (blob, cap) = match joint_prefetch::authorized_reference(
            binding, ingress, &block, parent, selector,
        ) {
            Ok(x) => x,
            Err(_) => return terminal(&mut stream, id, REJECT, &[]),
        };
        if blob != claimed {
            return terminal(&mut stream, id, REJECT, &[]);
        }
        let _download = match blobs.download() {
            Ok(l) => l,
            Err(_) => return terminal(&mut stream, id, BUSY, &[]),
        };
        send(&mut stream, id, OK, &[])?;
        let bytes = read_frame(&mut stream, blob.bytes() as usize)?;
        joint_prefetch::require_blob(blob, cap, &bytes)?;
        cancellation.check()?;
        if Instant::now() >= expires {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Joint upload expired",
            ));
        }
        if ingress.retain_public_blob(&bytes).map_err(error)? != blob {
            return Err(invalid());
        }
        return terminal(&mut stream, id, OK, &[]);
    }
    let command = match tag {
        STATUS if data.is_empty() => Command::Status,
        joint::SNAPSHOT if data.is_empty() => Command::JointSnapshot,
        INPUT => {
            let current = snapshot(handle, expires)?;
            packet.drain(..HEADER);
            Command::JointInput(packet, current)
        }
        GET_BLOCK => {
            let hash = hash(data)?;
            let body = match bodies.acquire() {
                Ok(l) => l,
                Err(_) => return terminal(&mut stream, id, BUSY, &[]),
            };
            Command::GetBlock(hash, body)
        }
        GET_CHECKPOINT => Command::GetJointCheckpoint(word(data)?),
        CHECKPOINT => Command::JointCheckpoint(
            JointCheckpoint::decode(data).map_err(error)?,
            snapshot(handle, expires)?,
        ),
        PUT_BLOCK | SUBMIT => {
            if tag == SUBMIT && identity != *owner {
                return terminal(&mut stream, id, REJECT, &[]);
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
                Ok(l) => l,
                Err(_) => return terminal(&mut stream, id, BUSY, &[]),
            };
            send(&mut stream, id, OK, &[])?;
            let bytes = read_frame(&mut stream, n)?;
            if bytes.len() != n {
                return Err(invalid());
            }
            let block = CandidateBlock::new(header, bytes).map_err(error)?;
            let current = match service.prepare(&block, expires) {
                Ok(s) => s,
                Err(e) => return terminal(&mut stream, id, result_tag(&e), &[]),
            };
            Command::JointBlock(
                OwnedBlock {
                    block,
                    _lease: body,
                },
                tag == SUBMIT,
                current,
            )
        }
        _ => return Err(invalid()),
    };
    let result = match handle.call_reserved_joint(command, lease, expires) {
        Ok((reply, _lease)) => match reply {
            Reply::Ok => send(&mut stream, id, OK, &[]),
            Reply::Status { slot, context } => {
                let mut b = slot.to_le_bytes().to_vec();
                b.extend_from_slice(&context);
                send(&mut stream, id, OK, &b)
            }
            Reply::JointSnapshot(s) => {
                let mut b = s.slot.to_le_bytes().to_vec();
                b.extend_from_slice(&s.context);
                b.extend_from_slice(&s.parent);
                send(&mut stream, id, OK, &b)
            }
            Reply::NeedBlock(hash) => send(&mut stream, id, NEED_BLOCK, &hash),
            Reply::JointCheckpoint(Some(c)) => send(&mut stream, id, RECORD, &c.encode()),
            Reply::JointCheckpoint(None) => send(&mut stream, id, NONE, &[]),
            Reply::Block(block) => {
                let mut b = block.block.header().encode().to_vec();
                b.extend_from_slice(&(block.block.body().len() as u32).to_le_bytes());
                send(&mut stream, id, BLOCK, &b)?;
                write_frame(&mut stream, block.block.body(), MAX_BODY_BYTES)
            }
            _ => Err(invalid()),
        },
        Err(e) => send(&mut stream, id, result_tag(&e), &[]),
    };
    result?;
    finish(&mut stream)
}
fn synchronize(
    client: &super::JointFinalityClient,
    binding: &JointBinding,
    ingress: &JointEvidenceIngress,
    handle: &Handle,
    bodies: &BodyGate,
    blobs: &BlobGate,
) -> io::Result<()> {
    let _control = handle.reserve_control()?;
    let expires = super::JointFinalityClient::expires()?;
    let local = snapshot(handle, expires)?;
    let remote = client.observed_slot_until(expires)?;
    if remote == 0 {
        return Err(invalid());
    }
    if remote > local.slot {
        let checkpoint = client
            .checkpoint_until(local.slot - 1, expires)?
            .ok_or_else(invalid)?;
        if checkpoint.candidate().slot() != local.slot {
            return Err(invalid());
        }
        let block = client.block(
            checkpoint.candidate().header().id(),
            bodies.acquire()?,
            expires,
        )?;
        joint_prefetch::prefetch(
            client,
            binding,
            ingress,
            blobs,
            &block.block,
            local,
            expires,
        )?;
        handle.call_joint(Command::JointBlock(block, false, local), expires)?;
        let current = snapshot(handle, expires)?;
        match handle.call_joint(Command::JointCheckpoint(checkpoint, current), expires)? {
            Reply::Ok => (),
            _ => return Err(invalid()),
        }
        return Ok(());
    }
    if remote < local.slot {
        return Ok(());
    }
    for index in 0..MAX_COMMANDS {
        let bytes = match handle.call_joint(Command::Outbound(index), expires)? {
            Reply::Outbound(Some(b)) => b,
            Reply::Outbound(None) => break,
            _ => return Err(invalid()),
        };
        let missing = match client.send(INPUT, &bytes, expires) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::InvalidData => continue,
            Err(e) => return Err(e),
        };
        if let Some(id) = missing {
            let block =
                match handle.call_joint(Command::GetBlock(id, bodies.acquire()?), expires)? {
                    Reply::Block(b) => b,
                    _ => return Err(invalid()),
                };
            client.upload(&block.block, PUT_BLOCK, expires)?;
            client.send(INPUT, &bytes, expires)?;
        }
    }
    Ok(())
}
