//! Transport-independent, bounded request lifecycle for local protocol experiments.
//!
//! Transport-assigned IDs, session challenges and attempt tokens provide lifecycle
//! correlation, not identity authentication, authorization or computation proofs.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

pub type NodeId = u64;
pub type RequestId = u64;
pub const MAX_NEIGHBORS: usize = 32;
pub const MAX_PAYLOAD_BYTES: usize = 4096;
pub const MAX_OUTSTANDING_REQUESTS: usize = 64;
pub const MAX_PENDING_JOBS: usize = 64;
pub const REPLAY_WINDOW: u64 = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeRole {
    Client,
    Peer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Session {
    initiator: NodeId,
    nonce: u64,
    challenge: u64,
}

/// Public correlation token. Pass the accepted token back to `respond`; an old
/// worker completion must never answer a newer request with the same logical ID.
/// The token is deliberately not an authorization credential or secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestToken {
    session: Session,
    requester: NodeId,
    sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
        challenge: u64,
    },
    Ack {
        nonce: u64,
        challenge: u64,
    },
    Request {
        id: RequestId,
        token: RequestToken,
        payload: Vec<u8>,
    },
    Response {
        id: RequestId,
        token: RequestToken,
    },
    Cancel {
        id: RequestId,
        token: RequestToken,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub from: NodeId,
    pub to: NodeId,
    pub message: Message,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtocolEvent {
    Send(Envelope),
    Connected(NodeId),
    Request {
        from: NodeId,
        id: RequestId,
        token: RequestToken,
        payload: Vec<u8>,
    },
    Response {
        from: NodeId,
        id: RequestId,
    },
    /// The work owner should stop the matching accepted attempt if still running.
    Cancelled {
        from: NodeId,
        id: RequestId,
        token: RequestToken,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    NotConnected,
    InvalidEnvelope,
    ResourceLimit,
    DuplicateRequest,
    Replay,
    UnexpectedResponse,
    UnknownRequest,
}

#[derive(Default)]
struct ReplayWindow {
    highest: u64,
    bits: u128,
}
impl ReplayWindow {
    fn fresh(&self, sequence: u64) -> bool {
        sequence != 0
            && (sequence > self.highest || {
                let distance = self.highest - sequence;
                distance < REPLAY_WINDOW && self.bits & (1u128 << distance) == 0
            })
    }
    fn record(&mut self, sequence: u64) {
        if sequence > self.highest {
            let distance = sequence - self.highest;
            self.bits = if distance >= REPLAY_WINDOW {
                0
            } else {
                self.bits << distance
            };
            self.highest = sequence;
        }
        self.bits |= 1u128 << (self.highest - sequence);
    }
}

struct Connection {
    session: Session,
    next_sequence: u64,
    received: ReplayWindow,
}

/// Owns neighbor/session state, at most 64 outbound requests and 64 inbound jobs.
/// The transport owns identity assignment, delivery, timeouts and disconnects.
/// Reordering is bounded to the last 128 attempts per direction/session.
/// Recreating a node requires a fresh transport incarnation or flushing old frames.
pub struct ProtocolNode {
    id: NodeId,
    role: NodeRole,
    next_nonce: u64,
    pending: BTreeMap<NodeId, u64>,
    offered: BTreeMap<NodeId, Session>,
    connected: BTreeMap<NodeId, Connection>,
    outbound: BTreeMap<(NodeId, RequestId), RequestToken>,
    inbound: BTreeMap<(NodeId, RequestId), RequestToken>,
}

impl ProtocolNode {
    pub fn new(id: NodeId, role: NodeRole) -> Self {
        Self {
            id,
            role,
            next_nonce: 1,
            pending: BTreeMap::new(),
            offered: BTreeMap::new(),
            connected: BTreeMap::new(),
            outbound: BTreeMap::new(),
            inbound: BTreeMap::new(),
        }
    }
    pub fn id(&self) -> NodeId {
        self.id
    }
    pub fn role(&self) -> NodeRole {
        self.role
    }
    pub fn connected(&self, id: NodeId) -> bool {
        self.connected.contains_key(&id)
    }
    pub fn outstanding_requests(&self) -> usize {
        self.outbound.len()
    }
    pub fn pending_jobs(&self) -> usize {
        self.inbound.len()
    }
    /// Revokes the route and all its work. Live-node challenge counters never reset.
    pub fn forget(&mut self, id: NodeId) {
        self.pending.remove(&id);
        self.offered.remove(&id);
        self.connected.remove(&id);
        self.clear_work(id);
    }
    fn clear_work(&mut self, id: NodeId) {
        self.outbound.retain(|(peer, _), _| *peer != id);
        self.inbound.retain(|(peer, _), _| *peer != id);
    }
    fn check_neighbor(&self, id: NodeId) -> Result<(), ProtocolError> {
        if id == self.id {
            return Err(ProtocolError::InvalidEnvelope);
        }
        let all: BTreeSet<_> = self
            .pending
            .keys()
            .chain(self.offered.keys())
            .chain(self.connected.keys())
            .copied()
            .collect();
        if !all.contains(&id) && all.len() >= MAX_NEIGHBORS {
            return Err(ProtocolError::ResourceLimit);
        }
        Ok(())
    }
    fn nonce(&mut self) -> Result<u64, ProtocolError> {
        let value = self.next_nonce;
        self.next_nonce = value.checked_add(1).ok_or(ProtocolError::ResourceLimit)?;
        Ok(value)
    }
    fn send(&self, to: NodeId, message: Message) -> ProtocolEvent {
        ProtocolEvent::Send(Envelope {
            from: self.id,
            to,
            message,
        })
    }
    fn establish(&mut self, peer: NodeId, session: Session) {
        if self
            .connected
            .get(&peer)
            .is_some_and(|c| c.session == session)
        {
            return;
        }
        self.clear_work(peer);
        self.connected.insert(
            peer,
            Connection {
                session,
                next_sequence: 1,
                received: ReplayWindow::default(),
            },
        );
    }
    fn check_token(
        &self,
        from: NodeId,
        token: RequestToken,
        requester: NodeId,
    ) -> Result<(), ProtocolError> {
        let connection = self
            .connected
            .get(&from)
            .ok_or(ProtocolError::NotConnected)?;
        if token.session != connection.session
            || token.requester != requester
            || token.sequence == 0
        {
            return Err(ProtocolError::InvalidEnvelope);
        }
        Ok(())
    }
    /// Concurrent discovery converges on the lower node ID as initiator. Both
    /// endpoints contribute a live-node monotonic challenge to the session.
    pub fn discover(&mut self, id: NodeId) -> Result<Vec<ProtocolEvent>, ProtocolError> {
        self.check_neighbor(id)?;
        if self.connected(id) || self.pending.contains_key(&id) {
            return Ok(Vec::new());
        }
        let nonce = self.nonce()?;
        self.pending.insert(id, nonce);
        Ok(vec![self.send(id, Message::Ping { nonce })])
    }
    /// Reserves a slot until a matching response, cancellation or `forget`.
    /// The same logical ID may be outstanding to different peers.
    pub fn request(
        &mut self,
        to: NodeId,
        id: RequestId,
        payload: Vec<u8>,
    ) -> Result<ProtocolEvent, ProtocolError> {
        if !self.connected(to) {
            return Err(ProtocolError::NotConnected);
        }
        if payload.len() > MAX_PAYLOAD_BYTES || self.outbound.len() >= MAX_OUTSTANDING_REQUESTS {
            return Err(ProtocolError::ResourceLimit);
        }
        if self.outbound.contains_key(&(to, id)) {
            return Err(ProtocolError::DuplicateRequest);
        }
        let connection = self.connected.get_mut(&to).expect("checked connection");
        let sequence = connection.next_sequence;
        connection.next_sequence = sequence
            .checked_add(1)
            .ok_or(ProtocolError::ResourceLimit)?;
        let token = RequestToken {
            session: connection.session,
            requester: self.id,
            sequence,
        };
        self.outbound.insert((to, id), token);
        Ok(self.send(to, Message::Request { id, token, payload }))
    }
    /// Consumes exactly the accepted work token, once. Stale completions cannot
    /// consume a new same-ID job. No payload is treated as a computation proof.
    pub fn respond(
        &mut self,
        to: NodeId,
        id: RequestId,
        token: RequestToken,
    ) -> Result<ProtocolEvent, ProtocolError> {
        self.check_token(to, token, to)?;
        let accepted = self
            .inbound
            .get(&(to, id))
            .ok_or(ProtocolError::UnknownRequest)?;
        if *accepted != token {
            return Err(ProtocolError::InvalidEnvelope);
        }
        self.inbound.remove(&(to, id));
        Ok(self.send(to, Message::Response { id, token }))
    }
    /// Releases the local outbound slot immediately. The transport must deliver
    /// the returned Cancel or disconnect: remote slots release only on delivery.
    /// A Cancel delivered before its Request also prevents that Request executing.
    pub fn cancel_request(&mut self, to: NodeId, id: RequestId) -> Option<ProtocolEvent> {
        self.outbound
            .remove(&(to, id))
            .map(|token| self.send(to, Message::Cancel { id, token }))
    }
    /// Cancels every outbound attempt with this logical ID (possibly many peers).
    pub fn cancel_requests(&mut self, id: RequestId) -> Vec<ProtocolEvent> {
        let peers: Vec<_> = self
            .outbound
            .keys()
            .filter(|(_, request)| *request == id)
            .map(|(peer, _)| *peer)
            .collect();
        peers
            .into_iter()
            .filter_map(|peer| self.cancel_request(peer, id))
            .collect()
    }
    /// Local work failure/cancellation releases its slot while keeping the token
    /// terminal in the replay window. The caller owns informing the requester.
    pub fn discard_request(
        &mut self,
        from: NodeId,
        id: RequestId,
        token: RequestToken,
    ) -> Result<(), ProtocolError> {
        self.check_token(from, token, from)?;
        if self.inbound.get(&(from, id)) != Some(&token) {
            return Err(ProtocolError::UnknownRequest);
        }
        self.inbound.remove(&(from, id));
        Ok(())
    }
    pub fn receive(&mut self, envelope: Envelope) -> Result<Vec<ProtocolEvent>, ProtocolError> {
        if envelope.to != self.id {
            return Err(ProtocolError::InvalidEnvelope);
        }
        self.check_neighbor(envelope.from)?;
        let from = envelope.from;
        match envelope.message {
            Message::Ping { nonce } => {
                if nonce == 0 {
                    return Err(ProtocolError::InvalidEnvelope);
                }
                if self.pending.contains_key(&from) {
                    if self.id < from {
                        return Ok(Vec::new());
                    }
                    self.pending.remove(&from);
                }
                let matching = self
                    .offered
                    .get(&from)
                    .copied()
                    .or_else(|| self.connected.get(&from).map(|c| c.session))
                    .filter(|s| s.initiator == from && s.nonce == nonce);
                let session = match matching {
                    Some(session) => session,
                    None => Session {
                        initiator: from,
                        nonce,
                        challenge: self.nonce()?,
                    },
                };
                if self
                    .connected
                    .get(&from)
                    .is_none_or(|c| c.session != session)
                {
                    self.offered.insert(from, session);
                }
                Ok(vec![self.send(
                    from,
                    Message::Pong {
                        nonce,
                        challenge: session.challenge,
                    },
                )])
            }
            Message::Pong { nonce, challenge } => {
                if challenge == 0 {
                    return Err(ProtocolError::InvalidEnvelope);
                }
                let session = Session {
                    initiator: self.id,
                    nonce,
                    challenge,
                };
                if self.pending.get(&from) != Some(&nonce) {
                    if self
                        .connected
                        .get(&from)
                        .is_some_and(|c| c.session == session)
                    {
                        return Ok(vec![self.send(from, Message::Ack { nonce, challenge })]);
                    }
                    return Err(ProtocolError::InvalidEnvelope);
                }
                self.pending.remove(&from);
                self.offered.remove(&from);
                self.establish(from, session);
                Ok(vec![
                    ProtocolEvent::Connected(from),
                    self.send(from, Message::Ack { nonce, challenge }),
                ])
            }
            Message::Ack { nonce, challenge } => {
                let session = Session {
                    initiator: from,
                    nonce,
                    challenge,
                };
                if self.offered.get(&from) != Some(&session) {
                    if self
                        .connected
                        .get(&from)
                        .is_some_and(|c| c.session == session)
                    {
                        return Ok(Vec::new());
                    }
                    return Err(ProtocolError::InvalidEnvelope);
                }
                self.offered.remove(&from);
                self.pending.remove(&from);
                self.establish(from, session);
                Ok(vec![ProtocolEvent::Connected(from)])
            }
            Message::Request { id, token, payload } => {
                self.check_token(from, token, from)?;
                if self.role != NodeRole::Peer {
                    return Err(ProtocolError::NotConnected);
                }
                if payload.len() > MAX_PAYLOAD_BYTES {
                    return Err(ProtocolError::ResourceLimit);
                }
                let connection = self.connected.get(&from).expect("checked token");
                if !connection.received.fresh(token.sequence) {
                    return Err(ProtocolError::Replay);
                }
                if self.inbound.contains_key(&(from, id)) {
                    return Err(ProtocolError::DuplicateRequest);
                }
                if self.inbound.len() >= MAX_PENDING_JOBS {
                    return Err(ProtocolError::ResourceLimit);
                }
                self.connected
                    .get_mut(&from)
                    .expect("checked token")
                    .received
                    .record(token.sequence);
                self.inbound.insert((from, id), token);
                Ok(vec![ProtocolEvent::Request {
                    from,
                    id,
                    token,
                    payload,
                }])
            }
            Message::Response { id, token } => {
                self.check_token(from, token, self.id)?;
                if self.outbound.get(&(from, id)) != Some(&token) {
                    return Err(ProtocolError::UnexpectedResponse);
                }
                self.outbound.remove(&(from, id));
                Ok(vec![ProtocolEvent::Response { from, id }])
            }
            Message::Cancel { id, token } => {
                self.check_token(from, token, from)?;
                let accepted = self.inbound.get(&(from, id)) == Some(&token);
                let fresh = self
                    .connected
                    .get(&from)
                    .expect("checked token")
                    .received
                    .fresh(token.sequence);
                if !accepted && !fresh {
                    return Err(ProtocolError::Replay);
                }
                if fresh {
                    self.connected
                        .get_mut(&from)
                        .expect("checked token")
                        .received
                        .record(token.sequence);
                }
                if accepted {
                    self.inbound.remove(&(from, id));
                }
                Ok(vec![ProtocolEvent::Cancelled { from, id, token }])
            }
        }
    }
}
