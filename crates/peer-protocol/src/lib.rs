//! Transport-independent message state machine for honest, local protocol experiments.
//!
//! IDs are transport-assigned identities, not authenticated identities. This crate
//! provides neither Byzantine agreement nor encryption, authorization, or query proofs.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

pub type NodeId = u64;
pub type RequestId = u64;
pub const MAX_NEIGHBORS: usize = 32;
pub const MAX_PAYLOAD_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeRole {
    Client,
    Peer,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Ping { nonce: u64 },
    Pong { nonce: u64 },
    Ack { nonce: u64 },
    Request { id: RequestId, payload: Vec<u8> },
    Response { id: RequestId },
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
        payload: Vec<u8>,
    },
    Response {
        from: NodeId,
        id: RequestId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    UnknownNeighbor,
    NotConnected,
    InvalidEnvelope,
    ResourceLimit,
}

/// Owns bounded connection state. The transport owns discovery hints, clock,
/// retries, removal, identity authentication, and message delivery.
pub struct ProtocolNode {
    id: NodeId,
    role: NodeRole,
    next_nonce: u64,
    pending: BTreeMap<NodeId, u64>,
    offered: BTreeMap<NodeId, u64>,
    connected: BTreeSet<NodeId>,
}

impl ProtocolNode {
    pub fn new(id: NodeId, role: NodeRole) -> Self {
        Self {
            id,
            role,
            next_nonce: 1,
            pending: BTreeMap::new(),
            offered: BTreeMap::new(),
            connected: BTreeSet::new(),
        }
    }
    pub fn id(&self) -> NodeId {
        self.id
    }
    pub fn role(&self) -> NodeRole {
        self.role
    }
    pub fn connected(&self, id: NodeId) -> bool {
        self.connected.contains(&id)
    }
    pub fn forget(&mut self, id: NodeId) {
        self.pending.remove(&id);
        self.offered.remove(&id);
        self.connected.remove(&id);
    }
    fn known(&self, id: NodeId) -> bool {
        self.connected.contains(&id)
            || self.pending.contains_key(&id)
            || self.offered.contains_key(&id)
    }
    fn check_neighbor(&self, id: NodeId) -> Result<(), ProtocolError> {
        if id == self.id {
            return Err(ProtocolError::InvalidEnvelope);
        }
        let all: BTreeSet<_> = self
            .pending
            .keys()
            .chain(self.offered.keys())
            .chain(self.connected.iter())
            .copied()
            .collect();
        if !self.known(id) && all.len() >= MAX_NEIGHBORS {
            return Err(ProtocolError::ResourceLimit);
        }
        Ok(())
    }
    fn send(&self, to: NodeId, message: Message) -> ProtocolEvent {
        ProtocolEvent::Send(Envelope {
            from: self.id,
            to,
            message,
        })
    }
    /// Starts discovery from a transport-provided address. No link exists until
    /// both endpoints have consumed their handshake messages.
    pub fn discover(&mut self, id: NodeId) -> Result<Vec<ProtocolEvent>, ProtocolError> {
        self.check_neighbor(id)?;
        if self.connected(id) || self.pending.contains_key(&id) {
            return Ok(Vec::new());
        }
        let nonce = self.next_nonce;
        self.next_nonce = self
            .next_nonce
            .checked_add(1)
            .ok_or(ProtocolError::ResourceLimit)?;
        self.pending.insert(id, nonce);
        Ok(vec![self.send(id, Message::Ping { nonce })])
    }
    pub fn request(
        &self,
        to: NodeId,
        id: RequestId,
        payload: Vec<u8>,
    ) -> Result<ProtocolEvent, ProtocolError> {
        if !self.connected(to) {
            return Err(ProtocolError::NotConnected);
        }
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(ProtocolError::ResourceLimit);
        }
        Ok(self.send(to, Message::Request { id, payload }))
    }
    pub fn respond(&self, to: NodeId, id: RequestId) -> Result<ProtocolEvent, ProtocolError> {
        if !self.connected(to) {
            return Err(ProtocolError::NotConnected);
        }
        Ok(self.send(to, Message::Response { id }))
    }
    pub fn receive(&mut self, envelope: Envelope) -> Result<Vec<ProtocolEvent>, ProtocolError> {
        if envelope.to != self.id {
            return Err(ProtocolError::InvalidEnvelope);
        }
        self.check_neighbor(envelope.from)?;
        let from = envelope.from;
        match envelope.message {
            Message::Ping { nonce } => {
                self.offered.insert(from, nonce);
                Ok(vec![self.send(from, Message::Pong { nonce })])
            }
            Message::Pong { nonce } => {
                if self.pending.get(&from) != Some(&nonce) {
                    return Err(ProtocolError::InvalidEnvelope);
                }
                self.pending.remove(&from);
                self.connected.insert(from);
                Ok(vec![
                    ProtocolEvent::Connected(from),
                    self.send(from, Message::Ack { nonce }),
                ])
            }
            Message::Ack { nonce } => {
                if self.offered.get(&from) != Some(&nonce) {
                    return Err(ProtocolError::InvalidEnvelope);
                }
                self.offered.remove(&from);
                self.connected.insert(from);
                Ok(vec![ProtocolEvent::Connected(from)])
            }
            Message::Request { id, payload } => {
                if !self.connected(from) || self.role != NodeRole::Peer {
                    return Err(ProtocolError::NotConnected);
                }
                if payload.len() > MAX_PAYLOAD_BYTES {
                    return Err(ProtocolError::ResourceLimit);
                }
                Ok(vec![ProtocolEvent::Request { from, id, payload }])
            }
            Message::Response { id } => {
                if !self.connected(from) {
                    return Err(ProtocolError::NotConnected);
                }
                Ok(vec![ProtocolEvent::Response { from, id }])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sent(event: ProtocolEvent) -> Envelope {
        match event {
            ProtocolEvent::Send(value) => value,
            _ => panic!("expected message"),
        }
    }
    fn connected_pair() -> (ProtocolNode, ProtocolNode) {
        let mut client = ProtocolNode::new(1, NodeRole::Client);
        let mut peer = ProtocolNode::new(2, NodeRole::Peer);
        let ping = sent(client.discover(2).unwrap().remove(0));
        let pong = sent(peer.receive(ping).unwrap().remove(0));
        let mut events = client.receive(pong).unwrap();
        let ack = sent(events.remove(1));
        peer.receive(ack).unwrap();
        (client, peer)
    }
    #[test]
    fn address_hint_does_not_establish_link_without_handshake() {
        let mut client = ProtocolNode::new(1, NodeRole::Client);
        client.discover(2).unwrap();
        assert!(!client.connected(2));
        assert_eq!(
            client.request(2, 1, vec![]),
            Err(ProtocolError::NotConnected)
        );
    }
    #[test]
    fn matching_handshake_enables_request_response_delivery() {
        let (mut client, mut peer) = connected_pair();
        let request = sent(
            client
                .request(2, 7, b"encrypted-plan-reference".to_vec())
                .unwrap(),
        );
        assert_eq!(
            peer.receive(request).unwrap(),
            vec![ProtocolEvent::Request {
                from: 1,
                id: 7,
                payload: b"encrypted-plan-reference".to_vec()
            }]
        );
        let response = sent(peer.respond(1, 7).unwrap());
        assert_eq!(
            client.receive(response).unwrap(),
            vec![ProtocolEvent::Response { from: 2, id: 7 }]
        );
    }
    #[test]
    fn forged_pong_cannot_complete_discovery() {
        let mut node = ProtocolNode::new(1, NodeRole::Client);
        node.discover(2).unwrap();
        let forged = Envelope {
            from: 2,
            to: 1,
            message: Message::Pong { nonce: 999 },
        };
        assert_eq!(node.receive(forged), Err(ProtocolError::InvalidEnvelope));
        assert!(!node.connected(2));
    }
    #[test]
    fn forgetting_peer_revokes_route() {
        let (mut client, _) = connected_pair();
        client.forget(2);
        assert_eq!(
            client.request(2, 7, vec![]),
            Err(ProtocolError::NotConnected)
        );
    }
    #[test]
    fn request_payload_has_bounded_size() {
        let (client, _) = connected_pair();
        assert_eq!(
            client.request(2, 7, vec![0; MAX_PAYLOAD_BYTES + 1]),
            Err(ProtocolError::ResourceLimit)
        );
    }

    #[test]
    fn connected_peers_can_request_and_receive_responses_from_each_other() {
        let mut a = ProtocolNode::new(11, NodeRole::Peer);
        let mut b = ProtocolNode::new(12, NodeRole::Peer);
        let ping = sent(a.discover(12).unwrap().remove(0));
        let pong = sent(b.receive(ping).unwrap().remove(0));
        let ack = sent(a.receive(pong).unwrap().remove(1));
        b.receive(ack).unwrap();
        let request = sent(a.request(12, 9, vec![1, 2]).unwrap());
        assert!(matches!(
            b.receive(request).unwrap().as_slice(),
            [ProtocolEvent::Request {
                from: 11,
                id: 9,
                ..
            }]
        ));
        let response = sent(b.respond(11, 9).unwrap());
        assert_eq!(
            a.receive(response).unwrap(),
            vec![ProtocolEvent::Response { from: 12, id: 9 }]
        );
    }
}
