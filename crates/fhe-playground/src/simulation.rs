//! Local transport adapter. Virtual time and visualization live here, outside the
//! transport-independent protocol and encrypted-storage library.
use std::collections::{BTreeMap, VecDeque};

use peer_protocol::{Envelope, Message, NodeRole, ProtocolEvent, ProtocolNode};

use crate::{LabError, PeerConfig};
pub use peer_protocol::{NodeId, RequestId};
pub const MAX_CLIENTS: usize = 8;
const MAX_PACKETS: usize = 1024;
const MAX_LOG: usize = 40;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketKind {
    Ping,
    Pong,
    Ack,
    Request,
    Response,
}

#[derive(Clone, Debug)]
pub struct NetworkNode {
    pub id: NodeId,
    pub name: String,
    pub role: NodeRole,
    pub peer_id: Option<usize>,
    pub online: bool,
}

#[derive(Clone, Debug)]
pub struct NetworkLink {
    pub from: NodeId,
    pub to: NodeId,
}

#[derive(Clone, Debug)]
pub struct NetworkPacket {
    pub id: u64,
    pub from: NodeId,
    pub to: NodeId,
    pub kind: PacketKind,
    pub progress: f32,
    pub request_id: Option<RequestId>,
}

#[derive(Clone, Debug)]
pub struct NetworkLog {
    pub time_ms: f64,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct NetworkSnapshot {
    pub time_ms: f64,
    pub speed: f64,
    pub paused: bool,
    pub nodes: Vec<NetworkNode>,
    pub links: Vec<NetworkLink>,
    pub packets: Vec<NetworkPacket>,
    pub recent: Vec<NetworkLog>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    Request {
        client_id: NodeId,
        peer_id: usize,
        request_id: RequestId,
    },
    Response {
        client_id: NodeId,
        peer_id: usize,
        request_id: RequestId,
    },
}

struct Node {
    info: NetworkNode,
    protocol: ProtocolNode,
    delay_ms: u64,
}
struct Packet {
    id: u64,
    envelope: Envelope,
    start_ms: f64,
    end_ms: f64,
}

/// Owns virtual time and bounded in-process message delivery, not FHE keys/data.
/// Packets carry an operation reference into the shared local FHE worker, not a
/// production wire encoding of ciphertexts. Only actual deliveries are reported.
pub struct DemoNetwork {
    nodes: BTreeMap<NodeId, Node>,
    packets: Vec<Packet>,
    recent: VecDeque<NetworkLog>,
    next_id: NodeId,
    next_packet: u64,
    time_ms: f64,
    speed: f64,
    paused: bool,
    discover: bool,
}

impl Default for DemoNetwork {
    fn default() -> Self {
        Self {
            nodes: BTreeMap::new(),
            packets: Vec::new(),
            recent: VecDeque::new(),
            next_id: 1,
            next_packet: 1,
            time_ms: 0.0,
            speed: 1.0,
            paused: false,
            discover: false,
        }
    }
}

impl DemoNetwork {
    pub fn add_client(&mut self, name: String) -> Result<NodeId, LabError> {
        if self
            .nodes
            .values()
            .filter(|node| node.info.role == NodeRole::Client)
            .count()
            >= MAX_CLIENTS
        {
            return Err(LabError::InvalidInput(
                "Use at most 8 local clients.".into(),
            ));
        }
        validate_name(&name)?;
        Ok(self.add(name.trim().into(), NodeRole::Client, None, 0, true))
    }
    pub fn add_peer(
        &mut self,
        id: usize,
        config: &PeerConfig,
        online: bool,
    ) -> Result<NodeId, LabError> {
        config.validate()?;
        if self
            .nodes
            .values()
            .filter(|node| node.info.role == NodeRole::Peer)
            .count()
            >= crate::MAX_PEERS
        {
            return Err(LabError::InvalidInput("Use at most 16 local peers.".into()));
        }
        if self.peer_node(id).is_some() {
            return Err(LabError::InvalidInput("Duplicate storage peer ID.".into()));
        }
        Ok(self.add(
            config.name.trim().into(),
            NodeRole::Peer,
            Some(id),
            config.delay_ms,
            online,
        ))
    }
    fn add(
        &mut self,
        name: String,
        role: NodeRole,
        peer_id: Option<usize>,
        delay_ms: u64,
        online: bool,
    ) -> NodeId {
        let id = self.next_id;
        self.next_id += 1;
        self.nodes.insert(
            id,
            Node {
                info: NetworkNode {
                    id,
                    name,
                    role,
                    peer_id,
                    online,
                },
                protocol: ProtocolNode::new(id, role),
                delay_ms,
            },
        );
        self.log(format!("Node {id} added; discovery pending"));
        self.discover = true;
        id
    }
    pub fn node(&self, id: NodeId) -> Option<NetworkNode> {
        self.nodes.get(&id).map(|node| node.info.clone())
    }
    pub fn peer_node(&self, id: usize) -> Option<NodeId> {
        self.nodes
            .values()
            .find(|node| node.info.peer_id == Some(id))
            .map(|node| node.info.id)
    }
    pub fn connected(&self, from: NodeId, to: NodeId) -> bool {
        self.nodes
            .get(&from)
            .zip(self.nodes.get(&to))
            .is_some_and(|(a, b)| {
                a.info.online
                    && b.info.online
                    && a.protocol.connected(to)
                    && b.protocol.connected(from)
            })
    }
    pub fn remove(&mut self, id: NodeId) -> Result<NetworkNode, LabError> {
        let removed = self
            .nodes
            .remove(&id)
            .ok_or_else(|| LabError::InvalidInput("Unknown node.".into()))?;
        for node in self.nodes.values_mut() {
            node.protocol.forget(id);
        }
        self.packets
            .retain(|packet| packet.envelope.from != id && packet.envelope.to != id);
        self.log(format!("Node {id} removed; routes revoked"));
        Ok(removed.info)
    }
    pub fn configure_peer(
        &mut self,
        id: usize,
        config: &PeerConfig,
        online: bool,
    ) -> Result<(), LabError> {
        config.validate()?;
        let node_id = self
            .peer_node(id)
            .ok_or_else(|| LabError::InvalidInput("Unknown peer.".into()))?;
        let node = self.nodes.get_mut(&node_id).expect("known peer");
        let changed = node.info.online != online;
        node.info.name = config.name.trim().into();
        node.delay_ms = config.delay_ms;
        node.info.online = online;
        if changed {
            let ids: Vec<_> = self
                .nodes
                .keys()
                .copied()
                .filter(|other| *other != node_id)
                .collect();
            for other in ids {
                self.nodes
                    .get_mut(&node_id)
                    .expect("known peer")
                    .protocol
                    .forget(other);
                self.nodes
                    .get_mut(&other)
                    .expect("known neighbor")
                    .protocol
                    .forget(node_id);
            }
            self.packets
                .retain(|packet| packet.envelope.from != node_id && packet.envelope.to != node_id);
            self.discover = true;
            self.log(format!(
                "Node {node_id} {}",
                if online {
                    "online; discovery pending"
                } else {
                    "offline; routes revoked"
                }
            ));
        }
        Ok(())
    }
    pub fn set_simulation(&mut self, speed: f64, paused: bool) -> Result<(), LabError> {
        if !speed.is_finite() || !(0.05..=20.0).contains(&speed) {
            return Err(LabError::InvalidInput(
                "Simulation speed must be 0.05..20x.".into(),
            ));
        }
        self.speed = speed;
        self.paused = paused;
        Ok(())
    }
    pub fn cancel_request(&mut self, id: RequestId) {
        self.packets
            .retain(|packet| request_id(&packet.envelope.message) != Some(id));
        self.log(format!("Request {id} cancelled; staged changes discarded"));
    }
    pub fn request(&mut self, client: NodeId, peer: usize, id: RequestId) -> Result<(), LabError> {
        let to = self
            .peer_node(peer)
            .ok_or_else(|| LabError::InvalidInput("Required peer was removed.".into()))?;
        if !self.connected(client, to) {
            return Err(LabError::InvalidInput(
                "Client discovery has not established every required peer route yet.".into(),
            ));
        }
        // The reference addresses ciphertext work owned by the local FHE worker.
        let event = self
            .nodes
            .get(&client)
            .expect("connected client")
            .protocol
            .request(to, id, id.to_le_bytes().to_vec())
            .map_err(protocol_error)?;
        self.enqueue_event(event)?;
        Ok(())
    }
    pub fn respond(&mut self, peer: usize, client: NodeId, id: RequestId) -> Result<(), LabError> {
        let from = self
            .peer_node(peer)
            .ok_or_else(|| LabError::InvalidInput("Required peer was removed.".into()))?;
        if !self.connected(from, client) {
            return Err(LabError::InvalidInput(
                "Response route was disconnected.".into(),
            ));
        }
        let event = self
            .nodes
            .get(&from)
            .expect("known peer")
            .protocol
            .respond(client, id)
            .map_err(protocol_error)?;
        self.enqueue_event(event)?;
        Ok(())
    }
    /// Advances delivery, never compute time. Pausing/speed changes affect both
    /// discovery and query messages, independently of the measured FHE CPU work.
    pub fn advance(&mut self, wall_seconds: f64) -> Vec<Delivery> {
        if self.paused {
            return Vec::new();
        }
        let elapsed = if wall_seconds.is_finite() {
            wall_seconds.clamp(0.0, 1.0)
        } else {
            0.0
        };
        self.time_ms += elapsed * 1000.0 * self.speed;
        if self.discover {
            self.discover = false;
            let ids: Vec<_> = self.nodes.keys().copied().collect();
            for (index, from) in ids.iter().copied().enumerate() {
                for to in ids.iter().copied().skip(index + 1) {
                    let pair = self
                        .nodes
                        .get(&from)
                        .zip(self.nodes.get(&to))
                        .expect("known pair");
                    if !pair.0.info.online
                        || !pair.1.info.online
                        || (pair.0.info.role == NodeRole::Client
                            && pair.1.info.role == NodeRole::Client)
                    {
                        continue;
                    }
                    let initiator = if pair.0.info.role == NodeRole::Peer
                        && pair.1.info.role == NodeRole::Client
                    {
                        to
                    } else {
                        from
                    };
                    let target = if initiator == from { to } else { from };
                    if let Ok(events) = self
                        .nodes
                        .get_mut(&initiator)
                        .expect("known node")
                        .protocol
                        .discover(target)
                    {
                        for event in events {
                            let _ = self.enqueue_event(event);
                        }
                    }
                }
            }
        }
        let mut delivered = Vec::new();
        // Process one due batch per tick. Replies receive their own transport
        // delay; advancing one large tick cannot instantly finish a handshake.
        let mut ready = Vec::new();
        let mut in_flight = Vec::new();
        for packet in self.packets.drain(..) {
            if packet.end_ms <= self.time_ms {
                ready.push(packet);
            } else {
                in_flight.push(packet);
            }
        }
        self.packets = in_flight;
        ready.sort_by(|a, b| a.end_ms.total_cmp(&b.end_ms).then(a.id.cmp(&b.id)));
        for packet in ready {
            let from = packet.envelope.from;
            let to = packet.envelope.to;
            if self.nodes.get(&from).is_none_or(|node| !node.info.online) {
                continue;
            }
            let Some(target) = self.nodes.get_mut(&to).filter(|node| node.info.online) else {
                continue;
            };
            let role = target.info.role;
            let peer = target.info.peer_id;
            let events = match target.protocol.receive(packet.envelope) {
                Ok(events) => events,
                Err(_) => continue,
            };
            for event in events {
                match event {
                    ProtocolEvent::Send(_) => {
                        let _ = self.enqueue_event(event);
                    }
                    ProtocolEvent::Connected(other) => {
                        if self.connected(to, other) {
                            self.log(format!("Link {to} ↔ {other} established"));
                        }
                    }
                    ProtocolEvent::Request { from, id, .. } if role == NodeRole::Peer => {
                        delivered.push(Delivery::Request {
                            client_id: from,
                            peer_id: peer.expect("peer mapping"),
                            request_id: id,
                        });
                        self.log(format!("Request {id}: client {from} → peer {to}"));
                    }
                    ProtocolEvent::Response { from, id } if role == NodeRole::Client => {
                        if let Some(peer_id) =
                            self.nodes.get(&from).and_then(|node| node.info.peer_id)
                        {
                            delivered.push(Delivery::Response {
                                client_id: to,
                                peer_id,
                                request_id: id,
                            });
                            self.log(format!("Response {id}: peer {from} → client {to}"));
                        }
                    }
                    _ => {}
                }
            }
        }
        delivered
    }
    fn enqueue_event(&mut self, event: ProtocolEvent) -> Result<(), LabError> {
        let ProtocolEvent::Send(envelope) = event else {
            return Ok(());
        };
        if self.packets.len() >= MAX_PACKETS {
            return Err(LabError::InvalidInput(
                "Transport packet budget exhausted.".into(),
            ));
        }
        let delay = self
            .nodes
            .get(&envelope.from)
            .zip(self.nodes.get(&envelope.to))
            .map(|(a, b)| a.delay_ms.max(b.delay_ms))
            .unwrap_or(0);
        let end_ms = self.time_ms + 350.0 + delay as f64;
        self.packets.push(Packet {
            id: self.next_packet,
            envelope,
            start_ms: self.time_ms,
            end_ms,
        });
        self.next_packet += 1;
        Ok(())
    }
    fn log(&mut self, message: String) {
        if self.recent.len() == MAX_LOG {
            self.recent.pop_front();
        }
        self.recent.push_back(NetworkLog {
            time_ms: self.time_ms,
            message,
        });
    }
    pub fn snapshot(&self) -> NetworkSnapshot {
        let ids: Vec<_> = self.nodes.keys().copied().collect();
        let mut links = Vec::new();
        for (index, from) in ids.iter().copied().enumerate() {
            for to in ids.iter().copied().skip(index + 1) {
                if self.connected(from, to) {
                    links.push(NetworkLink { from, to });
                }
            }
        }
        NetworkSnapshot {
            time_ms: self.time_ms,
            speed: self.speed,
            paused: self.paused,
            nodes: self.nodes.values().map(|node| node.info.clone()).collect(),
            links,
            packets: self
                .packets
                .iter()
                .map(|packet| NetworkPacket {
                    id: packet.id,
                    from: packet.envelope.from,
                    to: packet.envelope.to,
                    kind: match &packet.envelope.message {
                        Message::Ping { .. } => PacketKind::Ping,
                        Message::Pong { .. } => PacketKind::Pong,
                        Message::Ack { .. } => PacketKind::Ack,
                        Message::Request { .. } => PacketKind::Request,
                        Message::Response { .. } => PacketKind::Response,
                    },
                    progress: ((self.time_ms - packet.start_ms) / (packet.end_ms - packet.start_ms))
                        .clamp(0.0, 1.0) as f32,
                    request_id: request_id(&packet.envelope.message),
                })
                .collect(),
            recent: self.recent.iter().cloned().collect(),
        }
    }
}

fn request_id(message: &Message) -> Option<RequestId> {
    match message {
        Message::Request { id, .. } | Message::Response { id } => Some(*id),
        _ => None,
    }
}
fn protocol_error(error: peer_protocol::ProtocolError) -> LabError {
    LabError::InvalidInput(format!("Protocol rejected message: {error:?}"))
}
fn validate_name(name: &str) -> Result<(), LabError> {
    if name.trim().is_empty() || name.len() > 48 || name.chars().any(char::is_control) {
        return Err(LabError::InvalidInput(
            "Client name must contain 1..48 bytes without control characters.".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn network() -> (DemoNetwork, NodeId, NodeId) {
        let mut network = DemoNetwork::default();
        let client = network.add_client("Client".into()).unwrap();
        let peer = network.add_peer(7, &PeerConfig::numbered(7), true).unwrap();
        (network, client, peer)
    }
    fn discover(network: &mut DemoNetwork) {
        for _ in 0..6 {
            network.advance(0.4);
        }
    }
    #[test]
    fn new_nodes_have_no_links_until_delivered_ping_pong_and_ack() {
        let (mut network, client, peer) = network();
        assert!(network.snapshot().links.is_empty());
        network.advance(0.01);
        assert_eq!(network.snapshot().packets[0].kind, PacketKind::Ping);
        assert!(!network.connected(client, peer));
        discover(&mut network);
        assert!(network.connected(client, peer));
    }
    #[test]
    fn speed_and_pause_govern_message_delivery_independently_of_compute() {
        let (mut network, _, _) = network();
        network.set_simulation(0.1, true).unwrap();
        network.advance(1.0);
        assert_eq!(network.snapshot().time_ms, 0.0);
        network.set_simulation(0.1, false).unwrap();
        network.advance(0.01);
        network.advance(1.0);
        assert_eq!(network.snapshot().packets[0].kind, PacketKind::Ping);
        network.set_simulation(4.0, false).unwrap();
        discover(&mut network);
        assert_eq!(network.snapshot().links.len(), 1);
    }
    #[test]
    fn request_and_response_are_deliveries_not_visual_timer_pulses() {
        let (mut network, client, _) = network();
        discover(&mut network);
        network.request(client, 7, 42).unwrap();
        assert!(network.advance(0.1).is_empty());
        assert_eq!(
            network.advance(0.4),
            vec![Delivery::Request {
                client_id: client,
                peer_id: 7,
                request_id: 42
            }]
        );
        network.respond(7, client, 42).unwrap();
        assert_eq!(
            network.advance(0.4),
            vec![Delivery::Response {
                client_id: client,
                peer_id: 7,
                request_id: 42
            }]
        );
    }
    #[test]
    fn deleting_client_discards_inflight_response_without_reassigning_identity() {
        let (mut network, client, _) = network();
        discover(&mut network);
        network.respond(7, client, 42).unwrap();
        network.remove(client).unwrap();
        let replacement = network.add_client("Replacement".into()).unwrap();
        assert_ne!(client, replacement);
        assert!(network.advance(1.0).is_empty());
        assert!(
            !network
                .snapshot()
                .packets
                .iter()
                .any(|packet| packet.to == client)
        );
    }
    #[test]
    fn toggling_peer_offline_revokes_existing_links_and_requires_new_handshake() {
        let (mut network, client, peer) = network();
        discover(&mut network);
        network
            .configure_peer(7, &PeerConfig::numbered(7), false)
            .unwrap();
        assert!(!network.connected(client, peer));
        network
            .configure_peer(7, &PeerConfig::numbered(7), true)
            .unwrap();
        assert!(!network.connected(client, peer));
        discover(&mut network);
        assert!(network.connected(client, peer));
    }
}
