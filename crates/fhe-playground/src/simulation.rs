//! Local transport adapter. Virtual time and visualization live here, outside the
//! transport-independent protocol and encrypted-storage library.
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use peer_protocol::{Envelope, Message, NodeRole, ProtocolEvent, ProtocolNode, RequestToken};

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
    Cancel,
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
struct IssuedJob {
    id: RequestId,
    targets: BTreeSet<NodeId>,
    fanout_closed: bool,
}

/// Owns virtual time and bounded in-process message delivery, not FHE keys/data.
/// Packets carry an operation reference into the shared local FHE worker, not a
/// production wire encoding of ciphertexts. Only actual deliveries are reported.
pub struct DemoNetwork {
    nodes: BTreeMap<NodeId, Node>,
    packets: Vec<Packet>,
    accepted: BTreeMap<(NodeId, NodeId, RequestId), RequestToken>,
    issued: BTreeMap<NodeId, IssuedJob>,
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
            accepted: BTreeMap::new(),
            issued: BTreeMap::new(),
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
        self.accepted
            .retain(|(client, peer, _), _| *client != id && *peer != id);
        self.issued.remove(&id);
        for job in self.issued.values_mut() {
            if job.targets.remove(&id) {
                job.fanout_closed = true;
            }
        }
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
            for job in self.issued.values_mut() {
                if job.targets.contains(&node_id) {
                    job.fanout_closed = true;
                }
            }
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
            self.accepted
                .retain(|(client, peer, _), _| *client != node_id && *peer != node_id);
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
        // Local work is stopped immediately. Remote job slots remain reserved
        // until a real Cancel delivery (or transport disconnection).
        for job in self.issued.values_mut() {
            if job.id == id {
                job.fanout_closed = true;
            }
        }
        self.packets.retain(|packet| !matches!(packet.envelope.message,
            Message::Request { id: request, .. } | Message::Response { id: request, .. } if request == id));
        self.accepted.retain(|(_, _, request), _| *request != id);
        let events: Vec<_> = self
            .nodes
            .values_mut()
            .flat_map(|node| node.protocol.cancel_requests(id))
            .collect();
        for event in events {
            let ProtocolEvent::Send(ref envelope) = event else {
                continue;
            };
            let (from, to) = (envelope.from, envelope.to);
            if self.enqueue_event(event).is_err() {
                // A full transport cannot silently lose cancellation forever.
                // Explicit local transport teardown releases both endpoints.
                self.revoke_route(from, to);
                self.log(format!(
                    "Cancel {id}: packet budget exhausted; route {from} ↔ {to} revoked"
                ));
            }
        }
        self.log(format!("Request {id} cancelled; control delivery pending"));
    }
    fn revoke_route(&mut self, from: NodeId, to: NodeId) {
        for (client, peer) in [(from, to), (to, from)] {
            if let Some(job) = self.issued.get_mut(&client)
                && job.targets.contains(&peer)
            {
                job.fanout_closed = true;
            }
        }
        if let Some(node) = self.nodes.get_mut(&from) {
            node.protocol.forget(to);
        }
        if let Some(node) = self.nodes.get_mut(&to) {
            node.protocol.forget(from);
        }
        self.accepted.retain(|(client, peer, _), _| {
            !((*client == from && *peer == to) || (*client == to && *peer == from))
        });
        self.packets.retain(|packet| {
            !((packet.envelope.from == from && packet.envelope.to == to)
                || (packet.envelope.from == to && packet.envelope.to == from))
        });
        self.discover = true;
    }
    /// Uses advancing logical job IDs per client; the current ID may fan out
    /// once to each distinct peer before any response begins. Cancellation or
    /// target removal/disconnection closes that job's fanout across every peer,
    /// including replacements. Only a strictly higher job ID can open fanout again.
    /// This adapter keeps ID-only worker deliveries; the protocol itself supports
    /// general ID reuse through explicit per-attempt tokens.
    pub fn request(&mut self, client: NodeId, peer: usize, id: RequestId) -> Result<(), LabError> {
        if self
            .nodes
            .get(&client)
            .is_none_or(|node| node.info.role != NodeRole::Client)
        {
            return Err(LabError::InvalidInput(
                "Query requests require a known client node.".into(),
            ));
        }
        let to = self
            .peer_node(peer)
            .ok_or_else(|| LabError::InvalidInput("Required peer was removed.".into()))?;
        if !self.connected(client, to) {
            return Err(LabError::InvalidInput(
                "Client discovery has not established every required peer route yet.".into(),
            ));
        }
        // Delivery/worker completions carry logical IDs. Do not recycle an ID
        // after retirement, even to a replacement/previously unused peer: an old
        // ID-only completion must never answer a new attempt. Initial fanout is
        // allowed only while the current logical job is still open.
        if self.issued.get(&client).is_some_and(|job| {
            id < job.id || (id == job.id && (job.fanout_closed || job.targets.contains(&to)))
        }) {
            return Err(LabError::InvalidInput(
                "Request IDs must advance after fanout closes or a route was already used.".into(),
            ));
        }
        self.check_packet_budget()?;
        // The reference addresses ciphertext work owned by the local FHE worker.
        let event = self
            .nodes
            .get_mut(&client)
            .expect("connected client")
            .protocol
            .request(to, id, id.to_le_bytes().to_vec())
            .map_err(protocol_error)?;
        self.enqueue_event(event)?;
        let job = self.issued.entry(client).or_insert_with(|| IssuedJob {
            id,
            targets: BTreeSet::new(),
            fanout_closed: false,
        });
        if id > job.id {
            job.id = id;
            job.targets.clear();
            job.fanout_closed = false;
        }
        job.targets.insert(to);
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
        self.check_packet_budget()?;
        let token = *self.accepted.get(&(client, from, id)).ok_or_else(|| {
            LabError::InvalidInput("No accepted request attempt for this response.".into())
        })?;
        let event = self
            .nodes
            .get_mut(&from)
            .expect("known peer")
            .protocol
            .respond(client, id, token)
            .map_err(protocol_error)?;
        self.enqueue_event(event)?;
        self.accepted.remove(&(client, from, id));
        self.close_fanout(client, id);
        Ok(())
    }
    fn close_fanout(&mut self, client: NodeId, id: RequestId) {
        if let Some(job) = self.issued.get_mut(&client)
            && job.id == id
        {
            job.fanout_closed = true;
        }
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
                            self.enqueue_control(event);
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
                        self.enqueue_control(event);
                    }
                    ProtocolEvent::Connected(other) => {
                        if self.connected(to, other) {
                            self.log(format!("Link {to} ↔ {other} established"));
                        }
                    }
                    ProtocolEvent::Request {
                        from, id, token, ..
                    } if role == NodeRole::Peer => {
                        self.accepted.insert((from, to, id), token);
                        delivered.push(Delivery::Request {
                            client_id: from,
                            peer_id: peer.expect("peer mapping"),
                            request_id: id,
                        });
                        self.log(format!("Request {id}: client {from} → peer {to}"));
                    }
                    ProtocolEvent::Response { from, id } if role == NodeRole::Client => {
                        self.close_fanout(to, id);
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
                    ProtocolEvent::Cancelled { from, id, token } => {
                        if self.accepted.get(&(from, to, id)) == Some(&token) {
                            self.accepted.remove(&(from, to, id));
                        }
                        self.log(format!(
                            "Cancel {id}: node {from} → node {to}; remote slot released"
                        ));
                    }
                    _ => {}
                }
            }
        }
        delivered
    }
    fn enqueue_control(&mut self, event: ProtocolEvent) {
        let ProtocolEvent::Send(ref envelope) = event else {
            return;
        };
        let (from, to) = (envelope.from, envelope.to);
        if self.enqueue_event(event).is_err() {
            // Discovery/handshake may already have reserved protocol state.
            // A dropped control frame must not leave that route pending forever.
            self.revoke_route(from, to);
            self.log(format!(
                "Control queue exhausted; route {from} ↔ {to} revoked; discovery retry pending"
            ));
        }
    }
    fn enqueue_event(&mut self, event: ProtocolEvent) -> Result<(), LabError> {
        let ProtocolEvent::Send(envelope) = event else {
            return Ok(());
        };
        self.check_packet_budget()?;
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
    fn check_packet_budget(&self) -> Result<(), LabError> {
        if self.packets.len() >= MAX_PACKETS {
            return Err(LabError::InvalidInput(
                "Transport packet budget exhausted.".into(),
            ));
        }
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
                        Message::Cancel { .. } => PacketKind::Cancel,
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
        Message::Request { id, .. } | Message::Response { id, .. } | Message::Cancel { id, .. } => {
            Some(*id)
        }
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
        network.request(client, 7, 42).unwrap();
        network.advance(0.4);
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

    #[test]
    fn cancellation_is_delayed_control_traffic_and_pause_keeps_the_remote_slot() {
        let (mut network, client, peer) = network();
        discover(&mut network);
        network.request(client, 7, 42).unwrap();
        assert_eq!(network.advance(0.4).len(), 1);
        network.cancel_request(42);
        assert!(network.respond(7, client, 42).is_err());
        assert_eq!(network.nodes[&client].protocol.outstanding_requests(), 0);
        assert_eq!(network.nodes[&peer].protocol.pending_jobs(), 1);
        let packets = network.snapshot().packets;
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].kind, PacketKind::Cancel);
        assert_eq!(packets[0].request_id, Some(42));
        network.set_simulation(1.0, true).unwrap();
        assert!(network.advance(1.0).is_empty());
        assert_eq!(network.nodes[&peer].protocol.pending_jobs(), 1);
        network.set_simulation(1.0, false).unwrap();
        assert!(network.advance(0.4).is_empty());
        assert_eq!(network.nodes[&peer].protocol.pending_jobs(), 0);
        assert!(network.request(client, 7, 42).is_err());
        network.request(client, 7, 43).unwrap();
        assert_eq!(network.advance(0.4).len(), 1);
        assert!(network.respond(7, client, 42).is_err());
        network.respond(7, client, 43).unwrap();
        assert_eq!(network.advance(0.4).len(), 1);
    }

    #[test]
    fn duplicate_transport_request_emits_work_once_and_unsolicited_response_is_refused() {
        let (mut network, client, _) = network();
        discover(&mut network);
        assert!(network.respond(7, client, 42).is_err());
        network.request(client, 7, 42).unwrap();
        let duplicate = network.packets[0].envelope.clone();
        network
            .enqueue_event(ProtocolEvent::Send(duplicate))
            .unwrap();
        assert_eq!(
            network.advance(0.4),
            vec![Delivery::Request {
                client_id: client,
                peer_id: 7,
                request_id: 42,
            }]
        );
        network.respond(7, client, 42).unwrap();
        assert!(network.respond(7, client, 42).is_err());
        assert_eq!(network.advance(0.4).len(), 1);
        assert!(network.advance(0.4).is_empty());
    }

    #[test]
    fn repeated_cancelled_jobs_release_slots_after_control_delivery() {
        let (mut network, client, _) = network();
        discover(&mut network);
        for id in 0..(peer_protocol::MAX_PENDING_JOBS as u64 + 5) {
            network.request(client, 7, id).unwrap();
            assert_eq!(network.advance(0.4).len(), 1);
            network.cancel_request(id);
            assert!(network.advance(0.4).is_empty());
        }
        network.request(client, 7, 1000).unwrap();
        assert_eq!(network.advance(0.4).len(), 1);
        network.respond(7, client, 1000).unwrap();
        assert_eq!(network.advance(0.4).len(), 1);
    }

    #[test]
    fn queue_rejection_does_not_reserve_a_request_and_cancel_overflow_revokes_route() {
        let (mut network, client, peer) = network();
        discover(&mut network);
        network.request(client, 7, 42).unwrap();
        network.advance(0.4);
        for _ in 0..MAX_PACKETS {
            network
                .enqueue_event(ProtocolEvent::Send(Envelope {
                    from: client,
                    to: peer,
                    message: Message::Ping { nonce: 999 },
                }))
                .unwrap();
        }
        assert!(network.request(client, 7, 43).is_err());
        assert_eq!(network.nodes[&client].protocol.outstanding_requests(), 1);
        assert!(network.respond(7, client, 42).is_err());
        network.cancel_request(42);
        assert!(!network.connected(client, peer));
        assert_eq!(network.nodes[&client].protocol.outstanding_requests(), 0);
        assert_eq!(network.nodes[&peer].protocol.pending_jobs(), 0);
        assert!(network.snapshot().packets.is_empty());
        discover(&mut network);
        network.request(client, 7, 43).unwrap();
        assert_eq!(network.advance(0.4).len(), 1);
    }

    #[test]
    fn disconnect_discards_pending_work_and_requires_a_fresh_worker_id() {
        let (mut network, client, _) = network();
        discover(&mut network);
        network.request(client, 7, 42).unwrap();
        network.advance(0.4);
        network
            .configure_peer(7, &PeerConfig::numbered(7), false)
            .unwrap();
        network
            .configure_peer(7, &PeerConfig::numbered(7), true)
            .unwrap();
        discover(&mut network);
        assert!(network.respond(7, client, 42).is_err());
        assert!(network.request(client, 7, 42).is_err());
        network.request(client, 7, 43).unwrap();
        assert_eq!(network.advance(0.4).len(), 1);
        network.respond(7, client, 43).unwrap();
        assert_eq!(network.advance(0.4).len(), 1);
    }

    #[test]
    fn current_job_id_can_fan_out_to_distinct_peers_but_cannot_be_recycled() {
        let (mut network, client, _) = network();
        network.add_peer(8, &PeerConfig::numbered(8), true).unwrap();
        discover(&mut network);
        network.request(client, 7, 42).unwrap();
        network.request(client, 8, 42).unwrap();
        assert!(network.request(client, 7, 42).is_err());
        assert_eq!(network.advance(0.4).len(), 2);
        network.respond(7, client, 42).unwrap();
        network.respond(8, client, 42).unwrap();
        assert_eq!(network.advance(0.4).len(), 2);
        assert!(network.request(client, 7, 41).is_err());
        assert!(network.request(client, 8, 42).is_err());
        network.request(client, 7, 43).unwrap();
        assert_eq!(network.advance(0.4).len(), 1);
    }

    #[test]
    fn replacing_a_target_retires_the_job_before_an_old_id_only_completion_can_respond() {
        let (mut network, client, original_peer) = network();
        discover(&mut network);
        network.request(client, 7, 42).unwrap();
        assert_eq!(network.advance(0.4).len(), 1);
        network.remove(original_peer).unwrap();
        let replacement = network.add_peer(7, &PeerConfig::numbered(7), true).unwrap();
        assert_ne!(original_peer, replacement);
        discover(&mut network);

        assert!(network.request(client, 7, 42).is_err());
        assert!(network.respond(7, client, 42).is_err());
        network.request(client, 7, 43).unwrap();
        assert_eq!(network.advance(0.4).len(), 1);
        assert!(network.respond(7, client, 42).is_err());
        network.respond(7, client, 43).unwrap();
        assert_eq!(network.advance(0.4).len(), 1);
    }

    #[test]
    fn cancellation_retires_the_job_even_for_a_previously_unused_peer() {
        let (mut network, client, _) = network();
        network.add_peer(8, &PeerConfig::numbered(8), true).unwrap();
        discover(&mut network);
        network.request(client, 7, 42).unwrap();
        network.advance(0.4);
        network.cancel_request(42);

        assert!(network.request(client, 8, 42).is_err());
        assert!(network.respond(8, client, 42).is_err());
        network.advance(0.4);
        network.request(client, 8, 43).unwrap();
        assert_eq!(network.advance(0.4).len(), 1);
        network.respond(8, client, 43).unwrap();
        assert_eq!(network.advance(0.4).len(), 1);
    }

    #[test]
    fn response_begin_closes_fanout_and_completed_job_stays_retired_after_replacement() {
        let (mut network, client, original_peer) = network();
        network.add_peer(8, &PeerConfig::numbered(8), true).unwrap();
        discover(&mut network);
        network.request(client, 7, 42).unwrap();
        network.advance(0.4);
        network.respond(7, client, 42).unwrap();
        assert!(network.request(client, 8, 42).is_err());
        assert_eq!(network.advance(0.4).len(), 1);
        network.remove(original_peer).unwrap();
        network.add_peer(7, &PeerConfig::numbered(7), true).unwrap();
        discover(&mut network);

        assert!(network.request(client, 7, 42).is_err());
        assert!(network.request(client, 8, 42).is_err());
        assert!(network.respond(7, client, 42).is_err());
        network.request(client, 7, 43).unwrap();
        network.request(client, 8, 43).unwrap();
        assert_eq!(network.advance(0.4).len(), 2);
        assert!(network.respond(7, client, 42).is_err());
    }

    #[test]
    fn target_disconnection_closes_the_job_for_every_remaining_peer() {
        let (mut network, client, _) = network();
        network.add_peer(8, &PeerConfig::numbered(8), true).unwrap();
        discover(&mut network);
        network.request(client, 7, 42).unwrap();
        network.advance(0.4);
        network
            .configure_peer(7, &PeerConfig::numbered(7), false)
            .unwrap();

        assert!(network.request(client, 8, 42).is_err());
        network.request(client, 8, 43).unwrap();
        assert_eq!(network.advance(0.4).len(), 1);
        network.respond(8, client, 43).unwrap();
        assert_eq!(network.advance(0.4).len(), 1);
    }

    #[test]
    fn a_full_cancel_queue_does_not_leave_new_discovery_permanently_pending() {
        let (mut network, client, _) = network();
        discover(&mut network);
        for id in 0..MAX_PACKETS as u64 {
            network.request(client, 7, id).unwrap();
            network.cancel_request(id);
        }
        assert_eq!(network.snapshot().packets.len(), MAX_PACKETS);
        assert!(
            network
                .snapshot()
                .packets
                .iter()
                .all(|packet| packet.kind == PacketKind::Cancel)
        );
        let new_peer = network.add_peer(8, &PeerConfig::numbered(8), true).unwrap();

        // No virtual time passes: discovery hits the full control queue. The
        // adapter must roll back its reserved handshake and retry after drain.
        assert!(network.advance(0.0).is_empty());
        assert!(!network.connected(client, new_peer));
        // At most one drain tick plus Ping/Pong/Ack hops and one margin tick.
        for _ in 0..5 {
            network.advance(0.4);
            if network.connected(client, new_peer) {
                break;
            }
        }
        assert!(network.connected(client, new_peer));
        network.request(client, 8, MAX_PACKETS as u64).unwrap();
        assert_eq!(network.advance(0.4).len(), 1);
        network.respond(8, client, MAX_PACKETS as u64).unwrap();
        assert_eq!(network.advance(0.4).len(), 1);
    }
}
