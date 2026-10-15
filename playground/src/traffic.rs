//! Bounded playback of observed frame I/O. This clock never controls the network.
use fhe_playground::{NetworkPacket, PacketKind};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub(super) struct Observation {
    pub packet: NetworkPacket,
    pub operation: String,
    pub bytes: u64,
}
pub(super) type LiveTraffic = Arc<Mutex<VecDeque<Observation>>>;
pub(super) const MAX_OBSERVATIONS: usize = 1024;
const MAX_VISIBLE: usize = 256;
const DURATION: f64 = 1.1;

struct Flight {
    packet: NetworkPacket,
    start: f64,
}
pub(super) struct Playback {
    pub speed: f32,
    pub health: bool,
    clock: f64,
    last_frame: Option<f64>,
    seen: BTreeSet<u64>,
    order: VecDeque<u64>,
    flights: VecDeque<Flight>,
    labels: BTreeMap<u64, String>,
    pub omitted: usize,
}
impl Default for Playback {
    fn default() -> Self {
        Self {
            speed: 0.5,
            health: false,
            clock: 0.0,
            last_frame: None,
            seen: BTreeSet::new(),
            order: VecDeque::new(),
            flights: VecDeque::new(),
            labels: BTreeMap::new(),
            omitted: 0,
        }
    }
}
impl Playback {
    pub fn observe_io(&mut self, observation: &Observation) {
        self.observe(&observation.packet);
        if self.seen.contains(&observation.packet.id) {
            self.labels.insert(
                observation.packet.id,
                format!(
                    "{} · {} application bytes",
                    observation.operation, observation.bytes
                ),
            );
        }
    }
    pub fn description(&self, id: u64) -> &str {
        self.labels
            .get(&id)
            .map_or("Observed network frame", String::as_str)
    }
    pub fn observe(&mut self, packet: &NetworkPacket) {
        if !self.seen.insert(packet.id) {
            return;
        }
        self.order.push_back(packet.id);
        while self.order.len() > 8192 {
            if let Some(id) = self.order.pop_front() {
                self.seen.remove(&id);
                self.labels.remove(&id);
            }
        }
        if !self.health && is_health(packet.kind) {
            return;
        }
        // Briefly stagger real observations on the same pair, without creating
        // a long sequential backlog or pretending this is their measured RTT.
        let same_pair = self
            .flights
            .iter()
            .filter(|flight| {
                let p = &flight.packet;
                (p.from == packet.from && p.to == packet.to)
                    || (p.from == packet.to && p.to == packet.from)
            })
            .count();
        self.flights.push_back(Flight {
            packet: packet.clone(),
            start: self.clock + same_pair.min(10) as f64 * 0.055,
        });
        if self.flights.len() > MAX_VISIBLE {
            self.flights.pop_front();
            self.omitted += 1;
        }
    }
    pub fn advance(&mut self, now: f64) {
        if !now.is_finite() {
            return;
        }
        if let Some(previous) = self.last_frame {
            self.clock += (now - previous).clamp(0.0, 0.1) * f64::from(self.speed.clamp(0.0, 1.0));
        }
        self.last_frame = Some(now);
        self.flights
            .retain(|flight| self.clock < flight.start + DURATION);
    }
    pub fn packets(&self) -> Vec<NetworkPacket> {
        self.flights
            .iter()
            .filter(|flight| {
                self.clock >= flight.start && (self.health || !is_health(flight.packet.kind))
            })
            .map(|flight| {
                let mut packet = flight.packet.clone();
                packet.progress = ((self.clock - flight.start) / DURATION).clamp(0.0, 1.0) as f32;
                packet
            })
            .collect()
    }
    pub fn playing(&self) -> bool {
        self.speed > 0.0 && !self.flights.is_empty()
    }
    pub fn can_sync(&self) -> bool {
        !self.flights.is_empty()
    }
    pub fn queued(&self) -> usize {
        self.flights.len()
    }
    pub fn sync_live(&mut self) {
        self.flights.clear();
        self.speed = 1.0;
        self.last_frame = None;
        self.omitted = 0;
        // Keep seen IDs: the latest coalesced snapshot must not replay skipped I/O.
    }
}
fn is_health(kind: PacketKind) -> bool {
    matches!(kind, PacketKind::Ping | PacketKind::Pong | PacketKind::Ack)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn packet(id: u64) -> NetworkPacket {
        NetworkPacket {
            id,
            from: 1,
            to: 2,
            kind: PacketKind::Request,
            progress: 1.0,
            request_id: Some(9),
        }
    }
    #[test]
    fn observed_completed_io_moves_visually_and_zero_speed_freezes_it() {
        let mut replay = Playback::default();
        replay.observe(&packet(1));
        replay.advance(0.0);
        replay.advance(0.1);
        let moved = replay.packets()[0].progress;
        assert!(moved > 0.0 && moved < 1.0);
        replay.speed = 0.0;
        replay.advance(10.0);
        assert_eq!(replay.packets()[0].progress, moved);
        assert!(!replay.playing());
    }
    #[test]
    fn repeated_snapshots_do_not_restart_or_duplicate_a_real_observation() {
        let mut replay = Playback::default();
        replay.observe(&packet(1));
        replay.advance(0.0);
        for i in 1..40 {
            replay.advance(f64::from(i) * 0.1);
            replay.observe(&packet(1));
        }
        assert!(replay.packets().is_empty());
    }
    #[test]
    fn playback_is_bounded_and_background_health_is_opt_in() {
        let mut replay = Playback::default();
        let mut health = packet(1);
        health.kind = PacketKind::Ping;
        replay.observe(&health);
        assert!(replay.packets().is_empty());
        for id in 2..1002 {
            replay.observe(&packet(id));
        }
        assert_eq!(replay.flights.len(), MAX_VISIBLE);
        assert_eq!(replay.omitted, 1000 - MAX_VISIBLE);
    }
    #[test]
    fn syncing_skips_only_the_visual_tail_and_does_not_replay_the_latest_snapshot() {
        let mut replay = Playback {
            speed: 0.0,
            ..Default::default()
        };
        replay.observe(&packet(1));
        assert!(replay.can_sync());
        replay.sync_live();
        assert_eq!(replay.speed, 1.0);
        assert!(!replay.can_sync());
        replay.observe(&packet(1));
        assert!(replay.packets().is_empty());
        replay.observe(&packet(2));
        assert_eq!(
            replay
                .packets()
                .iter()
                .map(|packet| packet.id)
                .collect::<Vec<_>>(),
            [2]
        );
    }
}
