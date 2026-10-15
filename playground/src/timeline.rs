//! One monotonic display clock for real observations, snapshots and command results.
//! It changes presentation only; protocol execution never reads this clock.
use std::{collections::VecDeque, time::Instant};

const MAX_PENDING: usize = 4096;

pub(crate) struct Timeline<T> {
    origin: Instant,
    last_wall: Instant,
    position: f64,
    pending: VecDeque<(f64, T)>,
}
impl<T> Default for Timeline<T> {
    fn default() -> Self {
        Self::new(Instant::now())
    }
}
impl<T> Timeline<T> {
    pub fn new(now: Instant) -> Self {
        Self {
            origin: now,
            last_wall: now,
            position: 0.0,
            pending: VecDeque::new(),
        }
    }
    pub fn record(&mut self, at: Instant, event: T) {
        let seconds = at.saturating_duration_since(self.origin).as_secs_f64();
        // Producers serialize timestamps with their enqueue. Clamp defensively so
        // observations reported late never move a newer displayed state backwards.
        let seconds = self
            .pending
            .back()
            .map_or(seconds, |(last, _)| seconds.max(*last));
        self.pending.push_back((seconds, event));
    }
    /// Trim optional display telemetry only. Command results remain queued and
    /// the display clock is never advanced as a consequence of buffer pressure.
    pub fn trim_optional(&mut self, optional: impl Fn(&T) -> bool) -> usize {
        let mut removed = 0;
        while self.pending.len() > MAX_PENDING {
            let Some(index) = self.pending.iter().position(|(_, event)| optional(event)) else {
                break;
            };
            self.pending.remove(index);
            removed += 1;
        }
        removed
    }
    pub fn advance(&mut self, now: Instant, speed: f32) {
        self.position += now.saturating_duration_since(self.last_wall).as_secs_f64()
            * f64::from(speed.clamp(0.0, 1.0));
        self.last_wall = now;
    }
    pub fn pop_ready(&mut self) -> Option<(f64, T)> {
        if self
            .pending
            .front()
            .is_some_and(|(at, _)| *at <= self.position)
        {
            self.pending.pop_front()
        } else {
            None
        }
    }
    pub fn pop_any(&mut self) -> Option<(f64, T)> {
        self.pending.pop_front()
    }
    pub fn catch_up(&mut self, now: Instant) {
        self.position = now.saturating_duration_since(self.origin).as_secs_f64();
        self.last_wall = now;
    }
    pub fn position(&self) -> f64 {
        self.position
    }
    pub fn queued(&self) -> usize {
        self.pending.len()
    }
    pub fn lag(&self) -> f64 {
        (self
            .last_wall
            .saturating_duration_since(self.origin)
            .as_secs_f64()
            - self.position)
            .max(0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn slow_display_preserves_send_receive_result_and_state_order() {
        let start = Instant::now();
        let mut log = Timeline::new(start);
        for (millis, event) in [
            (100, "sent"),
            (200, "received"),
            (250, "verified result"),
            (300, "new head"),
        ] {
            log.record(start + Duration::from_millis(millis), event);
        }
        log.advance(start + Duration::from_millis(400), 0.5);
        assert_eq!(log.pop_ready().map(|(_, e)| e), Some("sent"));
        assert_eq!(log.pop_ready().map(|(_, e)| e), Some("received"));
        assert!(log.pop_ready().is_none());
        log.advance(start + Duration::from_millis(600), 0.5);
        assert_eq!(log.pop_ready().map(|(_, e)| e), Some("verified result"));
        assert_eq!(log.pop_ready().map(|(_, e)| e), Some("new head"));
    }
    #[test]
    fn changing_speed_during_a_query_keeps_one_position_and_live_keeps_every_result() {
        let start = Instant::now();
        let mut log = Timeline::new(start);
        log.record(start + Duration::from_millis(100), "sent");
        log.record(start + Duration::from_millis(200), "received");
        log.record(start + Duration::from_millis(300), "result");
        log.advance(start + Duration::from_millis(100), 1.0);
        assert_eq!(log.pop_ready().map(|(_, e)| e), Some("sent"));
        log.advance(start + Duration::from_secs(5), 0.0);
        assert!(log.pop_ready().is_none());
        log.catch_up(start + Duration::from_secs(5));
        assert_eq!(log.pop_ready().map(|(_, e)| e), Some("received"));
        assert_eq!(log.pop_ready().map(|(_, e)| e), Some("result"));
        assert_eq!(log.queued(), 0);
    }
}
