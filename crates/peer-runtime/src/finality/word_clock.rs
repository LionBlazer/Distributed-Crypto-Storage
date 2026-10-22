//! Local scheduling only; no candidate, vote, proof or freshness authority.
//! Empty Word slots need no nil-vote rounds until authenticated work arrives.
use std::time::Instant;

pub(super) struct WordClock {
    context: [u8; 32],
    started: Option<Instant>,
}
impl WordClock {
    pub fn new(context: [u8; 32], resumed: bool, now: Instant) -> Self {
        Self {
            context,
            started: resumed.then_some(now),
        }
    }
    pub fn enter(&mut self, context: [u8; 32]) -> bool {
        if self.context == context {
            return false;
        }
        self.context = context;
        self.started = None;
        true
    }
    /// Call only AFTER real owner/native admission or authenticated consensus
    /// decoding. Retain the handler's original start so verification is counted.
    /// A retransmission can never postpone an already armed deadline.
    pub fn observe(&mut self, context: [u8; 32], handler_started: Instant) {
        if self.context == context {
            self.started.get_or_insert(handler_started);
        }
    }
    pub fn started(&self) -> Option<Instant> {
        self.started
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn idle_slot_and_foreign_context_cannot_start_a_timeout() {
        let now = Instant::now();
        let mut clock = WordClock::new([1; 32], false, now);
        clock.observe([2; 32], now + Duration::from_secs(10));
        assert_eq!(clock.started(), None);
        assert!(!clock.enter([1; 32]));
        assert_eq!(clock.started(), None);
    }

    #[test]
    fn admitted_work_counts_verification_and_retries_cannot_postpone_it() {
        let handler_started = Instant::now();
        let verification_finished = handler_started + Duration::from_millis(700);
        let mut clock = WordClock::new([1; 32], false, handler_started);
        clock.observe([1; 32], handler_started);
        clock.observe([1; 32], verification_finished);
        clock.observe([1; 32], handler_started + Duration::from_secs(10));
        let deadline = clock.started().unwrap() + Duration::from_secs(1);
        assert_eq!(deadline - verification_finished, Duration::from_millis(300));
    }

    #[test]
    fn only_a_new_context_returns_an_active_slot_to_idle() {
        let now = Instant::now();
        let mut clock = WordClock::new([1; 32], false, now);
        clock.observe([1; 32], now);
        assert!(!clock.enter([1; 32]));
        assert_eq!(clock.started(), Some(now));
        assert!(clock.enter([2; 32]));
        clock.observe([1; 32], now);
        assert_eq!(clock.started(), None);
        let next = now + Duration::from_secs(2);
        clock.observe([2; 32], next);
        assert_eq!(clock.started(), Some(next));
    }

    #[test]
    fn resumed_consensus_starts_immediately_without_another_submission() {
        let now = Instant::now();
        let mut clock = WordClock::new([1; 32], true, now);
        clock.observe([1; 32], now + Duration::from_secs(3));
        assert_eq!(clock.started(), Some(now));
    }
}
