//! Read-only mining metadata from the SAME closed historical Journal.
use super::*;
use version_journal::Header;

impl JointHistory {
    /// Construct an unsigned-work header at this exact current sealed parent.
    /// Actual branch retarget/state rules and timestamp validation come from the
    /// owned Journal. This checks owner permission but does NOT check application
    /// proofs, mine, publish, issue a receipt or establish current-network freshness.
    pub fn candidate_header(
        &self,
        parent: &VerifiedJointParent,
        body: &Body,
        timestamp: u64,
        now: u64,
    ) -> Result<Header> {
        self.live()?;
        let actual = &self.last.as_ref().ok_or(Error::Context)?.checked;
        if parent.binding_id() != self.binding.id()
            || parent.application_descriptor().encode() != actual.application_descriptor().encode()
            || parent.head() != actual.head()
            || parent.slot() != actual.slot()
            || parent.decision_id() != actual.decision_id()
            || parent.control() != actual.control()
            || self.journal.ancestry_floor() != actual.head()
            || self.context.slot() != actual.slot().checked_add(1).ok_or(Error::ResourceLimit)?
            || self.context.previous_decision() != actual.decision_id()
        {
            return Err(Error::Context);
        }
        if let Body::Transition(transition) = body {
            transition.check_authorization(
                &self.binding.journal_genesis().owner,
                parent.head().genesis,
            )?;
        }
        let header = self
            .journal
            .candidate(parent.head().block, body, timestamp)?;
        self.journal.validate_mining_candidate(&header, now)?;
        Ok(header)
    }
}
