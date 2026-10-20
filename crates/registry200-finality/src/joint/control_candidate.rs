//! Read-only, concrete own-Control preflight. No QC, import or receipt is issued.
use super::*;

impl JointHistory {
    /// Recheck the exact current owner-signed candidate and all Source/Life/Kind
    /// premises, without publishing a Journal node or advancing any context.
    /// This result is intentionally `()` and cannot authorize a later import;
    /// `apply_control` performs its normal complete verification again.
    pub fn check_control_candidate(
        &self,
        block: &CandidateBlock,
        expected: &ControlExpectation,
    ) -> Result<()> {
        self.live()?;
        let parent = self.journal.ancestry_floor();
        expected.require_context(&self.binding, &self.context, parent)?;
        expected.require_block(&self.binding, block)?;
        let candidate =
            JointCandidate::for_context(&self.binding, &self.context, block.header().clone())?;
        verify_candidate(
            &self.binding,
            &self.journal,
            &self.verifier,
            &self.context,
            parent,
            &candidate,
            block.body(),
        )?;
        Ok(())
    }
}
