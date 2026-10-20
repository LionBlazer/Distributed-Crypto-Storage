//! Read-only exact own-Acquire preflight. It issues no import or proof receipt.
use super::*;
impl JointHistory {
    /// Authenticate the actual candidate and freshly check the fixed
    /// input16/output118/Source/Life/Link composition before an owner saves Body.
    /// `apply_acquire` still independently checks the real QC and all premises.
    pub fn check_acquire_candidate(
        &self,
        block: &CandidateBlock,
        expected: &AcquireExpectation,
    ) -> Result<()> {
        self.live()?;
        let parent = self.journal.ancestry_floor();
        expected.require_context(&self.binding, &self.context, parent)?;
        let candidate =
            JointCandidate::for_context(&self.binding, &self.context, block.header().clone())?;
        require_candidate_context(&self.binding, &self.context, parent, &candidate)?;
        drop(self.verifier.check_acquire_block(
            &self.journal,
            block.header(),
            block.body(),
            block.header().timestamp,
            expected.inputs(),
        )?);
        Ok(())
    }
}
