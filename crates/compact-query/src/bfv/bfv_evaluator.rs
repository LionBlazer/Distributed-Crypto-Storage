use super::*;
impl Evaluator {
    pub fn evaluate_indexed_insert(
        &self,
        request: &[u8],
    ) -> Result<bfv_core::EvaluatedIndexedInsert> {
        Ok(self.peer.evaluate_indexed_insert_for_experiment(request)?)
    }
    pub fn evaluate_indexed_select(
        &self,
        request: &[u8],
    ) -> Result<bfv_core::EvaluatedIndexedSelect> {
        Ok(self.peer.evaluate_indexed_select_for_experiment(request)?)
    }
    pub fn evaluate_exact_aggregate(&self, request: &[u8]) -> Result<bfv_core::EvaluatedQuery> {
        Ok(self
            .peer
            .evaluate_exact_index_aggregate_for_experiment(request)?)
    }
    pub fn evaluate_indexed_update(
        &self,
        request: &[u8],
    ) -> Result<bfv_core::EvaluatedIndexedUpdate> {
        Ok(self.peer.evaluate_indexed_update(request)?)
    }
    pub fn profile(&self) -> ParameterProfile {
        self.peer.profile()
    }
    pub fn public_setup_bytes(&self) -> Result<bfv_core::PublicSetupBytes> {
        Ok(self.setup.byte_counts()?)
    }
    /// Original public setup only. No secret-key bytes cross this boundary.
    pub fn encode_public_setup_for_experiment(&self) -> Result<Vec<u8>> {
        Ok(self.setup.to_bytes()?)
    }
}
