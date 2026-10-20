//! Typed Joint client over the one bounded concrete proof transport engine.
use super::{
    invalid, joint_prefetch::ProofBlobSelector, owner::Certificate, proof_application::Kind,
    proof_client::Client,
};
use peer_transport::{Connector, Endpoint};
use protocol_storage::BlobId;
use registry200_finality::{
    CandidateBlock,
    joint::{JointBinding, JointCheckpoint},
};
use std::io;

/// A transport handle. Responses still require independent application/QC replay.
#[derive(Clone)]
pub struct JointFinalityClient {
    inner: Client,
}
impl JointFinalityClient {
    pub fn new(connector: Connector, endpoint: Endpoint, binding: &JointBinding) -> Self {
        Self {
            inner: Client::new(connector, endpoint, Kind::Joint, binding.id()),
        }
    }
    pub fn cancel(&self) {
        self.inner.cancel()
    }
    pub fn observed_slot(&self) -> io::Result<u64> {
        self.inner.observed_slot()
    }
    pub fn checkpoint_after(&self, slot: u64) -> io::Result<Option<JointCheckpoint>> {
        match self.inner.checkpoint_after(slot)? {
            Some(Certificate::Joint(c)) => Ok(Some(c)),
            None => Ok(None),
            _ => Err(invalid()),
        }
    }
    /// Import acknowledgement only, not a QC, SQL result or fresh lock grant.
    pub fn submit(&self, block: &CandidateBlock) -> io::Result<()> {
        self.inner.submit(block)
    }
    pub fn submit_checkpoint(&self, checkpoint: &JointCheckpoint) -> io::Result<()> {
        self.inner.submit_checkpoint(&checkpoint.encode())
    }
    pub fn candidate_block(&self, id: [u8; 32]) -> io::Result<CandidateBlock> {
        self.inner.candidate_block(id)
    }
    pub fn put_proof_blob(
        &self,
        block: &CandidateBlock,
        selector: ProofBlobSelector,
        id: BlobId,
        bytes: &[u8],
    ) -> io::Result<()> {
        self.inner.put_proof_blob(block, selector, id, bytes)
    }
}
