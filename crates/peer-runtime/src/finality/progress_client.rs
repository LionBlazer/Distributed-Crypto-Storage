//! Distinct Progress transport. No decoded response supplies proof authority.
use super::{
    invalid, joint_prefetch::ProofBlobSelector, owner::Certificate, proof_application::Kind,
    proof_client::Client,
};
use peer_transport::{Connector, Endpoint};
use protocol_storage::BlobId;
use registry200_finality::{
    CandidateBlock,
    progress::{Binding, Checkpoint},
};
use std::io;

/// An unverified fixed-role reference in the actual owner-signed Progress Body.
/// It neither authorizes an arbitrary file nor marks any premise verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgressProofBlobSelector(ProofBlobSelector);
impl ProgressProofBlobSelector {
    pub fn manifest(ordinal: u16) -> io::Result<Self> {
        if ordinal > 1 {
            return Err(invalid());
        }
        ProofBlobSelector::manifest(ordinal).map(Self)
    }
    pub fn catalog(role: u16, ordinal: u16) -> io::Result<Self> {
        ProofBlobSelector::catalog(role, ordinal).map(Self)
    }
}
/// Distinct installed Progress protocol, with no old-binding conversion.
/// ```compile_fail
/// fn foreign(c: peer_runtime::Connector, e: peer_runtime::Endpoint,
///     b: &registry200_finality::joint::JointBinding) {
///     let _ = peer_runtime::finality::ProgressFinalityClient::new(c, e, b);
/// }
/// ```
#[derive(Clone)]
pub struct ProgressFinalityClient {
    inner: Client,
}
impl ProgressFinalityClient {
    pub fn new(connector: Connector, endpoint: Endpoint, binding: &Binding) -> Self {
        Self {
            inner: Client::new(connector, endpoint, Kind::Progress, binding.id()),
        }
    }
    pub fn cancel(&self) {
        self.inner.cancel()
    }
    /// An availability hint, never an agreed or fresh-head proof.
    pub fn observed_slot(&self) -> io::Result<u64> {
        self.inner.observed_slot()
    }
    pub fn checkpoint_after(&self, slot: u64) -> io::Result<Option<Checkpoint>> {
        match self.inner.checkpoint_after(slot)? {
            Some(Certificate::Progress(c)) => Ok(Some(c)),
            None => Ok(None),
            _ => Err(invalid()),
        }
    }
    /// Success acknowledges import only. Independently apply the actual QC,
    /// exact original Body and own expectation through Progress History.
    pub fn submit(&self, block: &CandidateBlock) -> io::Result<()> {
        self.inner.submit(block)
    }
    pub fn submit_checkpoint(&self, checkpoint: &Checkpoint) -> io::Result<()> {
        self.inner.submit_checkpoint(&checkpoint.encode())
    }
    pub fn candidate_block(&self, id: [u8; 32]) -> io::Result<CandidateBlock> {
        self.inner.candidate_block(id)
    }
    pub fn put_proof_blob(
        &self,
        block: &CandidateBlock,
        selector: ProgressProofBlobSelector,
        id: BlobId,
        bytes: &[u8],
    ) -> io::Result<()> {
        self.inner.put_proof_blob(block, selector.0, id, bytes)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn progress_manifest_has_exactly_two_roles_and_catalog_roles_stay_bounded() {
        assert!(ProgressProofBlobSelector::manifest(0).is_ok());
        assert!(ProgressProofBlobSelector::manifest(1).is_ok());
        assert!(ProgressProofBlobSelector::manifest(2).is_err());
        assert!(ProgressProofBlobSelector::catalog(0, 0).is_err());
        assert!(ProgressProofBlobSelector::catalog(12, 0).is_err());
        assert!(ProgressProofBlobSelector::catalog(11, 117).is_ok());
        // The active Joint protocol retains its existing third role.
        assert!(ProofBlobSelector::manifest(2).is_ok());
    }
}
