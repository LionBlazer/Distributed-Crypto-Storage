//! Distinct Word TLS transport. Decoded replies do not establish proof or freshness.
use super::{invalid, owner::Certificate, proof_application::Kind, proof_client::Client};
use peer_transport::{Connector, Endpoint};
use registry200_finality::{
    CandidateBlock,
    word::{Binding, Checkpoint},
};
use std::io;

/// Typed installed Word protocol. A successful submit is an import observation,
/// not a lock lease or accepted SQL result. Verify exact owner intent, original
/// native proofs, ancestry and QC independently before using a checkpoint.
/// ```compile_fail
/// fn foreign(c:peer_runtime::Connector,e:peer_runtime::Endpoint,b:&registry200_finality::progress::Binding) {
///     let _=peer_runtime::finality::WordFinalityClient::new(c,e,b);
/// }
/// ```
#[derive(Clone)]
pub struct WordFinalityClient {
    inner: Client,
}
impl WordFinalityClient {
    pub fn new(connector: Connector, endpoint: Endpoint, binding: &Binding) -> Self {
        Self {
            inner: Client::new(connector, endpoint, Kind::Word, binding.id()),
        }
    }
    pub fn cancel(&self) {
        self.inner.cancel()
    }
    /// Availability hint only, with no agreed/fresh-head authority.
    pub fn observed_slot(&self) -> io::Result<u64> {
        self.inner.observed_slot()
    }
    pub fn checkpoint_after(&self, slot: u64) -> io::Result<Option<Checkpoint>> {
        match self.inner.checkpoint_after(slot)? {
            Some(Certificate::Word(c)) => Ok(Some(c)),
            None => Ok(None),
            _ => Err(invalid()),
        }
    }
    pub fn submit(&self, block: &CandidateBlock) -> io::Result<()> {
        self.inner.submit(block)
    }
    pub fn submit_checkpoint(&self, checkpoint: &Checkpoint) -> io::Result<()> {
        self.inner.submit_checkpoint(&checkpoint.encode())
    }
    pub fn candidate_block(&self, id: [u8; 32]) -> io::Result<CandidateBlock> {
        self.inner.candidate_block(id)
    }
}
