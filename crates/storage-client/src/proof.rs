//! Query-scoped RPC scheduling and failover. Only the caller's exact proof
//! verification can accept a reply; peer work permits remain bounded separately.
use super::{Error, Participant, Result};
use peer_runtime::{Operation, ProofReply, RemotePeer, Request, Response};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

pub(super) struct ProofJob<'a> {
    pub object: [u8; 32],
    pub setup: [u8; 32],
    pub operation: Operation,
    pub ciphertext: &'a [u8],
}

type ExecutorKey = (SocketAddr, [u8; 32]);

#[derive(Default)]
pub(super) struct ProofRequests {
    permits: Mutex<BTreeMap<ExecutorKey, Arc<Mutex<()>>>>,
}
impl ProofRequests {
    pub fn request<T>(
        &self,
        preferred: &RemotePeer,
        peers: &[Participant],
        job: ProofJob<'_>,
        verify: impl Fn(&ProofReply) -> Result<T>,
    ) -> Result<(ProofReply, T)> {
        let mut candidates = vec![preferred];
        candidates.extend(
            peers
                .iter()
                .map(|peer| &peer.remote)
                .filter(|peer| peer.endpoint() != preferred.endpoint()),
        );
        let mut last_error = None;
        for remote in candidates {
            let endpoint = remote.endpoint();
            let permit = self
                .permits
                .lock()
                .map_err(|_| super::session::protocol("Proof scheduler failed"))?
                .entry((endpoint.address, endpoint.identity))
                .or_default()
                .clone();
            let response = {
                // Two shard workers can fail over onto the same surviving peer.
                // Queue our own RPCs there instead of exhausting its Busy retry
                // deadline. Other peers and local verification remain concurrent.
                let _guard = permit
                    .lock()
                    .map_err(|_| super::session::protocol("Proof executor queue failed"))?;
                super::session::call_bounded(remote, || Request::Prove {
                    object: job.object,
                    setup: job.setup,
                    operation: job.operation,
                    ciphertext: job.ciphertext.to_vec(),
                })
            };
            match response {
                Ok(Response::Proved(reply)) => match verify(&reply) {
                    Ok(checked) => return Ok((reply, checked)),
                    Err(error) => last_error = Some(error),
                },
                Ok(_) => last_error = Some(Error::MissingComputationProof),
                Err(error) => last_error = Some(Error::Transport(error)),
            }
        }
        Err(last_error.unwrap_or(Error::MissingComputationProof))
    }
}
