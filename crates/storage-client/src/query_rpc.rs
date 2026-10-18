//! Query-scoped RPC scheduling and failover. Only the caller's exact proof
//! verification can accept a reply; peer work permits remain bounded separately.
use super::{Error, Participant, Result};
use peer_runtime::{
    Operation, ProofReply, ReceivedVersionBytes, RemoteError, RemotePeer, Request, Response,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

pub(super) struct ProofJob<'a> {
    pub object: [u8; 32],
    pub setup: [u8; 32],
    pub operation: Operation,
    pub ciphertext: &'a [u8],
}

#[cfg(test)]
mod raw_tests;
#[cfg(test)]
mod tests;

type ExecutorKey = (SocketAddr, [u8; 32]);

#[derive(Default)]
struct Executor {
    unavailable: Option<io::ErrorKind>,
    missing_objects: BTreeSet<[u8; 32]>,
}

#[derive(Default)]
pub(super) struct Requests {
    permits: Mutex<BTreeMap<ExecutorKey, Arc<Mutex<Executor>>>>,
    remember_failures: bool,
}
impl Requests {
    /// Reads share this state across initial/final freshness, fetch and all
    /// proof jobs. The next query retries endpoints with independent state.
    pub fn read_query() -> Self {
        Self {
            remember_failures: true,
            ..Self::default()
        }
    }

    pub fn call(
        &self,
        remote: &RemotePeer,
        object: Option<[u8; 32]>,
        request: impl Fn() -> Request,
    ) -> io::Result<Response> {
        self.with_endpoint(remote, object, || {
            super::session::call_bounded(remote, request)
        })
    }

    pub fn fetch_version(
        &self,
        remote: &RemotePeer,
        data_head: &[u8],
        index_head: &[u8],
    ) -> io::Result<Option<ReceivedVersionBytes>> {
        self.with_endpoint(remote, None, || {
            super::session::retry_busy(|| remote.fetch_version(data_head, index_head))
        })
    }

    fn with_endpoint<T>(
        &self,
        remote: &RemotePeer,
        object: Option<[u8; 32]>,
        send: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        let endpoint = remote.endpoint();
        let permit = self
            .permits
            .lock()
            .map_err(|_| io::Error::other("Query RPC scheduler failed"))?
            .entry((endpoint.address, endpoint.identity))
            .or_default()
            .clone();
        // Check failures under the same queue lock as the RPC, so a second
        // worker cannot repeat an endpoint failure discovered by the first.
        let mut executor = permit
            .lock()
            .map_err(|_| io::Error::other("Query RPC executor queue failed"))?;
        if self.remember_failures {
            if let Some(kind) = executor.unavailable {
                return Err(io::Error::new(kind, "Executor unavailable for this query"));
            }
            if object.is_some_and(|id| executor.missing_objects.contains(&id)) {
                return Err(io::Error::other(
                    "Encrypted object unavailable for this query",
                ));
            }
        }
        let response = send();
        if self.remember_failures
            && let Err(error) = &response
        {
            if error.kind() == io::ErrorKind::Interrupted {
                return response;
            }
            match error
                .get_ref()
                .and_then(|source| source.downcast_ref::<RemoteError>())
            {
                Some(RemoteError::NotFound | RemoteError::Integrity) => {
                    if let Some(id) = object {
                        executor.missing_objects.insert(id);
                    }
                }
                // Busy retains its existing bounded retry. Other application
                // errors do not establish that unrelated objects are unavailable.
                Some(_) => {}
                None => executor.unavailable = Some(error.kind()),
            }
        }
        response
    }

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
            // The endpoint queue is released before genuine local verification.
            let response = self.call(remote, Some(job.object), || Request::Prove {
                object: job.object,
                setup: job.setup,
                operation: job.operation,
                ciphertext: job.ciphertext.to_vec(),
            });
            match response {
                Ok(Response::Proved(reply)) => match verify(&reply) {
                    Ok(checked) => return Ok((reply, checked)),
                    Err(error) => last_error = Some(error),
                },
                Ok(_) => last_error = Some(Error::MissingComputationProof),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    return Err(Error::Transport(error));
                }
                Err(error) => last_error = Some(Error::Transport(error)),
            }
        }
        Err(last_error.unwrap_or(Error::MissingComputationProof))
    }
}
