use crate::wire::*;
use peer_transport::{Connector, Endpoint, MAX_FRAME_BYTES, read_frame, write_frame};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

#[derive(Clone, Debug)]
pub struct Trace {
    pub peer: [u8; 32],
    pub operation: String,
    pub request_id: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub elapsed_ms: f64,
    pub succeeded: bool,
}
/// Observed application-frame I/O, independent of result/proof acceptance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivityPhase {
    RequestSent,
    ReplyReceived,
}
#[derive(Clone, Debug)]
pub struct RpcActivity {
    pub peer: [u8; 32],
    pub operation: String,
    pub request_id: u64,
    pub phase: ActivityPhase,
    pub bytes: u64,
}
#[derive(Clone)]
pub struct RemotePeer {
    endpoint: Endpoint,
    connector: Connector,
    next: Arc<AtomicU64>,
    trace: Option<Arc<dyn Fn(Trace) + Send + Sync>>,
    activity: Option<Arc<dyn Fn(RpcActivity) + Send + Sync>>,
    control: Option<peer_transport::RequestControl>,
}
impl RemotePeer {
    pub fn new(endpoint: Endpoint, connector: Connector) -> Self {
        Self {
            endpoint,
            connector,
            next: Arc::new(AtomicU64::new(1)),
            trace: None,
            activity: None,
            control: None,
        }
    }
    pub fn with_trace(mut self, trace: Arc<dyn Fn(Trace) + Send + Sync>) -> Self {
        self.trace = Some(trace);
        self
    }
    /// Reports a frame only after its actual write/read completes. Callbacks run
    /// synchronously and should return promptly; they receive no payload or keys.
    /// A received frame still needs decoding, request binding and proof checks.
    pub fn with_activity(mut self, activity: Arc<dyn Fn(RpcActivity) + Send + Sync>) -> Self {
        self.activity = Some(activity);
        self
    }
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
    /// An operation scope affects these owner RPCs only. Cancellation closes
    /// local sockets; it neither stops peers nor rolls back durable mutations.
    pub fn with_control(mut self, control: peer_transport::RequestControl) -> Self {
        self.control = Some(control);
        self
    }
    pub fn call(&self, request: Request) -> io::Result<Response> {
        let cancellation = self.control.as_ref().and_then(|control| control.current());
        if let Some(token) = &cancellation {
            token.check()?;
        }
        let id = self
            .next
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| io::Error::other("Request identity space exhausted"))?;
        let (response_limit, custody_tag) = match &request {
            Request::FetchPages(_) => (crate::MAX_PAGE_BATCH_RESPONSE_BYTES, Some(12)),
            Request::FetchReadImage(_) => (crate::MAX_READ_IMAGE_RESPONSE_BYTES, Some(13)),
            Request::StoreDelta(_) => (crate::MAX_STORE_DELTA_RESPONSE_BYTES, Some(2)),
            _ => (MAX_FRAME_BYTES, None),
        };
        let name = request.name().to_string();
        let started = Instant::now();
        let bytes = encode(&WireRequest {
            version: 2,
            id,
            request,
        })?;
        let mut received = 0;
        let mut sent = 0;
        let result = (|| {
            let mut stream = self
                .connector
                .connect_cancellable(&self.endpoint, cancellation.as_ref())?;
            write_frame(&mut stream, &bytes, MAX_FRAME_BYTES)?;
            sent = bytes.len() as u64;
            if let Some(activity) = &self.activity {
                activity(RpcActivity {
                    peer: self.endpoint.identity,
                    operation: name.clone(),
                    request_id: id,
                    phase: ActivityPhase::RequestSent,
                    bytes: sent,
                });
            }
            let payload = read_frame(&mut stream, response_limit)?;
            received = payload.len() as u64;
            if let Some(activity) = &self.activity {
                activity(RpcActivity {
                    peer: self.endpoint.identity,
                    operation: name.clone(),
                    request_id: id,
                    phase: ActivityPhase::ReplyReceived,
                    bytes: received,
                });
            }
            crate::wire::check_version(&payload)?;
            let response: WireResponse = match custody_tag {
                Some(tag) => decode_custody_response(&payload, response_limit, tag)?,
                None => decode_response(&payload)?,
            };
            if response.version != 2 || response.id != id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Response version/request binding mismatch",
                ));
            }
            response.result.map_err(io::Error::other)
        })();
        let result = if cancellation
            .as_ref()
            .is_some_and(|token| token.is_cancelled())
        {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "RPC operation cancelled",
            ))
        } else {
            result
        };
        if let Some(trace) = &self.trace {
            trace(Trace {
                peer: self.endpoint.identity,
                operation: name,
                request_id: id,
                request_bytes: sent,
                response_bytes: received,
                elapsed_ms: started.elapsed().as_secs_f64() * 1000.0,
                succeeded: result.is_ok(),
            });
        }
        result
    }
    /// Reads exactly the requested encrypted pages and verifies Merkle membership
    /// against the caller's trusted heads. The caller still owns AEAD, complete
    /// selection, computation proofs and required journal freshness.
    pub fn fetch_pages(
        &self,
        request: &crate::PageBatchRequest,
    ) -> io::Result<Vec<(crate::PageAddress, compact_store::VerifiedPage)>> {
        match self.call(Request::FetchPages(request.clone()))? {
            Response::Pages(batch) => batch
                .verify(request)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected page response",
            )),
        }
    }
    /// Fetches a static public-geometry image footprint, checking the exact
    /// request and every returned prefix proof. No SQL or freshness is accepted.
    pub fn fetch_read_image(
        &self,
        request: &crate::ReadImageRequest,
    ) -> io::Result<crate::ReadImage> {
        match self.call(Request::FetchReadImage(request.clone()))? {
            Response::ReadImage(image) => {
                image
                    .verify(request)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                Ok(image)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected read image response",
            )),
        }
    }
    pub fn status(&self) -> io::Result<Status> {
        match self.call(Request::Status)? {
            Response::Status(status) => Ok(status),
            _ => Err(io::Error::other("Unexpected status response")),
        }
    }
}
