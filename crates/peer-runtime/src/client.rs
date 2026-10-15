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
}
impl RemotePeer {
    pub fn new(endpoint: Endpoint, connector: Connector) -> Self {
        Self {
            endpoint,
            connector,
            next: Arc::new(AtomicU64::new(1)),
            trace: None,
            activity: None,
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
    pub fn call(&self, request: Request) -> io::Result<Response> {
        let id = self
            .next
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| io::Error::other("Request identity space exhausted"))?;
        let name = request.name().to_string();
        let started = Instant::now();
        let bytes = encode(&WireRequest {
            version: 1,
            id,
            request,
        })?;
        let mut received = 0;
        let mut sent = 0;
        let result = (|| {
            let mut stream = self.connector.connect(&self.endpoint)?;
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
            let payload = read_frame(&mut stream, MAX_FRAME_BYTES)?;
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
            let response: WireResponse = decode(&payload)?;
            if response.version != 1 || response.id != id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Response version/request binding mismatch",
                ));
            }
            response.result.map_err(io::Error::other)
        })();
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
    pub fn status(&self) -> io::Result<Status> {
        match self.call(Request::Status)? {
            Response::Status(status) => Ok(status),
            _ => Err(io::Error::other("Unexpected status response")),
        }
    }
}
