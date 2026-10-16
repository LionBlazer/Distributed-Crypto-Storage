//! Optional bounded metadata recording for the genuine process fixture.
use peer_runtime::{ActivityPhase, RpcActivity, Trace};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use storage_client::Participant;

const MAX_EVENTS: usize = 4096;
#[derive(Clone)]
pub(super) struct RpcRecorder {
    state: Arc<Mutex<Recording>>,
    case: &'static str,
}
struct Recording {
    started: Option<Instant>,
    events: Vec<Event>,
    truncated: bool,
}
struct Event {
    at: Duration,
    peer: u64,
    request: u64,
    operation: String,
    detail: Detail,
}
enum Detail {
    Activity {
        phase: ActivityPhase,
        bytes: u64,
    },
    Complete {
        elapsed_ms: f64,
        request_bytes: u64,
        response_bytes: u64,
        succeeded: bool,
    },
}
impl RpcRecorder {
    pub(super) fn optional(case: &'static str) -> Option<Self> {
        std::env::var_os("DCS_TEST_RPC_PROFILE").map(|_| Self {
            case,
            state: Arc::new(Mutex::new(Recording {
                started: None,
                events: Vec::with_capacity(MAX_EVENTS),
                truncated: false,
            })),
        })
    }
    pub(super) fn attach(&self, mut participant: Participant) -> Participant {
        let peer = participant.id;
        let activity = self.clone();
        let trace = self.clone();
        participant.remote = participant
            .remote
            .with_activity(Arc::new(move |event: RpcActivity| {
                activity.record(
                    peer,
                    event.request_id,
                    event.operation,
                    Detail::Activity {
                        phase: event.phase,
                        bytes: event.bytes,
                    },
                );
            }))
            .with_trace(Arc::new(move |event: Trace| {
                trace.record(
                    peer,
                    event.request_id,
                    event.operation,
                    Detail::Complete {
                        elapsed_ms: event.elapsed_ms,
                        request_bytes: event.request_bytes,
                        response_bytes: event.response_bytes,
                        succeeded: event.succeeded,
                    },
                );
            }));
        participant
    }
    fn record(&self, peer: u64, request: u64, operation: String, detail: Detail) {
        let mut recording = self.state.lock().expect("test RPC observation recorder");
        let Some(started) = recording.started else {
            return;
        };
        if recording.events.len() == MAX_EVENTS {
            recording.truncated = true;
            return;
        }
        recording.events.push(Event {
            at: started.elapsed(),
            peer,
            request,
            operation,
            detail,
        });
    }
    pub(super) fn start(&self) {
        let mut recording = self.state.lock().expect("test RPC observation recorder");
        recording.events.clear();
        recording.truncated = false;
        recording.started = Some(Instant::now());
    }
    pub(super) fn finish(&self) {
        let (elapsed, events, truncated) = {
            let mut recording = self.state.lock().expect("test RPC observation recorder");
            let started = recording
                .started
                .take()
                .expect("started test RPC observation");
            (
                started.elapsed(),
                std::mem::take(&mut recording.events),
                recording.truncated,
            )
        };
        // Emit only after the actual UPDATE and all callbacks finish. No payload,
        // SQL, plaintext row, credential, proof or key enters these metadata records.
        println!(
            "rpc_observation={}",
            serde_json::json!({
                "event": "summary", "case": self.case, "elapsed_ms": elapsed.as_secs_f64() * 1000.,
                "event_count": events.len(), "event_limit": MAX_EVENTS, "truncated": truncated,
            })
        );
        for event in events {
            let time_ms = event.at.as_secs_f64() * 1000.;
            let mut value = serde_json::json!({
                "peer": event.peer, "request_id": event.request,
                "operation": event.operation, "time_ms": time_ms,
            });
            match event.detail {
                Detail::Activity { phase, bytes } => {
                    value["event"] = "activity".into();
                    value["phase"] = match phase {
                        ActivityPhase::RequestSent => "request_sent",
                        ActivityPhase::ReplyReceived => "reply_received",
                    }
                    .into();
                    value["application_bytes"] = bytes.into();
                }
                Detail::Complete {
                    elapsed_ms,
                    request_bytes,
                    response_bytes,
                    succeeded,
                } => {
                    value["event"] = "complete".into();
                    value["elapsed_ms"] = elapsed_ms.into();
                    // Trace elapsed starts before request serialization. This
                    // reconstructed start differs only by callback dispatch time.
                    value["approx_start_ms"] = (time_ms - elapsed_ms).max(0.).into();
                    value["application_request_bytes"] = request_bytes.into();
                    value["application_response_bytes"] = response_bytes.into();
                    value["succeeded"] = succeeded.into();
                }
            }
            println!("rpc_observation={value}");
        }
    }
}
