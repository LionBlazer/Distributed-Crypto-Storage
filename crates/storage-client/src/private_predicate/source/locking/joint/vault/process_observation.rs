//! Test-only bounded observation of actual RPCs; acknowledgements confer no proof.
use super::*;

#[derive(Clone, Copy, Debug)]
pub(super) enum Kind {
    Manifest,
    Catalog,
    Submit,
    Checkpoint,
    Body,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Observation {
    kind: Kind,
    peer: usize,
    item: usize,
    bytes: usize,
}
impl Observation {
    pub(super) const fn new(kind: Kind, peer: usize, item: usize, bytes: usize) -> Self {
        Self {
            kind,
            peer,
            item,
            bytes,
        }
    }
    fn trace(self, event: &str, attempt: u64, started: Instant, error: Option<io::ErrorKind>) {
        eprintln!(
            "Owner RPC pid={} kind={:?} peer={} item={} bytes={} event={} attempt={} elapsed_ms={:.3} error={:?}",
            std::process::id(),
            self.kind,
            self.peer,
            self.item,
            self.bytes,
            event,
            attempt,
            started.elapsed().as_secs_f64() * 1000.,
            error
        );
    }
}

pub(super) fn until<T>(
    observation: Observation,
    action: impl FnMut() -> io::Result<Option<T>>,
) -> io::Result<T> {
    observe_until(observation, Instant::now() + WAIT, action)
}

// A single availability probe, not a wait for consensus. The caller must
// independently authenticate any returned checkpoint before skipping work.
// Only this RPC's transient failure becomes absence; proof failures outside
// the observation remain hard errors.
pub(super) fn once<T>(
    observation: Observation,
    action: impl FnOnce() -> io::Result<Option<T>>,
) -> io::Result<Option<T>> {
    let started = Instant::now();
    observation.trace("probe-start", 1, started, None);
    match action() {
        Ok(value) => {
            observation.trace(
                if value.is_some() {
                    "probe-observed"
                } else {
                    "probe-absent"
                },
                1,
                started,
                None,
            );
            Ok(value)
        }
        Err(error) if transient(error.kind()) => {
            observation.trace("probe-unavailable", 1, started, Some(error.kind()));
            Ok(None)
        }
        Err(error) => {
            observation.trace("probe-rejected", 1, started, Some(error.kind()));
            Err(error)
        }
    }
}

// This bounds admission of retries and checks again after synchronous return.
// Existing RPC I/O/absolute deadlines and joins remain in force; this helper
// never detaches started work or invents a shorter production socket timeout.
fn observe_until<T>(
    observation: Observation,
    deadline: Instant,
    mut action: impl FnMut() -> io::Result<Option<T>>,
) -> io::Result<T> {
    let started = Instant::now();
    let mut attempt = 0u64;
    observation.trace("start", attempt, started, None);
    loop {
        if Instant::now() >= deadline {
            observation.trace("expired", attempt, started, Some(io::ErrorKind::TimedOut));
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Actual owner OS operation deadline",
            ));
        }
        attempt += 1;
        let result = action();
        if Instant::now() >= deadline {
            // A remote import may have happened. Do not turn a late observation
            // into SQL success or replace the saved original invocation.
            observation.trace("expired", attempt, started, Some(io::ErrorKind::TimedOut));
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Actual owner OS operation deadline",
            ));
        }
        let error = match result {
            Ok(Some(value)) => {
                observation.trace("observed", attempt, started, None);
                return Ok(value);
            }
            Ok(None) => None,
            Err(error) if transient(error.kind()) => Some(error.kind()),
            Err(error) => {
                observation.trace("rejected", attempt, started, Some(error.kind()));
                return Err(error);
            }
        };
        if attempt.is_power_of_two() {
            observation.trace("retry", attempt, started, error);
        }
        std::thread::park_timeout(Duration::from_millis(25));
    }
}

fn transient(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::WouldBlock
            | io::ErrorKind::TimedOut
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::NotConnected
    )
}

#[test]
fn lost_tcp_ack_retries_the_exact_original_bytes_and_joins_the_receiver() {
    use std::net::{Shutdown, TcpStream};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = listener.local_addr().unwrap();
    let original = *b"PUBLIC ORIGINAL REQUEST";
    let received = std::thread::scope(|scope| {
        let receiver = scope.spawn(|| -> io::Result<Vec<[u8; 23]>> {
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut received = Vec::new();
            while received.len() < 2 {
                let (mut socket, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::park_timeout(Duration::from_millis(1));
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                socket.set_read_timeout(Some(Duration::from_secs(1)))?;
                let mut bytes = [0; 23];
                socket.read_exact(&mut bytes)?;
                received.push(bytes);
                if received.len() == 1 {
                    socket.shutdown(Shutdown::Both)?;
                } else {
                    socket.write_all(b"ACK")?;
                }
            }
            Ok(received)
        });
        let observed = observe_until(
            Observation::new(Kind::Submit, 0, 0, original.len()),
            Instant::now() + Duration::from_secs(3),
            || {
                let mut socket = TcpStream::connect(endpoint)?;
                socket.set_read_timeout(Some(Duration::from_secs(1)))?;
                socket.write_all(&original)?;
                let mut acknowledgement = [0; 3];
                socket.read_exact(&mut acknowledgement)?;
                if acknowledgement != *b"ACK" {
                    return Err(io::Error::other("Wrong public test ACK"));
                }
                Ok(Some(()))
            },
        );
        let received = receiver.join().unwrap().unwrap();
        observed.unwrap();
        received
    });
    assert_eq!(received, [original, original]);
}

#[test]
fn rejected_or_cancelled_observation_is_never_retried_as_availability() {
    for kind in [
        io::ErrorKind::InvalidData,
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::Interrupted,
    ] {
        let mut calls = 0;
        let result: io::Result<()> = observe_until(
            Observation::new(Kind::Checkpoint, 2, 0, 0),
            Instant::now() + Duration::from_secs(1),
            || {
                calls += 1;
                Err(io::Error::new(kind, "PUBLIC refusal"))
            },
        );
        assert_eq!(result.unwrap_err().kind(), kind);
        assert_eq!(calls, 1);
    }
}

#[test]
fn expired_observation_does_not_start_another_rpc() {
    let mut calls = 0;
    let result = observe_until(
        Observation::new(Kind::Body, 1, 0, 0),
        Instant::now() - Duration::from_secs(1),
        || {
            calls += 1;
            Ok(Some(()))
        },
    );
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(calls, 0);
}

#[test]
fn one_tcp_checkpoint_probe_falls_back_on_absence_or_lost_ack_but_rejects_malformed_data() {
    use std::net::TcpStream;

    // These public frames test observation policy only, never QC acceptance.
    for reply in [
        Some(b"ABSENT".as_slice()),
        None,
        Some(b"MALFORMED".as_slice()),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = listener.local_addr().unwrap();
        let original = b"PUBLIC CHECKPOINT PROBE";
        let mut calls = 0;
        let (observed, received) = std::thread::scope(|scope| {
            let receiver = scope.spawn(|| -> io::Result<Vec<u8>> {
                let deadline = Instant::now() + Duration::from_secs(3);
                let mut socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error)
                            if error.kind() == io::ErrorKind::WouldBlock
                                && Instant::now() < deadline =>
                        {
                            std::thread::park_timeout(Duration::from_millis(1));
                        }
                        Err(error) => return Err(error),
                    }
                };
                socket.set_read_timeout(Some(Duration::from_secs(1)))?;
                socket.set_write_timeout(Some(Duration::from_secs(1)))?;
                let request = peer_transport::read_frame(&mut socket, 64)?;
                if let Some(reply) = reply {
                    peer_transport::write_frame(&mut socket, reply, 64)?;
                }
                Ok(request)
            });
            let observed: io::Result<Option<()>> =
                once(Observation::new(Kind::Checkpoint, 0, 0, 0), || {
                    calls += 1;
                    let mut socket = TcpStream::connect_timeout(&endpoint, Duration::from_secs(1))?;
                    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
                    socket.set_write_timeout(Some(Duration::from_secs(1)))?;
                    peer_transport::write_frame(&mut socket, original, 64)?;
                    let reply = peer_transport::read_frame(&mut socket, 64)?;
                    if reply == b"ABSENT" {
                        Ok(None)
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Malformed public probe frame",
                        ))
                    }
                });
            (observed, receiver.join())
        });
        // Every actual socket worker is joined before outcome assertions.
        assert_eq!(received.unwrap().unwrap().as_slice(), original);
        assert_eq!(calls, 1);
        if reply == Some(b"MALFORMED".as_slice()) {
            assert_eq!(observed.unwrap_err().kind(), io::ErrorKind::InvalidData);
        } else {
            assert!(observed.unwrap().is_none());
        }
    }
}

#[test]
fn one_probe_does_not_turn_rejection_or_cancellation_into_missing_evidence() {
    for kind in [
        io::ErrorKind::InvalidData,
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::Interrupted,
    ] {
        let mut calls = 0;
        let observed: io::Result<Option<()>> =
            once(Observation::new(Kind::Checkpoint, 0, 0, 0), || {
                calls += 1;
                Err(io::Error::new(kind, "PUBLIC refusal"))
            });
        assert_eq!(observed.unwrap_err().kind(), kind);
        assert_eq!(calls, 1);
    }
}
