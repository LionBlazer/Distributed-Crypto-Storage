//! Private actor queue contracts only. No signer, proof, SQL or native evaluator.
//! Import as a cfg(test) child module of finality::actor.
use super::{Command, Envelope, Handle, Reply, Snapshot};
use crate::finality::{BodyGate, InboxBytes, OwnedCompact};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, TryRecvError},
    },
    thread,
    time::{Duration, Instant},
};

const WAIT: Duration = Duration::from_secs(5);

fn queue(capacity: usize) -> (Handle, Receiver<Envelope>) {
    let (tx, rx) = mpsc::sync_channel(capacity);
    (
        Handle {
            tx,
            bytes: Arc::new(InboxBytes(Arc::new(AtomicUsize::new(0)))),
            stop: Arc::new(AtomicBool::new(false)),
        },
        rx,
    )
}
fn used(handle: &Handle) -> usize {
    handle.bytes.0.load(Ordering::Acquire)
}
fn error_kind(result: io::Result<Reply>) -> io::ErrorKind {
    match result {
        Err(error) => error.kind(),
        Ok(_) => panic!("queue rejection unexpectedly returned a reply"),
    }
}

#[test]
fn joint_metadata_calls_preserve_the_exact_expiry_and_release_their_leases() {
    for get_block in [false, true] {
        let (handle, receiver) = queue(1);
        let bodies = BodyGate::new();
        let expected_id = [0x32; 32];
        let command = if get_block {
            Command::GetBlock(expected_id, bodies.acquire().unwrap())
        } else {
            Command::Outbound(0)
        };
        let expires = Instant::now() + WAIT;
        let caller_handle = handle.clone();
        let caller = thread::spawn(move || caller_handle.call_joint(command, expires));
        let Envelope {
            command,
            reply,
            bytes,
            expires: received,
            queued_at: _,
        } = receiver.recv_timeout(WAIT).unwrap();
        assert_eq!(received, Some(expires));
        assert_eq!(used(&handle), 256);
        match command {
            Command::GetBlock(id, lease) => {
                assert!(get_block);
                assert_eq!(id, expected_id);
                assert!(bodies.acquire().is_err());
                drop(lease);
                // A terminal owner error forwards transparently and releases
                // the input lease. This test supplies no candidate/proof bytes.
                drop(bytes);
                assert!(
                    reply
                        .send(Err(io::Error::other("queue-only missing candidate")))
                        .is_ok()
                );
                assert_eq!(error_kind(caller.join().unwrap()), io::ErrorKind::Other);
            }
            Command::Outbound(0) => {
                assert!(!get_block);
                assert!(reply.send(Ok((Reply::Outbound(None), bytes))).is_ok());
                assert!(matches!(caller.join().unwrap(), Ok(Reply::Outbound(None))));
            }
            _ => panic!("unexpected metadata command"),
        }
        assert_eq!(used(&handle), 0);
        assert!(bodies.acquire().is_ok());
    }
}

#[test]
fn joint_queue_rejections_release_control_and_body_leases() {
    for resolve_compact in [false, true] {
        let (handle, receiver) = queue(1);
        assert_eq!(
            error_kind(handle.call_joint(Command::Outbound(0), Instant::now())),
            io::ErrorKind::TimedOut,
        );
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
        assert_eq!(used(&handle), 0);

        let bodies = BodyGate::new();
        let body_command = |id| {
            let lease = bodies.acquire().unwrap();
            if resolve_compact {
                // Deliberately unverified metadata/dummy bytes exercise only
                // actual queue rejection and ownership, never resolution,
                // a signer, native computation or an authenticated Body.
                Command::WordResolve(
                    OwnedCompact {
                        header: version_journal::Header {
                            genesis: [1; 32],
                            parent: [2; 32],
                            height: 3,
                            timestamp: 4,
                            target: version_journal::Target([255; 32]),
                            body_hash: id,
                            state_root: [6; 32],
                            nonce: 0,
                        },
                        body: vec![0; 8],
                        _lease: lease,
                    },
                    Snapshot {
                        slot: 3,
                        context: [7; 32],
                        parent: [2; 32],
                    },
                )
            } else {
                Command::GetBlock(id, lease)
            }
        };
        assert_eq!(
            error_kind(handle.call_joint(body_command([0x33; 32]), Instant::now())),
            io::ErrorKind::TimedOut,
        );
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
        assert_eq!(used(&handle), 0);
        assert!(bodies.acquire().is_ok());

        // Occupy the real bounded queue without consuming its envelope. The
        // second caller releases only its own control and Body reservations.
        let (reply, _response) = mpsc::sync_channel(1);
        assert!(
            handle
                .tx
                .try_send(Envelope {
                    command: Command::Outbound(1),
                    reply,
                    bytes: handle.bytes.acquire(256).unwrap(),
                    expires: Some(Instant::now() + WAIT),
                    queued_at: None,
                })
                .is_ok()
        );
        assert_eq!(
            error_kind(handle.call_joint(body_command([0x44; 32]), Instant::now() + WAIT)),
            io::ErrorKind::WouldBlock,
        );
        assert_eq!(used(&handle), 256);
        assert!(bodies.acquire().is_ok());
        drop(receiver);
        assert_eq!(used(&handle), 0);

        assert_eq!(
            error_kind(handle.call_joint(body_command([0x55; 32]), Instant::now() + WAIT)),
            io::ErrorKind::BrokenPipe,
        );
        assert_eq!(used(&handle), 0);
        assert!(bodies.acquire().is_ok());
    }
}

#[test]
fn queued_joint_caller_joins_the_actual_reply_even_after_its_expiry() {
    let (handle, receiver) = queue(1);
    let caller_handle = handle.clone();
    let (finished, completion) = mpsc::sync_channel(1);
    let caller = thread::spawn(move || {
        let expires = Instant::now() + Duration::from_millis(250);
        let result = caller_handle.call_joint(Command::Outbound(0), expires);
        assert!(finished.send(result).is_ok());
    });
    let Envelope {
        command,
        reply,
        bytes,
        expires,
        queued_at: _,
    } = receiver.recv_timeout(WAIT).unwrap();
    assert!(matches!(command, Command::Outbound(0)));
    let expires = expires.unwrap();
    let wait_past_expiry =
        expires.saturating_duration_since(Instant::now()) + Duration::from_millis(20);
    // Waiting on the caller's completion channel is the clock boundary under
    // test, not simulated proof work or an arbitrary scheduling sleep.
    assert!(matches!(
        completion.recv_timeout(wait_past_expiry),
        Err(RecvTimeoutError::Timeout)
    ));
    assert!(Instant::now() >= expires);
    assert_eq!(
        used(&handle),
        256,
        "in-flight work still owns its input lease"
    );
    assert!(reply.send(Ok((Reply::Outbound(None), bytes))).is_ok());
    assert!(matches!(
        completion.recv_timeout(WAIT).unwrap(),
        Ok(Reply::Outbound(None))
    ));
    caller.join().unwrap();
    assert_eq!(used(&handle), 0);
}
