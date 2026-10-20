//! PUBLIC untrusted transport bytes, not valid BFV proofs or SQL answers.
//! These cases own framing/credit/cancellation only; production accept/finish
//! remain the real verifiers and require the existing genuine stream gates.
use super::*;
use std::{
    io::{Cursor, Write},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::Duration,
};

struct Duplex {
    incoming: Cursor<Vec<u8>>,
    outgoing: Vec<u8>,
}
impl Duplex {
    fn new(incoming: Vec<u8>) -> Self {
        Self {
            incoming: Cursor::new(incoming),
            outgoing: Vec::new(),
        }
    }
}
impl Read for Duplex {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.incoming.read(bytes)
    }
}
impl Write for Duplex {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.outgoing.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn binding() -> StreamBinding {
    StreamBinding {
        id: 42,
        digest: [0x51; 32],
        nonce: [0x52; 32],
    }
}
fn frame(b: StreamBinding, kind: u8, ordinal: usize, bytes: &[u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    b.send(&mut wire, kind, ordinal, bytes).unwrap();
    wire
}

#[test]
fn one_lookahead_sends_each_of_118_ordered_credits_once_and_leaves_terminal_unconsumed() {
    let b = binding();
    let mut incoming = Vec::new();
    for ordinal in 0..bfv_mul_relin_proof::PROOF_RECORDS {
        incoming.extend(frame(b, PROOF, ordinal, &[ordinal as u8]));
    }
    incoming.extend(frame(b, END, bfv_mul_relin_proof::PROOF_RECORDS, &[]));
    let mut stream = Duplex::new(incoming);
    let first = b.send(&mut stream, NEXT, 0, &[]).unwrap();
    let mut sent = first;
    let mut received = 0;
    for ordinal in 0..bfv_mul_relin_proof::PROOF_RECORDS {
        let before = stream.outgoing.len();
        let mut next_credit = 0;
        let bytes = receive_output_record(
            &mut stream,
            &b,
            ordinal,
            Instant::now(),
            None,
            &mut |n| received += n,
            |n| {
                sent += n;
                next_credit += 1;
            },
        )
        .unwrap();
        // Returned bytes are deliberately not cryptographic evidence. The real
        // caller must still accept them; this helper cannot mint any result.
        assert_eq!(bytes, [ordinal as u8]);
        if ordinal + 1 < bfv_mul_relin_proof::PROOF_RECORDS {
            assert_eq!(next_credit, 1);
            let credit = b
                .receive_observed(
                    &mut &stream.outgoing[before..],
                    NEXT,
                    ordinal + 1,
                    0,
                    |_| {},
                )
                .unwrap();
            assert!(credit.is_empty());
        } else {
            assert_eq!(next_credit, 0);
            assert_eq!(stream.outgoing.len(), before);
        }
    }
    let mut credits = stream.outgoing.as_slice();
    for ordinal in 0..bfv_mul_relin_proof::PROOF_RECORDS {
        assert!(
            b.receive_observed(&mut credits, NEXT, ordinal, 0, |_| {})
                .unwrap()
                .is_empty()
        );
    }
    assert!(credits.is_empty(), "No duplicate or 119th demand");
    assert_eq!(sent, first * bfv_mul_relin_proof::PROOF_RECORDS);
    assert!(received > 0);
    assert!(
        b.receive_observed(
            &mut stream,
            END,
            bfv_mul_relin_proof::PROOF_RECORDS,
            0,
            |_| {}
        )
        .unwrap()
        .is_empty()
    );
    assert_eq!(stream.read(&mut [0]).unwrap(), 0);
}

#[test]
fn malformed_truncated_foreign_and_extra_roles_issue_no_speculative_credit() {
    let b = binding();
    let mut truncated = frame(b, PROOF, 0, &[7]);
    truncated.pop();
    let foreign = StreamBinding {
        nonce: [0x77; 32],
        ..b
    };
    let mut bomb = frame(b, PROOF, 0, &[7]);
    let cap = bfv_mul_relin_proof::RECORD_HEADER + bfv_mul_relin_proof::MAX_PROOF_BYTES;
    bomb[8..16].copy_from_slice(&((cap + 97) as u64).to_be_bytes());
    let cases = [
        truncated,
        frame(b, PROOF, 1, &[7]),
        frame(foreign, PROOF, 0, &[7]),
        frame(b, END, 0, &[]),
        frame(b, FAILED, 0, &[1]),
        bomb,
    ];
    for wire in cases {
        let mut stream = Duplex::new(wire);
        let mut credits = 0;
        assert!(
            receive_output_record(
                &mut stream,
                &b,
                0,
                Instant::now(),
                None,
                &mut |_| {},
                |_| credits += 1,
            )
            .is_err()
        );
        assert_eq!(credits, 0);
        assert!(stream.outgoing.is_empty());
    }
    let mut stream = Duplex::new(frame(b, PROOF, bfv_mul_relin_proof::PROOF_RECORDS, &[7]));
    assert!(
        receive_output_record(
            &mut stream,
            &b,
            bfv_mul_relin_proof::PROOF_RECORDS,
            Instant::now(),
            None,
            &mut |_| {},
            |_| panic!("No extra-role credit"),
        )
        .is_err()
    );
    assert_eq!(
        stream.incoming.position(),
        0,
        "Reject extra role before reading its body"
    );
    assert!(stream.outgoing.is_empty());
}

#[test]
fn cancellation_before_or_after_one_credit_returns_no_record_for_native_acceptance() {
    let b = binding();
    let stopped = peer_transport::Cancellation::default();
    stopped.cancel();
    let mut untouched = Duplex::new(frame(b, PROOF, 0, &[7]));
    let result = receive_output_record(
        &mut untouched,
        &b,
        0,
        Instant::now(),
        Some(&stopped),
        &mut |_| {},
        |_| panic!("A pre-cancelled session cannot request work"),
    );
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
    assert_eq!(untouched.incoming.position(), 0);
    assert!(untouched.outgoing.is_empty());

    let token = peer_transport::Cancellation::default();
    let mut stream = Duplex::new(frame(b, PROOF, 0, &[7]));
    let result = receive_output_record(
        &mut stream,
        &b,
        0,
        Instant::now(),
        Some(&token),
        &mut |_| token.cancel(),
        |_| panic!("Cancellation after read must prevent next credit"),
    );
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
    assert!(stream.outgoing.is_empty());

    let token = peer_transport::Cancellation::default();
    let mut stream = Duplex::new(frame(b, PROOF, 0, &[7]));
    let result = receive_output_record(
        &mut stream,
        &b,
        0,
        Instant::now(),
        Some(&token),
        &mut |_| {},
        |_| token.cancel(),
    );
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
    let mut credits = stream.outgoing.as_slice();
    assert!(
        b.receive_observed(&mut credits, NEXT, 1, 0, |_| {})
            .unwrap()
            .is_empty()
    );
    assert!(
        credits.is_empty(),
        "At most the one already written credit escapes cancellation"
    );
}

#[test]
fn actual_loopback_peer_receives_next_credit_before_the_current_record_is_accepted() {
    let b = binding();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut peer, _) = listener.accept().unwrap();
    for socket in [&client, &peer] {
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
    }
    let (seen, observed) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || -> io::Result<()> {
        b.receive_observed(&mut peer, NEXT, 0, 0, |_| {})?;
        b.send(&mut peer, PROOF, 0, &[7])?;
        b.receive_observed(&mut peer, NEXT, 1, 0, |_| {})?;
        seen.send(()).map_err(io::Error::other)
    });
    let result = b.send(&mut client, NEXT, 0, &[]).and_then(|_| {
        receive_output_record(
            &mut client,
            &b,
            0,
            Instant::now(),
            None,
            &mut |_| {},
            |_| {},
        )
    });
    drop(client);
    let joined = worker.join();
    let next_seen = observed.recv_timeout(Duration::from_secs(1));
    // Release sockets and join the actual peer BEFORE any assertion, including
    // the failure path. No native verifier or positive SQL answer is simulated.
    assert!(joined.unwrap().is_ok());
    assert!(next_seen.is_ok());
    assert_eq!(result.unwrap(), [7]);
}
