//! Connection-scoped real FHE proving. No retained jobs, owner secrets or SQL grants.
use super::*;
use crate::private_product::{self as protocol, *};
use bfv_mul_relin_proof::{Expected, INPUT_FRAMES, InputEvidence, Provenance, Prover};
use bfv_relinearization_key_source::PreparedKey;
use std::io::Write;
use std::time::Instant;

pub(super) fn serve(
    shared: &Arc<Shared>,
    remote: [u8; 32],
    id: u64,
    request: PrivateProductRequest,
    start_bytes: usize,
    stream: &mut peer_transport::AcceptedConnection,
) -> io::Result<()> {
    // The request is already byte-bounded, but no manifest/SDK/proof work runs
    // for an unprivileged TLS identity.
    if remote != shared.owner {
        return Err(rejected("unauthorized private product"));
    }
    let digest = request.digest();
    let mut nonce = [0; 32];
    getrandom::getrandom(&mut nonce).map_err(rejected)?;
    let binding = StreamBinding { id, digest, nonce };
    let started = Instant::now();
    let _deadline = peer_transport::ConnectionDeadline::new(&stream.sock, SESSION_BUDGET)?;
    let mut sent = 0usize;
    let mut received = start_bytes;
    let result = (|| -> io::Result<()> {
        let _permit = shared.proof_busy.try_acquire().map_err(io::Error::other)?;
        let (setup, heads) = {
            let mut state = shared.state.lock().map_err(rejected)?;
            let version = state
                .store
                .audit_version(&request.object)
                .map_err(rejected)?;
            let heads = [version.data_head().encode(), version.index_head().encode()];
            let setup = state
                .setups
                .get(&request.setup)
                .ok_or_else(|| rejected("unknown public setup"))?
                .public
                .clone();
            (setup, heads)
        };
        let provenance = Provenance::decode_claim(setup, &request.provenance).map_err(rejected)?;
        request.require_envelope(&provenance)?;
        if provenance.encodings()[0].expected.source_claim().heads != heads {
            return Err(rejected("private product custody mismatch"));
        }
        budget(shared, stream, started)?;
        sent += binding.send(stream, READY, 0, &[])?;
        let mut frames: [Vec<u8>; INPUT_FRAMES] = std::array::from_fn(|_| Vec::new());
        for (ordinal, frame) in frames.iter_mut().enumerate() {
            budget(shared, stream, started)?;
            *frame = binding.receive_observed(
                stream,
                INPUT,
                ordinal,
                bfv_mul_relin_proof::input_frame_limit(ordinal).unwrap(),
                |bytes| received = received.saturating_add(bytes),
            )?;
            if frame.is_empty() {
                return Err(rejected("empty input proof"));
            }
        }
        {
            budget(shared, stream, started)?;
            let evidence = InputEvidence::from_frames(frames.each_ref().map(Vec::as_slice))
                .map_err(rejected)?;
            provenance.verify_inputs(&evidence).map_err(rejected)?;
        }
        // All uploaded input proof buffers die before SDK/output proof work.
        drop(frames);
        budget(shared, stream, started)?;
        let evaluator = PeerEvaluator::from_public_setup(provenance.setup()).map_err(rejected)?;
        let evaluated = evaluator
            .evaluate_private_coefficient_predicate_for_experiment(&request.ciphertext)
            .map_err(rejected)?;
        let raw = evaluated
            .ciphertext_for_experiment()
            .map_err(rejected)?
            .to_vec();
        drop(evaluator);
        let key =
            PreparedKey::from_original(provenance.setup(), request.setup).map_err(rejected)?;
        let expected = Expected::new(provenance, raw).map_err(rejected)?;
        let mut prover = Prover::new(&expected, &key).map_err(rejected)?;
        budget(shared, stream, started)?;
        sent += binding.send(stream, OUTPUT, 0, &evaluated.output)?;
        let claims = prover
            .graph()
            .claims()
            .encode(bfv_mul_relin_proof::profile_digest());
        sent += binding.send(stream, CLAIMS, 0, &claims)?;
        drop(claims);
        for ordinal in 0..bfv_mul_relin_proof::PROOF_RECORDS {
            budget(shared, stream, started)?;
            // Demand follows successful client verification of the preceding
            // stage. Disconnect/cancellation is observed before more native work.
            binding.receive_observed(stream, NEXT, ordinal, 0, |bytes| {
                received = received.saturating_add(bytes)
            })?;
            budget(shared, stream, started)?;
            // Native proving is synchronous. Cancellation/expiry prevents the
            // next stage and delivery, not the in-flight native computation.
            let record = prover
                .prove_next()
                .map_err(rejected)?
                .ok_or_else(|| rejected("missing proof record"))?;
            budget(shared, stream, started)?;
            sent += binding.send(stream, PROOF, ordinal, &record)?;
        }
        if prover.prove_next().map_err(rejected)?.is_some() {
            return Err(rejected("extra proof record"));
        }
        budget(shared, stream, started)?;
        sent += binding.send(stream, END, bfv_mul_relin_proof::PROOF_RECORDS, &[])?;
        Ok(())
    })();
    if let Err(error) = &result {
        let code = if matches!(
            error
                .get_ref()
                .and_then(|e| e.downcast_ref::<RemoteError>()),
            Some(RemoteError::Busy)
        ) {
            2
        } else {
            1
        };
        if let Ok(bytes) = binding.send(stream, FAILED, 0, &[code]) {
            sent = sent.saturating_add(bytes);
        }
    }
    stream.conn.send_close_notify();
    let _ = stream.flush();
    if let Ok(mut state) = shared.state.lock() {
        state.received = state.received.saturating_add(received as u64);
        state.sent = state.sent.saturating_add(sent as u64);
        state.sequence = state.sequence.saturating_add(1);
        let sequence = state.sequence;
        state.recent.push_back(Observation {
            sequence,
            time_ms: now(),
            remote,
            operation: "private-product".into(),
            received_bytes: received as u64,
            sent_bytes: sent as u64,
            succeeded: result.is_ok(),
        });
        while state.recent.len() > 128 {
            state.recent.pop_front();
        }
    }
    result
}
fn budget(
    shared: &Shared,
    stream: &peer_transport::AcceptedConnection,
    started: Instant,
) -> io::Result<()> {
    if shared.stop.load(Ordering::Acquire) {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "peer stopping"));
    }
    let remaining = protocol::SESSION_BUDGET
        .checked_sub(started.elapsed())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "private product expired"))?;
    let timeout = remaining.min(protocol::IO_BUDGET);
    stream.sock.set_read_timeout(Some(timeout))?;
    stream.sock.set_write_timeout(Some(timeout))
}
