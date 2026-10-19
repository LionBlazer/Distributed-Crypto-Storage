use super::*;
use crate::private_product::*;
use bfv_mul_relin_proof::{Expected, InputEvidence, Provenance, Verifier};
use bfv_query_core::EvaluatedPrivateCoefficientPredicate;
use bfv_relinearization_key_source::PreparedKey;
use std::io::Read;

impl RemotePeer {
    /// Execute the actual private-input FHE product on this peer, verifying all
    /// input and output proof bytes against caller-owned independent provenance.
    /// Returns no SQL result, freshness certificate or lock grant.
    pub fn prove_private_product(
        &self,
        object: [u8; 32],
        provenance: Provenance,
        ciphertext: &[u8],
        inputs: &InputEvidence<'_>,
    ) -> io::Result<CheckedPrivateProduct> {
        let started = Instant::now();
        let cancellation = self.control.as_ref().and_then(|control| control.current());
        check_budget(started, cancellation.as_ref())?;
        let start = PrivateProductRequest::new(object, &provenance, ciphertext)?;
        InputEvidence::from_frames(inputs.frames()).map_err(rejected)?;
        check_budget(started, cancellation.as_ref())?;
        let key = PreparedKey::from_original(provenance.setup(), start.setup).map_err(rejected)?;
        check_budget(started, cancellation.as_ref())?;
        let id = self
            .next
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| rejected("request identity exhausted"))?;
        let digest = start.digest();
        let request = encode(&WireRequest {
            version: 2,
            id,
            request: Request::PrivateProduct(start),
        })?;
        let mut sent = 0;
        let mut received = 0;
        let result = (|| -> io::Result<CheckedPrivateProduct> {
            let mut stream = self
                .connector
                .connect_cancellable(&self.endpoint, cancellation.as_ref())?;
            let _deadline = stream.deadline(SESSION_BUDGET)?;
            stream.set_io_timeout(IO_BUDGET)?;
            write_frame(&mut stream, &request, MAX_FRAME_BYTES)?;
            sent += request.len();
            self.product_activity(id, ActivityPhase::RequestSent, request.len());
            let mut observed = |bytes| {
                received += bytes;
                self.product_activity(id, ActivityPhase::ReplyReceived, bytes);
            };
            let binding = StreamBinding::ready_observed(&mut stream, id, digest, &mut observed)?;
            for (ordinal, proof) in inputs.frames().into_iter().enumerate() {
                check_budget(started, cancellation.as_ref())?;
                let bytes = binding.send(&mut stream, INPUT, ordinal, proof)?;
                sent += bytes;
                self.product_activity(id, ActivityPhase::RequestSent, bytes);
            }
            let response =
                binding.receive_observed(&mut stream, OUTPUT, 0, response_cap(), &mut observed)?;
            check_budget(started, cancellation.as_ref())?;
            let response = EvaluatedPrivateCoefficientPredicate {
                output: response,
                ct_ct_multiplications: 1,
            };
            response
                .require_request(provenance.setup(), ciphertext)
                .map_err(rejected)?;
            let output = response
                .ciphertext_for_experiment()
                .map_err(rejected)?
                .to_vec();
            check_budget(started, cancellation.as_ref())?;
            let expected = Expected::new(provenance, output).map_err(rejected)?;
            let mut verifier = Verifier::new(&expected, &key);
            {
                let claims = binding.receive_observed(
                    &mut stream,
                    CLAIMS,
                    0,
                    bfv_mul_relin_proof::MAX_CLAIMS_BYTES,
                    &mut observed,
                )?;
                check_budget(started, cancellation.as_ref())?;
                verifier.accept_claims(&claims).map_err(rejected)?;
            }
            check_budget(started, cancellation.as_ref())?;
            verifier.verify_inputs(inputs).map_err(rejected)?;
            for ordinal in 0..bfv_mul_relin_proof::PROOF_RECORDS {
                check_budget(started, cancellation.as_ref())?;
                let demand = binding.send(&mut stream, NEXT, ordinal, &[])?;
                sent += demand;
                self.product_activity(id, ActivityPhase::RequestSent, demand);
                let record = binding.receive_observed(
                    &mut stream,
                    PROOF,
                    ordinal,
                    bfv_mul_relin_proof::RECORD_HEADER + bfv_mul_relin_proof::MAX_PROOF_BYTES,
                    &mut observed,
                )?;
                check_budget(started, cancellation.as_ref())?;
                verifier.accept(&record).map_err(rejected)?;
            }
            let end = binding.receive_observed(
                &mut stream,
                END,
                bfv_mul_relin_proof::PROOF_RECORDS,
                0,
                &mut observed,
            )?;
            if !end.is_empty() {
                return Err(rejected("nonempty terminal"));
            }
            let mut trailing = [0];
            if stream.read(&mut trailing)? != 0 {
                return Err(rejected("trailing stream bytes"));
            }
            check_budget(started, cancellation.as_ref())?;
            let product = verifier.finish().map_err(rejected)?;
            Ok(CheckedPrivateProduct {
                product,
                response: response.output,
            })
        })();
        if let Some(trace) = &self.trace {
            trace(Trace {
                peer: self.endpoint.identity,
                operation: "private-product".into(),
                request_id: id,
                request_bytes: sent as u64,
                response_bytes: received as u64,
                elapsed_ms: started.elapsed().as_secs_f64() * 1000.,
                succeeded: result.is_ok(),
            });
        }
        result
    }
    fn product_activity(&self, id: u64, phase: ActivityPhase, bytes: usize) {
        if let Some(activity) = &self.activity {
            activity(RpcActivity {
                peer: self.endpoint.identity,
                operation: "private-product".into(),
                request_id: id,
                phase,
                bytes: bytes as u64,
            });
        }
    }
}
fn check_budget(
    started: Instant,
    cancellation: Option<&peer_transport::Cancellation>,
) -> io::Result<()> {
    if let Some(token) = cancellation {
        token.check()?;
    }
    if started.elapsed() >= SESSION_BUDGET {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "private product expired",
        ));
    }
    Ok(())
}
