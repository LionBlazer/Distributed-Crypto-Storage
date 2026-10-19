use super::*;
use crate::private_product::*;
use bfv_mul_relin_proof::{Expected, InputEvidence, Provenance, Verifier};
use bfv_product_evidence::{CatalogId, ProductStore, RecordingVerifier};
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
        self.private_product(object, provenance, ciphertext, inputs, None)
            .map(|(checked, _)| checked)
    }
    /// Execute the SAME genuine proof path and retain its public evidence in
    /// the caller's typed participant depot. Only END+EOF and full verification
    /// publish a catalog; cancellation/quota failure returns no checked result.
    /// A retained catalog supplies no SQL, freshness, finality or lock grant.
    pub fn prove_private_product_recorded(
        &self,
        object: [u8; 32],
        provenance: Provenance,
        ciphertext: &[u8],
        inputs: &InputEvidence<'_>,
        store: &mut ProductStore,
    ) -> io::Result<RecordedPrivateProduct> {
        let (checked, catalog) =
            self.private_product(object, provenance, ciphertext, inputs, Some(store))?;
        Ok(RecordedPrivateProduct {
            checked,
            catalog: catalog.ok_or_else(|| rejected("missing completed product catalog"))?,
        })
    }
    fn private_product(
        &self,
        object: [u8; 32],
        provenance: Provenance,
        ciphertext: &[u8],
        inputs: &InputEvidence<'_>,
        recording: Option<&mut ProductStore>,
    ) -> io::Result<(CheckedPrivateProduct, Option<CatalogId>)> {
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
        let result = (|| -> io::Result<(CheckedPrivateProduct, Option<CatalogId>)> {
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
            let mut verifier = match recording {
                Some(store) => ProductVerification::Recorded(Box::new(
                    RecordingVerifier::new(
                        store,
                        &expected,
                        &key,
                        object,
                        ciphertext,
                        &response.output,
                    )
                    .map_err(retention_error)?,
                )),
                None => ProductVerification::Ephemeral(Box::new(Verifier::new(&expected, &key))),
            };
            {
                let claims = binding.receive_observed(
                    &mut stream,
                    CLAIMS,
                    0,
                    bfv_mul_relin_proof::MAX_CLAIMS_BYTES,
                    &mut observed,
                )?;
                check_budget(started, cancellation.as_ref())?;
                verifier.accept_claims(&claims)?;
            }
            check_budget(started, cancellation.as_ref())?;
            verifier.verify_inputs(inputs)?;
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
                verifier.accept(&record)?;
            }
            let end = binding.receive_observed(
                &mut stream,
                END,
                bfv_mul_relin_proof::PROOF_RECORDS,
                0,
                &mut observed,
            )?;
            check_budget(started, cancellation.as_ref())?;
            let (product, catalog) =
                verifier.finish(&end, &mut stream, started, cancellation.as_ref())?;
            Ok((
                CheckedPrivateProduct {
                    product,
                    response: response.output,
                },
                catalog,
            ))
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

// A closed choice of the SAME actual verifier. No peer-supplied verification
// policy, cached receipt or configurable accept callback is introduced.
enum ProductVerification<'a> {
    Ephemeral(Box<Verifier<'a>>),
    Recorded(Box<RecordingVerifier<'a>>),
}
impl ProductVerification<'_> {
    fn accept_claims(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Ephemeral(v) => v.accept_claims(bytes).map_err(rejected),
            Self::Recorded(v) => v.accept_claims(bytes).map_err(retention_error),
        }
    }
    fn verify_inputs(&mut self, inputs: &InputEvidence<'_>) -> io::Result<()> {
        match self {
            Self::Ephemeral(v) => v.verify_inputs(inputs).map_err(rejected),
            Self::Recorded(v) => v.verify_inputs(inputs).map_err(retention_error),
        }
    }
    fn accept(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Ephemeral(v) => v.accept(bytes).map_err(rejected),
            Self::Recorded(v) => v.accept(bytes).map_err(retention_error),
        }
    }
    fn finish(
        self,
        end: &[u8],
        stream: &mut impl Read,
        started: Instant,
        cancellation: Option<&peer_transport::Cancellation>,
    ) -> io::Result<(bfv_mul_relin_proof::CheckedProduct, Option<CatalogId>)> {
        match self {
            Self::Ephemeral(v) => {
                if !end.is_empty() {
                    return Err(rejected("nonempty terminal"));
                }
                let mut trailing = [0];
                if stream.read(&mut trailing)? != 0 {
                    return Err(rejected("trailing stream bytes"));
                }
                check_budget(started, cancellation)?;
                Ok(((*v).finish().map_err(rejected)?, None))
            }
            Self::Recorded(v) => {
                let completed = (*v).finish(end, stream).map_err(retention_error)?;
                check_budget(started, cancellation)?;
                let (product, catalog) = completed.publish().map_err(retention_error)?.into_parts();
                Ok((product, Some(catalog)))
            }
        }
    }
}
fn retention_error(error: bfv_product_evidence::Error) -> io::Error {
    // Preserve the concrete storage/quota/proof error for the caller, rather
    // than collapsing a local ResourceLimit into an indistinguishable string.
    io::Error::new(io::ErrorKind::InvalidData, error)
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
