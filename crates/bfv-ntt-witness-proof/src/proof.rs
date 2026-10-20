//! Job-specific public preprocessing and one full NTT proof. Verification never
//! accepts an auxiliary certificate and never runs the NTT evaluator.
use crate::{
    Error, MAX_PROOF_BYTES,
    backend::{self, Backend, POLICY_BITS, Proof},
    codec,
};
use bfv_ntt_circuit::{Basis, Direction, Output, Request, evaluate_with_certificate};
use p3_multi_stark::{
    ProverInstance, ProverInstances, VerifierInstance, VerifierInstances, prove_with_security,
    verify_with_security,
};
use p3_sumcheck::layout::Table;
use p3_whir::QueryOpenings;
use serde::Serialize;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Instant;

pub(crate) const HEADER: usize = 256;
#[derive(Clone, Debug, Serialize)]
pub struct ProverTimings {
    pub arithmetic_and_certificate_ms: f64,
    pub public_setup_ms: f64,
    /// Certificate-to-trace conversion, included in trace_proving_encoding_ms.
    pub witness_build_ms: f64,
    pub trace_proving_encoding_ms: f64,
    pub total_ms: f64,
}
#[derive(Clone, Debug, Serialize)]
pub struct VerifierTimings {
    pub public_setup_ms: f64,
    pub proof_verification_ms: f64,
    pub total_ms: f64,
}
pub struct Generated {
    pub output: Output,
    pub proof: Vec<u8>,
    pub timings: ProverTimings,
}
/// One arithmetic stage only. This type cannot become a production operation.
#[derive(Debug)]
pub struct CheckedNtt {
    direction: Direction,
    basis: Basis,
    input: [u8; 64],
    output: [u8; 64],
    report: backend::SecurityReport,
    pub timings: VerifierTimings,
}
impl CheckedNtt {
    pub fn direction(&self) -> Direction {
        self.direction
    }
    pub fn basis(&self) -> Basis {
        self.basis
    }
    /// Verifier-rebuilt SDK assessment retained only after proof verification succeeds.
    pub fn security_report(&self) -> &crate::SecurityReport {
        &self.report
    }
    pub fn matches(&self, input: &Request, output: &Output) -> bool {
        self.direction == input.direction()
            && self.basis == input.basis()
            && self.input == backend::digest(&input.encode())
            && self.output == backend::digest(&output.encode())
    }
}
fn header(input: &Request, output: &Output, payload: usize) -> [u8; HEADER] {
    let mut bytes = [0; HEADER];
    bytes[..8].copy_from_slice(b"BFVNTW01");
    bytes[8..72].copy_from_slice(&backend::profile_digest(input.direction(), input.basis()));
    bytes[72..104].copy_from_slice(&input.binding());
    bytes[104] = backend::tag(input.direction());
    bytes[105] = input.basis().index();
    bytes[106] = if input.direction() == Direction::Forward {
        1
    } else {
        2
    };
    bytes[107] = if input.direction() == Direction::Forward {
        2
    } else {
        1
    };
    bytes[112..176].copy_from_slice(&backend::digest(&input.encode()));
    bytes[176..240].copy_from_slice(&backend::digest(&output.encode()));
    bytes[240..248].copy_from_slice(&(payload as u64).to_le_bytes());
    bytes[248..252].copy_from_slice(&((input.direction().stages() + 5) as u32).to_le_bytes());
    bytes
}
pub(crate) fn encode_frame(
    input: &Request,
    output: &Output,
    proof: &Proof,
) -> Result<Vec<u8>, Error> {
    let payload = postcard::to_allocvec(proof).map_err(|_| Error::ProofEncoding)?;
    if payload.len() > MAX_PROOF_BYTES - HEADER {
        return Err(Error::ProofLength);
    }
    let mut bytes = header(input, output, payload.len()).to_vec();
    bytes.extend(payload);
    Ok(bytes)
}
pub(crate) fn decode_frame(input: &Request, output: &Output, bytes: &[u8]) -> Result<Proof, Error> {
    if bytes.len() < HEADER || bytes.len() > MAX_PROOF_BYTES {
        return Err(Error::ProofLength);
    }
    if bytes[..HEADER] != header(input, output, bytes.len() - HEADER) {
        return Err(Error::Frame);
    }
    let proof: Proof = codec::decode(&bytes[HEADER..])?;
    if postcard::to_allocvec(&proof).map_err(|_| Error::ProofEncoding)? != bytes[HEADER..] {
        return Err(Error::ProofEncoding);
    }
    Ok(proof)
}
/// Bounded protocol layout before handing adversarial data to the SDK.
/// The SDK still checks every exact transcript, query, Merkle and polynomial rule.
fn layout(proof: &Proof, backend: &Backend) -> Result<(), Error> {
    let report = &backend.report;
    if proof.indexed.is_some()
        || proof.bus.is_some()
        || proof.sumcheck.round_polys.len() != 22
        || proof.sumcheck.round_polys.iter().any(|p| p.len() != 3)
        || !proof.sumcheck.pow_witnesses.is_empty()
    {
        return Err(Error::ProofEncoding);
    }
    let lookup = proof.lookup.as_ref().ok_or(Error::ProofEncoding)?;
    if lookup.layers.len() != 22
        || lookup
            .layers
            .iter()
            .enumerate()
            .any(|(i, l)| l.round_polys.len() != i)
    {
        return Err(Error::ProofEncoding);
    }
    let public = proof
        .preprocessed_opening
        .as_ref()
        .ok_or(Error::ProofEncoding)?;
    for (opening, schedule, is_public) in [
        (&proof.opening, &report.main_pcs, false),
        (public, &report.preprocessed_pcs, true),
    ] {
        if opening.evals.len() != report.air_count
            || opening.evals.iter().zip(&report.tables).any(|(e, t)| {
                e.current().len()
                    != if is_public {
                        t.preprocessed_width
                    } else {
                        t.main_width
                    }
                    || !e.next().is_empty()
            })
        {
            return Err(Error::ProofEncoding);
        }
        let whir = &opening.whir;
        if !whir.initial_ood_answers.is_empty()
            || whir.rounds.len() + 1 != schedule.queries.len()
            || whir.initial_sumcheck.polynomial_evaluations.len() != schedule.folding[0]
            || !whir.initial_sumcheck.pow_witnesses.is_empty()
            || whir
                .final_poly
                .as_ref()
                .is_none_or(|p| p.num_evals() != (1 << schedule.final_variables))
            || whir.final_sumcheck.as_ref().is_none_or(|p| {
                p.polynomial_evaluations.len() != schedule.final_variables
                    || !p.pow_witnesses.is_empty()
            })
        {
            return Err(Error::ProofEncoding);
        }
        for (i, round) in whir.rounds.iter().enumerate() {
            if !round.ood_answers.is_empty()
                || round.sumcheck.polynomial_evaluations.len() != schedule.folding[i + 1]
                || !round.sumcheck.pow_witnesses.is_empty()
            {
                return Err(Error::ProofEncoding);
            }
            let good = match &round.openings {
                QueryOpenings::Base(o) => {
                    i == 0 && bounded_rows(o, schedule.queries[i], 1 << schedule.folding[i])
                }
                QueryOpenings::Extension(o) => {
                    i != 0 && bounded_rows(o, schedule.queries[i], 1 << schedule.folding[i])
                }
            };
            if !good {
                return Err(Error::ProofEncoding);
            }
        }
        let last = schedule.queries.len() - 1;
        let good = match &whir.final_openings {
            QueryOpenings::Base(o) => {
                last == 0 && bounded_rows(o, schedule.queries[last], 1 << schedule.folding[last])
            }
            QueryOpenings::Extension(o) => {
                last != 0 && bounded_rows(o, schedule.queries[last], 1 << schedule.folding[last])
            }
        };
        if !good {
            return Err(Error::ProofEncoding);
        }
    }
    Ok(())
}
fn bounded_rows<T>(
    opening: &p3_whir::SharedProofOpening<T, p3_merkle_tree::PrunedMerklePaths<u64, 8>>,
    queries: usize,
    width: usize,
) -> bool {
    opening.rows.len() == queries
        && opening.rows.iter().all(|r| r.len() == width)
        && opening.proof.sibling_hashes.len() <= queries * backend::MAX_MERKLE_DEPTH
}
pub fn prove(input: &Request) -> Result<Generated, Error> {
    let total = Instant::now();
    let evaluation = evaluate_with_certificate(input).map_err(|_| Error::Statement)?;
    let arithmetic_and_certificate_ms = total.elapsed().as_secs_f64() * 1000.;
    let start = Instant::now();
    let backend = Backend::new(input, &evaluation.output)?;
    let public_setup_ms = start.elapsed().as_secs_f64() * 1000.;
    let start = Instant::now();
    let traces = backend
        .machine
        .witness(&evaluation.aux)
        .map_err(|_| Error::Statement)?;
    let witness_build_ms = start.elapsed().as_secs_f64() * 1000.;
    let instances = ProverInstances::new(
        backend
            .machine
            .airs()
            .iter()
            .zip(traces)
            .map(|(a, t)| ProverInstance::new(a, Table::new(t.transpose()), &backend.prover, &[]))
            .collect(),
    );
    let proof = prove_with_security(
        &backend.config,
        instances,
        0,
        POLICY_BITS,
        &mut backend.config.challenger(
            backend::profile_digest(input.direction(), input.basis()),
            &input.encode(),
            &evaluation.output.encode(),
        ),
    )
    .map_err(|_| Error::Proving)?;
    layout(&proof, &backend)?;
    let bytes = encode_frame(input, &evaluation.output, &proof)?;
    Ok(Generated {
        output: evaluation.output,
        proof: bytes,
        timings: ProverTimings {
            arithmetic_and_certificate_ms,
            public_setup_ms,
            witness_build_ms,
            trace_proving_encoding_ms: start.elapsed().as_secs_f64() * 1000.,
            total_ms: total.elapsed().as_secs_f64() * 1000.,
        },
    })
}
pub fn verify(input: &Request, output: &Output, bytes: &[u8]) -> Result<CheckedNtt, Error> {
    catch_unwind(AssertUnwindSafe(|| verify_inner(input, output, bytes)))
        .unwrap_or(Err(Error::Verification))
}
fn verify_inner(input: &Request, output: &Output, bytes: &[u8]) -> Result<CheckedNtt, Error> {
    let total = Instant::now();
    let proof = decode_frame(input, output, bytes)?;
    let start = Instant::now();
    let backend = Backend::new(input, output)?;
    layout(&proof, &backend)?;
    let public_setup_ms = start.elapsed().as_secs_f64() * 1000.;
    let Backend {
        machine,
        config,
        prover,
        verifier,
        report,
    } = backend;
    // The verifier retains no proving preprocessed codeword or main witness.
    drop(prover);
    let start = Instant::now();
    let instances = VerifierInstances::new(
        machine
            .airs()
            .iter()
            .map(|a| VerifierInstance::new(a, &verifier, a.height().ilog2() as usize, &[]))
            .collect(),
    );
    verify_with_security(
        &config,
        instances,
        &proof,
        0,
        POLICY_BITS,
        &mut config.challenger(
            backend::profile_digest(input.direction(), input.basis()),
            &input.encode(),
            &output.encode(),
        ),
    )
    .map_err(|_| Error::Verification)?;
    Ok(CheckedNtt {
        direction: input.direction(),
        basis: input.basis(),
        input: backend::digest(&input.encode()),
        output: backend::digest(&output.encode()),
        report,
        timings: VerifierTimings {
            public_setup_ms,
            proof_verification_ms: start.elapsed().as_secs_f64() * 1000.,
            total_ms: total.elapsed().as_secs_f64() * 1000.,
        },
    })
}
