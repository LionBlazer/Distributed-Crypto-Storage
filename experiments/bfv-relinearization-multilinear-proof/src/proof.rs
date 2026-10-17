//! One public-Aux arithmetic proof, with verifier-owned preprocessing and SDK keys.
use crate::{
    Error, MAX_PROOF_BYTES,
    backend::{self, Backend, POLICY_BITS, Proof},
    codec,
};
use bfv_multilinear_stark::Val;
use bfv_relinearization_circuit::{
    Aux, DEGREE, Output, Request, Role, decode_aux, evaluate_with_certificate,
};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_multi_stark::{
    ProverInstance, ProverInstances, VerifierInstance, VerifierInstances, prove_with_security,
    verify_with_security,
};
use p3_sumcheck::layout::Table;
use p3_whir::QueryOpenings;
use serde::Serialize;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Instant;
pub(crate) const HEADER: usize = 144;
#[derive(Clone, Debug, Serialize)]
pub struct ProverTimings {
    pub arithmetic_and_certificate_ms: f64,
    pub public_setup_ms: f64,
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
/// One public arithmetic relation, without a key-authority or complete-operation capability.
#[derive(Debug)]
pub struct CheckedStage {
    role: Role,
    keyset_context: [u8; 32],
    input: [u8; 64],
    output: [u8; 64],
    pub timings: VerifierTimings,
}
impl CheckedStage {
    pub fn role(&self) -> Role {
        self.role
    }
    pub fn keyset_context(&self) -> [u8; 32] {
        self.keyset_context
    }
    pub fn matches(&self, input: &Request, output: &Output) -> bool {
        self.role == input.role()
            && output.role() == input.role()
            && self.keyset_context == input.keyset_context()
            && output.keyset_context() == input.keyset_context()
            && self.input == backend::digest(&input.encode())
            && self.output == backend::digest(&output.encode())
    }
}
fn header(input: &Request) -> [u8; HEADER] {
    let mut bytes = [0; HEADER];
    bytes[..8].copy_from_slice(b"BFVRLM01");
    bytes[8..72].copy_from_slice(&backend::profile_digest(input.role()));
    bytes[72..104].copy_from_slice(&input.binding());
    bytes[104..136].copy_from_slice(&input.keyset_context());
    bytes[136] = input.role() as u8;
    bytes[137] = match input.role() {
        Role::Embed => 1,
        Role::AccumulateAndAdd => 2,
    };
    bytes[138] = input.role().input_moduli().len() as u8;
    bytes[139] = input.role().output_moduli().len() as u8;
    bytes
}
pub(crate) fn encode_frame(input: &Request, aux: &Aux, proof: &Proof) -> Result<Vec<u8>, Error> {
    let payload = postcard::to_allocvec(proof).map_err(|_| Error::ProofEncoding)?;
    let aux = aux.encode();
    let size = HEADER
        .checked_add(aux.len())
        .and_then(|n| n.checked_add(payload.len()))
        .filter(|&n| n <= MAX_PROOF_BYTES)
        .ok_or(Error::ProofLength)?;
    if aux.len() != input.role().aux_bytes() {
        return Err(Error::Statement);
    }
    let mut bytes = header(input).to_vec();
    bytes.reserve(size - HEADER);
    bytes.extend(aux);
    bytes.extend(payload);
    Ok(bytes)
}
pub(crate) fn decode_frame(input: &Request, bytes: &[u8]) -> Result<(Aux, Proof), Error> {
    let split = HEADER
        .checked_add(input.role().aux_bytes())
        .ok_or(Error::ProofLength)?;
    if bytes.len() <= split || bytes.len() > MAX_PROOF_BYTES {
        return Err(Error::ProofLength);
    }
    if bytes[..HEADER] != header(input) {
        return Err(Error::Frame);
    }
    let aux = decode_aux(&bytes[HEADER..split]).map_err(|_| Error::Statement)?;
    if aux.encode() != bytes[HEADER..split] {
        return Err(Error::Statement);
    }
    let proof: Proof = codec::decode(&bytes[split..])?;
    if postcard::to_allocvec(&proof).map_err(|_| Error::ProofEncoding)? != bytes[split..] {
        return Err(Error::ProofEncoding);
    }
    Ok((aux, proof))
}
fn layout(proof: &Proof, backend: &Backend) -> Result<(), Error> {
    let report = &backend.report;
    if proof.lookup.is_some()
        || proof.indexed.is_some()
        || proof.bus.is_some()
        || proof.sumcheck.round_polys.len() != 13
        || proof
            .sumcheck
            .round_polys
            .iter()
            .any(|p| p.len() != report.constraint_degree + 1)
        || !proof.sumcheck.pow_witnesses.is_empty()
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
        if opening.evals.len() != 1
            || opening.evals[0].current().len()
                != if is_public {
                    report.preprocessed_width
                } else {
                    1
                }
            || !opening.evals[0].next().is_empty()
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
    let evaluated = evaluate_with_certificate(input).map_err(|_| Error::Statement)?;
    let arithmetic_and_certificate_ms = total.elapsed().as_secs_f64() * 1000.;
    let start = Instant::now();
    let backend = Backend::new(input, &evaluated.output, &evaluated.aux)?;
    let public_setup_ms = start.elapsed().as_secs_f64() * 1000.;
    let start = Instant::now();
    let wire = backend::envelope(input, &evaluated.aux);
    let out = evaluated.output.encode();
    let profile = backend::profile_digest(input.role());
    // All arithmetic values and carries are public preprocessing. This zero main
    // column is constrained by the existing AIR, not claimed as a private execution.
    let trace = RowMajorMatrix::new(vec![Val::ZERO; DEGREE], 1);
    let instances = ProverInstances::new(vec![ProverInstance::new(
        &backend.air,
        Table::new(trace.transpose()),
        &backend.prover,
        &backend.values,
    )]);
    let proof = prove_with_security(
        &backend.config,
        instances,
        0,
        POLICY_BITS,
        &mut backend.config.challenger(profile, &wire, &out),
    )
    .map_err(|_| Error::Proving)?;
    layout(&proof, &backend)?;
    let bytes = encode_frame(input, &evaluated.aux, &proof)?;
    Ok(Generated {
        output: evaluated.output,
        proof: bytes,
        timings: ProverTimings {
            arithmetic_and_certificate_ms,
            public_setup_ms,
            trace_proving_encoding_ms: start.elapsed().as_secs_f64() * 1000.,
            total_ms: total.elapsed().as_secs_f64() * 1000.,
        },
    })
}
/// Verifies the exact public relation without reduction, NTT, MAC or quotient/carry reevaluation.
pub fn verify(input: &Request, output: &Output, bytes: &[u8]) -> Result<CheckedStage, Error> {
    catch_unwind(AssertUnwindSafe(|| verify_inner(input, output, bytes)))
        .unwrap_or(Err(Error::Verification))
}
fn verify_inner(input: &Request, output: &Output, bytes: &[u8]) -> Result<CheckedStage, Error> {
    let total = Instant::now();
    let (aux, proof) = decode_frame(input, bytes)?;
    let start = Instant::now();
    let backend = Backend::new(input, output, &aux)?;
    layout(&proof, &backend)?;
    let public_setup_ms = start.elapsed().as_secs_f64() * 1000.;
    let wire = backend::envelope(input, &aux);
    let out = output.encode();
    let profile = backend::profile_digest(input.role());
    let Backend {
        air,
        values,
        config,
        prover,
        verifier,
        ..
    } = backend;
    drop(prover);
    let start = Instant::now();
    let instances = VerifierInstances::new(vec![VerifierInstance::new(
        &air,
        &verifier,
        backend::LOG_HEIGHT,
        &values,
    )]);
    verify_with_security(
        &config,
        instances,
        &proof,
        0,
        POLICY_BITS,
        &mut config.challenger(profile, &wire, &out),
    )
    .map_err(|_| Error::Verification)?;
    Ok(CheckedStage {
        role: input.role(),
        keyset_context: input.keyset_context(),
        input: backend::digest(&input.encode()),
        output: backend::digest(&out),
        timings: VerifierTimings {
            public_setup_ms,
            proof_verification_ms: start.elapsed().as_secs_f64() * 1000.,
            total_ms: total.elapsed().as_secs_f64() * 1000.,
        },
    })
}
