use crate::{
    Context, Error, Expected, MAX_COMPONENT_PROOF_BYTES, MAX_FRAME_BYTES,
    backend::{self, Backend, POLICY_BITS, Proof},
    codec,
};
use bfv_ntt_circuit::{Output, Request, evaluate_with_certificate};
use p3_field::PrimeCharacteristicRing;
use p3_multi_stark::{
    ProverInstance, ProverInstances, VerifierInstance, VerifierInstances, prove_with_security,
    verify_with_security,
};
use p3_sumcheck::layout::Table;
use p3_whir::QueryOpenings;
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    time::Instant,
};

pub(crate) const HEADER: usize = 320;
pub struct Generated {
    pub outputs: Vec<Output>,
    pub frame: Vec<u8>,
    pub report: backend::SecurityReport,
    pub generation_ms: f64,
}
/// Sealed full arithmetic result; never a partial grant, SQL or setup/freshness authority.
pub struct CheckedBatch {
    input: [u8; 64],
    output: [u8; 64],
    profile: [u8; 64],
    pub verification_ms: f64,
}
impl CheckedBatch {
    pub fn matches(&self, expected: &Expected) -> bool {
        self.profile == backend::profile(expected)
            && self.input == backend::digest(&expected.request_wire())
            && self.output == backend::digest(&expected.output_wire())
    }
}
fn header(expected: &Expected, lengths: &[usize; 4]) -> Result<[u8; HEADER], Error> {
    let count = expected.component_count();
    let mut total = 0usize;
    for (i, &n) in lengths.iter().enumerate() {
        if (i < count
            && (n == 0 || n > MAX_COMPONENT_PROOF_BYTES || n > backend::COMPONENT_SERIALIZED_BOUND))
            || (i >= count && n != 0)
        {
            return Err(Error::ResourceLimit);
        }
        total = total.checked_add(n).ok_or(Error::ResourceLimit)?;
    }
    if total > MAX_FRAME_BYTES - HEADER {
        return Err(Error::ResourceLimit);
    }
    let mut b = [0; HEADER];
    b[..8].copy_from_slice(b"BFVNTB02");
    b[8..72].copy_from_slice(&backend::profile(expected));
    b[72..104].copy_from_slice(&expected.context().query);
    b[104..136].copy_from_slice(&expected.context().setup);
    b[136..200].copy_from_slice(&backend::digest(&expected.request_wire()));
    b[200..264].copy_from_slice(&backend::digest(&expected.output_wire()));
    b[264..268].copy_from_slice(&(expected.requests().len() as u32).to_le_bytes());
    b[268..272].copy_from_slice(&(total as u32).to_le_bytes());
    for (i, &n) in lengths.iter().enumerate() {
        b[272 + i * 4..276 + i * 4].copy_from_slice(&(n as u32).to_le_bytes());
    }
    Ok(b)
}
fn assemble(
    expected: &Expected,
    lengths: [usize; 4],
    mut bytes: Vec<u8>,
) -> Result<Vec<u8>, Error> {
    let prefix = header(expected, &lengths)?;
    let expected_length = HEADER + lengths.iter().sum::<usize>();
    if bytes.len() != expected_length {
        return Err(Error::Frame);
    }
    bytes[..HEADER].copy_from_slice(&prefix);
    Ok(bytes)
}
#[cfg(test)]
pub(crate) fn encode(expected: &Expected, proofs: &[Proof]) -> Result<Vec<u8>, Error> {
    if proofs.len() != expected.component_count() {
        return Err(Error::Frame);
    }
    let payloads = proofs
        .iter()
        .map(|p| postcard::to_allocvec(p).map_err(|_| Error::Encoding))
        .collect::<Result<Vec<_>, _>>()?;
    encode_payloads(expected, &payloads)
}
#[cfg(test)]
pub(crate) fn encode_payloads(expected: &Expected, payloads: &[Vec<u8>]) -> Result<Vec<u8>, Error> {
    if payloads.len() != expected.component_count() {
        return Err(Error::Frame);
    }
    let mut lengths = [0; 4];
    for (i, p) in payloads.iter().enumerate() {
        lengths[i] = p.len();
    }
    let prefix = header(expected, &lengths)?;
    let mut b = prefix.to_vec();
    for p in payloads {
        b.extend(p);
    }
    Ok(b)
}
pub(crate) fn decode(expected: &Expected, bytes: &[u8]) -> Result<Vec<Proof>, Error> {
    if bytes.len() < HEADER || bytes.len() > MAX_FRAME_BYTES {
        return Err(Error::ResourceLimit);
    }
    let mut lengths = [0; 4];
    for (i, n) in lengths.iter_mut().enumerate() {
        *n = u32::from_le_bytes(
            bytes[272 + i * 4..276 + i * 4]
                .try_into()
                .map_err(|_| Error::Frame)?,
        ) as usize;
    }
    if bytes[..HEADER] != header(expected, &lengths)?
        || bytes.len() != HEADER + lengths.iter().sum::<usize>()
    {
        return Err(Error::Frame);
    }
    let payload = &bytes[HEADER..];
    // Postcard fixed arrays have no length prefix. This ONE deserialize call
    // shares one nested budget across every component before Vec reservations.
    // The independently supplied Expected, never the frame, chooses the array.
    let proofs: Vec<Proof> = match expected.component_count() {
        1 => Vec::from(codec::decode::<[Proof; 1]>(payload)?),
        2 => Vec::from(codec::decode::<[Proof; 2]>(payload)?),
        4 => Vec::from(codec::decode::<[Proof; 4]>(payload)?),
        _ => return Err(Error::Statement),
    };
    let mut at = 0usize;
    for (i, p) in proofs.iter().enumerate() {
        let canonical = postcard::to_allocvec(p).map_err(|_| Error::Encoding)?;
        let end = at.checked_add(lengths[i]).ok_or(Error::ResourceLimit)?;
        if canonical.len() != lengths[i] || canonical != payload[at..end] {
            return Err(Error::Encoding);
        }
        at = end;
    }
    Ok(proofs)
}
pub(crate) fn layout(proof: &Proof, backend: &Backend) -> Result<(), Error> {
    let r = &backend.report;
    if proof.commitment.num_roots() != 1
        || proof.indexed.is_some()
        || proof.bus.is_some()
        || proof.sumcheck.round_polys.len() != r.outer_rounds
        || proof.sumcheck.round_polys.iter().any(|p| p.len() != 3)
        || !proof.sumcheck.pow_witnesses.is_empty()
    {
        return Err(Error::Encoding);
    }
    let lookup = proof.lookup.as_ref().ok_or(Error::Encoding)?;
    if lookup.layers.len() != r.lookup_rounds
        || lookup
            .layers
            .iter()
            .enumerate()
            .any(|(i, l)| l.round_polys.len() != i)
    {
        return Err(Error::Encoding);
    }
    let public = proof.preprocessed_opening.as_ref().ok_or(Error::Encoding)?;
    for (opening, schedule, is_public) in [
        (&proof.opening, &r.main_pcs, false),
        (public, &r.preprocessed_pcs, true),
    ] {
        if opening.evals.len() != r.air_count
            || opening.evals.iter().zip(&r.tables).any(|(e, t)| {
                e.current().len()
                    != (if is_public {
                        t.preprocessed_width
                    } else {
                        t.main_width
                    })
                    || !e.next().is_empty()
            })
        {
            return Err(Error::Encoding);
        }
        let w = &opening.whir;
        if !w.initial_ood_answers.is_empty()
            || w.rounds.len() + 1 != schedule.queries.len()
            || w.initial_sumcheck.polynomial_evaluations.len() != schedule.folding[0]
            || !w.initial_sumcheck.pow_witnesses.is_empty()
            || w.final_poly
                .as_ref()
                .is_none_or(|p| p.num_evals() != (1 << schedule.final_variables))
            || w.final_pow_witness != backend::Val::ZERO
            || w.final_sumcheck.as_ref().is_none_or(|p| {
                p.polynomial_evaluations.len() != schedule.final_variables
                    || !p.pow_witnesses.is_empty()
            })
        {
            return Err(Error::Encoding);
        }
        for (i, round) in w.rounds.iter().enumerate() {
            if round.commitment.as_ref().is_none_or(|c| c.num_roots() != 1)
                || round.pow_witness != backend::Val::ZERO
                || !round.ood_answers.is_empty()
                || round.sumcheck.polynomial_evaluations.len() != schedule.folding[i + 1]
                || !round.sumcheck.pow_witnesses.is_empty()
            {
                return Err(Error::Encoding);
            }
            let good = match &round.openings {
                QueryOpenings::Base(o) => i == 0 && rows(o, schedule, i)?,
                QueryOpenings::Extension(o) => i != 0 && rows(o, schedule, i)?,
            };
            if !good {
                return Err(Error::Encoding);
            }
        }
        let i = schedule.queries.len() - 1;
        let good = match &w.final_openings {
            QueryOpenings::Base(o) => i == 0 && rows(o, schedule, i)?,
            QueryOpenings::Extension(o) => i != 0 && rows(o, schedule, i)?,
        };
        if !good {
            return Err(Error::Encoding);
        }
    }
    Ok(())
}
fn rows<T>(
    o: &p3_whir::SharedProofOpening<T, p3_merkle_tree::PrunedMerklePaths<u64, 8>>,
    schedule: &backend::Schedule,
    phase: usize,
) -> Result<bool, Error> {
    let queries = schedule.queries[phase];
    let depth = backend::query_depth(schedule, phase)?;
    let maximum = backend::frontier_bound(queries, depth)?;
    Ok(o.rows.len() == queries
        && o.rows
            .iter()
            .all(|row| row.len() == 1 << schedule.folding[phase])
        && o.proof.sibling_hashes.len() <= maximum)
}
fn prove_component(
    expected: &Expected,
    ordinal: usize,
) -> Result<(Vec<u8>, backend::ComponentReport), Error> {
    let backend = Backend::new(expected, ordinal)?;
    let range = expected.component_range(ordinal)?;
    let mut aux = Vec::with_capacity(2);
    for (request, output) in expected.requests()[range.clone()]
        .iter()
        .zip(&expected.outputs()[range])
    {
        let evaluation = evaluate_with_certificate(request).map_err(|_| Error::Statement)?;
        if evaluation.output.encode() != output.encode() {
            return Err(Error::Statement);
        }
        aux.push(evaluation.aux);
    }
    let traces = backend
        .machine
        .witness(&aux)
        .map_err(|_| Error::Statement)?;
    drop(aux);
    let instances = ProverInstances::new(
        backend
            .machine
            .airs()
            .iter()
            .zip(traces)
            .map(|(a, t)| ProverInstance::new(a, Table::new(t.transpose()), &backend.prover, &[]))
            .collect(),
    )
    .with_lookup_materialization(p3_multi_stark::LookupMaterialization::Streaming);
    let raw = prove_with_security(
        &backend.config,
        instances,
        0,
        POLICY_BITS,
        &mut backend::challenger(&backend.config, expected, ordinal)?,
    )
    .map_err(|_| Error::Proving)?;
    layout(&raw, &backend)?;
    let instances = VerifierInstances::new(
        backend
            .machine
            .airs()
            .iter()
            .map(|a| VerifierInstance::new(a, &backend.verifier, a.height().ilog2() as usize, &[]))
            .collect(),
    );
    verify_with_security(
        &backend.config,
        instances,
        &raw,
        0,
        POLICY_BITS,
        &mut backend::challenger(&backend.config, expected, ordinal)?,
    )
    .map_err(|_| Error::Verification)?;
    let payload = postcard::to_allocvec(&raw).map_err(|_| Error::Encoding)?;
    if payload.len() > MAX_COMPONENT_PROOF_BYTES
        || payload.len() > backend.report.bounds.serialized_bytes
    {
        return Err(Error::ResourceLimit);
    }
    // This function's scope drops raw proof, AIRs, PK, VK and PCS data before
    // the caller starts the next unit. Only bytes and diagnostics escape.
    Ok((payload, backend.report))
}
pub fn prove(context: Context, requests: &[Request]) -> Result<Generated, Error> {
    crate::statement::validate_requests(context, requests)?;
    let start = Instant::now();
    let mut outputs = Vec::with_capacity(requests.len());
    for request in requests {
        // Retain only the full output, not every operation's private Aux.
        let evaluation = evaluate_with_certificate(request).map_err(|_| Error::Statement)?;
        outputs.push(evaluation.output);
    }
    let expected = Expected::new(context, requests.to_vec(), outputs.clone())?;
    let mut assessed = Vec::with_capacity(expected.component_count());
    for ordinal in 0..expected.component_count() {
        let backend = Backend::new(&expected, ordinal)?;
        assessed.push(backend.report.clone());
        drop(backend);
    }
    // Whole union floor before any private trace or proof. Setup here commits
    // fixed public PP only; prover Aux is regenerated one pair at a time.
    let _ = backend::summarize(&expected, assessed)?;
    let mut frame = vec![0; HEADER];
    let mut lengths = [0; 4];
    let mut reports = Vec::with_capacity(expected.component_count());
    for (ordinal, length) in lengths
        .iter_mut()
        .enumerate()
        .take(expected.component_count())
    {
        let (payload, report) = prove_component(&expected, ordinal)?;
        *length = payload.len();
        if frame
            .len()
            .checked_add(payload.len())
            .is_none_or(|n| n > MAX_FRAME_BYTES)
        {
            return Err(Error::ResourceLimit);
        }
        frame.extend(payload);
        reports.push(report);
    }
    let frame = assemble(&expected, lengths, frame)?;
    let report = backend::summarize(&expected, reports)?;
    Ok(Generated {
        outputs,
        frame,
        report,
        generation_ms: start.elapsed().as_secs_f64() * 1000.,
    })
}
pub fn verify(expected: &Expected, frame: &[u8]) -> Result<CheckedBatch, Error> {
    catch_unwind(AssertUnwindSafe(|| verify_inner(expected, frame)))
        .unwrap_or(Err(Error::Verification))
}
fn verify_component(
    expected: &Expected,
    ordinal: usize,
    raw: Proof,
) -> Result<backend::ComponentReport, Error> {
    let backend = Backend::new(expected, ordinal)?;
    layout(&raw, &backend)?;
    let Backend {
        machine,
        config,
        prover,
        verifier,
        report,
    } = backend;
    drop(prover);
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
        &raw,
        0,
        POLICY_BITS,
        &mut backend::challenger(&config, expected, ordinal)?,
    )
    .map_err(|_| Error::Verification)?;
    Ok(report)
}
fn verify_inner(expected: &Expected, frame: &[u8]) -> Result<CheckedBatch, Error> {
    let started = Instant::now();
    let proofs = decode(expected, frame)?;
    let mut reports = Vec::with_capacity(expected.component_count());
    for (ordinal, raw) in proofs.into_iter().enumerate() {
        reports.push(verify_component(expected, ordinal, raw)?);
    }
    // No CheckedComponent exists. The only result follows ALL actual SDK
    // verifications and an independently reconstructed conservative union floor.
    let _ = backend::summarize(expected, reports)?;
    Ok(CheckedBatch {
        profile: backend::profile(expected),
        input: backend::digest(&expected.request_wire()),
        output: backend::digest(&expected.output_wire()),
        verification_ms: started.elapsed().as_secs_f64() * 1000.,
    })
}
