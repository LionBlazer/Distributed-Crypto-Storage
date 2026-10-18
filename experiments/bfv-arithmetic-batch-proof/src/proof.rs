//! No auxiliary is decoded, transmitted or recomputed by the verifier.
use crate::{
    COMPONENTS, Context, Error, Expected, MAX_FRAME_BYTES, RelationOutput, RelationRequest,
    backend::{self, Backend, POLICY_BITS, Proof},
    codec,
    machine::Aux,
    statement,
};
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
    pub outputs: Vec<RelationOutput>,
    pub frame: Vec<u8>,
    pub report: backend::SecurityReport,
    pub generation_ms: f64,
}
/// Only the seventeen fixed public arithmetic relations, with no graph authority.
#[derive(Debug)]
pub struct CheckedBatch {
    input: [u8; 64],
    output: [u8; 64],
    profile: [u8; 64],
    report: backend::SecurityReport,
    pub verification_ms: f64,
}
impl CheckedBatch {
    /// Verifier-rebuilt assessments of all three phases with their existing union bound.
    pub fn security_report(&self) -> &backend::SecurityReport {
        &self.report
    }
    pub fn matches(&self, expected: &Expected) -> bool {
        self.profile == backend::profile(expected.context())
            && self.input == backend::digest(&expected.request_wire())
            && self.output == backend::digest(&expected.output_wire())
    }
}
fn header(expected: &Expected, lengths: &[usize; COMPONENTS]) -> Result<[u8; HEADER], Error> {
    let mut total = 0usize;
    for &length in lengths {
        if length == 0 || length > backend::COMPONENT_SERIALIZED_BOUND {
            return Err(Error::ResourceLimit);
        }
        total = total.checked_add(length).ok_or(Error::ResourceLimit)?;
    }
    if total > MAX_FRAME_BYTES - HEADER {
        return Err(Error::ResourceLimit);
    }
    let mut b = [0; HEADER];
    b[..8].copy_from_slice(b"BFVABP02");
    b[8..72].copy_from_slice(&backend::profile(expected.context()));
    b[72..104].copy_from_slice(&expected.context().query);
    b[104..136].copy_from_slice(&expected.context().setup);
    b[136..200].copy_from_slice(&backend::digest(&expected.request_wire()));
    b[200..264].copy_from_slice(&backend::digest(&expected.output_wire()));
    b[264..268].copy_from_slice(&17u32.to_le_bytes());
    b[268..272].copy_from_slice(&(COMPONENTS as u32).to_le_bytes());
    b[272..276].copy_from_slice(&(total as u32).to_le_bytes());
    for (i, &length) in lengths.iter().enumerate() {
        b[276 + 4 * i..280 + 4 * i].copy_from_slice(&(length as u32).to_le_bytes());
    }
    // Canonical phase boundaries, independently fixed rather than selected by wire.
    for (i, (start, end)) in [(0u8, 4u8), (4, 14), (14, 17)].into_iter().enumerate() {
        b[288 + 2 * i] = start;
        b[289 + 2 * i] = end;
    }
    Ok(b)
}
#[cfg(test)]
pub(crate) fn encode(expected: &Expected, proofs: &[Proof; COMPONENTS]) -> Result<Vec<u8>, Error> {
    let payloads = proofs
        .iter()
        .map(|p| postcard::to_allocvec(p).map_err(|_| Error::Encoding))
        .collect::<Result<Vec<_>, _>>()?;
    encode_payloads(expected, &payloads)
}
#[cfg(test)]
pub(crate) fn encode_payloads(expected: &Expected, payloads: &[Vec<u8>]) -> Result<Vec<u8>, Error> {
    if payloads.len() != COMPONENTS {
        return Err(Error::Frame);
    }
    let lengths = core::array::from_fn(|i| payloads[i].len());
    let mut bytes = header(expected, &lengths)?.to_vec();
    for payload in payloads {
        bytes.extend(payload);
    }
    Ok(bytes)
}
pub(crate) fn decode(expected: &Expected, bytes: &[u8]) -> Result<[Proof; COMPONENTS], Error> {
    if bytes.len() < HEADER || bytes.len() > MAX_FRAME_BYTES {
        return Err(Error::ResourceLimit);
    }
    let lengths = core::array::from_fn(|i| {
        u32::from_le_bytes(
            bytes[276 + 4 * i..280 + 4 * i]
                .try_into()
                .expect("checked header"),
        ) as usize
    });
    if bytes[..HEADER] != header(expected, &lengths)?
        || bytes.len() != HEADER + lengths.iter().sum::<usize>()
    {
        return Err(Error::Frame);
    }
    let payload = &bytes[HEADER..];
    // Fixed arrays add no Postcard length. ONE decoder charges all nested Vecs
    // in ALL THREE proofs before their reservations; there is no per-unit reset.
    let proofs: [Proof; COMPONENTS] = codec::decode(payload)?;
    let mut at = 0usize;
    for (i, proof) in proofs.iter().enumerate() {
        let canonical = postcard::to_allocvec(proof).map_err(|_| Error::Encoding)?;
        let end = at.checked_add(lengths[i]).ok_or(Error::ResourceLimit)?;
        if canonical.len() != lengths[i] || canonical != payload[at..end] {
            return Err(Error::Encoding);
        }
        at = end;
    }
    Ok(proofs)
}
pub(crate) fn layout(raw: &Proof, backend: &Backend) -> Result<(), Error> {
    let r = &backend.report;
    if raw.commitment.num_roots() != 1
        || raw.indexed.is_some()
        || raw.bus.is_some()
        || raw.sumcheck.round_polys.len() != r.outer_rounds
        || raw
            .sumcheck
            .round_polys
            .iter()
            .any(|p| p.len() != r.outer_degree)
        || !raw.sumcheck.pow_witnesses.is_empty()
    {
        return Err(Error::Encoding);
    }
    let lookup = raw.lookup.as_ref().ok_or(Error::Encoding)?;
    if lookup.layers.len() != r.lookup_rounds
        || lookup
            .layers
            .iter()
            .enumerate()
            .any(|(i, l)| l.round_polys.len() != i)
    {
        return Err(Error::Encoding);
    }
    let public = raw.preprocessed_opening.as_ref().ok_or(Error::Encoding)?;
    for (opening, schedule, is_public) in [
        (&raw.opening, &r.main_pcs, false),
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
    s: &backend::Schedule,
    phase: usize,
) -> Result<bool, Error> {
    let q = s.queries[phase];
    let maximum = backend::frontier_bound(q, backend::query_depth(s, phase)?)?;
    Ok(o.rows.len() == q
        && o.rows.iter().all(|r| r.len() == 1 << s.folding[phase])
        && o.proof.sibling_hashes.len() <= maximum)
}
pub(crate) fn evaluate(
    requests: &[RelationRequest],
) -> Result<(Vec<RelationOutput>, Vec<Aux>), Error> {
    let mut outputs = Vec::with_capacity(crate::RELATIONS);
    let mut aux = Vec::with_capacity(crate::RELATIONS);
    for r in requests {
        match r {
            RelationRequest::Scale(r) => {
                let e = bfv_scale_circuit::evaluate_with_certificate(r)
                    .map_err(|_| Error::Statement)?;
                outputs.push(RelationOutput::Scale(e.output));
                aux.push(Aux::Scale(e.aux));
            }
            RelationRequest::Tensor(r) => {
                let e = bfv_tensor_circuit::evaluate_with_certificate(r)
                    .map_err(|_| Error::Statement)?;
                outputs.push(RelationOutput::Tensor(e.output));
                aux.push(Aux::Tensor(e.aux));
            }
        }
    }
    Ok((outputs, aux))
}
pub fn prove(context: Context, requests: &[RelationRequest]) -> Result<Generated, Error> {
    statement::validate_requests(context, requests)?;
    let started = Instant::now();
    let mut outputs = Vec::with_capacity(crate::RELATIONS);
    for request in requests {
        let (mut result, aux) = evaluate(core::slice::from_ref(request))?;
        drop(aux);
        outputs.push(result.pop().ok_or(Error::Statement)?);
    }
    let expected = Expected::new(context, requests.to_vec(), outputs.clone())?;
    let mut assessed = Vec::with_capacity(COMPONENTS);
    for ordinal in 0..COMPONENTS {
        let backend = Backend::new(&expected, ordinal)?;
        assessed.push(backend.report.clone());
    }
    // Require the conservative whole floor before any main trace or proof.
    let _ = backend::summarize(assessed)?;
    let mut frame = vec![0; HEADER];
    let mut lengths = [0; COMPONENTS];
    let mut reports = Vec::with_capacity(COMPONENTS);
    for (ordinal, length) in lengths.iter_mut().enumerate() {
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
    frame[..HEADER].copy_from_slice(&header(&expected, &lengths)?);
    let report = backend::summarize(reports)?;
    Ok(Generated {
        outputs,
        frame,
        report,
        generation_ms: started.elapsed().as_secs_f64() * 1000.,
    })
}
pub(crate) fn prove_component(
    expected: &Expected,
    ordinal: usize,
) -> Result<(Vec<u8>, backend::ComponentReport), Error> {
    let backend = Backend::new(expected, ordinal)?;
    let range = statement::component_range(ordinal)?;
    let (outputs, aux) = evaluate(&expected.requests()[range.clone()])?;
    if outputs
        .iter()
        .zip(&expected.outputs()[range])
        .any(|(a, b)| a.encode() != b.encode())
    {
        return Err(Error::Statement);
    }
    drop(outputs);
    let traces = backend.machine.witness(&aux)?;
    drop(aux);
    let instances = ProverInstances::new(
        backend
            .machine
            .airs
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
            .airs
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
    if payload.len() > backend.report.bounds.serialized_bytes
        || payload.len() > backend::COMPONENT_SERIALIZED_BOUND
    {
        return Err(Error::ResourceLimit);
    }
    // Raw proof, AIRs, traces, PK, VK and PCS storage end before the next unit.
    // Only serialized public proof bytes and diagnostics escape this scope.
    Ok((payload, backend.report))
}
pub fn verify(expected: &Expected, frame: &[u8]) -> Result<CheckedBatch, Error> {
    catch_unwind(AssertUnwindSafe(|| verify_inner(expected, frame)))
        .unwrap_or(Err(Error::Verification))
}
fn verify_inner(expected: &Expected, frame: &[u8]) -> Result<CheckedBatch, Error> {
    let started = Instant::now();
    let proofs = decode(expected, frame)?;
    let mut reports = Vec::with_capacity(COMPONENTS);
    for (ordinal, raw) in proofs.into_iter().enumerate() {
        reports.push(verify_component(expected, ordinal, raw)?);
    }
    let report = backend::summarize(reports)?;
    Ok(CheckedBatch {
        input: backend::digest(&expected.request_wire()),
        output: backend::digest(&expected.output_wire()),
        profile: backend::profile(expected.context()),
        report,
        verification_ms: started.elapsed().as_secs_f64() * 1000.,
    })
}
pub(crate) fn verify_component(
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
            .airs
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
