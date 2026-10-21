//! Closed canonical frame and exact native five-round hiding PCS topology.
use super::{Error, Expected, Result, assessment::Assessment, profile};
use crate::air::{DEGREE_BITS, PP_WIDTH, WIDTH};
use bfv_hiding_stark::{Config, LOG_BLOWUP, QUERIES, Val};
use p3_batch_stark::BatchProof;
use p3_field::PrimeCharacteristicRing;

const MAGIC: &[u8; 8] = b"HLOGWP01";
pub(super) const HEADER_BYTES: usize = 96;
pub(super) const MAX_PAYLOAD: usize = 4 * 1024 * 1024;
pub(super) const MAX_SEQUENCE: usize = 4096;
// A conservative count of the fixed native shape is below857000 slots, including
// Gold's eight-byte arrays, EF5 wrappers and pruned Merkle frontiers.
pub(super) const MAX_SLOTS: usize = 1024 * 1024;

pub(super) fn payload<'a>(expected: &Expected, frame: &'a [u8]) -> Result<&'a [u8]> {
    if frame.len() < HEADER_BYTES || frame.len() > HEADER_BYTES + MAX_PAYLOAD {
        return Err(Error::Resource);
    }
    if &frame[..8] != MAGIC
        || frame[8..40] != profile()
        || frame[40..72] != expected.context
        || frame[72..76] != expected.output.to_le_bytes()
        || frame[80..96].iter().any(|&v| v != 0)
    {
        return Err(Error::Encoding);
    }
    let len = u32::from_le_bytes(frame[76..80].try_into().map_err(|_| Error::Encoding)?) as usize;
    if len == 0 || len > MAX_PAYLOAD || len.checked_add(HEADER_BYTES) != Some(frame.len()) {
        return Err(Error::Encoding);
    }
    Ok(&frame[HEADER_BYTES..])
}

pub(super) fn encode(
    expected: &Expected,
    proof: &BatchProof<Config>,
    assessment: &Assessment,
) -> Result<Vec<u8>> {
    check(proof, assessment)?;
    let bytes = postcard::to_allocvec(proof).map_err(|_| Error::Encoding)?;
    frame(expected, &bytes)
}
fn frame(expected: &Expected, bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.is_empty() || bytes.len() > MAX_PAYLOAD {
        return Err(Error::Resource);
    }
    let mut result = Vec::with_capacity(HEADER_BYTES + bytes.len());
    result.extend_from_slice(MAGIC);
    result.extend_from_slice(&profile());
    result.extend_from_slice(&expected.context);
    result.extend_from_slice(&expected.output.to_le_bytes());
    result.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    result.extend_from_slice(&[0; 16]);
    result.extend_from_slice(bytes);
    Ok(result)
}

pub(super) fn decode(bytes: &[u8], assessment: &Assessment) -> Result<BatchProof<Config>> {
    if bytes.is_empty() || bytes.len() > MAX_PAYLOAD {
        return Err(Error::Resource);
    }
    let (proof, tail) = bounded_postcard::take_from_bytes::<BatchProof<Config>>(
        bytes,
        bounded_postcard::Limits {
            max_sequence_elements: MAX_SEQUENCE,
            max_total_elements: MAX_SLOTS,
        },
    )
    .map_err(|error| match error {
        bounded_postcard::Error::Encoding => Error::Encoding,
        bounded_postcard::Error::ResourceLimit => Error::Resource,
    })?;
    if !tail.is_empty() {
        return Err(Error::Encoding);
    }
    check(&proof, assessment)?;
    if postcard::to_allocvec(&proof).map_err(|_| Error::Encoding)? != bytes {
        return Err(Error::Encoding);
    }
    Ok(proof)
}

pub(super) fn check(p: &BatchProof<Config>, assessment: &Assessment) -> Result<()> {
    let chunks = assessment.chunks();
    let aux = assessment.aux_width();
    if !(2..=8).contains(&chunks)
        || aux == 0
        || aux > 25
        || !(1..=4).contains(&assessment.packed_lookup_count())
        || p.degree_bits != [DEGREE_BITS]
        || p.opened_values.instances.len() != 1
        || p.lookup_terminals.len() != 1
        || !p.lookup_terminals[0]
            .as_ref()
            .is_some_and(|v| v.0 == bfv_hiding_stark::Challenge::ZERO)
        || p.lookup_pow_witness != Some(Val::ZERO)
        || p.ood_pow_witness != Val::ZERO
        || p.commitments.main.num_roots() != 1
        || p.commitments.quotient_chunks.num_roots() != 1
        || p.commitments.permutation.as_ref().map(|c| c.num_roots()) != Some(1)
        || p.commitments.random.as_ref().map(|c| c.num_roots()) != Some(1)
    {
        return Err(Error::Shape);
    }
    let opened = &p.opened_values.instances[0];
    let base = &opened.base_opened_values;
    if base.trace_local.len() != WIDTH
        || base.trace_next.is_some()
        || base.preprocessed.as_ref().map(|p| p.local.len()) != Some(PP_WIDTH)
        || base.preprocessed.as_ref().is_some_and(|p| p.next.is_some())
        || base.random.as_ref().map(Vec::len) != Some(5)
        || base.quotient_chunks.len() != chunks
        || base.quotient_chunks.iter().any(|v| v.len() != 5)
        || opened.permutation_local.len() != aux
        || opened.permutation_next.len() != aux
    {
        return Err(Error::Shape);
    }
    let (hidden, fri) = &p.opening_proof;
    if hidden.len() != 5 {
        return Err(Error::Shape);
    }
    for (round, matrices) in hidden.iter().enumerate() {
        let count = if round == 2 { chunks } else { 1 };
        let points = if round == 4 { 2 } else { 1 };
        let blind_width = if round == 3 { 0 } else { 5 };
        if matrices.len() != count
            || matrices
                .iter()
                .any(|m| m.len() != points || m.iter().any(|v| v.len() != blind_width))
        {
            return Err(Error::Shape);
        }
    }
    if fri.batch_pow_witness != Val::ZERO
        || fri.query_pow_witness != Val::ZERO
        || fri.commit_phase_commits.len() != 10
        || fri.commit_phase_commits.iter().any(|v| v.num_roots() != 1)
        || fri.commit_pow_witnesses.len() != 10
        || fri.commit_pow_witnesses.iter().any(|&v| v != Val::ZERO)
        || fri.input_openings.len() != 5
        || fri.commit_phase_openings.len() != 10
        || fri.final_poly.len() != 1
    {
        return Err(Error::Shape);
    }
    for (round, opened) in fri.input_openings.iter().enumerate() {
        let matrices = if round == 2 { chunks } else { 1 };
        let width = match round {
            0 | 2 => 10,
            1 => WIDTH + 5,
            3 => PP_WIDTH,
            4 => aux + 5,
            _ => return Err(Error::Shape),
        };
        if !rows(&opened.opened_values, matrices, width)
            || !rows(&opened.opening_proof.0, matrices, 4)
            || opened.opening_proof.1.sibling_hashes.len()
                > frontier_bound(DEGREE_BITS + LOG_BLOWUP)
        {
            return Err(Error::Shape);
        }
    }
    for (round, opened) in fri.commit_phase_openings.iter().enumerate() {
        if opened.sibling_values.len() != QUERIES
            || opened.sibling_values.iter().any(|v| v.len() != 1)
            || !rows(&opened.opening_proof.0, 1, 4)
            || opened.opening_proof.1.sibling_hashes.len()
                > frontier_bound(DEGREE_BITS + LOG_BLOWUP - 1 - round)
        {
            return Err(Error::Shape);
        }
    }
    Ok(())
}
fn rows<T>(values: &[Vec<Vec<T>>], matrices: usize, width: usize) -> bool {
    values.len() == QUERIES
        && values
            .iter()
            .all(|query| query.len() == matrices && query.iter().all(|row| row.len() == width))
}

/// At a binary-tree level, each missing sibling belongs to a distinct opened
/// parent. Their count is at most both Q and the number of parents at that level.
/// This positive sum remains an upper bound when query indices repeat.
pub(super) fn frontier_bound(depth: usize) -> usize {
    (0..depth)
        .map(|level| QUERIES.min(1 << (depth - level - 1)))
        .sum()
}

#[cfg(test)]
pub(super) fn repaired_frame(expected: &Expected, proof: &BatchProof<Config>) -> Vec<u8> {
    // Untrusted hostile bytes only: deliberately bypass output shape checks for negatives.
    frame(expected, &postcard::to_allocvec(proof).unwrap()).unwrap()
}
