//! Internal fixed hiding-FRI topology and canonical bounded SDK codec.
//! Caller-owned roles/profiles/limits and cryptographic verification stay outside.
use super::Config;
use crate::{PROOF_DEGREE_BITS, QUERIES, Val};
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::Proof;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Encoding,
    ResourceLimit,
    Shape,
}
/// Dimensions are selected only by a trusted statement policy, never decoded from a frame.
pub struct Topology {
    width: usize,
    chunks: usize,
}
impl Topology {
    pub fn checked(width: usize, chunks: usize) -> Result<Self, Error> {
        if width == 0 || width.checked_add(5).is_none() || !(2..=16).contains(&chunks) {
            return Err(Error::Shape);
        }
        Ok(Self { width, chunks })
    }
    pub fn check(&self, p: &Proof<Config>) -> Result<(), Error> {
        let v = &p.opened_values;
        if p.degree_bits != PROOF_DEGREE_BITS
            || p.ood_pow_witness != Val::ZERO
            || p.commitments.trace.num_roots() != 1
            || p.commitments.quotient_chunks.num_roots() != 1
            || p.commitments.random.as_ref().map(|c| c.num_roots()) != Some(1)
            || v.trace_local.len() != self.width
            || v.trace_next.as_ref().map(Vec::len) != Some(self.width)
            || v.preprocessed.is_some()
            || v.random.as_ref().map(Vec::len) != Some(5)
            || v.quotient_chunks.len() != self.chunks
            || v.quotient_chunks.iter().any(|c| c.len() != 5)
        {
            return Err(Error::Shape);
        }
        let (hidden, fri) = &p.opening_proof;
        if hidden.len() != 3 {
            return Err(Error::Shape);
        }
        for (round, matrices) in hidden.iter().enumerate() {
            let count = if round == 2 { self.chunks } else { 1 };
            let points = if round == 1 { 2 } else { 1 };
            if matrices.len() != count
                || matrices
                    .iter()
                    .any(|m| m.len() != points || m.iter().any(|v| v.len() != 5))
            {
                return Err(Error::Shape);
            }
        }
        if fri.batch_pow_witness != Val::ZERO
            || fri.query_pow_witness != Val::ZERO
            || fri.commit_phase_commits.len() != 10
            || fri.commit_phase_commits.iter().any(|c| c.num_roots() != 1)
            || fri.commit_pow_witnesses.len() != 10
            || fri.commit_pow_witnesses.iter().any(|v| *v != Val::ZERO)
            || fri.input_openings.len() != 3
            || fri.commit_phase_openings.len() != 10
            || fri.final_poly.len() != 1
        {
            return Err(Error::Shape);
        }
        for (batch, o) in fri.input_openings.iter().enumerate() {
            let matrices = if batch == 2 { self.chunks } else { 1 };
            let width = if batch == 1 { self.width + 5 } else { 10 };
            if !rows(&o.opened_values, matrices, width)
                || !rows(&o.opening_proof.0, matrices, 4)
                || o.opening_proof.1.sibling_hashes.len() > QUERIES * 13
            {
                return Err(Error::Shape);
            }
        }
        for (round, o) in fri.commit_phase_openings.iter().enumerate() {
            if o.sibling_values.len() != QUERIES
                || o.sibling_values.iter().any(|v| v.len() != 1)
                || !rows(&o.opening_proof.0, 1, 4)
                || o.opening_proof.1.sibling_hashes.len() > QUERIES * (12 - round)
            {
                return Err(Error::Shape);
            }
        }
        // The exact pruned frontier depends on transcript-derived queries. The
        // SDK reconstructs that frontier and rejects too few/many/reordered hashes.
        Ok(())
    }
}
fn rows<T>(values: &[Vec<Vec<T>>], matrices: usize, width: usize) -> bool {
    values.len() == QUERIES
        && values
            .iter()
            .all(|q| q.len() == matrices && q.iter().all(|row| row.len() == width))
}

pub fn serialize(proof: &Proof<Config>, shape: &Topology, cap: usize) -> Result<Vec<u8>, Error> {
    shape.check(proof)?;
    let bytes = postcard::to_allocvec(proof).map_err(|_| Error::Encoding)?;
    if bytes.len() > cap {
        return Err(Error::ResourceLimit);
    }
    Ok(bytes)
}
pub fn decode(
    bytes: &[u8],
    shape: &Topology,
    max_sequence_elements: usize,
    slots: usize,
) -> Result<Proof<Config>, Error> {
    let (proof, trailing) = bounded_postcard::take_from_bytes::<Proof<Config>>(
        bytes,
        bounded_postcard::Limits {
            max_sequence_elements,
            max_total_elements: slots,
        },
    )
    .map_err(|error| match error {
        bounded_postcard::Error::ResourceLimit => Error::ResourceLimit,
        bounded_postcard::Error::Encoding => Error::Encoding,
    })?;
    if !trailing.is_empty() {
        return Err(Error::Encoding);
    }
    shape.check(&proof)?;
    if postcard::to_allocvec(&proof).map_err(|_| Error::Encoding)? != bytes {
        return Err(Error::Encoding);
    }
    Ok(proof)
}
