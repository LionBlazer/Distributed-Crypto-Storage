//! Fixed Source-only candidate topology; no submitted dimensions or configuration.
use crate::config::Config;
use crate::{Error, Val};
use bfv_hiding_stark::{PROOF_DEGREE_BITS, QUERIES};
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::Proof;
pub(super) fn check(p: &Proof<Config>) -> Result<(), Error> {
    let v = &p.opened_values;
    if p.degree_bits != PROOF_DEGREE_BITS
        || p.ood_pow_witness != Val::ZERO
        || p.commitments.trace.num_roots() != 1
        || p.commitments.quotient_chunks.num_roots() != 1
        || p.commitments.random.as_ref().map(|c| c.num_roots()) != Some(1)
        || v.trace_local.len() != registry200_proof::source::layout::PACKED_WIDTH
        || v.trace_next.as_ref().map(Vec::len)
            != Some(registry200_proof::source::layout::PACKED_WIDTH)
        || v.preprocessed.is_some()
        || v.random.as_ref().map(Vec::len) != Some(5)
        || v.quotient_chunks.len() != 16
        || v.quotient_chunks.iter().any(|c| c.len() != 5)
    {
        return Err(Error::Shape);
    }
    let (hidden, fri) = &p.opening_proof;
    if hidden.len() != 3 {
        return Err(Error::Shape);
    }
    for (round, matrices) in hidden.iter().enumerate() {
        let count = if round == 2 { 16 } else { 1 };
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
        let matrices = if batch == 2 { 16 } else { 1 };
        let width = if batch == 1 {
            registry200_proof::source::layout::PACKED_WIDTH + 5
        } else {
            10
        };
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
fn rows<T>(values: &[Vec<Vec<T>>], matrices: usize, width: usize) -> bool {
    values.len() == QUERIES
        && values
            .iter()
            .all(|q| q.len() == matrices && q.iter().all(|row| row.len() == width))
}
