//! One bounded process-local entry. Admission consumes an already allocated SDK
//! proof, meters actual owned capacities, then performs actual verification.
//! This is not a bounded network decoder or a whole-process memory bound.
use super::{StateStatement, query::QueryStatement, version_tag};
use crate::backend::{Backend, Config, Error, PROOF_DEGREE_BITS, Val};
use crate::opening::selection::trace::Witness;
use p3_symmetric::MerkleCap;
use p3_uni_stark::{Commitments, Proof};
use std::mem::size_of;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum AdmissionError {
    Missing,
    Foreign,
    Capacity,
    Proof(Error),
}
impl From<Error> for AdmissionError {
    fn from(value: Error) -> Self {
        Self::Proof(value)
    }
}
impl From<AdmissionError> for Error {
    fn from(value: AdmissionError) -> Self {
        match value {
            AdmissionError::Proof(error) => error,
            _ => Self::Shape,
        }
    }
}

/// Untrusted owned input plus measured heap. No authority until admit verifies.
/// Non-Clone/nonserializable, no mutable proof or accounting accessor.
pub(super) struct Candidate {
    statement: StateStatement,
    proof: Proof<Config>,
    heap_bytes: usize,
}
impl Candidate {
    pub(super) fn new(
        statement: StateStatement,
        proof: Option<Proof<Config>>,
    ) -> Result<Self, AdmissionError> {
        if statement.source.relation != super::Relation::StateCertificate
            || statement.source.request != version_tag(&statement.source)
        {
            return Err(AdmissionError::Foreign);
        }
        let proof = proof.ok_or(AdmissionError::Missing)?;
        let (proof, mut bytes) = account_proof(proof)?;
        for packet in &statement.source.packets {
            bytes.vector(packet)?;
        }
        Ok(Self {
            statement,
            proof,
            heap_bytes: bytes.total,
        })
    }
    pub(super) fn owned_bytes(&self) -> Result<usize, AdmissionError> {
        size_of::<Self>()
            .checked_add(self.heap_bytes)
            .ok_or(AdmissionError::Capacity)
    }
}

/// Only admit constructs this, AFTER actual source proof verification.
/// Retains the original completed proof; never Backend/FFT/prover data/witness.
struct VerifiedStateCertificate {
    statement: StateStatement,
    proof: Proof<Config>,
    heap_bytes: usize,
}
pub(super) struct CertificateCache {
    limit: usize,
    entry: Option<VerifiedStateCertificate>,
}
pub(super) struct StateLease<'a> {
    certificate: &'a VerifiedStateCertificate,
}
impl CertificateCache {
    fn metadata_bytes() -> usize {
        // Reserve one lease header even when idle. &mut lease() permits at most
        // one outstanding lease; it owns no further heap or cloned certificate.
        size_of::<Self>()
            .checked_add(size_of::<StateLease<'static>>())
            .expect("Two fixed metadata headers fit usize")
    }
    pub(super) fn new(limit: usize) -> Result<Self, AdmissionError> {
        if Self::metadata_bytes() > limit {
            return Err(AdmissionError::Capacity);
        }
        Ok(Self { limit, entry: None })
    }
    pub(super) fn owned_bytes(&self) -> usize {
        Self::metadata_bytes()
            .checked_add(self.entry.as_ref().map_or(0, |e| e.heap_bytes))
            .expect("Admission checked owned capacity plus metadata")
    }
    pub(super) fn admit(
        &mut self,
        expected: &StateStatement,
        candidate: Candidate,
    ) -> Result<(), AdmissionError> {
        if !expected.matches(&candidate.statement.source) {
            return Err(AdmissionError::Foreign);
        }
        // Old entry + prospective candidate remain charged together. Refusing a
        // replacement or a failed verification cannot discard the old entry.
        let prospective = self
            .owned_bytes()
            .checked_add(candidate.owned_bytes()?)
            .ok_or(AdmissionError::Capacity)?;
        if prospective > self.limit {
            return Err(AdmissionError::Capacity);
        }
        Backend::new(&candidate.statement)?.verify(&candidate.statement, &candidate.proof)?;
        self.entry = Some(VerifiedStateCertificate {
            statement: candidate.statement,
            proof: candidate.proof,
            heap_bytes: candidate.heap_bytes,
        });
        Ok(())
    }
    pub(super) fn lease<'a>(
        &'a mut self,
        expected: &StateStatement,
    ) -> Result<StateLease<'a>, AdmissionError> {
        let certificate = self.entry.as_ref().ok_or(AdmissionError::Missing)?;
        if !expected.matches(&certificate.statement.source) {
            return Err(AdmissionError::Foreign);
        }
        Ok(StateLease { certificate })
    }
    pub(super) fn clear(&mut self) {
        self.entry = None;
    }
}
impl StateLease<'_> {
    pub(super) fn source_proof_degree_bits(&self) -> usize {
        self.certificate.proof.degree_bits
    }
    pub(super) fn prove_query(
        &self,
        statement: &QueryStatement,
        witness: &Witness,
    ) -> Result<Proof<Config>, Error> {
        statement.require_state(&self.certificate.statement)?;
        Backend::new(statement)?.prove_with_trace(statement, || witness.trace(statement.source()))
    }
    pub(super) fn verify_query(
        &self,
        statement: &QueryStatement,
        proof: &Proof<Config>,
    ) -> Result<(), Error> {
        statement.require_state(&self.certificate.statement)?;
        Backend::new(statement)?.verify(statement, proof)
    }
}

/// Checked arithmetic over owned allocations, not serialized lengths or len().
/// Vec capacities include nested Vec/SDK metadata headers exactly once per heap.
struct HeapBytes {
    total: usize,
}
impl HeapBytes {
    fn add(&mut self, bytes: usize) -> Result<(), AdmissionError> {
        self.total = self
            .total
            .checked_add(bytes)
            .ok_or(AdmissionError::Capacity)?;
        Ok(())
    }
    fn vector<T>(&mut self, values: &Vec<T>) -> Result<(), AdmissionError> {
        self.add(
            values
                .capacity()
                .checked_mul(size_of::<T>())
                .ok_or(AdmissionError::Capacity)?,
        )
    }
    fn rows<T>(&mut self, values: &Vec<Vec<T>>) -> Result<(), AdmissionError> {
        self.vector(values)?;
        for row in values {
            self.vector(row)?;
        }
        Ok(())
    }
    fn matrices<T>(&mut self, values: &Vec<Vec<Vec<T>>>) -> Result<(), AdmissionError> {
        self.vector(values)?;
        for matrix in values {
            self.rows(matrix)?;
        }
        Ok(())
    }
    fn rounds<T>(&mut self, values: &Vec<Vec<Vec<Vec<T>>>>) -> Result<(), AdmissionError> {
        self.vector(values)?;
        for round in values {
            self.matrices(round)?;
        }
        Ok(())
    }
    fn cap(
        &mut self,
        cap: MerkleCap<Val, [Val; 4]>,
    ) -> Result<MerkleCap<Val, [Val; 4]>, AdmissionError> {
        // SDK0.8 hides cap.capacity(). Consume its public into_roots(), measure
        // the actual returned allocation and rewrap the SAME checked roots.
        let roots = cap.into_roots();
        self.vector(&roots)?;
        Ok(MerkleCap::new(roots))
    }
}

/// Exhaustive traversal of this pinned Config's public owning proof layout.
/// No Serialize/Deserialize counting, unsafe access or assumptions capacity=len.
/// Temporary normalization/caller construction/allocator overhead/verifier work
/// are outside the retained-owned budget; no preallocation or peak-RAM claim.
fn account_proof(proof: Proof<Config>) -> Result<(Proof<Config>, HeapBytes), AdmissionError> {
    let Proof {
        commitments,
        opened_values,
        opening_proof,
        degree_bits,
        ood_pow_witness,
    } = proof;
    let Commitments {
        trace,
        quotient_chunks,
        random,
    } = commitments;
    let mut bytes = HeapBytes { total: 0 };
    let trace = bytes.cap(trace)?;
    let quotient_chunks = bytes.cap(quotient_chunks)?;
    let random = random.map(|c| bytes.cap(c)).transpose()?;
    bytes.vector(&opened_values.trace_local)?;
    if let Some(next) = &opened_values.trace_next {
        bytes.vector(next)?;
    }
    if let Some(preprocessed) = &opened_values.preprocessed {
        bytes.vector(&preprocessed.local)?;
        if let Some(next) = &preprocessed.next {
            bytes.vector(next)?;
        }
    }
    bytes.rows(&opened_values.quotient_chunks)?;
    if let Some(random) = &opened_values.random {
        bytes.vector(random)?;
    }
    let (hiding_openings, mut fri) = opening_proof;
    bytes.rounds(&hiding_openings)?;
    fri.commit_phase_commits = fri
        .commit_phase_commits
        .into_iter()
        .map(|cap| bytes.cap(cap))
        .collect::<Result<Vec<_>, _>>()?;
    bytes.vector(&fri.commit_phase_commits)?;
    bytes.vector(&fri.commit_pow_witnesses)?;
    bytes.vector(&fri.input_openings)?;
    for opening in &fri.input_openings {
        bytes.matrices(&opening.opened_values)?;
        bytes.matrices(&opening.opening_proof.0)?;
        bytes.vector(&opening.opening_proof.1.sibling_hashes)?;
    }
    bytes.vector(&fri.commit_phase_openings)?;
    for opening in &fri.commit_phase_openings {
        bytes.rows(&opening.sibling_values)?;
        bytes.matrices(&opening.opening_proof.0)?;
        bytes.vector(&opening.opening_proof.1.sibling_hashes)?;
    }
    bytes.vector(&fri.final_poly)?;
    if degree_bits != PROOF_DEGREE_BITS {
        return Err(AdmissionError::Proof(Error::SecurityProfile));
    }
    Ok((
        Proof {
            commitments: Commitments {
                trace,
                quotient_chunks,
                random,
            },
            opened_values,
            opening_proof: (hiding_openings, fri),
            degree_bits,
            ood_pow_witness,
        },
        bytes,
    ))
}

#[cfg(test)]
mod accounting_tests {
    use super::*;
    #[test]
    fn checked_owned_capacity_arithmetic_rejects_overflow_without_wrapping() {
        let mut bytes = HeapBytes { total: usize::MAX };
        assert_eq!(bytes.add(1), Err(AdmissionError::Capacity));
        assert_eq!(bytes.total, usize::MAX);
    }
}
