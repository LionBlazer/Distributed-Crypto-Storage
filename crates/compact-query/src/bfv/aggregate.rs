//! Complete authenticated selection composed with the genuine convolution proof.
use super::*;
use bfv_query_proof::{CheckedOperation, Operation};

/// Single-use exact source selection; private fields prevent caller-chosen rows.
pub struct PreparedProvableAggregate {
    request: Vec<u8>,
    pending: bfv_core::PendingPolynomialAggregate,
    heads: crate::ReadHeads,
}
impl PreparedProvableAggregate {
    pub fn request(&self) -> &[u8] {
        &self.request
    }
    fn ensure_current(&self, heads: &crate::ReadHeads) -> Result<()> {
        if heads != &self.heads {
            return Err(Error::WrongVersion);
        }
        Ok(())
    }
}

pub struct VerifiedAggregate {
    count: u32,
    sum: u32,
    evidence: CheckedOperation,
}
impl VerifiedAggregate {
    pub fn count(&self) -> u32 {
        self.count
    }
    pub fn sum(&self) -> Option<u32> {
        (self.count != 0).then_some(self.sum)
    }
    pub fn evidence(&self) -> &CheckedOperation {
        &self.evidence
    }
}

impl Owner {
    pub fn prepare_provable_aggregate(
        &self,
        table: &Table,
        predicate: Option<AgeRange>,
        budget: usize,
        limits: Limits,
    ) -> Result<PreparedProvableAggregate> {
        self.prepare_provable_aggregate_from_source(&table.read_view(), predicate, budget, limits)
    }
    /// Uses the same complete selection parser for full snapshots and immutable
    /// posting prefixes. The caller supplies independently authorized read heads.
    pub fn prepare_provable_aggregate_from_source(
        &self,
        source: &crate::ReadView<'_>,
        predicate: Option<AgeRange>,
        budget: usize,
        limits: Limits,
    ) -> Result<PreparedProvableAggregate> {
        let selection = self.proof_selection_read(
            source,
            predicate,
            crate::index::MaterializationBudget::aggregate(budget),
            limits,
        )?;
        let context = bfv_core::QueryContext::new(
            crate::random_id()?,
            selection.data_head.encode(),
            selection.index_head.encode(),
        );
        let prepared = self
            .key
            .prepare_polynomial_aggregate(context, &selection.fields)?;
        // Source plaintext is needed only for encrypting the genuine input, never
        // for computing the answer or retaining an aggregate retry capability.
        drop(selection);
        Ok(PreparedProvableAggregate {
            request: prepared.request,
            pending: prepared.pending,
            heads: source.heads().clone(),
        })
    }
    /// Retains the encrypted request and pending capability after a bad replica response.
    pub fn check_aggregate_proof(
        &self,
        table: &Table,
        prepared: &PreparedProvableAggregate,
        output: &[u8],
        proof: &[u8],
    ) -> Result<CheckedOperation> {
        self.check_aggregate_proof_for_heads(&table.read_heads(), prepared, output, proof)
    }
    /// Checks the exact retained request and complete logical table/head binding
    /// without retaining either source image while a peer computes its answer.
    pub fn check_aggregate_proof_for_heads(
        &self,
        heads: &crate::ReadHeads,
        prepared: &PreparedProvableAggregate,
        output: &[u8],
        proof: &[u8],
    ) -> Result<CheckedOperation> {
        prepared.ensure_current(heads)?;
        let input = self.linear.aggregate_circuit_request(prepared.request())?;
        bfv_query_proof::verify(&input, output, proof)
            .map_err(|error| Error::ComputationProof(error.to_string()))
    }
    pub fn complete_checked_aggregate(
        &self,
        table: &Table,
        prepared: PreparedProvableAggregate,
        output: &[u8],
        evidence: CheckedOperation,
    ) -> Result<VerifiedAggregate> {
        self.complete_checked_aggregate_for_heads(&table.read_heads(), prepared, output, evidence)
    }
    /// The network caller must establish agreed freshness before this consumes
    /// the one-use pending state and decrypts the genuine encrypted result.
    pub fn complete_checked_aggregate_for_heads(
        &self,
        heads: &crate::ReadHeads,
        prepared: PreparedProvableAggregate,
        output: &[u8],
        evidence: CheckedOperation,
    ) -> Result<VerifiedAggregate> {
        prepared.ensure_current(heads)?;
        let input = self.linear.aggregate_circuit_request(prepared.request())?;
        if evidence.operation() != Operation::PublicPolynomialProduct
            || !evidence.matches_statement(&input, output)
        {
            return Err(Error::ComputationProof(
                "Aggregate evidence belongs to another exact statement".into(),
            ));
        }
        let response = self
            .linear
            .restore_aggregate_circuit_output(prepared.request(), output)?;
        let answer = self
            .key
            .decrypt_polynomial_aggregate_unverified(prepared.pending, &response)?;
        Ok(VerifiedAggregate {
            count: answer.count,
            sum: answer.sum,
            evidence,
        })
    }
}
