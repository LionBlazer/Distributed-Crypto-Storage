//! Complete authenticated selection composed with the genuine convolution proof.
use super::*;
use bfv_query_proof::{CheckedOperation, Operation};

/// Single-use exact source selection; private fields prevent caller-chosen rows.
pub struct PreparedProvableAggregate {
    request: Vec<u8>,
    pending: bfv_core::PendingPolynomialAggregate,
    selection: ExactSelection,
}
impl PreparedProvableAggregate {
    pub fn request(&self) -> &[u8] {
        &self.request
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
        let selection =
            self.proof_selection(table, predicate, budget.min(crate::MAX_ROWS), limits)?;
        let context = bfv_core::QueryContext::new(
            crate::random_id()?,
            selection.data_head.encode(),
            selection.index_head.encode(),
        );
        let prepared = self
            .key
            .prepare_polynomial_aggregate(context, &selection.fields)?;
        Ok(PreparedProvableAggregate {
            request: prepared.request,
            pending: prepared.pending,
            selection,
        })
    }
    /// Retains the pending source on a bad replica so another real executor can be tried.
    pub fn check_aggregate_proof(
        &self,
        table: &Table,
        prepared: &PreparedProvableAggregate,
        output: &[u8],
        proof: &[u8],
    ) -> Result<CheckedOperation> {
        current(table, &prepared.selection)?;
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
        current(table, &prepared.selection)?;
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
