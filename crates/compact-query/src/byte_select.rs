//! Proof composition for schema-neutral BFV byte projection.
//!
//! This boundary proves complete arithmetic on a trusted prepared byte chunk. Its
//! caller must authenticate original row bytes, complete indexed selection, exact
//! chunk coverage, schema/query bindings and the fresh agreed storage version.
use crate::{Error, Result};
use bfv_query_core::{Owner, PreparedByteSelect, PublicUpdateEvaluator};
use bfv_query_proof::{CheckedOperation, Operation};

/// Decrypted peer bytes constructible only after checking the exact computation proof.
/// Complete SQL selection and version freshness remain the session's responsibility.
pub struct VerifiedByteSelection {
    bytes: Vec<u8>,
    evidence: CheckedOperation,
}
impl VerifiedByteSelection {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
    pub fn evidence(&self) -> &CheckedOperation {
        &self.evidence
    }
}

/// Verifies serialized evidence against the independently retained original request.
/// `output` is the canonical BFV product circuit output, not an arbitrary BFV response.
pub fn check(
    evaluator: &PublicUpdateEvaluator,
    prepared: &PreparedByteSelect,
    output: &[u8],
    proof: &[u8],
) -> Result<CheckedOperation> {
    let input = evaluator.byte_select_circuit_request(&prepared.request)?;
    bfv_query_proof::verify(&input, output, proof)
        .map_err(|error| Error::ComputationProof(error.to_string()))
}

/// Rebinds previously checked evidence before final decryption of actual peer output.
/// No plaintext original values or locally calculated answer can enter this operation.
pub fn complete_checked(
    owner: &Owner,
    evaluator: &PublicUpdateEvaluator,
    prepared: PreparedByteSelect,
    output: &[u8],
    checked: CheckedOperation,
) -> Result<VerifiedByteSelection> {
    let input = evaluator.byte_select_circuit_request(&prepared.request)?;
    if checked.operation() != Operation::PublicPolynomialProduct
        || !checked.matches_statement(&input, output)
    {
        return Err(Error::ComputationProof(
            "byte projection evidence belongs to another exact statement".to_owned(),
        ));
    }
    let response = evaluator.restore_byte_select_circuit_output(&prepared.request, output)?;
    let decrypted = owner.decrypt_byte_select_unverified(prepared.pending, &response)?;
    Ok(VerifiedByteSelection {
        bytes: decrypted.bytes,
        evidence: checked,
    })
}

#[cfg(test)]
mod tests;
