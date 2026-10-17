//! Actual Source+Bootstrap bytes. No independently selected Expected on wire.
use super::{
    CompositeProof, fixture, prove,
    statement::{Expected, Statement},
};
use crate::backend::Error as BackendError;
use crate::opening::{
    proof_wire::{self, Error, Frame, Role, Shape},
    statement::encode_digest,
};

pub(in crate::opening) fn encode(
    expected: &Expected,
    statement: &Statement,
    proof: &CompositeProof,
) -> Result<Vec<u8>, Error> {
    statement.require_expected(expected)?;
    proof_wire::encode(
        Role::Bootstrap,
        &[encode_digest(statement.registry)],
        proof.source.as_ref().ok_or(Error::Shape)?,
        &Shape::new(&expected.source)?,
        &proof.bootstrap,
        &Shape::new(statement)?,
    )
}

/// Fresh decode and actual Source-first SDK verification; returns only the
/// checked experimental statement, never a journal receipt or live lock grant.
pub(in crate::opening) fn verify(expected: &Expected, bytes: &[u8]) -> Result<Statement, Error> {
    proof_wire::guarded(|| {
        expected.require_contract()?;
        let frame = Frame::parse(Role::Bootstrap, bytes)?;
        let statement = Statement::checked(
            expected,
            frame.outputs.try_into().map_err(|_| Error::Encoding)?,
        )?;
        let (source, bootstrap) = proof_wire::decode_pair(
            &frame,
            &Shape::new(&expected.source)?,
            &Shape::new(&statement)?,
        )?;
        let proof = CompositeProof {
            source: Some(source),
            bootstrap,
        };
        super::verify(expected, &statement, &proof)?;
        Ok(statement)
    })
}

pub(super) fn gate(mode: &str) -> Result<(), BackendError> {
    if !matches!(mode, "security" | "prove") {
        return Err(BackendError::Shape);
    }
    let (expected, source_witness, witness) = fixture()?;
    let statement = witness.statement(&expected)?;
    crate::security(
        &statement,
        "public-nonsecret-private-registry-bootstrap-wire",
    )?;
    if mode == "prove" {
        let bytes = {
            let (statement, proof) = prove(&expected, &source_witness, &witness)?;
            encode(&expected, &statement, &proof).map_err(|_| BackendError::Verification)?
        };
        proof_wire::measured("bootstrap", &bytes, || {
            verify(&expected, &bytes).map(|_| ())
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
