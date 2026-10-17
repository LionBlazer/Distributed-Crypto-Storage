//! Actual cold canonical Source+Locking bytes; no StateLease/cache-ID branch.
use super::{
    CompositeProof, fixture, prove_composite,
    statement::{Expected, Statement, encoded},
};
use crate::backend::Error as BackendError;
use crate::opening::{
    Relation,
    proof_wire::{self, Error, Frame, Role, Shape},
};

pub(in crate::opening) fn encode(
    expected: &Expected,
    statement: &Statement,
    proof: &CompositeProof,
) -> Result<Vec<u8>, Error> {
    if expected.source.relation != Relation::CanonicalIndex {
        return Err(Error::Profile);
    }
    statement.require_expected(expected)?;
    proof_wire::encode(
        Role::Locking,
        &[
            encoded(statement.returned),
            encoded(statement.owned),
            encoded(statement.next),
        ],
        proof.source.as_ref().ok_or(Error::Shape)?,
        &Shape::new(&expected.source)?,
        &proof.locking,
        &Shape::new(statement)?,
    )
}

pub(in crate::opening) fn verify(expected: &Expected, bytes: &[u8]) -> Result<Statement, Error> {
    proof_wire::guarded(|| {
        if expected.source.relation != Relation::CanonicalIndex {
            return Err(Error::Profile);
        }
        let frame = Frame::parse(Role::Locking, bytes)?;
        let roots: &[[u8; 32]] = frame.outputs.as_chunks::<32>().0;
        if roots.len() != 3 {
            return Err(Error::Encoding);
        }
        let statement = Statement::checked(expected, roots[0], roots[1], roots[2])?;
        let (source, locking) = proof_wire::decode_pair(
            &frame,
            &Shape::new(&expected.source)?,
            &Shape::new(&statement)?,
        )?;
        let proof = CompositeProof {
            source: Some(source),
            locking,
        };
        super::verify_composite(expected, &statement, &proof)?;
        Ok(statement)
    })
}

pub(super) fn gate(mode: &str) -> Result<(), BackendError> {
    if !matches!(mode, "security" | "prove") {
        return Err(BackendError::Shape);
    }
    let (expected, source_witness, witness) = fixture()?;
    let statement = super::statement::proposed(&expected, &witness)?;
    crate::security(&statement, "public-nonsecret-cold-private-locking-wire")?;
    if mode == "prove" {
        let bytes = {
            let (statement, proof) = prove_composite(&expected, &source_witness, &witness)?;
            encode(&expected, &statement, &proof).map_err(|_| BackendError::Verification)?
        };
        proof_wire::measured("locking", &bytes, || verify(&expected, &bytes).map(|_| ()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
