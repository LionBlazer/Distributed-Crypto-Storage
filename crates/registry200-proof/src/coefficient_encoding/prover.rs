//! Typed private coefficient producer; Source proof verification is mandatory.
use super::{
    circuit::Witness,
    statement::{Expected, Statement},
    wire,
};
use crate::fixed::Backend;

/// Complete public statement and bounded Source/encoding pair. No private opening,
/// backend, raw proof, Key verification token or SQL permission is retained.
pub struct Evidence {
    statement: Statement,
    bytes: Vec<u8>,
}
impl Evidence {
    pub fn statement(&self) -> &Statement {
        &self.statement
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn into_parts(self) -> (Statement, Vec<u8>) {
        (self.statement, self.bytes)
    }
}

/// Checks the full witness/Expected association, then verifies actual Source
/// bytes and drops their decoded proof/backend before child assessment or trace.
/// The mathematical Key33 context still requires independent Key/Formation checks.
pub fn prove(
    expected: &Expected,
    witness: &Witness,
    source: &[u8],
) -> Result<Evidence, wire::Error> {
    witness.require_expected(expected)?;
    wire::verify_source(expected, source)?;
    let statement = witness.statement();
    let bytes = {
        let backend = Backend::encoding(&statement)?;
        let proof = backend.prove(witness.trace(&statement)?)?;
        backend.verify(&proof)?;
        wire::encode_with_source(expected, &statement, source, &proof)?
    };
    Ok(Evidence { statement, bytes })
}
