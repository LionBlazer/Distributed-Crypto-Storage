//! Typed private producer. Actual original Source verification is mandatory on EVERY call.
use super::{
    circuit::Witness,
    statement::{Expected, Statement},
    wire,
};
use crate::fixed::Backend;
/// UNVERIFIED public child evidence. The separate Source must be freshly verified again.
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
pub fn prove(
    expected: &Expected,
    witness: &Witness,
    original_source: &[u8],
) -> Result<Evidence, wire::Error> {
    witness.require_expected(expected)?;
    expected.verify_source(original_source)?;
    let statement = witness.statement();
    let bytes = {
        let backend = Backend::two_lane_encoding(&statement)?;
        let proof = backend.prove(witness.trace(&statement)?)?;
        if expected.role() != super::Role::VersionSourceAllOriginal {
            backend.verify(&proof)?;
        }
        wire::encode(expected, &statement, &proof)?
    };
    Ok(Evidence { statement, bytes })
}
