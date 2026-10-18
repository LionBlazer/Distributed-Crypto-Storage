//! Fixed canonical Source producer. Private witness and raw proofs never escape evidence.
use super::{Statement, circuit::Witness};
use crate::{admission::CanonicalSource, coefficient_encoding::wire, fixed::Backend};

/// Bounded public bytes and the immutable canonical claim actually proved.
/// This object is not an application-admission or freshness token.
pub struct SourceEvidence {
    statement: CanonicalSource,
    bytes: Vec<u8>,
}
impl SourceEvidence {
    pub fn statement(&self) -> &Statement {
        self.statement.claim()
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Assesses the fixed canonical AIR before allocating the private trace, proves,
/// self-verifies, and applies the existing bounded Source serialization contract.
pub fn prove(source: &CanonicalSource, witness: &Witness) -> Result<SourceEvidence, wire::Error> {
    let source = CanonicalSource::checked_claim(source.claim())?;
    let bytes = {
        let backend = Backend::source(source.claim())?;
        let proof = backend.prove(witness.trace(source.claim())?)?;
        backend.verify(&proof)?;
        wire::encode_source(source.claim(), &proof)?
    };
    Ok(SourceEvidence {
        statement: source,
        bytes,
    })
}
