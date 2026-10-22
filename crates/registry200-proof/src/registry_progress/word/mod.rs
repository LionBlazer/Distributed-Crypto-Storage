//! Fixed Word mathematics relative to independently retained Source and OldRoot.
//! Native verification grants no source authentication, history, freshness or SQL authority.
pub mod bootstrap;
mod expected;
mod inputs;
pub mod read;
mod statement;
mod transition;
use super::word_inventory::{probe, probe_wire};
pub use expected::{Claims, Expected};
pub use inputs::{
    CommandInput, CurrentRegistry, PrivateInputs, RegistryOpening, SourceOpening, WalkInput,
};
pub use statement::{StatementDomain, StatementOpening};
pub use transition::{
    PreparedTransition, TransitionMaterial, TransitionOpening, prepare_transition, registry_root,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Control,
    Predicate,
}
impl Role {
    pub(super) fn predicate(self) -> bool {
        self == Self::Predicate
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Shape,
    Resource,
    Security,
    Binding,
    Encoding,
    Setup,
    Proving,
    Backend,
    Verification,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Word mathematics rejected: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<probe::Error> for Error {
    fn from(e: probe::Error) -> Self {
        match e {
            probe::Error::Shape => Self::Shape,
            probe::Error::Resource => Self::Resource,
            probe::Error::Security => Self::Security,
            probe::Error::Binding => Self::Binding,
            probe::Error::Encoding => Self::Encoding,
            probe::Error::Setup => Self::Setup,
            probe::Error::Proving => Self::Proving,
            probe::Error::Backend => Self::Backend,
            probe::Error::Verification => Self::Verification,
        }
    }
}
pub type Result<T> = core::result::Result<T, Error>;
pub const MAX_EVIDENCE_BYTES: usize = probe_wire::MAX_FRAME_BYTES;
pub fn profile_digest() -> [u8; 32] {
    super::word_inventory::profile()
}
pub fn wire_profile_digest() -> [u8; 32] {
    probe_wire::profile()
}
/// Original fixed Stmt96 header; a public encoding constant, not an authorization.
pub fn statement_header() -> [crate::Val; 13] {
    super::word_inventory::header("statement")
        .try_into()
        .expect("fixed header13")
}
/// Original fixed Cmd160 prefix for independent owner serialization.
pub fn command_header() -> [crate::Val; 5] {
    use p3_field::PrimeCharacteristicRing;
    let d = super::word_inventory::domain("command");
    [d[0], d[1], d[2], d[3], crate::Val::ONE]
}
/// Original fixed Result160 prefix for independent owner serialization.
pub fn result_header() -> [crate::Val; 5] {
    use p3_field::PrimeCharacteristicRing;
    let d = super::word_inventory::domain("result");
    [d[0], d[1], d[2], d[3], crate::Val::ONE]
}
/// Fresh producer bytes are UNVERIFIED. No checked/current/accepted flag is serialized.
pub struct UnverifiedWordEvidence {
    bytes: Vec<u8>,
}
impl UnverifiedWordEvidence {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
/// Privately constructed move-only result of actual native Word verification.
/// It proves only the fixed relation relative to Source/OldRoot, without admission.
/// ```compile_fail
/// use registry200_proof::registry_progress::word::{Expected,VerifiedWord};
/// fn forge(expected:Expected)->VerifiedWord { VerifiedWord { expected } }
/// ```
/// ```compile_fail
/// use registry200_proof::registry_progress::word::VerifiedWord;
/// fn duplicate(x:&VerifiedWord)->VerifiedWord { x.clone() }
/// ```
pub struct VerifiedWord {
    expected: Expected,
}
impl VerifiedWord {
    pub fn expected(&self) -> &Expected {
        &self.expected
    }
}
/// Immutable ROLE-only public preprocessing. Holds no private input, RNG or verdict.
pub struct Prover {
    role: Role,
    inner: probe::ProverSetup,
}
impl Prover {
    pub fn new(role: Role) -> Result<Self> {
        Ok(Self {
            role,
            inner: probe::ProverSetup::new(role.predicate())?,
        })
    }
    /// Consumes and drops all original protected inputs, even on failure.
    pub fn produce(
        &self,
        expected: &Expected,
        inputs: PrivateInputs,
    ) -> Result<UnverifiedWordEvidence> {
        if self.role != expected.role() {
            return Err(Error::Binding);
        }
        Ok(UnverifiedWordEvidence {
            bytes: self.inner.produce(&expected.inner, &inputs.inner)?,
        })
    }
}
/// Independently constructed ROLE-only public setup, not a producer-supplied verifier.
pub struct Verifier {
    role: Role,
    inner: probe::VerifierSetup,
}
impl Verifier {
    pub fn new(role: Role) -> Result<Self> {
        Ok(Self {
            role,
            inner: probe::VerifierSetup::new(role.predicate())?,
        })
    }
    pub fn verify(&self, expected: &Expected, bytes: &[u8]) -> Result<VerifiedWord> {
        if self.role != expected.role() {
            return Err(Error::Binding);
        }
        self.inner.verify(&expected.inner, bytes)?;
        Ok(VerifiedWord {
            expected: expected.clone(),
        })
    }
}
pub fn prove(expected: &Expected, inputs: PrivateInputs) -> Result<UnverifiedWordEvidence> {
    Prover::new(expected.role())?.produce(expected, inputs)
}
/// Check full original header/binding before allocating cold public preprocessing.
pub fn verify(expected: &Expected, bytes: &[u8]) -> Result<VerifiedWord> {
    probe::require_frame(&expected.inner, bytes)?;
    Verifier::new(expected.role())?.verify(expected, bytes)
}
