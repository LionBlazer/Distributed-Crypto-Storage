//! One fused Stmt96/mask/Cw/Cs/QueryCt relation, without Word/DATA/SQL admission.
use super::{Error, Result, Val, data, program::query_formation as backend};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use sha2::{Digest, Sha256, Sha512};

pub const MAX_EVIDENCE_BYTES: usize = backend::MAX_FRAME_BYTES;

/// Fixed mathematical protocol identity; supplies no Source or key authority.
pub fn profile_digest() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(backend::DOMAIN);
    h.update(backend::wire_profile());
    h.update(data::profile_digest());
    h.update(b"all96-Stmt/header13/zero95/packedMask78..85;W[i]=16389*bit255-i/low256/high3840zero;originalCw4112/Cs528;all4096/same-S/E+-20/exact-K;no-Word-Source-admission");
    h.finalize().into()
}

/// Independently retained public endpoints. Construction verifies no proof.
/// The caller must separately authenticate the statement, DATA and original key.
#[derive(Clone)]
pub struct Expected {
    pub(super) core: data::Expected,
    pub(super) statement: [Val; 4],
    pub(super) header: [Val; 13],
}
impl Expected {
    pub fn checked(
        original: &data::Expected,
        statement: [Val; 4],
        header: [Val; 13],
    ) -> Result<Self> {
        let mut h = Sha512::new();
        h.update(b"DCS/fused-query-formation/complete-Expected/v1");
        h.update(profile_digest());
        h.update(original.binding());
        for value in statement.into_iter().chain(header) {
            h.update(value.as_canonical_u64().to_le_bytes());
        }
        let core = data::Expected::checked(
            original.request().clone(),
            h.finalize().into(),
            original.contexts(),
            original.roots(),
        )?;
        Ok(Self {
            core,
            statement,
            header,
        })
    }
    /// Rebound public metadata used when preparing the same guarded W/Cs inputs.
    /// This is not a DATA admission or a conversion of verified evidence.
    pub fn core_expected(&self) -> &data::Expected {
        &self.core
    }
    pub fn statement_root(&self) -> [Val; 4] {
        self.statement
    }
    pub fn header(&self) -> [Val; 13] {
        self.header
    }
    pub fn binding(&self) -> [u8; 64] {
        self.core.binding()
    }
    pub(super) fn values(&self) -> &[Val] {
        self.core.values()
    }
    pub(super) fn require_same(&self, other: &Self) -> Result<()> {
        self.core.require_same(&other.core)?;
        if self.statement != other.statement || self.header != other.header {
            return Err(Error::Binding);
        }
        Ok(())
    }
}
pub(super) struct Statement(pub(super) [Val; 96]);
impl Drop for Statement {
    fn drop(&mut self) {
        self.0.fill(Val::ZERO)
    }
}
/// Move-only guarded private inputs. No opening/key getters or serialization.
pub struct Prepared {
    pub(super) expected: Expected,
    pub(super) input: data::Prepared,
    pub(super) statement: Statement,
}
impl Prepared {
    /// Consume the SAME QueryCt preparation and the complete original statement.
    /// `input` must be prepared under `expected.core_expected()`.
    pub fn new(expected: &Expected, input: data::Prepared, statement: [Val; 96]) -> Result<Self> {
        let statement = Statement(statement);
        input.require_dense_expected(&expected.core)?;
        if statement.0[..13] != expected.header
            || statement.0[95] != Val::ZERO
            || statement.0[78..86]
                .iter()
                .any(|v| v.as_canonical_u64() > u32::MAX as u64)
            || statement_root(&statement.0) != expected.statement
        {
            return Err(Error::Binding);
        }
        Ok(Self {
            expected: expected.clone(),
            input,
            statement,
        })
    }
    pub(super) fn require_dense_expected(&self, expected: &Expected) -> Result<()> {
        self.expected.require_same(expected)
    }
    pub(super) fn dense_trace(self, expected: &Expected) -> Result<super::witness::PrivateTrace> {
        self.require_dense_expected(expected)?;
        self.input
            .inner
            .fused_query_trace(&expected.core, &self.statement.0, expected.statement)
    }
}

/// Producer bytes carry no verified/current/accepted flag.
pub struct UnverifiedFormationEvidence {
    bytes: Vec<u8>,
}
impl UnverifiedFormationEvidence {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
/// Move-only mathematical result, created only after the actual native verifier.
/// No DATA admission, Word semantics, freshness, completeness or SQL capability.
/// ```compile_fail
/// use bfv_ciphertext_formation::gold::query::{Expected, VerifiedFormation};
/// fn forge(expected: Expected) -> VerifiedFormation { VerifiedFormation { expected } }
/// ```
/// ```compile_fail
/// use bfv_ciphertext_formation::gold::query::VerifiedFormation;
/// fn duplicate(x: &VerifiedFormation) -> VerifiedFormation { x.clone() }
/// ```
pub struct VerifiedFormation {
    expected: Expected,
}
impl VerifiedFormation {
    pub fn expected(&self) -> &Expected {
        &self.expected
    }
}
pub fn prove(expected: &Expected, prepared: Prepared) -> Result<UnverifiedFormationEvidence> {
    Ok(UnverifiedFormationEvidence {
        bytes: backend::produce(expected, prepared)?,
    })
}
/// Bound/decode the distinct frame, rebuild public PP and run native verification.
/// No supplied setup, cached acceptance or alternative verifier is accepted.
pub fn verify(expected: &Expected, bytes: &[u8]) -> Result<VerifiedFormation> {
    backend::receive(expected, bytes)?;
    Ok(VerifiedFormation {
        expected: expected.clone(),
    })
}
pub(super) fn statement_root(words: &[Val; 96]) -> [Val; 4] {
    let mut state = [Val::ZERO; 12];
    for block in words.as_chunks::<8>().0 {
        let mut row = [Val::ZERO; bfv_hiding_stark::poseidon::WIDTH];
        state[..8].copy_from_slice(block);
        state = bfv_hiding_stark::poseidon::write(&mut row, state);
        row.fill(Val::ZERO);
    }
    let root = state[..4].try_into().expect("root4");
    state.fill(Val::ZERO);
    root
}
