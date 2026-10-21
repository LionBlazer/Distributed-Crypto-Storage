//! Genuine Source-first EMPTY Registry208 bootstrap. No application admission.
use super::{BootstrapExpected, BootstrapStatement, bootstrap_air as air, circuit::State};
use crate::{BackendError, Val, source};
pub use air::WIDTH;
use bfv_hiding_stark::{self as engine, Config, SecurityReport, codec};
use p3_air::BaseAir;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{Proof, StarkSecurityParams};
use zeroize::Zeroizing;

pub const HEADER: usize = 120;
pub const MAX_PROOF_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_FRAME: usize = HEADER + MAX_PROOF_BYTES;
pub const MAX_SEQUENCE_ELEMENTS: usize = 16_384;
pub const MAX_TOTAL_ELEMENTS: usize = 16 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"DCSPGB01";

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Encoding,
    ResourceLimit,
    Shape,
    Verification,
    Prerequisite,
    Proof(BackendError),
}
impl From<BackendError> for Error {
    fn from(e: BackendError) -> Self {
        Self::Proof(e)
    }
}
impl From<codec::Error> for Error {
    fn from(e: codec::Error) -> Self {
        match e {
            codec::Error::Encoding => Self::Encoding,
            codec::Error::ResourceLimit => Self::ResourceLimit,
            codec::Error::Shape => Self::Shape,
        }
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Registry progress bootstrap: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Private move-only captured opening. Construction is not proof verification.
/// Native field traces and SDK scratch are excluded from the clearing promise.
/// ```compile_fail
/// fn clone<T: Clone>() {} fn forbidden() { clone::<registry200_proof::registry_progress::BootstrapWitness>(); }
/// ```
pub struct BootstrapWitness {
    statement: BootstrapStatement,
    plain: Zeroizing<[u8; 2348]>,
    controllers: Zeroizing<[[u8; 32]; 2]>,
    salts: Zeroizing<[[u64; 4]; 3]>,
}
impl BootstrapWitness {
    /// Source-opening, enrollment and new Registry208 salts, respectively.
    /// Every opening is reconstructed before capture; the real Source proof is
    /// still mandatory on every prove/verify call.
    pub fn new(
        expected: &BootstrapExpected,
        plain: Zeroizing<[u8; 2348]>,
        controllers: Zeroizing<[[u8; 32]; 2]>,
        salts: Zeroizing<[[u64; 4]; 3]>,
    ) -> Result<Self, Error> {
        expected.require_same(expected)?;
        if controllers.contains(&[0; 32]) || salts.iter().flatten().any(|v| *v >= Val::ORDER_U64) {
            return Err(Error::Shape);
        }
        let native = (*salts).map(|s| s.map(Val::from_u64));
        let source_fields =
            source::commitment::opening_fields(expected.source(), native[0], &plain[..]);
        if source::commitment::digest(&source_fields) != expected.source().open_commitment {
            return Err(Error::Shape);
        }
        let table: Zeroizing<[u8; 32]> = Zeroizing::new(plain[124..156].try_into().unwrap());
        let enrollment = crate::lifecycle::circuit::commitment::enrollment_fields_opening(
            &expected.legacy(),
            &table,
            &controllers,
            native[1],
        );
        if source::commitment::digest(&enrollment) != expected.enrollment {
            return Err(Error::Shape);
        }
        let next = State::default().root(expected, &plain, &controllers, (*salts)[2])?;
        let statement =
            BootstrapStatement::from_claim(expected, source::statement::encode_digest(next))?;
        Ok(Self {
            statement,
            plain,
            controllers,
            salts,
        })
    }
    pub fn statement(&self) -> &BootstrapStatement {
        &self.statement
    }
    fn trace(&self) -> RowMajorMatrix<Val> {
        air::BootstrapAir::new(&self.statement).trace(&self.plain, &self.controllers, &self.salts)
    }
}

struct Backend {
    air: air::BootstrapAir,
    values: Vec<Val>,
    shape: codec::Topology,
    config: Config,
    parameters: StarkSecurityParams,
    report: SecurityReport,
}
impl Backend {
    fn new(statement: &BootstrapStatement) -> Result<Self, Error> {
        statement.expected.require_same(&statement.expected)?;
        let air = air::BootstrapAir::new(statement);
        let values = statement.values();
        let (parameters, report) = engine::analyze(&air)?;
        let report = report.require_target()?;
        if air.width() != WIDTH
            || air.num_public_values() != super::BOOTSTRAP_VALUES
            || values.len() != super::BOOTSTRAP_VALUES
            || air.preprocessed_width() != 0
            || air.main_next_row_columns().is_empty()
            || report.degree > 5
            || !(2..=16).contains(&report.quotient_chunks)
        {
            return Err(Error::Shape);
        }
        let shape = codec::Topology::checked(WIDTH, report.quotient_chunks)?;
        Ok(Self {
            air,
            values,
            shape,
            config: engine::config()?,
            parameters,
            report,
        })
    }
    fn prove(&self, trace: RowMajorMatrix<Val>) -> Result<Proof<Config>, Error> {
        Ok(engine::prove_with_config(
            &self.config,
            &self.air,
            trace,
            &self.values,
        )?)
    }
    fn verify(&self, proof: &Proof<Config>) -> Result<(), Error> {
        Ok(engine::verify_with_assessment(
            &self.config,
            &self.air,
            &self.parameters,
            self.report,
            proof,
            &self.values,
        )?)
    }
}
fn header(statement: &BootstrapStatement, n: usize) -> Result<Vec<u8>, Error> {
    if n == 0 || n > MAX_PROOF_BYTES {
        return Err(Error::ResourceLimit);
    }
    let mut bytes = Vec::with_capacity(HEADER);
    bytes.extend_from_slice(MAGIC);
    bytes.push(1);
    bytes.extend_from_slice(&[0; 7]);
    bytes.extend_from_slice(&super::bootstrap_profile_digest());
    bytes.extend_from_slice(&statement.identity());
    bytes.extend_from_slice(&(n as u32).to_le_bytes());
    bytes.extend_from_slice(&[0; 4]);
    Ok(bytes)
}
/// Canonical detached frame preflight only. It verifies no Source or child.
pub fn payload<'a>(statement: &BootstrapStatement, bytes: &'a [u8]) -> Result<&'a [u8], Error> {
    if bytes.len() > MAX_FRAME {
        return Err(Error::ResourceLimit);
    }
    if bytes.len() < HEADER {
        return Err(Error::Encoding);
    }
    let n = u32::from_le_bytes(bytes[112..116].try_into().unwrap()) as usize;
    if bytes[..HEADER] != header(statement, n)? {
        return Err(Error::Shape);
    }
    if HEADER.checked_add(n) != Some(bytes.len()) {
        return Err(Error::Encoding);
    }
    Ok(&bytes[HEADER..])
}
/// Genuine child and its complete immutable claim. No Source bytes are duplicated.
pub struct BootstrapEvidence {
    statement: BootstrapStatement,
    bytes: Vec<u8>,
}
impl BootstrapEvidence {
    pub fn statement(&self) -> &BootstrapStatement {
        &self.statement
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn into_parts(self) -> (BootstrapStatement, Vec<u8>) {
        (self.statement, self.bytes)
    }
}
pub fn prove_bootstrap(
    expected: &BootstrapExpected,
    witness: &BootstrapWitness,
    source_bytes: &[u8],
) -> Result<BootstrapEvidence, Error> {
    witness.statement.require_expected(expected)?;
    source::verification::verify(expected.source(), source_bytes)
        .map_err(|_| Error::Prerequisite)?;
    let backend = Backend::new(&witness.statement)?;
    let proof = backend.prove(witness.trace())?;
    backend.verify(&proof)?;
    let child = codec::serialize(&proof, &backend.shape, MAX_PROOF_BYTES)?;
    let mut bytes = header(&witness.statement, child.len())?;
    bytes.extend(child);
    Ok(BootstrapEvidence {
        statement: witness.statement.clone(),
        bytes,
    })
}
/// A freshly verified EMPTY Registry208 claim, not authorization/current ownership.
pub struct VerifiedBootstrap {
    statement: BootstrapStatement,
}
impl VerifiedBootstrap {
    pub fn statement(&self) -> &BootstrapStatement {
        &self.statement
    }
}
pub fn verify_bootstrap(
    expected: &BootstrapExpected,
    statement: &BootstrapStatement,
    source_bytes: &[u8],
    bytes: &[u8],
) -> Result<VerifiedBootstrap, Error> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        statement.require_expected(expected)?;
        let bytes = payload(statement, bytes)?;
        source::verification::verify(expected.source(), source_bytes)
            .map_err(|_| Error::Prerequisite)?;
        let backend = Backend::new(statement)?;
        let proof = codec::decode(
            bytes,
            &backend.shape,
            MAX_SEQUENCE_ELEMENTS,
            MAX_TOTAL_ELEMENTS,
        )?;
        backend.verify(&proof)?;
        Ok(VerifiedBootstrap {
            statement: statement.clone(),
        })
    }))
    .map_err(|_| Error::Verification)?
}

#[cfg(test)]
#[path = "bootstrap_tests.rs"]
pub(super) mod tests;
