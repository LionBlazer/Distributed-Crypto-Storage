//! Closed fresh Source/Encoding prerequisites and independent new-role claims.
pub use super::transition_trace::Witness;
use super::{BootstrapExpected, bootstrap, fields};
use crate::{
    BackendError, Val,
    admission::CanonicalSource,
    coefficient_encoding::{self as encoding, Role, statement::Statement as Query},
    source,
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use sha2::{Digest, Sha256, Sha512};

#[derive(Clone)]
enum RoleBinding {
    Control,
    Predicate(Box<Query>),
}
#[derive(Clone)]
pub struct Expected {
    pub(super) base: BootstrapExpected,
    pub(super) old: [Val; 4],
    pub(super) command: [Val; 4],
    role: RoleBinding,
}
impl Expected {
    pub fn control(
        source: &CanonicalSource,
        genesis: [u8; 32],
        parent: [u8; 32],
        enrollment: [u8; 32],
        old: [u8; 32],
        command: [u8; 32],
    ) -> Result<Self, BackendError> {
        Ok(Self {
            base: BootstrapExpected::new(source, genesis, parent, enrollment)?,
            old: source::statement::decode_digest(old)?,
            command: source::statement::decode_digest(command)?,
            role: RoleBinding::Control,
        })
    }
    pub fn predicate(
        query: &Query,
        genesis: [u8; 32],
        parent: [u8; 32],
        enrollment: [u8; 32],
        old: [u8; 32],
        command: [u8; 32],
    ) -> Result<Self, BackendError> {
        if query.expected.role() != Role::PrivateMask {
            return Err(BackendError::Shape);
        }
        let source = CanonicalSource::checked_claim(query.expected.source_claim())?;
        let mut e = Self::control(&source, genesis, parent, enrollment, old, command)?;
        e.role = RoleBinding::Predicate(Box::new(query.clone()));
        Ok(e)
    }
    pub fn source(&self) -> &source::Statement {
        self.base.source()
    }
    pub fn query(&self) -> Option<&Query> {
        match &self.role {
            RoleBinding::Control => None,
            RoleBinding::Predicate(q) => Some(q.as_ref()),
        }
    }
    pub fn is_predicate(&self) -> bool {
        self.query().is_some()
    }
    pub(super) fn context(&self) -> Vec<Val> {
        let mut out = self.base.context();
        out[..8].copy_from_slice(
            &source::statement::words(&profile_digest(self.is_predicate())).collect::<Vec<_>>(),
        );
        out
    }
    pub(super) fn scope(&self) -> [u8; 64] {
        let mut h = Sha512::new();
        h.update(b"DCS/registry-progress/fixed-statement-scope/v1/excludes-attempt-q-Copen-Cmask-Cw-proof");
        h.update(self.base.genesis);
        for v in self.base.enrollment {
            h.update(v.as_canonical_u64().to_le_bytes());
        }
        for bytes in self
            .source()
            .heads
            .iter()
            .map(|b| b.as_slice())
            .chain(self.source().packets.iter().map(Vec::as_slice))
        {
            h.update((bytes.len() as u64).to_le_bytes());
            h.update(bytes);
        }
        for v in self.source().key_commitment {
            h.update(v.as_canonical_u64().to_le_bytes());
        }
        if let Some(q) = self.query() {
            h.update(q.expected.bfv().full_setup());
            for v in q.expected.bfv().key().public_values() {
                h.update(v.as_canonical_u64().to_le_bytes());
            }
        }
        h.finalize().into()
    }
    pub fn require_same(&self, other: &Self) -> Result<(), BackendError> {
        self.base.require_same(&other.base)?;
        if self.old != other.old || self.command != other.command {
            return Err(BackendError::Shape);
        }
        match (self.query(), other.query()) {
            (None, None) => Ok(()),
            (Some(a), Some(b)) => {
                a.require_expected(&b.expected)?;
                if a.values() != b.values() {
                    return Err(BackendError::Shape);
                }
                Ok(())
            }
            _ => Err(BackendError::Shape),
        }
    }
}
#[derive(Clone)]
pub struct Statement {
    pub(super) expected: Expected,
    pub(super) next: [Val; 4],
    pub(super) result: [Val; 4],
}
impl Statement {
    pub fn from_claim(
        expected: &Expected,
        next: [u8; 32],
        result: [u8; 32],
    ) -> Result<Self, BackendError> {
        expected.require_same(expected)?;
        Ok(Self {
            expected: expected.clone(),
            next: source::statement::decode_digest(next)?,
            result: source::statement::decode_digest(result)?,
        })
    }
    pub fn expected(&self) -> &Expected {
        &self.expected
    }
    pub fn next(&self) -> [u8; 32] {
        source::statement::encode_digest(self.next)
    }
    pub fn result(&self) -> [u8; 32] {
        source::statement::encode_digest(self.result)
    }
    pub fn values(&self) -> Vec<Val> {
        let e = &self.expected;
        let mut out =
            source::statement::words(&profile_digest(e.is_predicate())).collect::<Vec<_>>();
        if let Some(q) = e.query() {
            out.extend(q.values());
        } else {
            out.extend(e.source().values());
        }
        out.extend(e.context());
        out.extend(e.old);
        out.extend(e.command);
        out.extend(self.next);
        out.extend(self.result);
        assert_eq!(
            out.len(),
            if e.is_predicate() {
                super::PREDICATE_VALUES
            } else {
                super::CONTROL_VALUES
            }
        );
        out
    }
    pub fn require_expected(&self, e: &Expected) -> Result<(), BackendError> {
        self.expected.require_same(e)
    }
    pub fn identity(&self) -> [u8; 64] {
        let mut h = Sha512::new();
        h.update(b"DCS/registry-progress/transition-public/v1");
        for v in self.values() {
            h.update(v.as_canonical_u64().to_le_bytes());
        }
        h.finalize().into()
    }
}
pub fn profile_digest(predicate: bool) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"DCS/registry-progress/closed-step/v2/fixed-source-no-SQL-no-finality");
    h.update(super::registry_profile_digest());
    h.update(super::statement_profile_digest());
    h.update(super::progress_profile_digest());
    h.update(crate::source::profile_digest(
        source::Relation::CanonicalIndex,
    ));
    if predicate {
        h.update(b"Predicate896/real-full-PrivateMask772/Start-Resume-WAIT-prefix-NOWAIT-cause-SKIP-before-OFFSET/no-SKIP-resume/Statement96-Progress48-Result160/full256mask-Cmd48-Cmd160/source-first");
        h.update(encoding::profile_digest(Role::PrivateMask));
    } else {
        h.update(b"Control815/Source691/Begin-Savepoint-RollbackTo-Release-End/no-Acquire-no-FailCurrent/parked-actor-only-EndAbort/stable-ID-whole-progress-carry");
    }
    h.update(b"waitCodes0WAIT1NOWAIT2SKIP/skip=attempt-conflict-skip/block=attempt-conflict-notSkip/visit=attempt-notConflict/limit0-no-search/OFFSET-consumed-rows-held/Source680-85/Enrollment64-8/Old208-26/Cmd160-20/New208-26/Result160-20/Stmt96-12/oldP48-6/newP48-6/Cmd48-6/215absorbs/H512/private-phase-mode-window-projection-holder-cursor/start-originalSQL=currentEncoding/resume-originalSQL-private-preserved-currentEncoding-fresh-blind");
    h.update(b"DCSPGR01/header120/controlTag1/predicateTag2/detached/actual-fresh-Source-first/matchingSourceBytes-no-cached-success/strictcanonical-native-codec/no-legacy-profile-reinterpretation");
    for n in [
        super::transition_layout::TRACE_WIDTH,
        512,
        if predicate {
            super::PREDICATE_VALUES
        } else {
            super::CONTROL_VALUES
        },
        bootstrap::HEADER,
        bootstrap::MAX_PROOF_BYTES,
        bootstrap::MAX_SEQUENCE_ELEMENTS,
        bootstrap::MAX_TOTAL_ELEMENTS,
    ] {
        h.update((n as u64).to_le_bytes());
    }
    h.finalize().into()
}

/// Full existing Encoding pair for Predicate; absent for the Control role.
pub struct Prerequisites<'a> {
    pub source: &'a [u8],
    pub query: Option<&'a [u8]>,
}
pub(super) fn prerequisites(e: &Expected, p: &Prerequisites<'_>) -> Result<(), bootstrap::Error> {
    match (e.query(), p.query) {
        (None, None) => source::verification::verify(e.source(), p.source)
            .map_err(|_| bootstrap::Error::Prerequisite),
        (Some(q), Some(bytes)) => {
            let frame = encoding::wire::BorrowedFrame::parse(&q.expected, bytes)
                .map_err(|_| bootstrap::Error::Prerequisite)?;
            if frame.source() != p.source {
                return Err(bootstrap::Error::Prerequisite);
            }
            let checked = encoding::wire::verify(&q.expected, bytes)
                .map_err(|_| bootstrap::Error::Prerequisite)?;
            if checked.statement().values() != q.values() {
                return Err(bootstrap::Error::Prerequisite);
            }
            Ok(())
        }
        _ => Err(bootstrap::Error::Prerequisite),
    }
}
pub(super) fn digest(values: &[Val]) -> [Val; 4] {
    fields::digest(values)
}

/// Explicit public-claim commitment mathematics, not a proof or authority.
pub fn command_commitment(
    e: &Expected,
    command: &crate::lifecycle::circuit::model::Command,
    revision: u64,
    controllers: &[[u8; 32]; 2],
    salt: [u64; 4],
) -> Result<[u8; 32], BackendError> {
    if salt.iter().any(|v| *v >= Val::ORDER_U64) {
        return Err(BackendError::Shape);
    }
    Ok(source::statement::encode_digest(digest(
        &super::transition_trace::command_fields(
            e,
            command,
            revision,
            controllers,
            salt.map(Val::from_u64),
        )?,
    )))
}
impl Expected {
    /// Public stable namespace metadata only; never an installed registry bank.
    pub fn registry_context(&self) -> &BootstrapExpected {
        &self.base
    }
    pub fn statement_scope(&self) -> [u8; 64] {
        self.scope()
    }
}

use super::{transition_air::ProgressAir, transition_layout::TRACE_WIDTH};
use bfv_hiding_stark::{self as engine, Config, SecurityReport, codec};
pub use bootstrap::Error;
use p3_air::BaseAir;
use p3_uni_stark::{Proof, StarkSecurityParams};
const MAGIC: &[u8; 8] = b"DCSPGR01";
struct Backend {
    air: ProgressAir,
    values: Vec<Val>,
    shape: codec::Topology,
    config: Config,
    parameters: StarkSecurityParams,
    report: SecurityReport,
}
impl Backend {
    fn new(s: &Statement) -> Result<Self, Error> {
        s.expected.require_same(&s.expected)?;
        let air = ProgressAir::new(s);
        let values = s.values();
        let (parameters, report) = engine::analyze(&air)?;
        let report = report.require_target()?;
        if air.width() != TRACE_WIDTH
            || values.len() != air.num_public_values()
            || air.preprocessed_width() != 0
            || air.main_next_row_columns().is_empty()
            || report.degree > 5
            || !(2..=16).contains(&report.quotient_chunks)
        {
            return Err(Error::Shape);
        }
        let shape = codec::Topology::checked(TRACE_WIDTH, report.quotient_chunks)?;
        Ok(Self {
            air,
            values,
            shape,
            config: engine::config()?,
            parameters,
            report,
        })
    }
    fn prove(&self, trace: p3_matrix::dense::RowMajorMatrix<Val>) -> Result<Proof<Config>, Error> {
        Ok(engine::prove_with_config(
            &self.config,
            &self.air,
            trace,
            &self.values,
        )?)
    }
    fn verify(&self, p: &Proof<Config>) -> Result<(), Error> {
        Ok(engine::verify_with_assessment(
            &self.config,
            &self.air,
            &self.parameters,
            self.report,
            p,
            &self.values,
        )?)
    }
}
fn header(s: &Statement, n: usize) -> Result<Vec<u8>, Error> {
    if n == 0 || n > bootstrap::MAX_PROOF_BYTES {
        return Err(Error::ResourceLimit);
    }
    let mut out = Vec::with_capacity(bootstrap::HEADER);
    out.extend_from_slice(MAGIC);
    out.push(if s.expected.is_predicate() { 2 } else { 1 });
    out.extend([0; 7]);
    out.extend(profile_digest(s.expected.is_predicate()));
    out.extend(s.identity());
    out.extend((n as u32).to_le_bytes());
    out.extend([0; 4]);
    Ok(out)
}
/// Canonical bounded detached-frame inspection, with no proof authority.
pub fn payload<'a>(s: &Statement, bytes: &'a [u8]) -> Result<&'a [u8], Error> {
    if bytes.len() > bootstrap::MAX_FRAME {
        return Err(Error::ResourceLimit);
    }
    if bytes.len() < bootstrap::HEADER {
        return Err(Error::Encoding);
    }
    let n = u32::from_le_bytes(bytes[112..116].try_into().unwrap()) as usize;
    if bytes[..bootstrap::HEADER] != header(s, n)? {
        return Err(Error::Shape);
    }
    if bootstrap::HEADER.checked_add(n) != Some(bytes.len()) {
        return Err(Error::Encoding);
    }
    Ok(&bytes[bootstrap::HEADER..])
}
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
/// Captured full Expected precedes all SDK work. Source/Encoding are freshly
/// verified and dropped, then security is assessed before any private trace.
pub fn prove(e: &Expected, w: &Witness, p: &Prerequisites<'_>) -> Result<Evidence, Error> {
    w.require_expected(e)?;
    prerequisites(e, p)?;
    let backend = Backend::new(w.statement())?;
    let proof = backend.prove(w.trace()?)?;
    backend.verify(&proof)?;
    let child = codec::serialize(&proof, &backend.shape, bootstrap::MAX_PROOF_BYTES)?;
    let mut bytes = header(w.statement(), child.len())?;
    bytes.extend(child);
    Ok(Evidence {
        statement: w.statement().clone(),
        bytes,
    })
}
/// Fresh mathematical step only. No SQL/finality/current-lock capability.
pub struct VerifiedStep {
    statement: Statement,
}
impl VerifiedStep {
    pub fn statement(&self) -> &Statement {
        &self.statement
    }
}
pub fn verify(
    e: &Expected,
    s: &Statement,
    p: &Prerequisites<'_>,
    bytes: &[u8],
) -> Result<VerifiedStep, Error> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        s.require_expected(e)?;
        let bytes = payload(s, bytes)?;
        prerequisites(e, p)?;
        let backend = Backend::new(s)?;
        let proof = codec::decode(
            bytes,
            &backend.shape,
            bootstrap::MAX_SEQUENCE_ELEMENTS,
            bootstrap::MAX_TOTAL_ELEMENTS,
        )?;
        backend.verify(&proof)?;
        Ok(VerifiedStep {
            statement: s.clone(),
        })
    }))
    .map_err(|_| Error::Verification)?
}

#[cfg(test)]
#[path = "transition_tests.rs"]
mod tests;
