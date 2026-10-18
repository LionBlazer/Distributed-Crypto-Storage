//! Verified Registry200 input -> real ciphertext-only public projection. No SQL/finality grant.
mod fixture;
#[cfg(test)]
mod tests;
use super::super::journal::ProjectionContext;
use super::{Expected as FormationExpected, Prerequisites};
use crate::primitive::PublicStatement;
use bfv_query_core::{
    BfvKeyAnchor, PublicSetup, PublicUpdateEvaluator, PublicUpdateParameters, QueryContext,
    RowProjection,
};
use bfv_query_proof::{CheckedOperation, Operation};
use p3_field::PrimeField64;
use peer_runtime::{ProofReply, RemotePeer, Request, Response, TargetVersion};
use sha2::{Digest, Sha256};
use version_journal::{Freshness, HeadRef, Journal};

#[derive(Debug)]
pub(in crate::opening) enum Error {
    Binding,
    Input(crate::backend::Error),
    Core(bfv_query_core::Error),
    Arithmetic(bfv_query_proof::Error),
    Journal(version_journal::Error),
    Process(crate::opening::peer_process::Error),
    Io(std::io::Error),
    UnexpectedReply,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Binding => f.write_str("Registry200 projection binding mismatch"),
            Self::Input(e) => write!(f, "{e}"),
            Self::Core(e) => write!(f, "{e}"),
            Self::Arithmetic(e) => write!(f, "{e}"),
            Self::Journal(e) => write!(f, "{e}"),
            Self::Process(e) => write!(f, "{e}"),
            Self::Io(e) => write!(f, "{e}"),
            Self::UnexpectedReply => f.write_str("Unexpected Registry200 projection RPC reply"),
        }
    }
}
impl std::error::Error for Error {}
impl From<crate::backend::Error> for Error {
    fn from(e: crate::backend::Error) -> Self {
        Self::Input(e)
    }
}
impl From<bfv_query_core::Error> for Error {
    fn from(e: bfv_query_core::Error) -> Self {
        Self::Core(e)
    }
}
impl From<bfv_query_proof::Error> for Error {
    fn from(e: bfv_query_proof::Error) -> Self {
        Self::Arithmetic(e)
    }
}
impl From<version_journal::Error> for Error {
    fn from(e: version_journal::Error) -> Self {
        Self::Journal(e)
    }
}
impl From<crate::opening::peer_process::Error> for Error {
    fn from(e: crate::opening::peer_process::Error) -> Self {
        Self::Process(e)
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
type Result<T> = std::result::Result<T, Error>;

/// Independent client bindings. QueryId16 is not the complete request32.
#[derive(Clone)]
pub(in crate::opening) struct Binding {
    pub request: [u8; 32],
    pub query_id: [u8; 16],
    pub target: TargetVersion,
    pub setup_id: [u8; 32],
    pub parameters: Vec<u8>,
    pub freshness: Freshness,
}
/// Complete public pins, never a verification receipt or a cached current lease.
#[derive(Clone)]
pub(in crate::opening) struct Expected {
    formation: FormationExpected,
    statement: bfv_ciphertext_formation::Statement,
    anchor: BfvKeyAnchor,
    control: ProjectionContext,
    binding: Binding,
    setup_bytes: Vec<u8>,
    parameters: PublicUpdateParameters,
}
impl Expected {
    pub(in crate::opening::registry_lifecycle) fn new(
        formation: FormationExpected,
        statement: bfv_ciphertext_formation::Statement,
        anchor: BfvKeyAnchor,
        control: ProjectionContext,
        binding: Binding,
        setup_bytes: &[u8],
    ) -> Result<Self> {
        control.require_producer(&formation.encoding)?;
        if formation.encoding.formation_commitment()? != *formation.mathematical.encoding() {
            return Err(Error::Binding);
        }
        let source = formation.encoding.formation_source();
        let (_, projection) = formation.encoding.projection_identity();
        if !(1..=3).contains(&projection) {
            return Err(Error::Binding);
        }
        let key = formation.mathematical.key();
        let scope = anchor.scope();
        if scope.database != key.expected.descriptor.database
            || scope.bfv_key_domain != key.expected.descriptor.key_domain
            || scope.epoch != key.expected.descriptor.key_epoch
            || anchor.coefficient_commitment()
                != key.expected.coefficients.map(|x| x.as_canonical_u64())
        {
            return Err(Error::Binding);
        }
        if binding.request != source.request
            || binding.target.data_head().encode() != source.heads[0]
            || binding.target.index_head().encode() != source.heads[1]
            || setup_bytes.len() as u64 > bfv_query_core::MAX_WIRE_BYTES
            || binding.parameters.len() > 1024
            || binding.setup_id != <[u8; 32]>::from(Sha256::digest(setup_bytes))
            || anchor.full_setup_id() != binding.setup_id
            || statement.full_setup_id != binding.setup_id
            || statement.expected.binding(binding.setup_id)
                != formation.mathematical.binding(binding.setup_id)
        {
            return Err(Error::Binding);
        }
        let setup = PublicSetup::from_bytes(setup_bytes)?;
        if setup.to_bytes()? != setup_bytes {
            return Err(Error::Binding);
        }
        let parameters = setup.update_parameters()?;
        if parameters.to_bytes()? != binding.parameters {
            return Err(Error::Binding);
        }
        Ok(Self {
            formation,
            statement,
            anchor,
            control,
            binding,
            setup_bytes: setup_bytes.to_vec(),
            parameters,
        })
    }
    fn identity(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(
            b"DCS/Registry200/actual-owner-certified-public-projection-job/v1/no-live-SQL-grant",
        );
        h.update(self.binding.request);
        h.update(self.binding.query_id);
        h.update(self.binding.target.data_head().encode());
        h.update(self.binding.target.index_head().encode());
        h.update(self.binding.target.object());
        h.update(self.binding.setup_id);
        h.update(self.control.identity());
        h.update(self.anchor.full_setup_id());
        h.update(self.anchor.scope().database);
        h.update(self.anchor.scope().bfv_key_domain);
        h.update(self.anchor.scope().epoch.to_le_bytes());
        for x in self.anchor.coefficient_commitment() {
            h.update(x.to_le_bytes());
        }
        let (_, projection) = self.formation.encoding.projection_identity();
        h.update([projection]);
        h.update(self.formation.mathematical.encoding().producer_identity());
        for x in self
            .formation
            .encoding
            .public_values()
            .into_iter()
            .chain(self.statement.public_values())
        {
            h.update(x.as_canonical_u64().to_le_bytes());
        }
        h.update((self.binding.parameters.len() as u64).to_le_bytes());
        h.update(&self.binding.parameters);
        h.update(bfv_query_proof::PROOF_PROFILE_ID);
        match self.binding.freshness {
            Freshness::LatestConfirmed => h.update([0]),
            Freshness::Exact(head) => {
                h.update([1]);
                hash_head(&mut h, head);
            }
            Freshness::AtLeast(head) => {
                h.update([2]);
                hash_head(&mut h, head);
            }
        }
        h.finalize().into()
    }
    fn projection(&self) -> Result<RowProjection> {
        match self.formation.encoding.projection_identity().1 {
            1 => Ok(RowProjection::Age),
            2 => Ok(RowProjection::Amount),
            3 => Ok(RowProjection::AgeAmount),
            _ => Err(Error::Binding),
        }
    }
    fn check_control(&self, journal: &Journal) -> Result<HeadRef> {
        Ok(self.control.check(journal, self.binding.freshness)?)
    }
}
fn hash_head(h: &mut Sha256, head: HeadRef) {
    h.update(head.genesis);
    h.update(head.database);
    h.update(head.block);
    h.update(head.height.to_le_bytes());
    h.update(head.state_root);
}

/// Only public bytes/metadata survive actual prerequisite verification.
pub(in crate::opening) struct Prepared {
    identity: [u8; 32],
    object: [u8; 32],
    setup_id: [u8; 32],
    setup_bytes: Vec<u8>,
    parameters: PublicUpdateParameters,
    request: Vec<u8>,
    canonical: Vec<u8>,
}
pub(in crate::opening) fn prepare(
    expected: &Expected,
    journal: &Journal,
    encoding_frame: &[u8],
    prerequisites: &Prerequisites<'_>,
    formation_frame: &[u8],
) -> Result<Prepared> {
    let setup = PublicSetup::from_bytes(&expected.setup_bytes)?;
    let checked = super::verify(
        &setup,
        &expected.anchor,
        &expected.formation,
        encoding_frame,
        prerequisites,
        formation_frame,
    )?;
    if checked.statement().public_values() != expected.statement.public_values() {
        return Err(Error::Binding);
    }
    expected.check_control(journal)?;
    let evaluator = PublicUpdateEvaluator::from_parameters(&expected.parameters)?;
    let context = QueryContext::new(
        expected.binding.query_id,
        expected.binding.target.data_head().encode(),
        expected.binding.target.index_head().encode(),
    );
    let request = evaluator.encode_public_select(
        context,
        expected.projection()?,
        expected.formation.mathematical.ciphertext().bytes(),
    )?;
    let canonical = evaluator.select_circuit_request(&request)?;
    Ok(Prepared {
        identity: expected.identity(),
        object: *expected.binding.target.object(),
        setup_id: expected.binding.setup_id,
        setup_bytes: expected.setup_bytes.clone(),
        parameters: expected.parameters.clone(),
        request,
        canonical,
    })
}
/// This owns a RAW peer reply, never a checked answer or a freshness token.
pub(in crate::opening) struct Received {
    prepared: Prepared,
    reply: ProofReply,
}
pub(in crate::opening) struct VerifiedEncryptedProjection {
    identity: [u8; 32],
    checked: CheckedOperation,
    encrypted_response: Vec<u8>,
    request: Vec<u8>,
    resolved: HeadRef,
}
impl VerifiedEncryptedProjection {
    pub(in crate::opening) fn identity(&self) -> [u8; 32] {
        self.identity
    }
    pub(in crate::opening) fn encrypted_response(&self) -> &[u8] {
        &self.encrypted_response
    }
    pub(in crate::opening) fn request(&self) -> &[u8] {
        &self.request
    }
    pub(in crate::opening) fn checked(&self) -> &CheckedOperation {
        &self.checked
    }
    pub(in crate::opening) fn resolved(&self) -> HeadRef {
        self.resolved
    }
}
impl Prepared {
    fn require_expected(&self, expected: &Expected) -> Result<()> {
        if self.identity != expected.identity() {
            return Err(Error::Binding);
        }
        Ok(())
    }
    pub(in crate::opening) fn check_before_io(
        &self,
        expected: &Expected,
        journal: &Journal,
    ) -> Result<()> {
        self.require_expected(expected)?;
        expected.check_control(journal)?;
        Ok(())
    }
    pub(in crate::opening) fn send(
        self,
        expected: &Expected,
        journal: &Journal,
        remote: &RemotePeer,
    ) -> Result<Received> {
        self.check_before_io(expected, journal)?;
        match remote.call(Request::InstallSetup(self.setup_bytes.clone()))? {
            Response::Setup(id) if id == self.setup_id => {}
            _ => return Err(Error::UnexpectedReply),
        }
        let reply = match remote.call(Request::Prove {
            object: self.object,
            setup: self.setup_id,
            operation: peer_runtime::Operation::Select,
            ciphertext: self.request.clone(),
        })? {
            Response::Proved(reply) => reply,
            _ => return Err(Error::UnexpectedReply),
        };
        Ok(Received {
            prepared: self,
            reply,
        })
    }
    pub(in crate::opening) fn run_remote(
        self,
        expected: &Expected,
        journal: &Journal,
        remote: &RemotePeer,
    ) -> Result<VerifiedEncryptedProjection> {
        self.send(expected, journal, remote)?
            .finish(expected, journal)
    }
}
impl Received {
    pub(in crate::opening) fn finish(
        self,
        expected: &Expected,
        journal: &Journal,
    ) -> Result<VerifiedEncryptedProjection> {
        let prepared = self.prepared;
        prepared.require_expected(expected)?;
        let checked =
            bfv_query_proof::verify(&prepared.canonical, &self.reply.output, &self.reply.proof)?;
        if checked.operation() != Operation::PublicPolynomialProduct
            || !checked.matches_statement(&prepared.canonical, &self.reply.output)
        {
            return Err(Error::Binding);
        }
        // The real post-RPC branch/control read happens AFTER actual arithmetic verification.
        let resolved = expected.check_control(journal)?;
        let evaluator = PublicUpdateEvaluator::from_parameters(&prepared.parameters)?;
        let response =
            evaluator.restore_select_circuit_output(&prepared.request, &self.reply.output)?;
        Ok(VerifiedEncryptedProjection {
            identity: prepared.identity,
            checked,
            encrypted_response: response,
            request: prepared.request,
            resolved,
        })
    }
}
pub(in crate::opening::registry_lifecycle) fn gate(
    mode: &str,
    executable: &std::path::Path,
) -> Result<()> {
    if mode != "prove" {
        return Err(Error::Binding);
    }
    let path = crate::opening::peer_process::checked_executable(executable)?;
    fixture::gate(&path)
}
