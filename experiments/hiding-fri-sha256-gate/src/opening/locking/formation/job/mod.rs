//! Nonaccepting source-certified input -> real ciphertext-only BFV public projection.
//! Client-bound same-C_plan public projection; no SQL permission/freshness/key authority.
pub(in crate::opening) mod fixture;
mod process;
#[cfg(test)]
mod tests;
use super::{Prerequisites, returned, statement as formation};
use crate::backend::Config;
use crate::{backend::Error as InputError, primitive::PublicStatement};
use bfv_query_core::{
    PublicSetup, PublicUpdateEvaluator, PublicUpdateParameters, QueryContext, RowProjection,
};
use bfv_query_proof::{CheckedOperation, Operation};
use p3_field::PrimeField64;
use p3_uni_stark::Proof;
use peer_runtime::{ProofReply, RemotePeer, Request, Response};
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub(in crate::opening) enum Error {
    Binding,
    Input(InputError),
    Core(bfv_query_core::Error),
    Arithmetic(bfv_query_proof::Error),
    Io(std::io::Error),
    UnexpectedReply,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Binding => write!(f, "Certified projection binding mismatch"),
            Self::Input(e) => write!(f, "Certified projection prerequisite: {e}"),
            Self::Core(e) => write!(f, "Certified projection codec: {e}"),
            Self::Arithmetic(e) => write!(f, "Certified projection arithmetic: {e}"),
            Self::Io(e) => write!(f, "Certified projection I/O: {e}"),
            Self::UnexpectedReply => write!(f, "Certified projection unexpected RPC reply"),
        }
    }
}
impl std::error::Error for Error {}
impl From<InputError> for Error {
    fn from(e: InputError) -> Self {
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
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
type Result<T> = std::result::Result<T, Error>;

/// All fields are CLIENT-owned independent expectations, not authority obtained
/// from a peer or from construction. The sealed compiler capability separately
/// supplies the public projection tied to the SAME exact private C_plan.
#[derive(Clone)]
pub(in crate::opening) struct Binding {
    pub(in crate::opening) request: [u8; 32],
    pub(in crate::opening) query_id: [u8; 16],
    pub(in crate::opening) parent: [u8; 32],
    pub(in crate::opening) target: peer_runtime::TargetVersion,
    pub(in crate::opening) setup_id: [u8; 32],
    pub(in crate::opening) parameters: Vec<u8>,
}
/// Sealed full formation statement and exact complete setup. No supplied CT,
/// canonical operand vector, B vector, trusted boolean or caller pending token.
pub(in crate::opening) struct Expected {
    formation: formation::Expected,
    query: crate::opening::locking::sql::BoundCompiledLockQuery,
    statement: formation::Statement,
    binding: Binding,
    setup_bytes: Vec<u8>,
    parameters: PublicUpdateParameters,
}
impl Expected {
    pub(in crate::opening) fn new(
        formation: formation::Expected,
        statement: formation::Statement,
        binding: Binding,
        query: crate::opening::locking::sql::BoundCompiledLockQuery,
        setup_bytes: &[u8],
    ) -> Result<Self> {
        formation.validate()?;
        statement.require_expected(&formation)?;
        query.require_returned(formation.producer())?;
        if query.request() != binding.request {
            return Err(Error::Binding);
        }
        let lock = formation.producer().lock();
        if binding.request != *lock.expected.request()
            || binding.parent != lock.expected.parent
            || binding.target.data_head().encode() != lock.expected.source.heads[0]
            || binding.target.index_head().encode() != lock.expected.source.heads[1]
            || setup_bytes.len() as u64 > bfv_query_core::MAX_WIRE_BYTES
            || binding.parameters.len() > 1024
            || binding.setup_id != <[u8; 32]>::from(Sha256::digest(setup_bytes))
        {
            return Err(Error::Binding);
        }
        let setup = PublicSetup::from_bytes(setup_bytes)?;
        // This outer codec contains opaque key bytes: preserving its exact wire
        // does NOT deserialize/reorder the upstream rotation-key HashMap.
        if setup.to_bytes()? != setup_bytes {
            return Err(Error::Binding);
        }
        let parameters = setup.update_parameters()?;
        if parameters.to_bytes()? != binding.parameters {
            return Err(Error::Binding);
        }
        Ok(Self {
            formation,
            query,
            statement,
            binding,
            setup_bytes: setup_bytes.to_vec(),
            parameters,
        })
    }
    fn identity(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"DCS/experimental/certified-public-projection-job/v1/no-SQL-grant");
        h.update(self.binding.request);
        h.update(self.binding.query_id);
        h.update(self.binding.parent);
        h.update(self.binding.target.data_head().encode());
        h.update(self.binding.target.index_head().encode());
        h.update(self.binding.target.object());
        h.update(self.binding.setup_id);
        h.update([match self.query.projection() {
            RowProjection::Age => 1,
            RowProjection::Amount => 2,
            RowProjection::AgeAmount => 3,
        }]);
        h.update((self.binding.parameters.len() as u64).to_le_bytes());
        h.update(&self.binding.parameters);
        h.update(bfv_query_proof::PROOF_PROFILE_ID);
        for v in self.statement.public_values() {
            h.update(v.as_canonical_u64().to_le_bytes());
        }
        h.finalize().into()
    }
}
/// Constructible ONLY after actual complete prerequisite verification. Owns only
/// public job/setup/descriptor bytes, never a key, plaintext, source witness,
/// Backend, StateLease or prerequisite proof. It is not a cached freshness token.
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
    parent: Option<returned::Evidence<'_, '_>>,
    prerequisites: &Prerequisites,
    proof: &Proof<Config>,
) -> Result<Prepared> {
    // Neither request construction nor any network call precedes this REAL chain:
    // canonical Source+Lock OR actual StateLease+Lock, Encoding, Key, 5 Basis, Local.
    super::verify(
        &expected.formation,
        &expected.statement,
        parent,
        prerequisites,
        proof,
    )?;
    let evaluator = PublicUpdateEvaluator::from_parameters(&expected.parameters)?;
    let context = QueryContext::new(
        expected.binding.query_id,
        expected.binding.target.data_head().encode(),
        expected.binding.target.index_head().encode(),
    );
    let request = evaluator.encode_public_select(
        context,
        expected.query.projection(),
        expected.formation.bases[0].expected.ciphertext().bytes(),
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
/// Exact arithmetic and certified-input linkage only. This type grants no lock,
/// mutation, SQL result, current agreed head, key authority or hidden projection.
pub(in crate::opening) struct VerifiedEncryptedProjection {
    identity: [u8; 32],
    checked: CheckedOperation,
    canonical_output: Vec<u8>,
    encrypted_response: Vec<u8>,
}
impl VerifiedEncryptedProjection {
    pub(in crate::opening) fn identity(&self) -> [u8; 32] {
        self.identity
    }
    pub(in crate::opening) fn checked(&self) -> &CheckedOperation {
        &self.checked
    }
    pub(in crate::opening) fn canonical_output(&self) -> &[u8] {
        &self.canonical_output
    }
    pub(in crate::opening) fn encrypted_response(&self) -> &[u8] {
        &self.encrypted_response
    }
}
impl Prepared {
    fn require_expected(&self, expected: &Expected) -> Result<()> {
        if self.identity != expected.identity() {
            return Err(Error::Binding);
        }
        Ok(())
    }
    pub(in crate::opening) fn finish(
        self,
        expected: &Expected,
        reply: ProofReply,
    ) -> Result<VerifiedEncryptedProjection> {
        self.require_expected(expected)?;
        let checked = bfv_query_proof::verify(&self.canonical, &reply.output, &reply.proof)?;
        if checked.operation() != Operation::PublicPolynomialProduct
            || !checked.matches_statement(&self.canonical, &reply.output)
        {
            return Err(Error::Binding);
        }
        let evaluator = PublicUpdateEvaluator::from_parameters(&self.parameters)?;
        let encrypted_response =
            evaluator.restore_select_circuit_output(&self.request, &reply.output)?;
        Ok(VerifiedEncryptedProjection {
            identity: self.identity,
            checked,
            canonical_output: reply.output,
            encrypted_response,
        })
    }
    /// Actual existing RPCs. RemotePeer owns its independent u64 envelope ID and
    /// validates response version/id; neither that ID nor TLS is a proof/finality.
    /// Known wrong reply variants remain successful RPCs but reject this job.
    pub(in crate::opening) fn run_remote(
        self,
        expected: &Expected,
        remote: &RemotePeer,
    ) -> Result<VerifiedEncryptedProjection> {
        self.require_expected(expected)?;
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
        self.finish(expected, reply)
    }
}
/// Explicit ciphertext-only worker. There is no source witness/key/plaintext
/// parameter and no fallback that echoes the input. This is not physical custody.
#[cfg(test)]
pub(in crate::opening) fn execute_public(
    parameters: &PublicUpdateParameters,
    request: &[u8],
) -> Result<ProofReply> {
    let evaluator = PublicUpdateEvaluator::from_parameters(parameters)?;
    let canonical = evaluator.select_circuit_request(request)?;
    let operation = bfv_query_proof::prove(&canonical)?;
    Ok(ProofReply {
        output: operation.output().to_vec(),
        proof: operation.proof().to_vec(),
    })
}
pub(crate) fn gate(
    mode: &str,
    peer_executable: &std::path::Path,
) -> std::result::Result<(), InputError> {
    if mode != "prove" {
        return Err(InputError::Shape);
    } // No fabricated new numeric AIR.
    let executable = process::checked_executable(peer_executable).map_err(|_| InputError::Shape)?;
    fixture::gate(&executable).map_err(|error| {
        eprintln!("Certified projection job: {error}");
        InputError::Verification
    })
}

#[cfg(test)]
pub(in crate::opening) fn execute_prepared_public(
    prepared: Prepared,
    expected: &Expected,
) -> Result<VerifiedEncryptedProjection> {
    prepared.require_expected(expected)?;
    let reply = execute_public(&prepared.parameters, &prepared.request)?;
    prepared.finish(expected, reply)
}
