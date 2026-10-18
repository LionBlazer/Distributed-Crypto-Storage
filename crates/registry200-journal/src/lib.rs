//! Concrete owner-authorized private-control application, verified by actual Source/Lifecycle proofs.
#![forbid(unsafe_code)]
pub mod control;
pub mod request;
pub use control::{Application, ApplicationDescriptor, Control, DESCRIPTOR_BYTES};
use registry200_proof::{admission::Expected, wire};
pub use request::{Operation, REQUEST_BYTES, Request, intent_query};
use version_journal::{Error, Genesis, Hash, Result, TransitionStatement, TransitionVerifier};
/// Called only by the real Journal, which verifies owner authorization before this callback.
/// Direct calls establish computation consistency only, never write authority.
pub struct RegistryVerifier {
    application: Application,
    genesis: Hash,
}
impl RegistryVerifier {
    pub fn new(application: Application, genesis: &Genesis) -> Result<Self> {
        application.require_genesis(genesis)?;
        let application =
            control::ApplicationDescriptor::from_application(&application)?.application()?;
        Ok(Self {
            application,
            genesis: genesis.id()?,
        })
    }
    pub fn check(&self, s: TransitionStatement<'_>) -> Result<()> {
        let app = &self.application;
        if s.genesis != self.genesis
            || s.database != app.database
            || s.application_commitment != app.id()
            || s.parent.genesis != self.genesis
            || s.parent.database != app.database
            || s.updates.len() != 1
            || s.previous_shards.len() != 2
            || s.next_shards.len() != 2
        {
            return Err(Error::WrongDomain);
        }
        if version_journal::state_root(s.previous_shards) != s.parent.state_root
            || version_journal::state_root(s.next_shards) != s.next_state_root
        {
            return Err(Error::InvalidTransition);
        }
        let old_heads = app.control(s.previous_shards)?;
        let next_heads = app.control(s.next_shards)?;
        let update = &s.updates[0];
        if update.id != app.control_id
            || update.old != old_heads
            || update.new != next_heads
            || update.old == update.new
        {
            return Err(Error::InvalidTransition);
        }
        let old = Control::decode(app, old_heads)?;
        let next = Control::decode(app, next_heads)?;
        let r = Request::decode(s.request)?;
        if r.genesis != s.genesis
            || r.parent != s.parent.block
            || r.application != app.id()
            || r.query
                != request::intent_query(
                    app,
                    s.genesis,
                    s.parent.block,
                    r.nonce,
                    r.enrollment,
                    r.operation,
                )
        {
            return Err(Error::WrongDomain);
        }
        let source = r.source(app)?;
        let source = registry200_proof::admission::CanonicalSource::checked_claim(&source)
            .map_err(|_| Error::RejectedComputationProof)?;
        let checked = match (r.operation, old) {
            (Operation::Bootstrap, Control::Pending) => {
                let e = Expected::bootstrap(&source, s.genesis, s.parent.block, r.enrollment)
                    .map_err(|_| Error::RejectedComputationProof)?;
                let verified =
                    wire::verify(&e, s.proof).map_err(|_| Error::RejectedComputationProof)?;
                Control::Active {
                    enrollment: r.enrollment,
                    registry: verified.next_root(),
                }
            }
            (
                Operation::Transition,
                Control::Active {
                    enrollment,
                    registry,
                },
            ) => {
                if r.enrollment != enrollment {
                    return Err(Error::InvalidTransition);
                }
                let e = Expected::transition(
                    &source,
                    s.genesis,
                    s.parent.block,
                    enrollment,
                    registry,
                    r.command,
                )
                .map_err(|_| Error::RejectedComputationProof)?;
                let verified =
                    wire::verify(&e, s.proof).map_err(|_| Error::RejectedComputationProof)?;
                let root = verified.next_root();
                if root == registry {
                    return Err(Error::InvalidTransition);
                }
                Control::Active {
                    enrollment,
                    registry: root,
                }
            }
            _ => return Err(Error::InvalidTransition),
        };
        if checked != next {
            return Err(Error::InvalidTransition);
        }
        Ok(())
    }
}
impl TransitionVerifier for RegistryVerifier {
    fn verify(&self, s: TransitionStatement<'_>) -> Result<()> {
        self.check(s)
    }
}
#[cfg(test)]
mod tests;
