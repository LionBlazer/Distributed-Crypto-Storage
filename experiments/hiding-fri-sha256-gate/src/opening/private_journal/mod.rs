//! Owner-authorized private-control Journal experiment. No live SQL grant/finality.
mod control;
mod fixture;
mod request;
#[cfg(test)]
mod tests;

use crate::opening::{locking, registry_bootstrap};
use control::{Application, Control};
use request::{Operation, Request};
use version_journal::{Error, Genesis, Hash, Result, TransitionStatement, TransitionVerifier};

/// The application/genesis are independently pinned before any imported body.
/// This verifier owns no owner/controller signing key and returns no grant token.
struct PrivateVerifier {
    application: Application,
    genesis: Hash,
}
impl PrivateVerifier {
    fn new(application: Application, genesis: &Genesis) -> Result<Self> {
        application.require_genesis(genesis)?;
        Ok(Self {
            application,
            genesis: genesis.id()?,
        })
    }
    fn check(&self, s: TransitionStatement<'_>) -> Result<()> {
        let app = &self.application;
        if s.genesis != self.genesis
            || s.database != app.database
            || s.application_commitment != app.id()
            || s.parent.genesis != self.genesis
            || s.parent.database != app.database
            || s.previous_shards.len() != 2
            || s.next_shards.len() != 2
            || s.updates.len() != 1
        {
            return Err(Error::WrongDomain);
        }
        if version_journal::state_root(s.previous_shards) != s.parent.state_root
            || version_journal::state_root(s.next_shards) != s.next_state_root
        {
            return Err(Error::InvalidTransition);
        }
        let source = s
            .previous_shards
            .iter()
            .find(|v| v.id == app.source_id)
            .ok_or(Error::InvalidTransition)?;
        let old = s
            .previous_shards
            .iter()
            .find(|v| v.id == app.control_id)
            .ok_or(Error::InvalidTransition)?;
        if source.heads != app.source {
            return Err(Error::WrongDomain);
        }
        let update = &s.updates[0];
        if update.id != app.control_id || update.old != old.heads || update.old == update.new {
            return Err(Error::InvalidTransition);
        }
        for (previous, next) in s.previous_shards.iter().zip(s.next_shards) {
            if previous.id != next.id
                || next.heads
                    != if previous.id == app.control_id {
                        update.new
                    } else {
                        previous.heads
                    }
            {
                return Err(Error::InvalidTransition);
            }
        }
        let old_control = Control::decode(app, old.heads)?;
        let new_control = Control::decode(app, update.new)?;
        let request = Request::decode(s.request)?;
        if request.genesis != s.genesis
            || request.parent != s.parent.block
            || request.application != app.id()
        {
            return Err(Error::WrongDomain);
        }
        let source = request.source(app)?;
        let checked = match (request.operation, old_control) {
            (Operation::Bootstrap, Control::Pending) => {
                if request.query
                    != request::bootstrap_query(
                        app,
                        s.genesis,
                        s.parent.block,
                        request.nonce,
                        request.enrollment,
                    )
                {
                    return Err(Error::InvalidTransition);
                }
                let expected = registry_bootstrap::statement::Expected::checked(
                    &source,
                    s.genesis,
                    s.parent.block,
                    request.enrollment,
                )
                .map_err(|_| Error::RejectedComputationProof)?;
                let verified = registry_bootstrap::wire::verify(&expected, s.proof)
                    .map_err(|_| Error::RejectedComputationProof)?;
                Control::Active {
                    enrollment: request.enrollment,
                    registry: verified.registry_root(),
                }
            }
            (
                Operation::Acquire,
                Control::Active {
                    enrollment,
                    registry,
                },
            ) => {
                if request.enrollment != enrollment {
                    return Err(Error::InvalidTransition);
                }
                let expected = locking::statement::Expected::checked(
                    &source,
                    s.genesis,
                    s.parent.block,
                    registry,
                    request.plan,
                )
                .map_err(|_| Error::RejectedComputationProof)?;
                let verified = locking::wire::verify(&expected, s.proof)
                    .map_err(|_| Error::RejectedComputationProof)?;
                let next = locking::statement::encoded(verified.next);
                // Explicit CAS guard in addition to the stable-head and Journal checks.
                if next == registry {
                    return Err(Error::InvalidTransition);
                }
                Control::Active {
                    enrollment,
                    registry: next,
                }
            }
            _ => return Err(Error::InvalidTransition),
        };
        if checked != new_control {
            return Err(Error::InvalidTransition);
        }
        Ok(())
    }
}
impl TransitionVerifier for PrivateVerifier {
    fn verify(&self, statement: TransitionStatement<'_>) -> Result<()> {
        self.check(statement)
    }
}

/// Checks the complete Body cap; a proof cap alone omits canonical Journal overhead.
fn bounded_body(
    profile: &version_journal::ProtocolProfile,
    transition: version_journal::AuthorizedTransition,
) -> Result<version_journal::Body> {
    let expected = body_size(
        transition.request.len(),
        transition.updates.len(),
        transition.proof.len(),
    )?;
    if expected > version_journal::MAX_BODY_BYTES || expected > profile.max_body_bytes as usize {
        return Err(Error::ResourceLimit);
    }
    let body = version_journal::Body::Transition(transition);
    if body.encode(profile)?.len() != expected {
        return Err(Error::InvalidEncoding);
    }
    Ok(body)
}

fn body_size(request: usize, updates: usize, proof: usize) -> Result<usize> {
    117usize
        .checked_add(request)
        .and_then(|n| n.checked_add(updates.checked_mul(456)?))
        .and_then(|n| n.checked_add(proof))
        .ok_or(Error::ResourceLimit)
}

pub(crate) fn gate(mode: &str) -> std::result::Result<(), crate::backend::Error> {
    fixture::gate(mode)
}
