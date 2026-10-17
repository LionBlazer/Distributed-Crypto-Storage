//! Owner-local preparation. Neither this builder nor its private state is a verifier.
use super::super::{
    model::{Command, Registry},
    statement::{self, Expected, Phase},
    trace::Witness,
    wire,
};
use super::{Application, Control, Error, Hash, Operation, Request, Result, backend, request};
use crate::backend::Val;
use crate::opening::{commitment, statement as source, trace as source_trace};
use ed25519_dalek::SigningKey;
use version_journal::{
    AuthorizedTransition, Body, Genesis, HeadPair, HeadRef, Journal, ShardUpdate,
};

/// An exact known validated protocol parent, not a client freshness/confirmation token.
/// Its control head is read from the independent Journal, never nominated by the opening.
pub(super) struct ValidatedParent {
    parent: HeadRef,
    heads: HeadPair,
    control: Control,
}
impl ValidatedParent {
    pub(super) fn read(app: &Application, journal: &Journal, parent: HeadRef) -> Result<Self> {
        app.require_genesis(journal.genesis())?;
        if parent.genesis != journal.genesis_id() || parent.database != app.database {
            return Err(Error::WrongDomain);
        }
        let heads = app.control(journal.validated_shards(parent)?)?;
        Ok(Self {
            parent,
            heads,
            control: Control::decode(app, heads)?,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PrivateState {
    pub(super) registry: Registry,
    pub(super) salt: [Val; 4],
}
/// The source is encrypted once. Only request/C_open change for each command.
pub(super) struct Inputs<'a> {
    pub(super) app: &'a Application,
    pub(super) source: &'a source::Statement,
    pub(super) source_witness: &'a source_trace::Witness,
    pub(super) opening: &'a Witness,
}
pub(super) struct Prepared<'a> {
    app: &'a Application,
    expected: Expected,
    witness: Witness,
    source_witness: &'a source_trace::Witness,
    old_heads: HeadPair,
    request: Request,
}
pub(super) struct Produced {
    pub(super) body: Body,
    pub(super) private: PrivateState,
    pub(super) outcome: u8,
    pub(super) returned: [bool; 4],
    pub(super) skipped: [bool; 4],
    #[cfg(test)]
    pub(super) expected: Expected,
}
impl<'a> Inputs<'a> {
    fn source(&self, query: Hash) -> Result<source::Statement> {
        self.app.require_source(self.source)?;
        let mut s = self.source.clone();
        s.request = query;
        s.open_commitment = commitment::digest(&commitment::opening_fields(
            &s,
            self.opening.salts[0],
            &self.opening.plain,
        ));
        Ok(s)
    }
    fn request(
        &self,
        accepted: &ValidatedParent,
        nonce: Hash,
        e: &Expected,
        operation: Operation,
        command: Hash,
    ) -> Request {
        Request {
            operation,
            genesis: accepted.parent.genesis,
            parent: accepted.parent.block,
            application: self.app.id(),
            nonce,
            query: e.source.request,
            enrollment: statement::encoded(e.enrollment),
            opening: statement::encoded(e.source.open_commitment),
            command,
            packets: e.source.packets.clone(),
        }
    }
    pub(super) fn bootstrap(
        &self,
        accepted: &ValidatedParent,
        nonce: Hash,
    ) -> Result<Prepared<'a>> {
        Control::decode(self.app, accepted.heads)?;
        if accepted.control != Control::Pending
            || self.opening.old != Registry::default()
            || self.opening.command.is_some()
        {
            return Err(Error::InvalidTransition);
        }
        let mut e = backend(Expected::bootstrap(
            self.source,
            accepted.parent.genesis,
            accepted.parent.block,
            [0; 32],
        ))?;
        let enrollment = commitment::digest(&statement::enrollment_fields(&e, self.opening));
        let query = request::intent_query(
            self.app,
            e.genesis,
            e.parent,
            nonce,
            statement::encoded(enrollment),
            Operation::Bootstrap,
        );
        e.source = self.source(query)?;
        e.enrollment = enrollment;
        let witness = self.opening.clone();
        let request = self.request(accepted, nonce, &e, Operation::Bootstrap, [0; 32]);
        Ok(Prepared {
            app: self.app,
            expected: e,
            witness,
            source_witness: self.source_witness,
            old_heads: accepted.heads,
            request,
        })
    }
    pub(super) fn transition(
        &self,
        accepted: &ValidatedParent,
        private: &PrivateState,
        command: Command,
        nonce: Hash,
    ) -> Result<Prepared<'a>> {
        Control::decode(self.app, accepted.heads)?;
        let Control::Active {
            enrollment,
            registry,
        } = accepted.control
        else {
            return Err(Error::InvalidTransition);
        };
        backend(private.registry.require_canonical())?;
        backend(command.require_shape())?;
        let query = request::intent_query(
            self.app,
            accepted.parent.genesis,
            accepted.parent.block,
            nonce,
            enrollment,
            Operation::Transition,
        );
        let source = self.source(query)?;
        let mut e = backend(Expected::transition(
            &source,
            accepted.parent.genesis,
            accepted.parent.block,
            enrollment,
            registry,
            [0; 32],
        ))?;
        let mut witness = self.opening.clone();
        witness.old = private.registry.clone();
        witness.command = Some(command);
        witness.salts[2] = private.salt;
        // Check externally accepted Cold BEFORE computing C_cmd or entering any trace factory.
        let opened = statement::digest(&statement::registry_fields(
            &e,
            &witness,
            &private.registry,
            private.salt,
        ));
        if statement::encoded(opened) != registry
            || commitment::digest(&statement::enrollment_fields(&e, &witness)) != e.enrollment
        {
            return Err(Error::InvalidTransition);
        }
        let command = statement::digest(&statement::command_fields(
            &e,
            &witness,
            witness.command.as_ref().unwrap(),
        ));
        e.phase = Phase::Transition {
            old: opened,
            command,
        };
        // Pure owner-side preflight, not part of public verification or authority.
        backend(witness.statement(&e))?;
        let request = self.request(
            accepted,
            nonce,
            &e,
            Operation::Transition,
            statement::encoded(command),
        );
        Ok(Prepared {
            app: self.app,
            expected: e,
            witness,
            source_witness: self.source_witness,
            old_heads: accepted.heads,
            request,
        })
    }
}
impl Prepared<'_> {
    #[cfg(test)]
    pub(super) fn encoding_inputs(&self) -> (&Expected, &Witness) {
        (&self.expected, &self.witness)
    }

    /// Actual proof generation; the independent Journal will verify the emitted bytes again.
    pub(super) fn prove(self, genesis: &Genesis, owner: &SigningKey) -> Result<Produced> {
        let app = self.app;
        app.require_genesis(genesis)?;
        if genesis.id() != Ok(self.expected.genesis)
            || genesis.owner != owner.verifying_key().to_bytes()
        {
            return Err(Error::Unauthorized);
        }
        let (next, outcome, returned, skipped, salt) = match self.expected.phase {
            Phase::Bootstrap => (
                Registry::default(),
                0,
                [false; 4],
                [false; 4],
                self.witness.salts[4],
            ),
            Phase::Transition { .. } => {
                let step = backend(self.witness.old.step(
                    self.witness.command.as_ref().unwrap(),
                    self.expected.parent,
                    self.witness.ages(),
                ))?;
                let salt = if step.outcome == 1 || step.outcome == 2 {
                    self.witness.salts[2]
                } else {
                    self.witness.salts[4]
                };
                (step.next, step.outcome, step.returned, step.skipped, salt)
            }
        };
        let (s, p) = backend(super::super::prove(
            &self.expected,
            self.source_witness,
            &self.witness,
        ))?;
        let proof =
            wire::encode(&self.expected, &s, &p).map_err(|_| Error::RejectedComputationProof)?;
        drop(p);
        let new = Control::Active {
            enrollment: statement::encoded(self.expected.enrollment),
            registry: statement::encoded(s.next),
        }
        .heads(app);
        let mut t = AuthorizedTransition {
            parent: self.expected.parent,
            request: self.request.encode()?,
            updates: vec![ShardUpdate {
                id: app.control_id,
                old: self.old_heads,
                new,
            }],
            proof,
            owner_signature: [0; 64],
        };
        t.sign(self.expected.genesis, owner);
        let body = Body::Transition(t);
        // The core codec checks the COMPLETE body against the unchanged pinned profile/cap.
        let _ = body.encode(&genesis.profile)?;
        Ok(Produced {
            body,
            private: PrivateState {
                registry: next,
                salt,
            },
            outcome,
            returned,
            skipped,
            #[cfg(test)]
            expected: self.expected,
        })
    }
    pub(super) fn statement(&self) -> Result<super::super::statement::Statement> {
        backend(self.witness.statement(&self.expected))
    }
    pub(super) fn source_statement(&self) -> &source::Statement {
        &self.expected.source
    }
}
