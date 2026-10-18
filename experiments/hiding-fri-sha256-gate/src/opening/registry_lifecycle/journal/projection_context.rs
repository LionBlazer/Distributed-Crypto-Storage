//! Re-read actual admitted Registry200 control state. This is not a global freshness oracle.
use super::super::{encoding, statement, wire};
use super::{Application, Control, Error, Hash, Operation, Request, Result};
use crate::primitive::PublicStatement;
use sha2::{Digest, Sha256};
use version_journal::{Body, Freshness, HeadPair, HeadRef, Journal};

/// Public context only. Construction reads the actual signed, validated Acquire
/// body; every use re-reads both the resolved branch and its conservative tip.
#[derive(Clone)]
pub(in crate::opening::registry_lifecycle) struct ProjectionContext {
    application: Application,
    parent: HeadRef,
    acquired: HeadRef,
    old: HeadPair,
    active: HeadPair,
    request: Vec<u8>,
    body_hash: Hash,
    producer: statement::Statement,
}
impl ProjectionContext {
    pub(super) fn new(
        application: &Application,
        journal: &Journal,
        acquired: HeadRef,
        encoded: &encoding::Statement,
        encoding_frame: &[u8],
    ) -> Result<Self> {
        application.require_genesis(journal.genesis())?;
        let decoded = encoding::decode_and_verify(encoded.formation_expected(), encoding_frame)
            .map_err(|_| Error::RejectedComputationProof)?;
        encoded
            .require_complete_formation_statement(&decoded)
            .map_err(|_| Error::RejectedComputationProof)?;
        let producer = encoded.projection_producer();
        let e = &producer.expected;
        application.require_source(&e.source)?;
        let statement::Phase::Transition { old, command } = e.phase else {
            return Err(Error::InvalidTransition);
        };
        if e.genesis != journal.genesis_id()
            || acquired.genesis != e.genesis
            || acquired.database != application.database
        {
            return Err(Error::WrongDomain);
        }
        let header = journal.header(acquired.block).ok_or(Error::UnknownHead)?;
        if header.parent != e.parent
            || header.height != acquired.height
            || header.state_root != acquired.state_root
        {
            return Err(Error::WrongDomain);
        }
        let parent_header = journal.header(e.parent).ok_or(Error::UnknownParent)?;
        let parent = HeadRef {
            genesis: e.genesis,
            database: application.database,
            block: e.parent,
            height: parent_header.height,
            state_root: parent_header.state_root,
        };
        let old_heads = application.control(journal.validated_shards(parent)?)?;
        let next_heads = application.control(journal.validated_shards(acquired)?)?;
        let expected_old = Control::Active {
            enrollment: statement::encoded(e.enrollment),
            registry: statement::encoded(old),
        }
        .heads(application);
        let expected_next = Control::Active {
            enrollment: statement::encoded(e.enrollment),
            registry: statement::encoded(producer.next),
        }
        .heads(application);
        if old_heads != expected_old || next_heads != expected_next || old_heads == next_heads {
            return Err(Error::InvalidTransition);
        }
        let bytes = journal.body(acquired.block).ok_or(Error::BodyUnavailable)?;
        let Body::Transition(t) = Body::decode(bytes, journal.profile())? else {
            return Err(Error::InvalidTransition);
        };
        if t.parent != e.parent
            || t.updates.len() != 1
            || t.updates[0].id != application.control_id
            || t.updates[0].old != old_heads
            || t.updates[0].new != next_heads
        {
            return Err(Error::InvalidTransition);
        }
        let request = Request::decode(&t.request)?;
        if request.operation != Operation::Transition
            || request.genesis != e.genesis
            || request.parent != e.parent
            || request.application != application.id()
            || request.query != e.source.request
            || request.enrollment != statement::encoded(e.enrollment)
            || request.opening != statement::encoded(e.source.open_commitment)
            || request.command != statement::encoded(command)
            || request.packets != e.source.packets
        {
            return Err(Error::WrongDomain);
        }
        let actual = wire::verify(e, &t.proof).map_err(|_| Error::RejectedComputationProof)?;
        if actual.public_values() != producer.public_values() {
            return Err(Error::RejectedComputationProof);
        }
        Ok(Self {
            application: application.clone(),
            parent,
            acquired,
            old: old_heads,
            active: next_heads,
            request: t.request,
            body_hash: Sha256::digest(bytes).into(),
            producer: producer.clone(),
        })
    }
    pub(in crate::opening::registry_lifecycle) fn require_producer(
        &self,
        encoded: &encoding::Statement,
    ) -> Result<()> {
        let actual = encoded.projection_producer();
        actual
            .require_expected(&self.producer.expected)
            .map_err(|_| Error::RejectedComputationProof)?;
        if actual.public_values() != self.producer.public_values() {
            return Err(Error::RejectedComputationProof);
        }
        Ok(())
    }
    pub(in crate::opening::registry_lifecycle) fn identity(&self) -> Hash {
        let mut h = Sha256::new();
        h.update(b"DCS/Registry200/actual-Acquire-control-projection-context/v1/no-live-grant");
        h.update(self.application.id());
        for head in [self.parent, self.acquired] {
            h.update(head.genesis);
            h.update(head.database);
            h.update(head.block);
            h.update(head.height.to_le_bytes());
            h.update(head.state_root);
        }
        h.update(self.old.data);
        h.update(self.old.index);
        h.update(self.active.data);
        h.update(self.active.index);
        h.update(&self.request);
        h.update(self.body_hash);
        h.finalize().into()
    }
    pub(in crate::opening::registry_lifecycle) fn acquired(&self) -> HeadRef {
        self.acquired
    }
    pub(in crate::opening::registry_lifecycle) fn check(
        &self,
        journal: &Journal,
        policy: Freshness,
    ) -> Result<HeadRef> {
        self.application.require_genesis(journal.genesis())?;
        let body = journal
            .body(self.acquired.block)
            .ok_or(Error::BodyUnavailable)?;
        if <Hash>::from(Sha256::digest(body)) != self.body_hash
            || self
                .application
                .control(journal.validated_shards(self.parent)?)?
                != self.old
            || self
                .application
                .control(journal.validated_shards(self.acquired)?)?
                != self.active
        {
            return Err(Error::InvalidTransition);
        }
        let resolved = journal.resolve(policy)?;
        let best = journal.best_validated();
        let resolved_shards = journal.shards(resolved, policy)?;
        if !journal.is_ancestor(self.acquired.block, resolved.block)
            || !journal.is_ancestor(self.acquired.block, best.block)
            || self.application.control(resolved_shards)? != self.active
            || self.application.control(journal.validated_shards(best)?)? != self.active
        {
            return Err(Error::StaleHead);
        }
        // Conservatively invalidate every later control transition. Empty work
        // descendants preserve the exact lease context; equal-root sibling forks do not.
        let empty = Body::Empty.encode(journal.profile())?;
        for descendant in [resolved.block, best.block] {
            let mut current = descendant;
            while current != self.acquired.block {
                if journal.body(current).ok_or(Error::BodyUnavailable)? != empty.as_slice() {
                    return Err(Error::StaleHead);
                }
                current = journal.header(current).ok_or(Error::UnknownHead)?.parent;
            }
        }
        Ok(resolved)
    }
}
