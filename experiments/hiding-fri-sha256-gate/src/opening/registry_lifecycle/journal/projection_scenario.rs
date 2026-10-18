//! PUBLIC NONSECRET accepted history. This owner fixture never executes a peer SQL query.
use super::super::model::{Command, Operation};
use super::{
    Error, PrivateVerifier, ProjectionContext, Result,
    fixture::Fixture,
    owner::{FormationEncodingRequest, PrivateState},
};
use crate::backend::{Error as BackendError, Val};
use p3_field::PrimeCharacteristicRing;
use version_journal::{Body, Freshness, Journal};

pub(in crate::opening::registry_lifecycle) struct ProjectionHistory {
    journal: Journal,
    context: ProjectionContext,
    fixture: Fixture,
    verifier: PrivateVerifier,
    _private: PrivateState,
}
impl ProjectionHistory {
    pub(in crate::opening::registry_lifecycle) fn journal(&self) -> &Journal {
        &self.journal
    }
    pub(in crate::opening::registry_lifecycle) fn context(&self) -> &ProjectionContext {
        &self.context
    }
    pub(in crate::opening::registry_lifecycle) fn policy(&self) -> Freshness {
        Freshness::AtLeast(self.context.acquired())
    }
    pub(in crate::opening::registry_lifecycle) fn bundle(&self) -> Result<peer_runtime::RawBundle> {
        let source = &self.fixture.source.source;
        let images: [Vec<u8>; 2] = core::array::from_fn(|i| {
            source.heads[i]
                .iter()
                .chain(&source.packets[i])
                .copied()
                .collect()
        });
        let data = compact_store::EncryptedSnapshot::decode(
            &images[0],
            crate::opening::statement::limits(),
        )
        .map_err(|_| Error::InvalidEncoding)?;
        let index = compact_store::EncryptedSnapshot::decode(
            &images[1],
            crate::opening::statement::limits(),
        )
        .map_err(|_| Error::InvalidEncoding)?;
        peer_runtime::RawBundle::from_snapshots(&data, &index).map_err(|_| Error::InvalidEncoding)
    }
    pub(in crate::opening::registry_lifecycle) fn confirm(&mut self) -> Result<()> {
        let parent = self.journal.best_validated();
        super::formation_scenario::append(
            &mut self.journal,
            &self.verifier,
            parent.block,
            &Body::Empty,
            2000 + parent.height,
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub(in crate::opening::registry_lifecycle) fn check_durable_reopen_and_retry(
        &self,
    ) -> Result<()> {
        use std::cell::Cell;
        use version_journal::{DurableJournal, TransitionStatement, TransitionVerifier};
        struct Count<'a> {
            inner: &'a PrivateVerifier,
            calls: Cell<usize>,
        }
        impl TransitionVerifier for Count<'_> {
            fn verify(&self, statement: TransitionStatement<'_>) -> Result<()> {
                self.calls.set(self.calls.get() + 1);
                self.inner.verify(statement)
            }
        }
        let directory = super::fixture::OwnedDirectory::new()?;
        let path = directory.journal();
        let count = Count {
            inner: &self.verifier,
            calls: Cell::new(0),
        };
        let namespace = [0xC8; 32];
        let mut durable = DurableJournal::create(&path, self.fixture.genesis.clone(), namespace)?;
        let blocks = self.journal.validated_blocks();
        for (header, body) in &blocks {
            durable.append_block((*header).clone(), body, 10000, &count)?;
        }
        let expected = self.context.check(durable.journal(), self.policy())?;
        let before_calls = count.calls.get();
        let before_disk = durable.disk_bytes();
        let (last_header, last_body) = blocks
            .iter()
            .find(|(header, _)| header.id() == self.context.acquired().block)
            .ok_or(Error::BodyUnavailable)?;
        durable.append_block((*last_header).clone(), last_body, 10000, &count)?;
        if count.calls.get() != before_calls || durable.disk_bytes() != before_disk {
            return Err(Error::InvalidTransition);
        }
        drop(durable);
        let before = count.calls.get();
        let reopened = DurableJournal::open(
            &path,
            self.fixture.genesis.clone(),
            namespace,
            10000,
            &count,
        )?;
        if self.context.check(reopened.journal(), self.policy())? != expected
            || count.calls.get() - before != before_calls
            || reopened.disk_bytes() != before_disk
        {
            return Err(Error::InvalidTransition);
        }
        drop(reopened);
        Ok(())
    }
    #[cfg(test)]
    pub(in crate::opening::registry_lifecycle) fn losing_same_root_sibling(
        &mut self,
    ) -> Result<()> {
        let acquired = self.context.acquired();
        let original = self
            .journal
            .header(acquired.block)
            .ok_or(Error::UnknownHead)?
            .clone();
        let wire = self
            .journal
            .body(acquired.block)
            .ok_or(Error::BodyUnavailable)?
            .to_vec();
        let body = Body::decode(&wire, self.journal.profile())?;
        let mut sibling = self.journal.candidate(original.parent, &body, 3000)?;
        sibling.nonce = original
            .nonce
            .checked_add(1)
            .ok_or(Error::MiningExhausted)?;
        sibling.mine(1024)?;
        if sibling.id() == acquired.block || sibling.state_root != acquired.state_root {
            return Err(Error::InvalidTransition);
        }
        self.journal
            .import_block(sibling.clone(), &wire, 10000, &self.verifier)?;
        let mut parent = sibling.id();
        // Two Empty children make this genuine sibling branch stronger than the
        // original Acquire+one-confirmation branch without changing control roots.
        for n in 0..2 {
            let header = super::formation_scenario::append(
                &mut self.journal,
                &self.verifier,
                parent,
                &Body::Empty,
                3001 + n,
            )?;
            parent = header.id();
        }
        let best = self.journal.best_validated();
        if best.state_root != acquired.state_root
            || self.journal.is_ancestor(acquired.block, best.block)
        {
            return Err(Error::InvalidTransition);
        }
        Ok(())
    }
    #[cfg(test)]
    pub(in crate::opening::registry_lifecycle) fn transition(
        &mut self,
        mut command: Command,
    ) -> Result<()> {
        let parent = self.journal.best_validated();
        command.sequence = if command.operation == Operation::Begin {
            0
        } else {
            self._private
                .registry
                .transactions
                .iter()
                .find(|t| t.id == command.transaction)
                .ok_or(Error::InvalidTransition)?
                .sequence
        };
        let produced = self.fixture.transition(
            &self.journal,
            parent,
            &self._private,
            command,
            [parent.height as u8; 32],
        )?;
        super::formation_scenario::append(
            &mut self.journal,
            &self.verifier,
            parent.block,
            &produced.body,
            2000 + parent.height,
        )?;
        self._private = produced.private;
        Ok(())
    }
}
/// Sparse candidates are original ordinals 0,2,3. The other transaction locks
/// its first `other_limit`; actor1 SKIPs those, owns OFFSET1 and returns LIMIT.
pub(in crate::opening::registry_lifecycle) fn produce(
    limit: u8,
    other_limit: u8,
) -> std::result::Result<(ProjectionHistory, super::FormationEncodingProduct), BackendError> {
    let result = (|| -> Result<_> {
        if limit > 4 || other_limit > 4 {
            return Err(Error::InvalidTransition);
        }
        let fixture = Fixture::new()?;
        let verifier = fixture.verifier()?;
        let mut journal = Journal::new(fixture.genesis.clone())?;
        let parent = journal.genesis_head();
        let bootstrap = fixture.bootstrap(&journal, parent, [0xD1; 32])?;
        super::formation_scenario::append(
            &mut journal,
            &verifier,
            parent.block,
            &bootstrap.body,
            1001,
        )?;
        let mut private = bootstrap.private;
        drop(bootstrap.body);
        for (id, principal) in [(1, 1), (2, 2)] {
            let parent = journal.best_validated();
            let begin = fixture.transition(
                &journal,
                parent,
                &private,
                Command::control(Operation::Begin, id, principal, 0),
                [0xD1 + id as u8; 32],
            )?;
            super::formation_scenario::append(
                &mut journal,
                &verifier,
                parent.block,
                &begin.body,
                1001 + id,
            )?;
            private = begin.private;
            drop(begin.body);
        }
        let parent = journal.best_validated();
        let mut other = Command::control(Operation::Acquire, 2, 2, 1);
        other.mask[16..].fill(255);
        other.mode = 4;
        other.limit = other_limit;
        other.projection = 2;
        let held = fixture.transition(&journal, parent, &private, other, [0xD4; 32])?;
        super::formation_scenario::append(&mut journal, &verifier, parent.block, &held.body, 1004)?;
        private = held.private;
        drop(held.body);
        let mut command = Command::control(Operation::Acquire, 1, 1, 1);
        command.mask[16..].fill(255);
        command.mode = 4;
        command.wait = 2;
        command.offset = 1;
        command.limit = limit;
        command.projection = 2;
        let parent = journal.best_validated();
        let prepared = fixture.prepare(&journal, parent, &private, command, [0xD5; 32])?;
        let sql = format!(
            "SELECT amount FROM records WHERE age>=128 OFFSET 1 LIMIT {limit} FOR UPDATE SKIP LOCKED"
        );
        let (product, private) =
            prepared.prove_formation_encoding_with_state(FormationEncodingRequest {
                journal: &mut journal,
                verifier: &verifier,
                genesis: &fixture.genesis,
                owner: &Fixture::owner(),
                sql: &sql,
                sql_nonce: [0xD6; 32],
                salt: [Val::from_u8(61); 4],
                timestamp: 1005,
                #[cfg(test)]
                alternate_salt: None,
            })?;
        let acquired = journal.best_validated();
        let context = ProjectionContext::new(
            &fixture.application,
            &journal,
            acquired,
            &product.statement,
            &product.frame,
        )?;
        let mut history = ProjectionHistory {
            journal,
            context,
            fixture,
            verifier,
            _private: private,
        };
        history.confirm()?;
        history.context.check(&history.journal, history.policy())?;
        Ok((history, product))
    })();
    result.map_err(|_| BackendError::Verification)
}
