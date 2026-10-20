//! Caller-owned private mathematics. Native execution is not verification.
use crate::{
    BackendError as Error, Val,
    lifecycle::circuit::model::{Command, Operation, Registry},
};
use p3_field::PrimeField64;
use zeroize::Zeroize;

fn salt(s: &[u64; 4]) -> Result<(), Error> {
    if s.iter().any(|x| *x >= Val::ORDER_U64) {
        Err(Error::Shape)
    } else {
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct StatementOpening {
    pub scope: [u8; 64],
    pub enrollment: [u64; 4],
    pub client: [u8; 32],
    pub call: u64,
    pub transaction: u64,
    pub principal: u8,
    pub controller: [u8; 32],
    pub invocation: [u8; 32],
    pub sql_identity: [u8; 32],
    pub snapshot: [u8; 32],
    pub mask: [u8; 32],
    pub mode: u8,
    pub wait: u8,
    pub offset: u8,
    pub limit: u8,
    pub projection: u8,
    pub salt: [u64; 4],
}
impl StatementOpening {
    pub fn require_shape(&self) -> Result<(), Error> {
        salt(&self.salt)?;
        salt(&self.enrollment)?;
        if self.client == [0; 32]
            || self.call == 0
            || self.transaction == 0
            || !(1..=2).contains(&self.principal)
            || self.controller == [0; 32]
            || self.invocation == [0; 32]
            || !(1..=4).contains(&self.mode)
            || self.wait > 2
            || self.offset > 4
            || self.limit > 4
            || !(1..=3).contains(&self.projection)
        {
            return Err(Error::Shape);
        }
        Ok(())
    }
    pub fn root(&self) -> Result<[Val; 4], Error> {
        self.require_shape()?;
        Ok(super::fields::digest(&super::fields::statement(self)))
    }
    fn matched(&self, age: u8) -> bool {
        self.mask[usize::from(age) / 8] & (1 << (age % 8)) != 0
    }
}
impl Zeroize for StatementOpening {
    fn zeroize(&mut self) {
        self.scope.zeroize();
        self.enrollment.zeroize();
        self.client.zeroize();
        self.call.zeroize();
        self.transaction.zeroize();
        self.principal.zeroize();
        self.controller.zeroize();
        self.invocation.zeroize();
        self.sql_identity.zeroize();
        self.snapshot.zeroize();
        self.mask.zeroize();
        self.mode.zeroize();
        self.wait.zeroize();
        self.offset.zeroize();
        self.limit.zeroize();
        self.projection.zeroize();
        self.salt.zeroize();
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ProgressOpening {
    pub statement: StatementOpening,
    pub microstep: u64,
    pub cursor: u8,
    pub visited: [bool; 4],
    pub selected: [bool; 4],
    pub holder: u64,
    pub holder_mode: u8,
    pub blocked_revision: u64,
    pub salt: [u64; 4],
}
impl ProgressOpening {
    pub fn require_shape(&self) -> Result<(), Error> {
        self.statement.require_shape()?;
        salt(&self.salt)?;
        if self.microstep == 0
            || self.cursor >= 4
            || self.holder == 0
            || self.holder == self.statement.transaction
            || !(1..=4).contains(&self.holder_mode)
            || !crate::lifecycle::conflicts(self.statement.mode, self.holder_mode)
            || self.statement.wait != 0
            || self.selected.iter().filter(|v| **v).count() >= usize::from(self.statement.limit)
            || (usize::from(self.cursor)..4).any(|i| self.visited[i] || self.selected[i])
            || (0..4).any(|i| self.selected[i] && !self.visited[i])
        {
            return Err(Error::Shape);
        }
        Ok(())
    }
    pub fn root(&self) -> Result<[Val; 4], Error> {
        self.require_shape()?;
        Ok(super::fields::digest(&super::fields::progress(self)?))
    }
}
impl Zeroize for ProgressOpening {
    fn zeroize(&mut self) {
        self.statement.zeroize();
        self.microstep.zeroize();
        self.cursor.zeroize();
        self.visited.zeroize();
        self.selected.zeroize();
        self.holder.zeroize();
        self.holder_mode.zeroize();
        self.blocked_revision.zeroize();
        self.salt.zeroize();
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct State {
    pub registry: Registry,
    pub progress: [Option<ProgressOpening>; 2],
}
impl Zeroize for State {
    fn zeroize(&mut self) {
        self.registry.zeroize();
        for p in self.progress.iter_mut().flatten() {
            p.zeroize();
        }
        self.progress = [None, None];
    }
}
impl State {
    /// Explicit private commitment mathematics, not a verified state token.
    pub fn root(
        &self,
        expected: &super::BootstrapExpected,
        plain: &[u8; 2348],
        controllers: &[[u8; 32]; 2],
        opening_salt: [u64; 4],
    ) -> Result<[Val; 4], Error> {
        use p3_field::PrimeCharacteristicRing;
        salt(&opening_salt)?;
        expected.require_same(expected)?;
        Ok(super::fields::digest(&super::fields::registry(
            expected,
            plain,
            controllers,
            self,
            opening_salt.map(Val::from_u64),
        )?))
    }
    pub fn require_canonical(&self) -> Result<(), Error> {
        self.registry.require_canonical()?;
        for (t, p) in self.progress.iter().enumerate() {
            if let Some(p) = p {
                p.require_shape()?;
                let tx = self.registry.transactions.get(t).ok_or(Error::Shape)?;
                if tx.id != p.statement.transaction
                    || tx.principal != p.statement.principal
                    || tx.snapshot != p.statement.snapshot
                    || tx.failed
                    || p.blocked_revision >= self.registry.revision
                    || (0..4).any(|i| p.visited[i] && tx.held[i] < p.statement.mode)
                {
                    return Err(Error::Shape);
                }
            }
        }
        Ok(())
    }
    /// Native owner-side control builder. Progress follows stable IDs through
    /// whole-slot compaction. Generic FailCurrent is deliberately unavailable.
    pub fn control(&self, c: &Command, parent: [u8; 32]) -> Result<Self, Error> {
        self.require_canonical()?;
        if matches!(c.operation, Operation::Acquire | Operation::FailCurrent) {
            return Err(Error::Shape);
        }
        if let Some(t) = self
            .registry
            .transactions
            .iter()
            .position(|t| t.id == c.transaction)
            && self.progress[t].is_some()
            && !(c.operation == Operation::End && c.abort)
        {
            return Err(Error::Shape);
        }
        let next = self.registry.step(c, parent, [0; 4])?.next;
        let progress = core::array::from_fn(|t| {
            next.transactions.get(t).and_then(|tx| {
                self.registry
                    .transactions
                    .iter()
                    .position(|old| old.id == tx.id)
                    .and_then(|i| self.progress[i].clone())
            })
        });
        let out = Self {
            registry: next,
            progress,
        };
        out.require_canonical()?;
        Ok(out)
    }
    /// Complete sequential fixed-source walk. This is never called by a proof
    /// verifier, nor is its Status a SQL result or a finalization receipt.
    pub fn predicate(
        &self,
        s: &StatementOpening,
        ages: [u8; 4],
        next_salt: [u64; 4],
    ) -> Result<Step, Error> {
        self.require_canonical()?;
        s.require_shape()?;
        salt(&next_salt)?;
        let actor = self
            .registry
            .transactions
            .iter()
            .position(|t| t.id == s.transaction)
            .ok_or(Error::Shape)?;
        let tx = &self.registry.transactions[actor];
        if tx.principal != s.principal || tx.snapshot != s.snapshot || tx.failed {
            return Err(Error::Shape);
        }
        let prior = self.progress[actor].as_ref();
        if prior.is_some_and(|p| p.statement != *s) {
            return Err(Error::Shape);
        }
        let cursor = prior.map_or(0, |p| p.cursor);
        let mut visited = prior.map_or([false; 4], |p| p.visited);
        let mut selected = prior.map_or([false; 4], |p| p.selected);
        let mut count = 0;
        for i in 0..usize::from(cursor) {
            if visited[i] != s.matched(ages[i])
                || selected[i] != (visited[i] && count >= usize::from(s.offset))
            {
                return Err(Error::Shape);
            }
            count += usize::from(visited[i]);
        }
        let microstep = prior
            .map_or(Some(1), |p| p.microstep.checked_add(1))
            .ok_or(Error::Shape)?;
        let mut delta = [false; 4];
        let mut skipped = [false; 4];
        let mut block = None;
        let mut end = cursor;
        for i in usize::from(cursor)..4 {
            if selected.iter().filter(|v| **v).count() >= usize::from(s.limit) {
                break;
            }
            end = i as u8 + 1;
            if !s.matched(ages[i]) {
                continue;
            }
            if let Some(other) = self.registry.transactions.get(1 - actor)
                && crate::lifecycle::conflicts(s.mode, other.held[i])
            {
                if s.wait == 2 {
                    skipped[i] = true;
                    continue;
                }
                block = Some((i, other.id, other.held[i]));
                end = i as u8;
                break;
            }
            delta[i] = true;
            visited[i] = true;
            selected[i] = count >= usize::from(s.offset);
            count += 1;
        }
        let mut next = self.clone();
        let status = if block.is_some() && s.wait == 1 {
            let c = Command::control(Operation::FailCurrent, tx.id, tx.principal, tx.sequence);
            next.registry = self.registry.step(&c, [0; 32], ages)?.next;
            next.progress[actor] = None;
            Status::Error
        } else {
            next.registry.revision = self.registry.revision.checked_add(1).ok_or(Error::Shape)?;
            next.registry.transactions[actor].sequence =
                tx.sequence.checked_add(1).ok_or(Error::Shape)?;
            for (i, visit) in delta.iter().enumerate() {
                if *visit {
                    next.registry.transactions[actor].held[i] = tx.held[i].max(s.mode);
                }
            }
            if let Some((_, holder, holder_mode)) = block {
                next.progress[actor] = Some(ProgressOpening {
                    statement: s.clone(),
                    microstep,
                    cursor: end,
                    visited,
                    selected,
                    holder,
                    holder_mode,
                    blocked_revision: self.registry.revision,
                    salt: next_salt,
                });
                Status::Parked
            } else {
                next.progress[actor] = None;
                Status::Done
            }
        };
        next.require_canonical()?;
        Ok(Step {
            next,
            status,
            resumed: prior.is_some(),
            old_cursor: cursor,
            cursor: end,
            visited,
            selected,
            delta,
            skipped,
            block: core::array::from_fn(|i| block.is_some_and(|b| b.0 == i)),
            holder: block.map_or(0, |b| b.1),
            holder_mode: block.map_or(0, |b| b.2),
            microstep,
        })
    }
}
/// Owner-side mathematical state only; no serialization or proof receipt.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Parked,
    Done,
    Error,
}
pub struct Step {
    pub next: State,
    pub status: Status,
    pub resumed: bool,
    pub old_cursor: u8,
    pub cursor: u8,
    pub visited: [bool; 4],
    pub selected: [bool; 4],
    pub delta: [bool; 4],
    pub skipped: [bool; 4],
    pub block: [bool; 4],
    pub holder: u64,
    pub holder_mode: u8,
    pub microstep: u64,
}
impl Step {
    /// Caller-owned Result160 preimage. The separate predicate-role proof
    /// grants no SQL permission; hashing this value never proves a transition.
    pub fn result_fields(
        &self,
        context: &[Val; 100],
        roots: [[Val; 4]; 3],
        statement: &StatementOpening,
        progress_roots: [[Val; 4]; 2],
        opening_salt: [u64; 4],
    ) -> Result<Vec<Val>, Error> {
        use p3_field::PrimeCharacteristicRing;
        salt(&opening_salt)?;
        statement.require_shape()?;
        Ok(super::fields::result(
            context,
            roots,
            statement,
            self,
            progress_roots,
            opening_salt.map(Val::from_u64),
        ))
    }
}
impl Zeroize for Step {
    fn zeroize(&mut self) {
        self.next.zeroize();
        self.resumed.zeroize();
        self.old_cursor.zeroize();
        self.cursor.zeroize();
        self.visited.zeroize();
        self.selected.zeroize();
        self.delta.zeroize();
        self.skipped.zeroize();
        self.block.zeroize();
        self.holder.zeroize();
        self.holder_mode.zeroize();
        self.microstep.zeroize();
        self.status = Status::Error;
    }
}
