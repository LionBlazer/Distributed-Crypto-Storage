use crate::*;
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LockEvent {
    pub row: RowKey,
    pub mode: LockMode,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Savepoint {
    pub name: SavepointName,
    pub events: usize,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Transaction {
    pub controller: ControllerId,
    pub next_sequence: u64,
    pub snapshot: Digest,
    pub status: TransactionStatus,
    pub events: Vec<LockEvent>,
    pub savepoints: Vec<Savepoint>,
}
pub(crate) type Holders = BTreeMap<RowKey, BTreeMap<TransactionId, LockMode>>;

/// Immutable branch-local public control state. No row values, keys, clocks,
/// transport handles or authoritative global current-head pointer live here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub(crate) context: Context,
    pub(crate) revision: u64,
    pub(crate) last_transaction: u64,
    pub(crate) transactions: BTreeMap<TransactionId, Transaction>,
}
impl State {
    pub fn new(context: Context) -> Self {
        Self {
            context,
            revision: 0,
            last_transaction: 0,
            transactions: BTreeMap::new(),
        }
    }
    pub fn context(&self) -> Context {
        self.context
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    /// Unfinished control records, including failed frames awaiting recovery/end.
    pub fn active_transactions(&self) -> usize {
        self.transactions.len()
    }
    pub fn next_transaction_id(&self) -> Result<TransactionId> {
        self.last_transaction
            .checked_add(1)
            .map(TransactionId)
            .ok_or(Error::CounterExhausted)
    }
    pub fn transaction(&self, id: TransactionId) -> Option<TransactionInfo> {
        self.transactions.get(&id).map(|tx| TransactionInfo {
            controller: tx.controller,
            next_sequence: tx.next_sequence,
            snapshot: tx.snapshot,
            status: tx.status,
        })
    }
    pub fn held_mode(&self, id: TransactionId, row: RowKey) -> Option<LockMode> {
        self.transactions
            .get(&id)?
            .events
            .iter()
            .filter(|event| event.row == row)
            .map(|event| event.mode)
            .max()
    }
    pub fn holders(&self, row: RowKey) -> Vec<(TransactionId, LockMode)> {
        self.transactions
            .keys()
            .filter_map(|id| self.held_mode(*id, row).map(|mode| (*id, mode)))
            .collect()
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        wire::encode_state(self)
    }
    pub fn decode(bytes: &[u8], expected: Context) -> Result<Self> {
        let state = wire::decode_state(bytes, expected)?;
        state.validate()?;
        Ok(state)
    }
    pub fn commitment(&self) -> Result<Commitment> {
        wire::state_commitment(self)
    }

    /// `actor` must already be authenticated and authorized by the caller. The
    /// journal adapter verifies controller intent plus outer owner authorization.
    /// A conflict leaves this entire state unchanged, including sequence/revision.
    /// `Blocked` is a runtime waiting seam, not implemented SQL blocking.
    pub fn transition(&self, actor: ControllerId, command: &Command) -> Result<Transition> {
        wire::validate_command(command, self.context.profile)?;
        if command.expected_revision != self.revision {
            return Err(Error::StaleRevision);
        }
        let revision = self
            .revision
            .checked_add(1)
            .ok_or(Error::CounterExhausted)?;
        let mut next = self.clone();
        let outcome = if let Action::Begin { snapshot } = command.action {
            if command.transaction != self.next_transaction_id()? || command.sequence != 0 {
                return Err(Error::WrongSequence);
            }
            if self.transactions.len() >= self.context.profile.max_transactions as usize {
                return Err(Error::ResourceLimit);
            }
            next.last_transaction = command.transaction.0;
            next.transactions.insert(
                command.transaction,
                Transaction {
                    controller: actor,
                    next_sequence: 1,
                    snapshot,
                    status: TransactionStatus::Active,
                    events: Vec::new(),
                    savepoints: Vec::new(),
                },
            );
            Outcome::Began(command.transaction)
        } else {
            let tx = next
                .transactions
                .get_mut(&command.transaction)
                .ok_or(Error::UnknownTransaction)?;
            if tx.controller != actor {
                return Err(Error::WrongController);
            }
            if tx.next_sequence != command.sequence {
                return Err(Error::WrongSequence);
            }
            if tx.status == TransactionStatus::Failed
                && !matches!(
                    command.action,
                    Action::RollbackTo { .. } | Action::End { .. }
                )
            {
                return Err(Error::TransactionFailed);
            }
            if !matches!(command.action, Action::End { .. }) {
                tx.next_sequence = tx
                    .next_sequence
                    .checked_add(1)
                    .ok_or(Error::CounterExhausted)?;
            }
            match &command.action {
                Action::Acquire {
                    candidates,
                    mode,
                    wait,
                    offset,
                    limit,
                } => {
                    if candidates.len() > self.context.profile.max_candidates as usize {
                        return Err(Error::ResourceLimit);
                    }
                    let mut held = self.lock_table();
                    // Only this transaction changes during one command. Cache
                    // other-owner conflict status once per distinct row, including
                    // repeated skipped references to a row with many holders.
                    let mut conflicts = BTreeMap::new();
                    let mut selected = Vec::new();
                    let mut skipped = Vec::new();
                    let mut passed = 0u64;
                    for (position, row) in candidates.iter().enumerate() {
                        if limit.is_some_and(|limit| selected.len() >= limit as usize) {
                            break;
                        }
                        let blocked = *conflicts.entry(*row).or_insert_with(|| {
                            held.get(row).is_some_and(|owners| {
                                owners.iter().any(|(id, strength)| {
                                    *id != command.transaction && mode.conflicts(*strength)
                                })
                            })
                        });
                        if blocked {
                            if *wait == WaitPolicy::SkipLocked {
                                skipped.push(position as u32);
                                continue;
                            }
                            let holders = held[row]
                                .iter()
                                .filter(|(id, strength)| {
                                    **id != command.transaction && mode.conflicts(**strength)
                                })
                                .map(|(id, _)| *id)
                                .collect();
                            let conflict = Conflict {
                                candidate: position as u32,
                                row: *row,
                                holders,
                            };
                            match wait {
                                WaitPolicy::SkipLocked => unreachable!(),
                                WaitPolicy::Wait => return Err(Error::Blocked(conflict)),
                                WaitPolicy::NoWait => return Err(Error::LockUnavailable(conflict)),
                            }
                        }
                        let own = held
                            .get(row)
                            .and_then(|owners| owners.get(&command.transaction))
                            .copied();
                        if own.is_none_or(|held| held < *mode) {
                            tx.events.push(LockEvent {
                                row: *row,
                                mode: *mode,
                            });
                            held.entry(*row)
                                .or_default()
                                .insert(command.transaction, *mode);
                        }
                        if passed >= u64::from(*offset) {
                            selected.push(position as u32);
                        }
                        passed += 1;
                    }
                    Outcome::Acquired(Selection { selected, skipped })
                }
                Action::FailCurrent => {
                    let cut = tx.savepoints.last().map_or(0, |point| point.events);
                    tx.events.truncate(cut);
                    tx.status = TransactionStatus::Failed;
                    Outcome::Failed
                }
                Action::Savepoint { name } => {
                    if tx.savepoints.len()
                        >= self.context.profile.max_savepoints_per_transaction as usize
                    {
                        return Err(Error::ResourceLimit);
                    }
                    tx.savepoints.push(Savepoint {
                        name: *name,
                        events: tx.events.len(),
                    });
                    Outcome::Savepoint
                }
                Action::RollbackTo { name } => {
                    let point = tx
                        .savepoints
                        .iter()
                        .rposition(|point| point.name == *name)
                        .ok_or(Error::UnknownSavepoint)?;
                    tx.events.truncate(tx.savepoints[point].events);
                    tx.savepoints.truncate(point + 1);
                    tx.status = TransactionStatus::Active;
                    Outcome::RolledBackTo
                }
                Action::Release { name } => {
                    let point = tx
                        .savepoints
                        .iter()
                        .rposition(|point| point.name == *name)
                        .ok_or(Error::UnknownSavepoint)?;
                    tx.savepoints.truncate(point);
                    Outcome::Released
                }
                Action::End { completion } => {
                    let actual = if tx.status == TransactionStatus::Failed {
                        Completion::Abort
                    } else {
                        *completion
                    };
                    next.transactions.remove(&command.transaction);
                    Outcome::Ended(actual)
                }
                Action::Begin { .. } => unreachable!(),
            }
        };
        next.revision = revision;
        next.encode()?;
        Ok(Transition {
            state: next,
            outcome,
        })
    }

    pub(crate) fn lock_table(&self) -> Holders {
        let mut held = Holders::new();
        for (id, tx) in &self.transactions {
            for event in &tx.events {
                held.entry(event.row)
                    .or_default()
                    .entry(*id)
                    .and_modify(|mode| *mode = (*mode).max(event.mode))
                    .or_insert(event.mode);
            }
        }
        held
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.context.profile.validate()?;
        if self.last_transaction > self.revision {
            return Err(Error::InvalidState);
        }
        if self.transactions.len() > self.context.profile.max_transactions as usize {
            return Err(Error::ResourceLimit);
        }
        let mut event_count = 0usize;
        for (id, tx) in &self.transactions {
            if id.0 == 0 || id.0 > self.last_transaction || tx.next_sequence == 0 {
                return Err(Error::InvalidState);
            }
            event_count = event_count
                .checked_add(tx.events.len())
                .ok_or(Error::ResourceLimit)?;
            if event_count > self.context.profile.max_lock_events as usize
                || tx.savepoints.len()
                    > self.context.profile.max_savepoints_per_transaction as usize
            {
                return Err(Error::ResourceLimit);
            }
            if tx
                .savepoints
                .iter()
                .any(|point| point.events > tx.events.len())
                || tx
                    .savepoints
                    .windows(2)
                    .any(|points| points[0].events > points[1].events)
            {
                return Err(Error::InvalidState);
            }
            if tx.status == TransactionStatus::Failed
                && tx.events.len() != tx.savepoints.last().map_or(0, |point| point.events)
            {
                return Err(Error::InvalidState);
            }
            let mut own = BTreeMap::new();
            for event in &tx.events {
                if own.get(&event.row).is_some_and(|mode| *mode >= event.mode) {
                    return Err(Error::InvalidState);
                }
                own.insert(event.row, event.mode);
            }
        }
        let held = self.lock_table();
        let count: usize = held.values().map(BTreeMap::len).sum();
        if count > self.context.profile.max_locks as usize {
            return Err(Error::ResourceLimit);
        }
        for owners in held.values() {
            if owners.len() > 1
                && (owners.values().any(|mode| *mode == LockMode::Update)
                    || (owners.values().any(|mode| *mode == LockMode::NoKeyUpdate)
                        && owners
                            .values()
                            .filter(|mode| **mode >= LockMode::Share)
                            .count()
                            > 1))
            {
                return Err(Error::InvalidState);
            }
        }
        Ok(())
    }
}
