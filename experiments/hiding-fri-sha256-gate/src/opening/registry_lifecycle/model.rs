//! Owner-local bounded state machine. This is a prover input builder, never a verifier.
use crate::backend::Error;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Savepoint {
    pub name: [u8; 32],
    pub held: [u8; 4],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Transaction {
    pub id: u64,
    pub principal: u8,
    pub sequence: u64,
    pub failed: bool,
    pub snapshot: [u8; 32],
    pub held: [u8; 4],
    pub savepoints: Vec<Savepoint>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Registry {
    pub revision: u64,
    pub allocator: u64,
    pub transactions: Vec<Transaction>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum Operation {
    Begin,
    Acquire,
    FailCurrent,
    Savepoint,
    RollbackTo,
    Release,
    End,
}
impl Operation {
    pub(super) const ALL: [Self; 7] = [
        Self::Begin,
        Self::Acquire,
        Self::FailCurrent,
        Self::Savepoint,
        Self::RollbackTo,
        Self::Release,
        Self::End,
    ];
}
#[derive(Clone, Debug)]
pub(super) struct Command {
    pub operation: Operation,
    pub transaction: u64,
    pub principal: u8,
    pub sequence: u64,
    pub name: [u8; 32],
    pub mask: [u8; 32],
    pub mode: u8,
    pub wait: u8,
    pub offset: u8,
    pub limit: u8,
    pub projection: u8,
    pub abort: bool,
}
impl Command {
    pub fn control(operation: Operation, transaction: u64, principal: u8, sequence: u64) -> Self {
        Self {
            operation,
            transaction,
            principal,
            sequence,
            name: [0; 32],
            mask: [0; 32],
            mode: 0,
            wait: 0,
            offset: 0,
            limit: 0,
            projection: 0,
            abort: false,
        }
    }
    pub fn require_shape(&self) -> Result<(), Error> {
        if !(1..=2).contains(&self.principal) || self.transaction == 0 {
            return Err(Error::Shape);
        }
        if self.operation == Operation::Acquire {
            if !(1..=4).contains(&self.mode)
                || self.wait > 2
                || self.offset > 4
                || self.limit > 4
                || self.projection > 3
            {
                return Err(Error::Shape);
            }
        } else if self.mask != [0; 32]
            || self.mode != 0
            || self.wait != 0
            || self.offset != 0
            || self.limit != 0
            || self.projection != 0
        {
            return Err(Error::Shape);
        }
        if !matches!(
            self.operation,
            Operation::Savepoint | Operation::RollbackTo | Operation::Release
        ) && self.name != [0; 32]
        {
            return Err(Error::Shape);
        }
        if self.operation != Operation::End && self.abort {
            return Err(Error::Shape);
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub(super) struct Step {
    pub next: Registry,
    /// 0 successful command, 1 atomic WAIT conflict, 2 atomic NOWAIT conflict,
    /// 3 successful End resolved as abort (including failed Commit).
    pub outcome: u8,
    pub search: [bool; 4],
    pub attempt: [bool; 4],
    pub conflict: [bool; 4],
    pub visit: [bool; 4],
    pub skipped: [bool; 4],
    pub returned: [bool; 4],
    pub block: [bool; 4],
}
pub(super) fn conflicts(request: u8, held: u8) -> bool {
    match request {
        1 => held == 4,
        2 => held >= 3,
        3 => held >= 2,
        4 => held != 0,
        _ => false,
    }
}
impl Registry {
    pub fn require_canonical(&self) -> Result<(), Error> {
        if self.transactions.len() > 2 || self.allocator > self.revision {
            return Err(Error::Shape);
        }
        let mut previous = 0;
        for tx in &self.transactions {
            if tx.id <= previous
                || tx.id > self.allocator
                || !(1..=2).contains(&tx.principal)
                || tx.sequence == 0
                || tx.held.iter().any(|m| *m > 4)
                || tx.savepoints.len() > 2
            {
                return Err(Error::Shape);
            }
            previous = tx.id;
            let mut saved = [0; 4];
            for frame in &tx.savepoints {
                if frame
                    .held
                    .iter()
                    .enumerate()
                    .any(|(i, m)| *m > 4 || *m < saved[i] || *m > tx.held[i])
                {
                    return Err(Error::Shape);
                }
                saved = frame.held;
            }
            if tx.failed && tx.held != saved {
                return Err(Error::Shape);
            }
        }
        if self.transactions.len() == 2 {
            for i in 0..4 {
                if conflicts(self.transactions[0].held[i], self.transactions[1].held[i]) {
                    return Err(Error::Shape);
                }
            }
        }
        Ok(())
    }
    pub fn step(&self, command: &Command, parent: [u8; 32], ages: [u8; 4]) -> Result<Step, Error> {
        self.require_canonical()?;
        command.require_shape()?;
        let revision = self.revision.checked_add(1).ok_or(Error::Shape)?;
        let mut result = Step {
            next: self.clone(),
            outcome: 0,
            search: [false; 4],
            attempt: [false; 4],
            conflict: [false; 4],
            visit: [false; 4],
            skipped: [false; 4],
            returned: [false; 4],
            block: [false; 4],
        };
        if command.operation == Operation::Begin {
            let id = self.allocator.checked_add(1).ok_or(Error::Shape)?;
            if self.transactions.len() == 2 || command.transaction != id || command.sequence != 0 {
                return Err(Error::Shape);
            }
            result.next.allocator = id;
            result.next.transactions.push(Transaction {
                id,
                principal: command.principal,
                sequence: 1,
                failed: false,
                snapshot: parent,
                held: [0; 4],
                savepoints: Vec::new(),
            });
        } else {
            let actor = self
                .transactions
                .iter()
                .position(|tx| tx.id == command.transaction)
                .ok_or(Error::Shape)?;
            let tx = &self.transactions[actor];
            if command.principal != tx.principal
                || command.sequence != tx.sequence
                || (tx.failed
                    && !matches!(command.operation, Operation::RollbackTo | Operation::End))
            {
                return Err(Error::Shape);
            }
            let sequence = if command.operation == Operation::End {
                tx.sequence
            } else {
                tx.sequence.checked_add(1).ok_or(Error::Shape)?
            };
            match command.operation {
                Operation::Acquire => {
                    let (mut passed, mut returned, mut stopped) = (0, 0, false);
                    for (i, age) in ages.into_iter().enumerate() {
                        let other = if self.transactions.len() == 2 {
                            self.transactions[1 - actor].held[i]
                        } else {
                            0
                        };
                        result.conflict[i] = conflicts(command.mode, other);
                        result.search[i] = !stopped && returned < command.limit;
                        result.attempt[i] = result.search[i]
                            && command.mask[usize::from(age) / 8] & (1 << (age % 8)) != 0;
                        if !result.attempt[i] {
                            continue;
                        }
                        if result.conflict[i] {
                            if command.wait == 2 {
                                result.skipped[i] = true;
                            } else {
                                result.block[i] = true;
                                result.outcome = command.wait + 1;
                                stopped = true;
                            }
                        } else {
                            result.visit[i] = true;
                            if passed >= command.offset {
                                result.returned[i] = true;
                                returned += 1;
                            }
                            passed += 1;
                        }
                    }
                    if result.outcome == 0 {
                        for i in 0..4 {
                            if result.visit[i] {
                                result.next.transactions[actor].held[i] =
                                    tx.held[i].max(command.mode);
                            }
                        }
                    }
                }
                Operation::FailCurrent => {
                    let t = &mut result.next.transactions[actor];
                    t.held = tx.savepoints.last().map_or([0; 4], |s| s.held);
                    t.failed = true;
                }
                Operation::Savepoint => {
                    if tx.savepoints.len() == 2 {
                        return Err(Error::Shape);
                    }
                    result.next.transactions[actor].savepoints.push(Savepoint {
                        name: command.name,
                        held: tx.held,
                    });
                }
                Operation::RollbackTo | Operation::Release => {
                    let target = tx
                        .savepoints
                        .iter()
                        .rposition(|s| s.name == command.name)
                        .ok_or(Error::Shape)?;
                    let t = &mut result.next.transactions[actor];
                    if command.operation == Operation::RollbackTo {
                        t.held = tx.savepoints[target].held;
                        t.failed = false;
                        t.savepoints.truncate(target + 1);
                    } else {
                        t.savepoints.truncate(target);
                    }
                }
                Operation::End => {
                    if command.abort || tx.failed {
                        result.outcome = 3;
                    }
                    result.next.transactions.remove(actor);
                }
                Operation::Begin => unreachable!(),
            }
            if result.outcome == 1 || result.outcome == 2 {
                return Ok(result);
            }
            if command.operation != Operation::End {
                result.next.transactions[actor].sequence = sequence;
            }
        }
        result.next.revision = revision;
        result.next.require_canonical()?;
        Ok(result)
    }
}
