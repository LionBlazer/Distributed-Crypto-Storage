use crate::state::{LockEvent, Savepoint, Transaction};
use crate::*;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

struct Writer {
    bytes: Vec<u8>,
    limit: usize,
}
impl Writer {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > self.limit)
        {
            return Err(Error::ResourceLimit);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    fn byte(&mut self, value: u8) -> Result<()> {
        self.put(&[value])
    }
    fn number(&mut self, value: u32) -> Result<()> {
        self.put(&value.to_le_bytes())
    }
    fn wide(&mut self, value: u64) -> Result<()> {
        self.put(&value.to_le_bytes())
    }
}
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], limit: usize) -> Result<Self> {
        if bytes.len() > limit {
            return Err(Error::ResourceLimit);
        }
        Ok(Self { bytes, offset: 0 })
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self.offset.checked_add(N).ok_or(Error::InvalidEncoding)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(Error::InvalidEncoding)?;
        self.offset = end;
        Ok(value.try_into().expect("fixed slice"))
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }
    fn number(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn wide(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    fn count(&mut self, limit: u32, minimum_bytes: usize) -> Result<usize> {
        let count = self.number()?;
        if count > limit {
            return Err(Error::ResourceLimit);
        }
        if (count as usize)
            .checked_mul(minimum_bytes)
            .is_none_or(|n| n > self.bytes.len() - self.offset)
        {
            return Err(Error::InvalidEncoding);
        }
        Ok(count as usize)
    }
    fn finish(self) -> Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::InvalidEncoding)
        }
    }
}

pub(crate) fn profile_commitment(profile: Profile) -> Digest {
    let mut hash = Sha256::new();
    hash.update(b"dcs/transaction-state/profile/v2");
    for value in [
        profile.max_transactions,
        profile.max_locks,
        profile.max_lock_events,
        profile.max_candidates,
        profile.max_savepoints_per_transaction,
        profile.max_state_bytes,
        profile.max_command_bytes,
    ] {
        hash.update(value.to_le_bytes());
    }
    hash.finalize().into()
}
fn context_write(writer: &mut Writer, context: Context) -> Result<()> {
    writer.put(&context.network)?;
    writer.put(&context.database)?;
    writer.put(&context.profile.commitment())
}
fn context_read(reader: &mut Reader<'_>, context: Context) -> Result<()> {
    if reader.array::<32>()? != context.network
        || reader.array::<16>()? != context.database
        || reader.array::<32>()? != context.profile.commitment()
    {
        return Err(Error::WrongDomain);
    }
    Ok(())
}
fn mode_byte(mode: LockMode) -> u8 {
    match mode {
        LockMode::KeyShare => 0,
        LockMode::Share => 1,
        LockMode::NoKeyUpdate => 2,
        LockMode::Update => 3,
    }
}
fn read_mode(reader: &mut Reader<'_>) -> Result<LockMode> {
    match reader.byte()? {
        0 => Ok(LockMode::KeyShare),
        1 => Ok(LockMode::Share),
        2 => Ok(LockMode::NoKeyUpdate),
        3 => Ok(LockMode::Update),
        _ => Err(Error::InvalidEncoding),
    }
}
fn row_write(writer: &mut Writer, row: RowKey) -> Result<()> {
    writer.put(&row.table)?;
    writer.put(&row.row)
}
fn row_read(reader: &mut Reader<'_>) -> Result<RowKey> {
    Ok(RowKey {
        table: reader.array()?,
        row: reader.array()?,
    })
}

pub(crate) fn encode_state(state: &State) -> Result<Vec<u8>> {
    let mut writer = Writer::new(state.context.profile.max_state_bytes as usize);
    writer.put(b"DCSTXS02")?;
    context_write(&mut writer, state.context)?;
    writer.wide(state.revision)?;
    writer.wide(state.last_transaction)?;
    writer.number(state.transactions.len() as u32)?;
    for (id, tx) in &state.transactions {
        writer.wide(id.0)?;
        writer.put(&tx.controller.0)?;
        writer.wide(tx.next_sequence)?;
        writer.put(&tx.snapshot)?;
        writer.byte(match tx.status {
            TransactionStatus::Active => 0,
            TransactionStatus::Failed => 1,
        })?;
        writer.number(tx.savepoints.len() as u32)?;
        for point in &tx.savepoints {
            writer.put(&point.name)?;
            writer.number(point.events as u32)?;
        }
        writer.number(tx.events.len() as u32)?;
        for event in &tx.events {
            row_write(&mut writer, event.row)?;
            writer.byte(mode_byte(event.mode))?;
        }
    }
    Ok(writer.bytes)
}
pub(crate) fn decode_state(bytes: &[u8], context: Context) -> Result<State> {
    context.profile.validate()?;
    let mut reader = Reader::new(bytes, context.profile.max_state_bytes as usize)?;
    if reader.array::<8>()? != *b"DCSTXS02" {
        return Err(Error::InvalidEncoding);
    }
    context_read(&mut reader, context)?;
    let revision = reader.wide()?;
    let last_transaction = reader.wide()?;
    let count = reader.count(context.profile.max_transactions, 89)?;
    let mut transactions = BTreeMap::new();
    let mut previous = 0;
    let mut total_events = 0;
    for _ in 0..count {
        let id = reader.wide()?;
        if id <= previous {
            return Err(Error::InvalidEncoding);
        }
        previous = id;
        let controller = ControllerId(reader.array()?);
        let next_sequence = reader.wide()?;
        let snapshot = reader.array()?;
        let status = match reader.byte()? {
            0 => TransactionStatus::Active,
            1 => TransactionStatus::Failed,
            _ => return Err(Error::InvalidEncoding),
        };
        let points = reader.count(context.profile.max_savepoints_per_transaction, 36)?;
        let mut savepoints = Vec::with_capacity(points);
        for _ in 0..points {
            savepoints.push(Savepoint {
                name: reader.array()?,
                events: reader.number()? as usize,
            });
        }
        let count = reader.count(context.profile.max_lock_events - total_events, 65)?;
        total_events += count as u32;
        let mut events = Vec::with_capacity(count);
        for _ in 0..count {
            events.push(LockEvent {
                row: row_read(&mut reader)?,
                mode: read_mode(&mut reader)?,
            });
        }
        transactions.insert(
            TransactionId(id),
            Transaction {
                controller,
                next_sequence,
                snapshot,
                status,
                events,
                savepoints,
            },
        );
    }
    reader.finish()?;
    Ok(State {
        context,
        revision,
        last_transaction,
        transactions,
    })
}

pub(crate) fn state_commitment(state: &State) -> Result<Commitment> {
    let image = state.encode()?;
    let mut hash = Sha256::new();
    hash.update(b"dcs/transaction-state/state/v2");
    hash.update(&image);
    let transactions = hash.finalize().into();
    let held = state.lock_table();
    let holder_count: usize = held.values().map(BTreeMap::len).sum();
    let mut hash = Sha256::new();
    hash.update(b"dcs/transaction-state/locks/v2");
    hash.update(state.context.network);
    hash.update(state.context.database);
    hash.update(state.context.profile.commitment());
    hash.update(state.revision.to_le_bytes());
    hash.update((holder_count as u32).to_le_bytes());
    for (row, owners) in held {
        for (id, mode) in owners {
            hash.update(row.table);
            hash.update(row.row);
            hash.update(id.0.to_le_bytes());
            hash.update([mode_byte(mode)]);
        }
    }
    Ok(Commitment {
        revision: state.revision,
        transactions,
        locks: hash.finalize().into(),
        transaction_count: state.transactions.len() as u32,
        holder_count: holder_count as u32,
    })
}

pub(crate) fn validate_command(command: &Command, profile: Profile) -> Result<()> {
    let payload = match &command.action {
        Action::Begin { .. }
        | Action::Savepoint { .. }
        | Action::RollbackTo { .. }
        | Action::Release { .. } => 32,
        Action::End { .. } => 1,
        Action::FailCurrent => 0,
        Action::Acquire {
            candidates, limit, ..
        } => {
            if candidates.len() > profile.max_candidates as usize {
                return Err(Error::ResourceLimit);
            }
            candidates
                .len()
                .checked_mul(64)
                .and_then(|bytes| bytes.checked_add(11 + usize::from(limit.is_some()) * 4))
                .ok_or(Error::ResourceLimit)?
        }
    };
    // Fixed magic/context/intent/sequence/action tag and controller signature.
    if payload
        .checked_add(305)
        .is_none_or(|bytes| bytes > profile.max_command_bytes as usize)
    {
        return Err(Error::ResourceLimit);
    }
    Ok(())
}
fn unsigned_intent(intent: &Intent, context: Context) -> Result<Vec<u8>> {
    context.profile.validate()?;
    validate_command(&intent.command, context.profile)?;
    let mut writer = Writer::new(context.profile.max_command_bytes as usize - 64);
    writer.put(b"DCSTXI02")?;
    context_write(&mut writer, context)?;
    for bytes in [
        &intent.genesis,
        &intent.parent,
        &intent.controller.0,
        &intent.statement,
    ] {
        writer.put(bytes)?;
    }
    writer.wide(intent.command.expected_revision)?;
    writer.wide(intent.command.transaction.0)?;
    writer.wide(intent.command.sequence)?;
    match &intent.command.action {
        Action::Begin { snapshot } => {
            writer.byte(0)?;
            writer.put(snapshot)?;
        }
        Action::Acquire {
            candidates,
            mode,
            wait,
            offset,
            limit,
        } => {
            if candidates.len() > context.profile.max_candidates as usize {
                return Err(Error::ResourceLimit);
            }
            writer.byte(1)?;
            writer.byte(mode_byte(*mode))?;
            writer.byte(match wait {
                WaitPolicy::Wait => 0,
                WaitPolicy::NoWait => 1,
                WaitPolicy::SkipLocked => 2,
            })?;
            writer.number(*offset)?;
            match limit {
                None => writer.byte(0)?,
                Some(limit) => {
                    writer.byte(1)?;
                    writer.number(*limit)?;
                }
            }
            writer.number(candidates.len() as u32)?;
            for row in candidates {
                row_write(&mut writer, *row)?;
            }
        }
        Action::FailCurrent => writer.byte(6)?,
        Action::Savepoint { name } => {
            writer.byte(2)?;
            writer.put(name)?;
        }
        Action::RollbackTo { name } => {
            writer.byte(3)?;
            writer.put(name)?;
        }
        Action::Release { name } => {
            writer.byte(4)?;
            writer.put(name)?;
        }
        Action::End { completion } => {
            writer.byte(5)?;
            writer.byte(match completion {
                Completion::Commit => 0,
                Completion::Abort => 1,
            })?;
        }
    }
    Ok(writer.bytes)
}
pub(crate) fn intent_message(intent: &Intent, context: Context) -> Result<Digest> {
    let mut hash = Sha256::new();
    hash.update(b"dcs/transaction-state/controller-authorization/v2");
    hash.update(unsigned_intent(intent, context)?);
    Ok(hash.finalize().into())
}
pub(crate) fn encode_intent(signed: &SignedIntent, context: Context) -> Result<Vec<u8>> {
    let mut bytes = unsigned_intent(&signed.intent, context)?;
    bytes.extend_from_slice(&signed.signature);
    Ok(bytes)
}
pub(crate) fn decode_intent(bytes: &[u8], context: Context) -> Result<SignedIntent> {
    context.profile.validate()?;
    let mut reader = Reader::new(bytes, context.profile.max_command_bytes as usize)?;
    if reader.array::<8>()? != *b"DCSTXI02" {
        return Err(Error::InvalidEncoding);
    }
    context_read(&mut reader, context)?;
    let genesis = reader.array()?;
    let parent = reader.array()?;
    let controller = ControllerId(reader.array()?);
    let statement = reader.array()?;
    let expected_revision = reader.wide()?;
    let transaction = TransactionId(reader.wide()?);
    let sequence = reader.wide()?;
    let action = match reader.byte()? {
        0 => Action::Begin {
            snapshot: reader.array()?,
        },
        1 => {
            let mode = read_mode(&mut reader)?;
            let wait = match reader.byte()? {
                0 => WaitPolicy::Wait,
                1 => WaitPolicy::NoWait,
                2 => WaitPolicy::SkipLocked,
                _ => return Err(Error::InvalidEncoding),
            };
            let offset = reader.number()?;
            let limit = match reader.byte()? {
                0 => None,
                1 => Some(reader.number()?),
                _ => return Err(Error::InvalidEncoding),
            };
            let count = reader.count(context.profile.max_candidates, 64)?;
            let mut candidates = Vec::with_capacity(count);
            for _ in 0..count {
                candidates.push(row_read(&mut reader)?);
            }
            Action::Acquire {
                candidates,
                mode,
                wait,
                offset,
                limit,
            }
        }
        2 => Action::Savepoint {
            name: reader.array()?,
        },
        3 => Action::RollbackTo {
            name: reader.array()?,
        },
        4 => Action::Release {
            name: reader.array()?,
        },
        5 => Action::End {
            completion: match reader.byte()? {
                0 => Completion::Commit,
                1 => Completion::Abort,
                _ => return Err(Error::InvalidEncoding),
            },
        },
        6 => Action::FailCurrent,
        _ => return Err(Error::InvalidEncoding),
    };
    let signature = reader.array()?;
    reader.finish()?;
    Ok(SignedIntent {
        intent: Intent {
            genesis,
            parent,
            controller,
            statement,
            command: Command {
                expected_revision,
                transaction,
                sequence,
                action,
            },
        },
        signature,
    })
}
