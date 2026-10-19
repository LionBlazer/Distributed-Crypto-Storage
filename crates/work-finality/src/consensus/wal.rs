use super::{
    Action, ApplicationVerifier, ByteBudget, Context, Decision, Error, Input, MAX_RECORD_BYTES,
    Result, RoundStep, Timeout,
    budget::FileCharge,
    codec::{self, Reader},
    kernel::Machine,
    messages::encode_actions,
};
use crate::{Hash, hash};
use ed25519_dalek::SigningKey;
use std::{
    fs::{File, OpenOptions, TryLockError},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

const HEADER_BYTES: usize = 8 + 32 + 32 + 32 + 8 + 32;
const RECORD_OVERHEAD: usize = 4 + 8 + 32 + 4 + 4 + 32 + 4 + 8;

/// Exclusive signer and single-slot protocol owner. The private key is moved
/// here and never exposed, cloned, debugged or serialized. No outbound signature,
/// lock/POL change or decision is published before its complete record syncs.
///
/// ```compile_fail
/// fn copy<V: work_finality::consensus::ApplicationVerifier>(v: &work_finality::consensus::DurableVoter<V>) { let _ = v.clone(); let _: work_finality::consensus::DurableVoter<V> = v.clone(); }
/// ```
/// ```compile_fail
/// fn key<V: work_finality::consensus::ApplicationVerifier>(v: &work_finality::consensus::DurableVoter<V>) { let _ = &v.key; }
/// ```
/// ```compile_fail
/// fn debug<V: work_finality::consensus::ApplicationVerifier>(v: &work_finality::consensus::DurableVoter<V>) { let _ = format!("{v:?}"); }
/// ```
pub struct DurableVoter<V: ApplicationVerifier> {
    context: Context,
    verifier: V,
    key: SigningKey,
    file: File,
    charge: FileCharge,
    length: u64,
    sequence: u64,
    previous: Hash,
    machine: Machine,
    poisoned: bool,
    #[cfg(test)]
    fault: Option<Fault>,
}
impl<V: ApplicationVerifier> DurableVoter<V> {
    /// Only for an explicitly NEW signer installation. Never call this as a
    /// recovery fallback. Recreating/rolling back a signer file with the same key
    /// can double-vote; protection against a malicious disk rollback is absent.
    pub fn create_new(
        path: impl AsRef<Path>,
        context: Context,
        verifier: V,
        key: SigningKey,
        budget: &ByteBudget,
    ) -> Result<Self> {
        require_key(&context, &key)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path.as_ref())?;
        lock(&file)?;
        let canonical = path.as_ref().canonicalize()?;
        let header = header(&context, key.verifying_key().to_bytes());
        let charge = budget.file(canonical, header.len() as u64)?;
        // On any error leave the new file intact. Never truncate or recreate.
        file.write_all(&header)?;
        file.sync_all()?;
        Ok(Self {
            context,
            verifier,
            key,
            file,
            charge,
            length: header.len() as u64,
            sequence: 0,
            previous: hash(b"dcs/work-finality/wal-header/v1", &[&header]),
            machine: Machine::new(),
            poisoned: false,
            #[cfg(test)]
            fault: None,
        })
    }
    /// Open ONLY an existing file under independently supplied pins. Full replay
    /// reruns signature, quorum and application checks and reproduces exact local
    /// signed actions. A corrupt/torn tail is an error, never a truncation request.
    pub fn open_existing(
        path: impl AsRef<Path>,
        context: Context,
        verifier: V,
        key: SigningKey,
        budget: &ByteBudget,
    ) -> Result<Self> {
        require_key(&context, &key)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path.as_ref())?;
        lock(&file)?;
        let length = file.metadata()?.len();
        if length < HEADER_BYTES as u64 || length > context.rules().max_wal_bytes() {
            return Err(Error::CorruptWal);
        }
        let charge = budget.file(path.as_ref().canonicalize()?, length)?;
        let mut received = [0; HEADER_BYTES];
        file.read_exact(&mut received)
            .map_err(|_| Error::CorruptWal)?;
        if received.as_slice() != header(&context, key.verifying_key().to_bytes()).as_slice() {
            return Err(Error::WrongContext);
        }
        let mut state = Self {
            context,
            verifier,
            key,
            file,
            charge,
            length,
            sequence: 0,
            previous: hash(b"dcs/work-finality/wal-header/v1", &[&received]),
            machine: Machine::new(),
            poisoned: false,
            #[cfg(test)]
            fault: None,
        };
        let mut position = HEADER_BYTES as u64;
        while position < length {
            let mut number = [0; 4];
            state
                .file
                .read_exact(&mut number)
                .map_err(|_| Error::CorruptWal)?;
            let n = u32::from_le_bytes(number) as usize;
            if !(RECORD_OVERHEAD..=MAX_RECORD_BYTES).contains(&n) || n as u64 > length - position {
                return Err(Error::CorruptWal);
            }
            // Total file length, record size and remaining bytes precede allocation.
            let mut record = vec![0; n];
            record[..4].copy_from_slice(&number);
            state
                .file
                .read_exact(&mut record[4..])
                .map_err(|_| Error::CorruptWal)?;
            state.replay(&record)?;
            position += n as u64;
        }
        if position != length {
            return Err(Error::CorruptWal);
        }
        Ok(state)
    }
    pub fn context(&self) -> &Context {
        &self.context
    }
    pub fn round(&self) -> u64 {
        self.machine.round()
    }
    pub fn step(&self) -> RoundStep {
        self.machine.step()
    }
    pub fn locked(&self) -> Option<(u64, Hash)> {
        self.machine.lock()
    }
    pub fn valid(&self) -> Option<(u64, Hash)> {
        self.machine.valid()
    }
    pub fn decision(&self) -> Option<&Decision> {
        if self.poisoned {
            None
        } else {
            self.machine.decision()
        }
    }
    pub fn file_bytes(&self) -> u64 {
        self.length
    }
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
    /// Exact persisted signatures may be re-gossiped after a lost response or
    /// restart. No fresh signature is created by this accessor.
    pub fn outbound(&self) -> Result<Vec<Action>> {
        self.live()?;
        Ok(self.machine.outbound())
    }
    /// Recovered/current active timer. Stale means no timer is enabled: prevote
    /// and precommit timers require their actual ANY quorum; a decision has none.
    pub fn timeout(&self) -> Result<Timeout> {
        self.live()?;
        self.machine.timer(&self.context)
    }
    pub fn handle_bytes(&mut self, bytes: &[u8]) -> Result<Vec<Action>> {
        self.live()?;
        let input = Input::decode(&self.context, bytes)?;
        self.handle(input)
    }
    /// Local owner entry point. Only the clock owner may deliver Timeout after
    /// its duration; only the local proposer chooses Propose. Untrusted network
    /// bytes must use handle_bytes, which rejects both local-control tags.
    pub fn handle(&mut self, input: Input) -> Result<Vec<Action>> {
        self.live()?;
        match self.file.metadata() {
            Ok(metadata) if metadata.len() == self.length => {}
            Ok(_) => {
                self.poisoned = true;
                return Err(Error::CorruptWal);
            }
            Err(error) => {
                self.poisoned = true;
                return Err(Error::Io(error));
            }
        }
        let encoded = input.encode()?;
        // All mutations and signatures are private until durable commit. Failure
        // leaves the old machine intact; no partially prepared action escapes.
        let mut prepared = self.machine.clone();
        let actions = prepared.apply(&self.context, &self.verifier, &self.key, &input)?;
        // Replaying one valid signature cannot exhaust the durable quota. Exact
        // semantic duplicates are no-ops, including alternative vote signatures.
        if prepared == self.machine && actions.is_empty() {
            return Ok(actions);
        }
        let output = encode_actions(&actions)?;
        let sequence = self.sequence.checked_add(1).ok_or(Error::ResourceLimit)?;
        let record = encode_record(sequence, self.previous, &encoded, &output)?;
        let next_hash = record_hash(&record)?;
        let next_length = self
            .length
            .checked_add(record.len() as u64)
            .ok_or(Error::ResourceLimit)?;
        if next_length > self.context.rules().max_wal_bytes() {
            return Err(Error::ResourceLimit);
        }
        // Charge BEFORE writing. An I/O failure keeps this conservative charge,
        // poisons the signer and requires an explicit recovery attempt.
        self.charge.grow(next_length)?;
        if let Err(error) = self.write_record(&record) {
            self.poisoned = true;
            return Err(Error::Io(error));
        }
        self.length = next_length;
        self.sequence = sequence;
        self.previous = next_hash;
        self.machine = prepared;
        Ok(actions)
    }
    fn live(&self) -> Result<()> {
        if self.poisoned {
            Err(Error::Poisoned)
        } else {
            Ok(())
        }
    }
    fn replay(&mut self, record: &[u8]) -> Result<()> {
        let mut r = Reader::new(record);
        if r.u32()? as usize != record.len()
            || r.u64()? != self.sequence.checked_add(1).ok_or(Error::CorruptWal)?
            || r.array::<32>()? != self.previous
        {
            return Err(Error::CorruptWal);
        }
        let input = r.blob(super::MAX_INPUT_BYTES)?;
        let output = r.blob(MAX_RECORD_BYTES)?;
        let checksum = r.array::<32>()?;
        if r.u32()? as usize != record.len() || r.array::<8>()? != *b"DCSWFR01" {
            return Err(Error::CorruptWal);
        }
        r.end()?;
        if checksum != record_hash(record)? {
            return Err(Error::CorruptWal);
        }
        let command = Input::decode_record(&self.context, input).map_err(|_| Error::CorruptWal)?;
        let mut next = self.machine.clone();
        let actions = next
            .apply(&self.context, &self.verifier, &self.key, &command)
            .map_err(|_| Error::CorruptWal)?;
        if next == self.machine && actions.is_empty() {
            return Err(Error::CorruptWal);
        }
        if encode_actions(&actions)? != output {
            return Err(Error::CorruptWal);
        }
        self.machine = next;
        self.sequence += 1;
        self.previous = checksum;
        Ok(())
    }
    fn write_record(&mut self, record: &[u8]) -> std::io::Result<()> {
        self.file.seek(SeekFrom::Start(self.length))?;
        #[cfg(test)]
        if let Some(Fault::Partial(n)) = self.fault {
            self.fault = None;
            self.file.write_all(&record[..n.min(record.len())])?;
            self.file.sync_all()?;
            return Err(std::io::Error::other(
                "PUBLIC test: crash after partial record",
            ));
        }
        self.file.write_all(record)?;
        #[cfg(test)]
        if self.fault == Some(Fault::BeforeSync) {
            self.fault = None;
            return Err(std::io::Error::other("PUBLIC test: sync failure"));
        }
        self.file.sync_all()?;
        #[cfg(test)]
        if self.fault == Some(Fault::AfterSync) {
            self.fault = None;
            return Err(std::io::Error::other(
                "PUBLIC test: crash after sync, before publication",
            ));
        }
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn inject(&mut self, fault: Fault) {
        self.fault = Some(fault);
    }
}
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fault {
    Partial(usize),
    BeforeSync,
    AfterSync,
}

fn header(context: &Context, public_key: Hash) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_BYTES);
    bytes.extend_from_slice(b"DCSWFW01");
    bytes.extend_from_slice(context.rules().id().as_bytes());
    bytes.extend_from_slice(&context.id());
    bytes.extend_from_slice(&public_key);
    bytes.extend_from_slice(&context.rules().max_wal_bytes().to_le_bytes());
    let checksum = hash(b"dcs/work-finality/wal-header-check/v1", &[&bytes]);
    bytes.extend_from_slice(&checksum);
    bytes
}
fn encode_record(sequence: u64, previous: Hash, input: &[u8], output: &[u8]) -> Result<Vec<u8>> {
    let length = RECORD_OVERHEAD
        .checked_add(input.len())
        .and_then(|n| n.checked_add(output.len()))
        .ok_or(Error::ResourceLimit)?;
    if length > MAX_RECORD_BYTES {
        return Err(Error::ResourceLimit);
    }
    let mut b = Vec::with_capacity(length);
    b.extend_from_slice(&(length as u32).to_le_bytes());
    b.extend_from_slice(&sequence.to_le_bytes());
    b.extend_from_slice(&previous);
    codec::blob(&mut b, input, super::MAX_INPUT_BYTES)?;
    codec::blob(&mut b, output, MAX_RECORD_BYTES)?;
    let checksum = hash(b"dcs/work-finality/wal-record/v1", &[&b]);
    b.extend_from_slice(&checksum);
    b.extend_from_slice(&(length as u32).to_le_bytes());
    b.extend_from_slice(b"DCSWFR01");
    Ok(b)
}
fn record_hash(record: &[u8]) -> Result<Hash> {
    let end = record.len().checked_sub(44).ok_or(Error::CorruptWal)?;
    Ok(hash(b"dcs/work-finality/wal-record/v1", &[&record[..end]]))
}
fn require_key(context: &Context, key: &SigningKey) -> Result<()> {
    if context
        .set()
        .weight(key.verifying_key().to_bytes())
        .is_none()
    {
        return Err(Error::WrongContext);
    }
    Ok(())
}
fn lock(file: &File) -> Result<()> {
    file.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => Error::Io(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "signer already owned",
        )),
        TryLockError::Error(error) => Error::Io(error),
    })
}
