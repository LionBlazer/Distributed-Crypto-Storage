use super::owner::{Candidate, Certificate, Owner, Snapshot};
use super::*;
use registry200_finality::joint::{DurableJointFinality, JointCheckpoint};
use registry200_finality::{Checkpoint, Descriptor, RegistryFinality};
use std::{
    sync::mpsc::{self, Receiver, SyncSender, TrySendError},
    thread::JoinHandle,
    time::Instant,
};
use work_finality::consensus::{Action, Input, RoundStep, Timeout};

pub(super) enum Command {
    Status,
    Input(Vec<u8>),
    Block(OwnedBlock, bool),
    GetBlock([u8; 32], BodyLease),
    Checkpoint(Checkpoint),
    GetCheckpoint(u64),
    Outbound(usize),
    JointSnapshot,
    JointBlock(OwnedBlock, bool, Snapshot),
    JointInput(Vec<u8>, Snapshot),
    JointCheckpoint(JointCheckpoint, Snapshot),
    GetJointCheckpoint(u64),
}
pub(super) enum Reply {
    Status { slot: u64, context: [u8; 32] },
    Ok,
    NeedBlock([u8; 32]),
    Block(OwnedBlock),
    Checkpoint(Option<Checkpoint>),
    Outbound(Option<Vec<u8>>),
    JointSnapshot(Snapshot),
    JointCheckpoint(Option<JointCheckpoint>),
}
struct Envelope {
    command: Command,
    reply: SyncSender<io::Result<(Reply, CommandLease)>>,
    bytes: CommandLease,
    expires: Option<Instant>,
}
#[derive(Clone)]
pub(super) struct Handle {
    tx: SyncSender<Envelope>,
    bytes: Arc<InboxBytes>,
    pub stop: Arc<AtomicBool>,
}
impl Handle {
    /// Reserve before allocating an announced remote control frame. The same
    /// lease follows its payload into the bounded owner queue, without overlap.
    pub(super) fn reserve_control(&self) -> io::Result<CommandLease> {
        self.bytes.acquire(super::wire::MAX_CONTROL)
    }
    pub fn call(&self, command: Command) -> io::Result<Reply> {
        if self.stop.load(Ordering::Acquire) {
            return Err(closed());
        }
        let bytes = match &command {
            Command::Input(b) => b.len(),
            Command::Checkpoint(c) => {
                c.certificate().len() + registry200_finality::DESCRIPTOR_BYTES + 12
            }
            _ => 256,
        };
        if bytes > work_finality::consensus::MAX_INPUT_BYTES {
            return Err(invalid());
        }
        let lease = self.bytes.acquire(bytes)?;
        self.call_reserved(command, lease)
            .map(|(reply, _lease)| reply)
    }
    pub(super) fn call_reserved(
        &self,
        command: Command,
        lease: CommandLease,
    ) -> io::Result<(Reply, CommandLease)> {
        if self.stop.load(Ordering::Acquire) {
            return Err(closed());
        }
        let (tx, rx) = mpsc::sync_channel(1);
        match self.tx.try_send(Envelope {
            command,
            reply: tx,
            bytes: lease,
            expires: None,
        }) {
            Ok(()) => (),
            Err(TrySendError::Full(_)) => return Err(busy()),
            Err(TrySendError::Disconnected(_)) => return Err(closed()),
        }
        rx.recv_timeout(RPC_BUDGET).map_err(|_| closed())?
    }
    /// Preserve ONE absolute Joint expiry across prefetch and queue waiting.
    /// Once enqueued, join synchronous work: a socket cancellation never drops
    /// the signer/gate while actual native proof verification is still running.
    pub(super) fn call_joint(&self, command: Command, expires: Instant) -> io::Result<Reply> {
        let bytes = match &command {
            Command::JointInput(b, _) => b.len(),
            Command::JointCheckpoint(c, _) => {
                c.certificate().len() + registry200_finality::joint::CANDIDATE_BYTES + 12
            }
            _ => 256,
        };
        if bytes > work_finality::consensus::MAX_INPUT_BYTES {
            return Err(invalid());
        }
        let lease = self.bytes.acquire(bytes)?;
        self.call_reserved_joint(command, lease, expires)
            .map(|(r, _)| r)
    }
    pub(super) fn call_reserved_joint(
        &self,
        command: Command,
        lease: CommandLease,
        expires: Instant,
    ) -> io::Result<(Reply, CommandLease)> {
        if self.stop.load(Ordering::Acquire) {
            return Err(closed());
        }
        require_time(expires)?;
        let (tx, rx) = mpsc::sync_channel(1);
        match self.tx.try_send(Envelope {
            command,
            reply: tx,
            bytes: lease,
            expires: Some(expires),
        }) {
            Ok(()) => (),
            Err(TrySendError::Full(_)) => return Err(busy()),
            Err(TrySendError::Disconnected(_)) => return Err(closed()),
        }
        rx.recv().map_err(|_| closed())?
    }
}
pub(super) fn spawn(
    owned: RegistryFinality,
    gate: crate::ProofGate,
) -> io::Result<(Handle, JoinHandle<io::Result<()>>)> {
    spawn_owned(Owner::Original(owned), gate, "dcs-registry-finality-owner")
}
pub(super) fn spawn_joint(
    owned: DurableJointFinality,
    gate: crate::ProofGate,
) -> io::Result<(Handle, JoinHandle<io::Result<()>>)> {
    spawn_owned(Owner::Joint(owned), gate, "dcs-joint-finality-owner")
}
fn spawn_owned(
    mut owned: Owner,
    gate: crate::ProofGate,
    name: &str,
) -> io::Result<(Handle, JoinHandle<io::Result<()>>)> {
    // Binding, current timeout and outbound state must be readable before launch.
    owned.pins()?.id();
    active_timer(&owned)?;
    owned.outbound()?;
    let (tx, rx) = mpsc::sync_channel(MAX_COMMANDS);
    let handle = Handle {
        tx,
        bytes: Arc::new(InboxBytes(Arc::new(AtomicUsize::new(0)))),
        stop: Arc::new(AtomicBool::new(false)),
    };
    let stop = handle.stop.clone();
    let join = std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            let result = run(&mut owned, gate, stop.clone(), rx);
            stop.store(true, Ordering::Release);
            result
        })?;
    Ok((handle, join))
}
fn run(
    owned: &mut Owner,
    gate: crate::ProofGate,
    stop: Arc<AtomicBool>,
    rx: Receiver<Envelope>,
) -> io::Result<()> {
    let mut timer = active_timer(owned)?;
    let mut due = deadline(timer)?;
    let mut pending = None;
    let mut proposed = None;
    while !stop.load(Ordering::Acquire) {
        let wait = due.map_or(Duration::from_millis(100), |d| {
            d.saturating_duration_since(Instant::now())
                .min(Duration::from_millis(100))
        });
        match rx.recv_timeout(wait) {
            Ok(envelope) => {
                let answer = envelope
                    .expires
                    .map_or(Ok(()), require_time)
                    .and_then(|()| process(owned, &gate, &mut pending, envelope.command))
                    .map(|reply| (reply, envelope.bytes));
                let _ = envelope.reply.send(answer);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => (),
        }
        if stop.load(Ordering::Acquire) {
            break;
        }
        let active = active_timer(owned)?;
        if active != timer {
            timer = active;
            due = deadline(timer)?;
        }
        if let Some(candidate) = pending.as_ref() {
            if candidate.slot() != owned.context()?.slot() {
                pending = None;
                proposed = None;
            } else if let Some(current) = timer
                && current.step() == RoundStep::Propose
                && proposed != Some((current.slot(), current.round()))
                && let Ok(_permit) = gate.try_acquire()
            {
                // A client may submit to every validator. Only the actual
                // elected proposer signs; other owners retain the same bounded
                // candidate for a later round. No caller selects our key/round.
                owned.propose(candidate)?;
                proposed = Some((current.slot(), current.round()));
                let active = active_timer(owned)?;
                if active != timer {
                    timer = active;
                    due = deadline(timer)?;
                }
            }
        }
        if let Some(current) = timer
            && due.is_some_and(|d| Instant::now() >= d)
        {
            match gate.try_acquire() {
                Ok(_permit) => {
                    owned.timeout(current)?;
                    timer = active_timer(owned)?;
                    due = deadline(timer)?;
                }
                Err(_) => {
                    // Preserve expired token; busy proof work cannot unlock or fake a timeout.
                    std::thread::park_timeout(Duration::from_millis(10));
                }
            }
        }
    }
    // Drop owned signer only after an in-flight native check returned. No worker
    // owns the signer/key or any actor lock, and cancellation never unlocks it.
    Ok(())
}
fn active_timer(owned: &Owner) -> io::Result<Option<Timeout>> {
    // The closed owner's Original arm preserves the exact Stale=>wait rule.
    owned.active_timer()
}
fn deadline(timer: Option<Timeout>) -> io::Result<Option<Instant>> {
    timer
        .map(|t| {
            Instant::now()
                .checked_add(Duration::from_millis(t.duration_ms()))
                .ok_or_else(invalid)
        })
        .transpose()
}
fn process(
    owned: &mut Owner,
    gate: &crate::ProofGate,
    pending: &mut Option<Candidate>,
    command: Command,
) -> io::Result<Reply> {
    match command {
        Command::Status => Ok(Reply::Status {
            slot: owned.context()?.slot(),
            context: owned.context()?.id(),
        }),
        Command::JointSnapshot => {
            require_joint(owned)?;
            Ok(Reply::JointSnapshot(owned.snapshot()?))
        }
        Command::GetBlock(id, lease) => Ok(Reply::Block(OwnedBlock {
            block: owned.block(id)?,
            _lease: lease,
        })),
        Command::GetCheckpoint(slot) => {
            require_original(owned)?;
            let checkpoint = match owned.checkpoint(slot)? {
                Some(Certificate::Original(c)) => Some(c),
                None => None,
                Some(Certificate::Joint(_)) => return Err(invalid()),
            };
            Ok(Reply::Checkpoint(checkpoint))
        }
        Command::GetJointCheckpoint(slot) => {
            require_joint(owned)?;
            let checkpoint = match owned.checkpoint(slot)? {
                Some(Certificate::Joint(c)) => Some(c),
                None => None,
                Some(Certificate::Original(_)) => return Err(invalid()),
            };
            Ok(Reply::JointCheckpoint(checkpoint))
        }
        Command::Outbound(index) => {
            if index >= MAX_COMMANDS {
                return Err(invalid());
            }
            let action = owned
                .outbound()?
                .into_iter()
                .filter(|action| {
                    matches!(
                        action,
                        Action::Proposal(_) | Action::Vote(_) | Action::Certificate { .. }
                    )
                })
                .nth(index);
            // Drop all other cloned actions before serializing ONE input. The
            // relay never owns an aggregate encoded message/certificate vector.
            let input = match action {
                Some(Action::Proposal(p)) => Some(Input::Proposal(p)),
                Some(Action::Vote(v)) => Some(Input::Vote(v)),
                Some(Action::Certificate { value, certificate }) => {
                    Some(Input::Certificate { value, certificate })
                }
                _ => None,
            };
            Ok(Reply::Outbound(
                input
                    .map(|input| input.encode().map_err(error))
                    .transpose()?,
            ))
        }
        Command::Block(owned_block, propose) => {
            require_original(owned)?;
            let _permit = gate.try_acquire().map_err(|_| busy())?;
            let d = owned.import(&owned_block.block)?;
            if propose {
                *pending = Some(d);
            }
            Ok(Reply::Ok)
        }
        Command::Input(bytes) => {
            require_original(owned)?;
            let input = Input::decode(owned.context()?, &bytes).map_err(error)?;
            let value = match &input {
                Input::Proposal(p) => Some(p.value()),
                Input::Certificate { value, .. } => Some(value.as_slice()),
                _ => None,
            };
            if let Some(value) = value {
                let d = Descriptor::decode(value).map_err(error)?;
                if !owned.has(d.header().id())? {
                    return Ok(Reply::NeedBlock(d.header().id()));
                }
            }
            let _permit = gate.try_acquire().map_err(|_| busy())?;
            owned.receive(&bytes)?;
            Ok(Reply::Ok)
        }
        Command::Checkpoint(checkpoint) => {
            require_original(owned)?;
            if checkpoint.descriptor().slot() != owned.context()?.slot() {
                return Err(invalid());
            }
            // Actual QC validation precedes even the missing-body fetch hint.
            owned
                .context()?
                .verify_commit(
                    &checkpoint.descriptor().encode(),
                    checkpoint.round(),
                    checkpoint.certificate(),
                )
                .map_err(error)?;
            if !owned.has(checkpoint.descriptor().header().id())? {
                return Ok(Reply::NeedBlock(checkpoint.descriptor().header().id()));
            }
            let _permit = gate.try_acquire().map_err(|_| busy())?;
            owned.commit(&Certificate::Original(checkpoint))?;
            Ok(Reply::Ok)
        }
        Command::JointBlock(block, propose, snapshot) => {
            require_joint(owned)?;
            let _permit = gate.try_acquire().map_err(|_| busy())?;
            require_snapshot(owned, snapshot)?;
            if block.block.header().id() == snapshot.parent {
                // Retry ONLY the actual last selected header/body. The real
                // durable last-context/QC/all-proof path is mandatory again.
                if version_journal::hash(block.block.body()) != block.block.header().body_hash {
                    return Err(invalid());
                }
                let previous = snapshot.slot.checked_sub(2).ok_or_else(invalid)?;
                let checkpoint = owned.checkpoint(previous)?.ok_or_else(invalid)?;
                if checkpoint.candidate().header() != block.block.header() {
                    return Err(invalid());
                }
                owned.commit(&checkpoint)?;
                return Ok(Reply::Ok);
            }
            let candidate = owned.import(&block.block)?;
            if propose {
                *pending = Some(candidate)
            }
            Ok(Reply::Ok)
        }
        Command::JointInput(bytes, snapshot) => {
            require_joint(owned)?;
            require_snapshot(owned, snapshot)?;
            let input = Input::decode(owned.context()?, &bytes).map_err(error)?;
            let value = match &input {
                Input::Proposal(p) => Some(p.value()),
                Input::Certificate { value, .. } => Some(value.as_slice()),
                _ => None,
            };
            if let Some(value) = value {
                let candidate = owned.pins()?.candidate(value)?;
                if !owned.has(candidate.header().id())? {
                    return Ok(Reply::NeedBlock(candidate.header().id()));
                }
            }
            let _permit = gate.try_acquire().map_err(|_| busy())?;
            require_snapshot(owned, snapshot)?;
            owned.receive(&bytes)?;
            Ok(Reply::Ok)
        }
        Command::JointCheckpoint(checkpoint, snapshot) => {
            require_joint(owned)?;
            require_snapshot(owned, snapshot)?;
            let current = owned.context()?.slot();
            if checkpoint.candidate().slot() == current {
                // The actual current QC precedes even a missing-body hint.
                owned
                    .context()?
                    .verify_commit(
                        &checkpoint.candidate().encode(),
                        checkpoint.round(),
                        checkpoint.certificate(),
                    )
                    .map_err(error)?;
                if !owned.has(checkpoint.candidate().header().id())? {
                    return Ok(Reply::NeedBlock(checkpoint.candidate().header().id()));
                }
            } else if checkpoint.candidate().slot().checked_add(1) != Some(current) {
                return Err(invalid());
            }
            let _permit = gate.try_acquire().map_err(|_| busy())?;
            require_snapshot(owned, snapshot)?;
            // A last-slot retry is checked by DurableJointFinality using its
            // retained real lastContext, QC, semantic successor and ALL proofs.
            owned.commit(&Certificate::Joint(checkpoint))?;
            Ok(Reply::Ok)
        }
    }
}
fn require_original(owned: &Owner) -> io::Result<()> {
    match owned {
        Owner::Original(_) => Ok(()),
        Owner::Joint(_) => Err(invalid()),
    }
}
fn require_joint(owned: &Owner) -> io::Result<()> {
    match owned {
        Owner::Joint(_) => Ok(()),
        Owner::Original(_) => Err(invalid()),
    }
}
fn require_snapshot(owned: &Owner, expected: Snapshot) -> io::Result<()> {
    if owned.snapshot()? != expected {
        return Err(invalid());
    }
    Ok(())
}
fn require_time(expires: Instant) -> io::Result<()> {
    if Instant::now() >= expires {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Joint operation expired before admission",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "joint_queue_tests.rs"]
mod joint_queue_tests;
