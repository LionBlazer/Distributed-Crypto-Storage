use super::*;
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
}
pub(super) enum Reply {
    Status { slot: u64, context: [u8; 32] },
    Ok,
    NeedBlock([u8; 32]),
    Block(OwnedBlock),
    Checkpoint(Option<Checkpoint>),
    Outbound(Option<Vec<u8>>),
}
struct Envelope {
    command: Command,
    reply: SyncSender<io::Result<(Reply, CommandLease)>>,
    bytes: CommandLease,
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
        }) {
            Ok(()) => (),
            Err(TrySendError::Full(_)) => return Err(busy()),
            Err(TrySendError::Disconnected(_)) => return Err(closed()),
        }
        rx.recv_timeout(RPC_BUDGET).map_err(|_| closed())?
    }
}
pub(super) fn spawn(
    mut owned: RegistryFinality,
    gate: crate::ProofGate,
) -> io::Result<(Handle, JoinHandle<io::Result<()>>)> {
    // Binding, current timeout and outbound state must be readable before launch.
    owned.binding().map_err(error)?;
    active_timer(&owned)?;
    owned.outbound().map_err(error)?;
    let (tx, rx) = mpsc::sync_channel(MAX_COMMANDS);
    let handle = Handle {
        tx,
        bytes: Arc::new(InboxBytes(Arc::new(AtomicUsize::new(0)))),
        stop: Arc::new(AtomicBool::new(false)),
    };
    let stop = handle.stop.clone();
    let join = std::thread::Builder::new()
        .name("dcs-registry-finality-owner".into())
        .spawn(move || {
            let result = run(&mut owned, gate, stop.clone(), rx);
            stop.store(true, Ordering::Release);
            result
        })?;
    Ok((handle, join))
}
fn run(
    owned: &mut RegistryFinality,
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
                let answer = process(owned, &gate, &mut pending, envelope.command)
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
            if candidate.slot() != owned.context().slot() {
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
                match owned.propose(candidate) {
                    Ok(_)
                    | Err(registry200_finality::Error::Consensus(
                        work_finality::consensus::Error::WrongProposer
                        | work_finality::consensus::Error::Stale,
                    )) => (),
                    Err(e) => return Err(error(e)),
                }
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
                    owned.on_timeout(current).map_err(error)?;
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
fn active_timer(owned: &RegistryFinality) -> io::Result<Option<Timeout>> {
    match owned.timeout() {
        Ok(timer) => Ok(Some(timer)),
        // A prevote/precommit timer is disabled until the actual required ANY
        // quorum exists. Absence of quorum means wait, never terminate/unlock.
        Err(registry200_finality::Error::Consensus(work_finality::consensus::Error::Stale)) => {
            Ok(None)
        }
        Err(e) => Err(error(e)),
    }
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
    owned: &mut RegistryFinality,
    gate: &crate::ProofGate,
    pending: &mut Option<Descriptor>,
    command: Command,
) -> io::Result<Reply> {
    match command {
        Command::Status => Ok(Reply::Status {
            slot: owned.context().slot(),
            context: owned.context().id(),
        }),
        Command::GetBlock(id, lease) => Ok(Reply::Block(OwnedBlock {
            block: owned.candidate_block(id).map_err(error)?,
            _lease: lease,
        })),
        Command::GetCheckpoint(slot) => Ok(Reply::Checkpoint(
            owned.checkpoint_after(slot).map_err(error)?,
        )),
        Command::Outbound(index) => {
            if index >= MAX_COMMANDS {
                return Err(invalid());
            }
            let action = owned
                .outbound()
                .map_err(error)?
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
            let _permit = gate.try_acquire().map_err(|_| busy())?;
            let d = owned
                .import_candidate(owned_block.block.header().clone(), owned_block.block.body())
                .map_err(error)?;
            if propose {
                *pending = Some(d);
            }
            Ok(Reply::Ok)
        }
        Command::Input(bytes) => {
            let input = Input::decode(owned.context(), &bytes).map_err(error)?;
            let value = match &input {
                Input::Proposal(p) => Some(p.value()),
                Input::Certificate { value, .. } => Some(value.as_slice()),
                _ => None,
            };
            if let Some(value) = value {
                let d = Descriptor::decode(value).map_err(error)?;
                if !owned.has_candidate(d.header().id()).map_err(error)? {
                    return Ok(Reply::NeedBlock(d.header().id()));
                }
            }
            let _permit = gate.try_acquire().map_err(|_| busy())?;
            owned.receive(&bytes).map_err(error)?;
            Ok(Reply::Ok)
        }
        Command::Checkpoint(checkpoint) => {
            if checkpoint.descriptor().slot() != owned.context().slot() {
                return Err(invalid());
            }
            // Actual QC validation precedes even the missing-body fetch hint.
            owned
                .context()
                .verify_commit(
                    &checkpoint.descriptor().encode(),
                    checkpoint.round(),
                    checkpoint.certificate(),
                )
                .map_err(error)?;
            if !owned
                .has_candidate(checkpoint.descriptor().header().id())
                .map_err(error)?
            {
                return Ok(Reply::NeedBlock(checkpoint.descriptor().header().id()));
            }
            let _permit = gate.try_acquire().map_err(|_| busy())?;
            owned.receive_checkpoint(&checkpoint).map_err(error)?;
            Ok(Reply::Ok)
        }
    }
}
