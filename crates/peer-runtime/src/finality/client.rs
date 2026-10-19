//! Source-only protocol implementation: no connection is opened at construction
//! or module initialization. Callers supply their own pinned TLS endpoint.
//! Status is untrusted observation; only the closed follower verifies an actual
//! application Body and quorum. These methods return no SQL or freshness grant.
use super::{
    actor::{Command, Handle, Reply},
    wire::*,
    *,
};
use peer_transport::{
    CancellableConnection, Cancellation, Connector, Endpoint, read_frame, write_frame,
};
use registry200_finality::{Binding, Checkpoint, Follower, VerifiedCheckpoint};
use std::io::Read;
use version_journal::{HEADER_BYTES, Header as BlockHeader, MAX_BODY_BYTES};

#[derive(Clone)]
pub struct FinalityClient {
    connector: Connector,
    endpoint: Endpoint,
    binding: [u8; 32],
    cancellation: Cancellation,
}

impl FinalityClient {
    pub fn new(connector: Connector, endpoint: Endpoint, binding: &Binding) -> Self {
        Self {
            connector,
            endpoint,
            binding: binding.id(),
            cancellation: Cancellation::default(),
        }
    }

    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    pub(super) fn with_cancellation(mut self, cancellation: Cancellation) -> Self {
        self.cancellation = cancellation;
        self
    }

    fn connect(&self) -> io::Result<CancellableConnection> {
        let stream = self
            .connector
            .connect_cancellable(&self.endpoint, Some(&self.cancellation))?;
        stream.set_io_timeout(RPC_BUDGET)?;
        Ok(stream)
    }

    fn exchange(&self, tag: u8, data: &[u8]) -> io::Result<(u8, Vec<u8>)> {
        let mut stream = self.connect()?;
        let _deadline = stream.deadline(RPC_BUDGET)?;
        write_frame(&mut stream, &encode(self.binding, tag, data)?, MAX_CONTROL)?;
        let response = match tag {
            STATUS => 40,
            GET_CHECKPOINT => registry200_finality::MAX_CHECKPOINT_BYTES,
            _ => 32,
        };
        let reply = self.read(&mut stream, response)?;
        require_end(&mut stream)?;
        Ok(reply)
    }

    fn read(
        &self,
        stream: &mut CancellableConnection,
        payload_limit: usize,
    ) -> io::Result<(u8, Vec<u8>)> {
        let mut bytes = read_frame(stream, HEADER + payload_limit)?;
        let (tag, data) = decode(self.binding, &bytes)?;
        match tag {
            BUSY if data.is_empty() => Err(busy()),
            REJECT if data.is_empty() => Err(invalid()),
            _ => {
                bytes.drain(..HEADER);
                Ok((tag, bytes))
            }
        }
    }

    /// A remote hint only. This cannot establish a fresh or finalized version.
    pub fn observed_slot(&self) -> io::Result<u64> {
        let (tag, data) = self.exchange(STATUS, &[])?;
        if tag != OK || data.len() != 40 {
            return Err(invalid());
        }
        word(&data[..8])
    }

    pub fn checkpoint_after(&self, slot: u64) -> io::Result<Option<Checkpoint>> {
        let (tag, data) = self.exchange(GET_CHECKPOINT, &slot.to_le_bytes())?;
        match tag {
            NONE if data.is_empty() => Ok(None),
            RECORD => Checkpoint::decode(&data).map(Some).map_err(error),
            _ => Err(invalid()),
        }
    }

    pub fn submit(&self, block: &CandidateBlock) -> io::Result<()> {
        self.upload(block, SUBMIT)
    }

    fn upload(&self, block: &CandidateBlock, tag: u8) -> io::Result<()> {
        let mut stream = self.connect()?;
        let _deadline = stream.deadline(RPC_BUDGET)?;
        let mut head = block.header().encode().to_vec();
        head.extend_from_slice(&(block.body().len() as u32).to_le_bytes());
        write_frame(&mut stream, &encode(self.binding, tag, &head)?, MAX_CONTROL)?;
        let (ready, data) = self.read(&mut stream, 0)?;
        if ready != OK || !data.is_empty() {
            return Err(invalid());
        }
        write_frame(&mut stream, block.body(), MAX_BODY_BYTES)?;
        let (reply, data) = self.read(&mut stream, 0)?;
        require_end(&mut stream)?;
        if reply == OK && data.is_empty() {
            Ok(())
        } else {
            Err(invalid())
        }
    }

    fn block(&self, id: [u8; 32], lease: BodyLease) -> io::Result<OwnedBlock> {
        let mut stream = self.connect()?;
        let _deadline = stream.deadline(RPC_BUDGET)?;
        write_frame(
            &mut stream,
            &encode(self.binding, GET_BLOCK, &id)?,
            MAX_CONTROL,
        )?;
        let (tag, data) = self.read(&mut stream, HEADER_BYTES + 4)?;
        if tag != BLOCK || data.len() != HEADER_BYTES + 4 {
            return Err(invalid());
        }
        let header = BlockHeader::decode(&data[..HEADER_BYTES]).map_err(error)?;
        let n =
            u32::from_le_bytes(data[HEADER_BYTES..].try_into().map_err(|_| invalid())?) as usize;
        if n == 0 || n > MAX_BODY_BYTES || header.id() != id {
            return Err(invalid());
        }
        let body = read_frame(&mut stream, n)?;
        if body.len() != n {
            return Err(invalid());
        }
        require_end(&mut stream)?;
        Ok(OwnedBlock {
            block: CandidateBlock::new(header, body).map_err(error)?,
            _lease: lease,
        })
    }

    pub fn follow_next(
        &self,
        follower: &mut Follower,
        gate: &crate::ProofGate,
    ) -> io::Result<Option<VerifiedCheckpoint>> {
        // The actual shared process gate precedes network buffers as well as
        // native verification. Actor exports need no such permit or state lock
        // across RPC, so this does not introduce a gate dependency cycle.
        let _permit = gate.try_acquire().map_err(|_| busy())?;
        if follower.context().slot() == 0 {
            return Err(invalid());
        }
        let Some(checkpoint) = self.checkpoint_after(follower.context().slot() - 1)? else {
            return Ok(None);
        };
        let body_gate = BodyGate::new();
        let block = self.block(checkpoint.descriptor().header().id(), body_gate.acquire()?)?;
        follower
            .apply(&checkpoint, &block.block)
            .map(Some)
            .map_err(error)
    }

    fn send(&self, tag: u8, data: &[u8]) -> io::Result<Option<[u8; 32]>> {
        let (tag, data) = self.exchange(tag, data)?;
        match tag {
            OK if data.is_empty() => Ok(None),
            NEED_BLOCK => hash(&data).map(Some),
            _ => Err(invalid()),
        }
    }
}

fn require_end(stream: &mut impl Read) -> io::Result<()> {
    if stream.read(&mut [0; 1])? != 0 {
        return Err(invalid());
    }
    Ok(())
}

/// Transfer one original bounded checkpoint at a time. No actor/shared-state
/// mutex remains held across an RPC, and no caller-supplied successor is used.
pub(super) fn synchronize(
    client: &FinalityClient,
    handle: &Handle,
    bodies: &BodyGate,
) -> io::Result<()> {
    // This one process-owned reservation spans all bounded remote control
    // reads and retained public QC/input metadata in this sequential pass.
    // The Body has its distinct single-owner lease; it is never copied here.
    let _control = handle.reserve_control()?;
    let local = match handle.call(Command::Status)? {
        Reply::Status { slot, .. } => slot,
        _ => return Err(invalid()),
    };
    let remote = client.observed_slot()?;
    if remote == 0 {
        return Err(invalid());
    }
    if remote > local {
        let checkpoint = client.checkpoint_after(local - 1)?.ok_or_else(invalid)?;
        if checkpoint.descriptor().slot() != local {
            return Err(invalid());
        }
        let block = client.block(checkpoint.descriptor().header().id(), bodies.acquire()?)?;
        handle.call(Command::Block(block, false))?;
        match handle.call(Command::Checkpoint(checkpoint))? {
            Reply::Ok => (),
            _ => return Err(invalid()),
        }
        return Ok(());
    }
    if remote < local {
        // Only the lagging relay fetches a checkpoint. A simultaneous push
        // would hold our single Body lease while the remote pull holds theirs:
        // both servers could reply Busy forever on the same retry cadence.
        // Every active peer therefore needs a reachable up-to-date neighbor.
        return Ok(());
    }
    for index in 0..MAX_COMMANDS {
        let bytes = match handle.call(Command::Outbound(index))? {
            Reply::Outbound(Some(bytes)) => bytes,
            Reply::Outbound(None) => break,
            _ => return Err(invalid()),
        };
        let missing = match client.send(INPUT, &bytes) {
            Ok(missing) => missing,
            // A receiver may already be in a later round of this SAME slot.
            // Its rejection of an older proposal must not suppress subsequent
            // genuine future-round votes that drive the normal jump rule.
            Err(e) if e.kind() == io::ErrorKind::InvalidData => continue,
            Err(e) => return Err(e),
        };
        if let Some(id) = missing {
            let block = match handle.call(Command::GetBlock(id, bodies.acquire()?))? {
                Reply::Block(block) => block,
                _ => return Err(invalid()),
            };
            client.upload(&block.block, PUT_BLOCK)?;
            client.send(INPUT, &bytes)?;
        }
    }
    Ok(())
}
