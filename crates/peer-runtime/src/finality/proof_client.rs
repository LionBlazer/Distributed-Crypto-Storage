//! Typed Joint transport. Returned status, bytes and checkpoints are untrusted
//! observations; only the closed durable owner checks proofs, QC and ancestry.
use super::{
    joint_prefetch::{ProofBlobSelector, require_blob},
    joint_wire as joint,
    wire::*,
    *,
};
use super::{owner::Certificate, proof_application::Kind};
use peer_transport::{
    CancellableConnection, Cancellation, Connector, Endpoint, read_frame, write_frame,
};
use protocol_storage::BlobId;
use std::{io::Read, time::Instant};
use version_journal::{HEADER_BYTES, Header, MAX_BODY_BYTES};

#[derive(Clone)]
pub(super) struct Client {
    connector: Connector,
    endpoint: Endpoint,
    binding: [u8; 32],
    kind: Kind,
    cancellation: Cancellation,
}
impl Client {
    pub fn new(connector: Connector, endpoint: Endpoint, kind: Kind, binding: [u8; 32]) -> Self {
        Self {
            connector,
            endpoint,
            binding,
            kind,
            cancellation: Cancellation::default(),
        }
    }
    pub fn cancel(&self) {
        self.cancellation.cancel()
    }
    pub(super) fn with_cancellation(mut self, cancellation: Cancellation) -> Self {
        self.cancellation = cancellation;
        self
    }
    pub(super) fn expires() -> io::Result<Instant> {
        Instant::now()
            .checked_add(joint::OPERATION_BUDGET)
            .ok_or_else(invalid)
    }
    fn remaining(&self, expires: Instant) -> io::Result<Duration> {
        self.cancellation.check()?;
        expires
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "Joint operation expired"))
    }
    fn connect(&self, expires: Instant) -> io::Result<CancellableConnection> {
        // The existing connector separately bounds TCP connect (2s) and TLS
        // handshake (IO_TIMEOUT). Do not begin one after that remaining margin.
        if self.remaining(expires)? <= peer_transport::IO_TIMEOUT + Duration::from_secs(2) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Joint connect budget exhausted",
            ));
        }
        let stream = self
            .connector
            .connect_cancellable(&self.endpoint, Some(&self.cancellation))?;
        stream.set_io_timeout(self.remaining(expires)?.min(joint::IO_BUDGET))?;
        Ok(stream)
    }
    fn read(&self, stream: &mut CancellableConnection, limit: usize) -> io::Result<(u8, Vec<u8>)> {
        let mut bytes = read_frame(stream, HEADER.checked_add(limit).ok_or_else(invalid)?)?;
        let (tag, data) = self.kind.decode(self.binding, &bytes)?;
        match tag {
            BUSY if data.is_empty() => Err(busy()),
            REJECT if data.is_empty() => Err(invalid()),
            _ => {
                bytes.drain(..HEADER);
                Ok((tag, bytes))
            }
        }
    }
    fn exchange(
        &self,
        tag: u8,
        data: &[u8],
        limit: usize,
        expires: Instant,
    ) -> io::Result<(u8, Vec<u8>)> {
        let mut stream = self.connect(expires)?;
        let _deadline = stream.deadline(self.remaining(expires)?)?;
        write_frame(
            &mut stream,
            &self.kind.encode(self.binding, tag, data)?,
            MAX_CONTROL,
        )?;
        let reply = self.read(&mut stream, limit)?;
        require_end(&mut stream)?;
        self.remaining(expires)?;
        Ok(reply)
    }
    /// A remote hint only. This does not establish an agreed or fresh version.
    pub fn observed_slot(&self) -> io::Result<u64> {
        self.observed_slot_until(Self::expires()?)
    }
    pub(super) fn observed_slot_until(&self, expires: Instant) -> io::Result<u64> {
        let (tag, data) = self.exchange(STATUS, &[], 40, expires)?;
        if tag != OK || data.len() != 40 {
            return Err(invalid());
        }
        word(&data[..8])
    }
    pub fn checkpoint_after(&self, slot: u64) -> io::Result<Option<Certificate>> {
        self.checkpoint_until(slot, Self::expires()?)
    }
    pub(super) fn checkpoint_until(
        &self,
        slot: u64,
        expires: Instant,
    ) -> io::Result<Option<Certificate>> {
        let (tag, data) = self.exchange(
            GET_CHECKPOINT,
            &slot.to_le_bytes(),
            self.kind.checkpoint_cap(),
            expires,
        )?;
        match tag {
            NONE if data.is_empty() => Ok(None),
            RECORD => Certificate::decode(self.kind, &data).map(Some),
            _ => Err(invalid()),
        }
    }
    /// Submit the exact owner-signed candidate. Success is an import response,
    /// never a SQL result, lock grant, QC or independently fresh-head proof.
    pub fn submit(&self, block: &CandidateBlock) -> io::Result<()> {
        self.upload(block, SUBMIT, Self::expires()?)
    }
    /// Submit an untrusted checkpoint, including an exact last-slot retry. The
    /// remote durable owner performs actual QC/proof replay; this returns no grant.
    pub fn submit_checkpoint(&self, checkpoint: &[u8]) -> io::Result<()> {
        if self
            .send(CHECKPOINT, checkpoint, Self::expires()?)?
            .is_some()
        {
            return Err(invalid());
        }
        Ok(())
    }
    /// Bounded untrusted bytes for independent replay. The caller owns the
    /// returned Body and its memory; hashes/TLS are not application verification.
    pub fn candidate_block(&self, id: [u8; 32]) -> io::Result<CandidateBlock> {
        Ok(self
            .block(id, BodyGate::new().acquire()?, Self::expires()?)?
            .block)
    }
    pub(super) fn upload(
        &self,
        block: &CandidateBlock,
        tag: u8,
        expires: Instant,
    ) -> io::Result<()> {
        let mut stream = self.connect(expires)?;
        let _deadline = stream.deadline(self.remaining(expires)?)?;
        let mut head = block.header().encode().to_vec();
        head.extend_from_slice(&(block.body().len() as u32).to_le_bytes());
        write_frame(
            &mut stream,
            &self.kind.encode(self.binding, tag, &head)?,
            MAX_CONTROL,
        )?;
        let (ready, data) = self.read(&mut stream, 0)?;
        if ready != OK || !data.is_empty() {
            return Err(invalid());
        }
        write_frame(&mut stream, block.body(), MAX_BODY_BYTES)?;
        let (reply, data) = self.read(&mut stream, 0)?;
        require_end(&mut stream)?;
        self.remaining(expires)?;
        if reply == OK && data.is_empty() {
            Ok(())
        } else {
            Err(invalid())
        }
    }
    /// The fixed role must belong to the ACTUAL owner-signed Body/catalog.
    /// The server checks that authorization before allocating the blob payload.
    pub fn put_proof_blob(
        &self,
        block: &CandidateBlock,
        selector: ProofBlobSelector,
        id: BlobId,
        bytes: &[u8],
    ) -> io::Result<()> {
        let cap = protocol_storage::MAX_BLOB_BYTES as usize;
        require_blob(id, cap, bytes)?;
        let expires = Self::expires()?;
        let n = (8usize + 40 + HEADER_BYTES + 4)
            .checked_add(block.body().len())
            .filter(|n| *n <= MAX_CONTROL - HEADER)
            .ok_or_else(invalid)?;
        let mut data = Vec::with_capacity(n);
        data.extend_from_slice(&selector.encode());
        encode_id(id, &mut data);
        data.extend_from_slice(&block.header().encode());
        data.extend_from_slice(&(block.body().len() as u32).to_le_bytes());
        data.extend_from_slice(block.body());
        // The complete authorization Body is part of the bounded control frame,
        // never another unbounded upload, and is not a proof-verification flag.
        let frame = self.kind.encode(self.binding, joint::PUT_BLOB, &data)?;
        let mut stream = self.connect(expires)?;
        let _deadline = stream.deadline(self.remaining(expires)?)?;
        write_frame(&mut stream, &frame, MAX_CONTROL)?;
        let (ready, data) = self.read(&mut stream, 0)?;
        if ready != OK || !data.is_empty() {
            return Err(invalid());
        }
        write_frame(&mut stream, bytes, cap)?;
        let (reply, data) = self.read(&mut stream, 0)?;
        require_end(&mut stream)?;
        self.remaining(expires)?;
        if reply == OK && data.is_empty() {
            Ok(())
        } else {
            Err(invalid())
        }
    }
    pub(super) fn fetch_blob(
        &self,
        id: BlobId,
        cap: usize,
        expires: Instant,
    ) -> io::Result<Vec<u8>> {
        if cap == 0 || cap > protocol_storage::MAX_BLOB_BYTES as usize || id.bytes() > cap as u64 {
            return Err(invalid());
        }
        let mut data = Vec::with_capacity(44);
        encode_id(id, &mut data);
        data.extend_from_slice(&(cap as u32).to_le_bytes());
        let mut stream = self.connect(expires)?;
        let _deadline = stream.deadline(self.remaining(expires)?)?;
        write_frame(
            &mut stream,
            &self.kind.encode(self.binding, joint::GET_BLOB, &data)?,
            MAX_CONTROL,
        )?;
        let (tag, data) = self.read(&mut stream, 40)?;
        if tag != joint::BLOB || decode_id(&data)? != id {
            return Err(invalid());
        }
        let bytes = read_frame(&mut stream, cap)?;
        require_end(&mut stream)?;
        self.remaining(expires)?;
        require_blob(id, cap, &bytes)?;
        Ok(bytes)
    }
    pub(super) fn block(
        &self,
        id: [u8; 32],
        lease: BodyLease,
        expires: Instant,
    ) -> io::Result<OwnedBlock> {
        let mut stream = self.connect(expires)?;
        let _deadline = stream.deadline(self.remaining(expires)?)?;
        write_frame(
            &mut stream,
            &self.kind.encode(self.binding, GET_BLOCK, &id)?,
            MAX_CONTROL,
        )?;
        let (tag, data) = self.read(&mut stream, HEADER_BYTES + 4)?;
        if tag != BLOCK || data.len() != HEADER_BYTES + 4 {
            return Err(invalid());
        }
        let header = Header::decode(&data[..HEADER_BYTES]).map_err(error)?;
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
        self.remaining(expires)?;
        Ok(OwnedBlock {
            block: CandidateBlock::new(header, body).map_err(error)?,
            _lease: lease,
        })
    }
    pub(super) fn send(
        &self,
        tag: u8,
        data: &[u8],
        expires: Instant,
    ) -> io::Result<Option<[u8; 32]>> {
        let (tag, data) = self.exchange(tag, data, 32, expires)?;
        match tag {
            OK if data.is_empty() => Ok(None),
            NEED_BLOCK => hash(&data).map(Some),
            _ => Err(invalid()),
        }
    }
}
pub(super) fn encode_id(id: BlobId, out: &mut Vec<u8>) {
    out.extend_from_slice(id.sha256());
    out.extend_from_slice(&id.bytes().to_le_bytes())
}
pub(super) fn decode_id(bytes: &[u8]) -> io::Result<BlobId> {
    if bytes.len() != 40 {
        return Err(invalid());
    }
    BlobId::new(
        bytes[..32].try_into().map_err(|_| invalid())?,
        word(&bytes[32..])?,
    )
    .map_err(error)
}
fn require_end(stream: &mut impl Read) -> io::Result<()> {
    if stream.read(&mut [0; 1])? != 0 {
        return Err(invalid());
    }
    Ok(())
}
