use crate::{
    AuthorizedTransition, Body, Error, Genesis, HEAD_BYTES, HEADER_BYTES, HeadPair, Header,
    MAX_BODY_BYTES, ProtocolProfile, Result, ShardState, ShardUpdate, Target,
};

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    pub(crate) fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(Error::InvalidEncoding)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(Error::InvalidEncoding)?;
        self.position = end;
        Ok(value)
    }
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error::InvalidEncoding)
    }
    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    pub(crate) fn finish(self) -> Result<()> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::InvalidEncoding)
        }
    }
}

impl ProtocolProfile {
    fn write(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.initial_target.0);
        bytes.extend_from_slice(&self.pow_limit.0);
        bytes.extend_from_slice(&self.block_spacing_secs.to_le_bytes());
        bytes.extend_from_slice(&self.retarget_interval.to_le_bytes());
        bytes.extend_from_slice(&self.max_future_secs.to_le_bytes());
        for value in [
            self.confirmation_depth,
            self.max_headers,
            self.max_shards,
            self.max_updates,
            self.max_body_bytes,
            self.max_request_bytes,
            self.max_proof_bytes,
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(&self.max_journal_bytes.to_le_bytes());
    }
    fn read(reader: &mut Reader<'_>) -> Result<Self> {
        let value = Self {
            initial_target: Target(reader.array()?),
            pow_limit: Target(reader.array()?),
            block_spacing_secs: reader.u64()?,
            retarget_interval: reader.u32()?,
            max_future_secs: reader.u64()?,
            confirmation_depth: reader.u32()?,
            max_headers: reader.u32()?,
            max_shards: reader.u32()?,
            max_updates: reader.u32()?,
            max_body_bytes: reader.u32()?,
            max_request_bytes: reader.u32()?,
            max_proof_bytes: reader.u32()?,
            max_journal_bytes: reader.u64()?,
        };
        value.validate()?;
        Ok(value)
    }
}

impl Genesis {
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(256 + self.initial_shards.len() * (8 + HEAD_BYTES * 2));
        bytes.extend_from_slice(b"DCSJG001");
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.database);
        bytes.extend_from_slice(&self.owner);
        bytes.extend_from_slice(&self.application_commitment);
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        self.profile.write(&mut bytes);
        bytes.extend_from_slice(&(self.initial_shards.len() as u32).to_le_bytes());
        for shard in &self.initial_shards {
            bytes.extend_from_slice(&shard.id.to_le_bytes());
            write_heads(&mut bytes, shard.heads);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 2 * 1024 * 1024 {
            return Err(Error::ResourceLimit);
        }
        let mut reader = Reader::new(bytes);
        if reader.take(8)? != b"DCSJG001" {
            return Err(Error::InvalidEncoding);
        }
        let network_id = reader.array()?;
        let database = reader.array()?;
        let owner = reader.array()?;
        let application_commitment = reader.array()?;
        let timestamp = reader.u64()?;
        let profile = ProtocolProfile::read(&mut reader)?;
        let count = reader.u32()? as usize;
        if count == 0 || count > profile.max_shards as usize {
            return Err(Error::ResourceLimit);
        }
        if bytes.len() < count * (8 + HEAD_BYTES * 2) {
            return Err(Error::InvalidEncoding);
        }
        let mut initial_shards = Vec::with_capacity(count);
        for _ in 0..count {
            initial_shards.push(ShardState {
                id: reader.u64()?,
                heads: read_heads(&mut reader)?,
            });
        }
        reader.finish()?;
        let value = Self {
            network_id,
            database,
            owner,
            application_commitment,
            timestamp,
            profile,
            initial_shards,
        };
        value.validate()?;
        Ok(value)
    }
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER_BYTES] {
        let mut bytes = [0; HEADER_BYTES];
        bytes[..8].copy_from_slice(b"DCSJH001");
        bytes[8..40].copy_from_slice(&self.genesis);
        bytes[40..72].copy_from_slice(&self.parent);
        bytes[72..80].copy_from_slice(&self.height.to_le_bytes());
        bytes[80..88].copy_from_slice(&self.timestamp.to_le_bytes());
        bytes[88..120].copy_from_slice(&self.target.0);
        bytes[120..152].copy_from_slice(&self.body_hash);
        bytes[152..184].copy_from_slice(&self.state_root);
        bytes[184..192].copy_from_slice(&self.nonce.to_le_bytes());
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HEADER_BYTES {
            return Err(Error::InvalidEncoding);
        }
        let mut reader = Reader::new(bytes);
        if reader.take(8)? != b"DCSJH001" {
            return Err(Error::InvalidEncoding);
        }
        let value = Self {
            genesis: reader.array()?,
            parent: reader.array()?,
            height: reader.u64()?,
            timestamp: reader.u64()?,
            target: Target(reader.array()?),
            body_hash: reader.array()?,
            state_root: reader.array()?,
            nonce: reader.u64()?,
        };
        reader.finish()?;
        Ok(value)
    }
}

impl Body {
    pub fn encode(&self, profile: &ProtocolProfile) -> Result<Vec<u8>> {
        profile.validate()?;
        let mut bytes = b"DCSJB001".to_vec();
        match self {
            Self::Empty => bytes.push(0),
            Self::Transition(transition) => {
                check_transition(transition, profile)?;
                let expected = 9usize
                    .checked_add(32 + 4 + transition.request.len() + 4)
                    .and_then(|v| v.checked_add(transition.updates.len() * 456))
                    .and_then(|v| v.checked_add(4 + transition.proof.len() + 64))
                    .ok_or(Error::ResourceLimit)?;
                if expected > profile.max_body_bytes as usize {
                    return Err(Error::ResourceLimit);
                }
                bytes.reserve(expected - bytes.len());
                bytes.push(1);
                bytes.extend_from_slice(&transition.parent);
                bytes.extend_from_slice(&(transition.request.len() as u32).to_le_bytes());
                bytes.extend_from_slice(&transition.request);
                bytes.extend_from_slice(&(transition.updates.len() as u32).to_le_bytes());
                for update in &transition.updates {
                    bytes.extend_from_slice(&update.id.to_le_bytes());
                    write_heads(&mut bytes, update.old);
                    write_heads(&mut bytes, update.new);
                }
                bytes.extend_from_slice(&(transition.proof.len() as u32).to_le_bytes());
                bytes.extend_from_slice(&transition.proof);
                bytes.extend_from_slice(&transition.owner_signature);
            }
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8], profile: &ProtocolProfile) -> Result<Self> {
        profile.validate()?;
        if bytes.len() > profile.max_body_bytes as usize || bytes.len() > MAX_BODY_BYTES {
            return Err(Error::ResourceLimit);
        }
        let mut reader = Reader::new(bytes);
        if reader.take(8)? != b"DCSJB001" {
            return Err(Error::InvalidEncoding);
        }
        let body = match reader.array::<1>()?[0] {
            0 => Self::Empty,
            1 => {
                let parent = reader.array()?;
                let request_len = reader.u32()? as usize;
                if request_len == 0 || request_len > profile.max_request_bytes as usize {
                    return Err(Error::ResourceLimit);
                }
                let request = reader.take(request_len)?.to_vec();
                let count = reader.u32()? as usize;
                if count == 0 || count > profile.max_updates as usize {
                    return Err(Error::ResourceLimit);
                }
                // Check the complete fixed-width update region before allocating.
                if bytes.len() < count * 456 {
                    return Err(Error::InvalidEncoding);
                }
                let mut updates = Vec::with_capacity(count);
                for _ in 0..count {
                    updates.push(ShardUpdate {
                        id: reader.u64()?,
                        old: read_heads(&mut reader)?,
                        new: read_heads(&mut reader)?,
                    });
                }
                let proof_len = reader.u32()? as usize;
                if proof_len == 0 || proof_len > profile.max_proof_bytes as usize {
                    return Err(Error::MissingComputationProof);
                }
                let proof = reader.take(proof_len)?.to_vec();
                Self::Transition(AuthorizedTransition {
                    parent,
                    request,
                    updates,
                    proof,
                    owner_signature: reader.array()?,
                })
            }
            _ => return Err(Error::InvalidEncoding),
        };
        reader.finish()?;
        if let Self::Transition(transition) = &body {
            check_transition(transition, profile)?;
        }
        Ok(body)
    }
}

fn check_transition(transition: &AuthorizedTransition, profile: &ProtocolProfile) -> Result<()> {
    if transition.request.is_empty()
        || transition.request.len() > profile.max_request_bytes as usize
        || transition.updates.is_empty()
        || transition.updates.len() > profile.max_updates as usize
    {
        return Err(Error::ResourceLimit);
    }
    if transition.proof.is_empty() {
        return Err(Error::MissingComputationProof);
    }
    if transition.proof.len() > profile.max_proof_bytes as usize {
        return Err(Error::ResourceLimit);
    }
    if transition.updates.windows(2).any(|w| w[0].id >= w[1].id) {
        return Err(Error::InvalidTransition);
    }
    Ok(())
}

fn write_heads(bytes: &mut Vec<u8>, heads: HeadPair) {
    bytes.extend_from_slice(&heads.data);
    bytes.extend_from_slice(&heads.index);
}
fn read_heads(reader: &mut Reader<'_>) -> Result<HeadPair> {
    Ok(HeadPair {
        data: reader.array()?,
        index: reader.array()?,
    })
}
