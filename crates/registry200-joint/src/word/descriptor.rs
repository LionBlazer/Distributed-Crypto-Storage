//! Complete independent immutable source installation, without an owner key or verdict.
use super::{Control, Error, Hash, Result, contract_digest};
use registry200_proof::source::{self, version::SourceVersionExpected};
use sha2::{Digest, Sha256};
use version_journal::{Genesis, HeadPair, ShardState};
pub const MAX_DESCRIPTOR_BYTES: usize = 16 * 1024;
const HEADER: usize = 376;
#[derive(Clone)]
pub struct Descriptor {
    network: Hash,
    source_id: u64,
    control_id: u64,
    source: SourceVersionExpected,
}
impl Descriptor {
    pub fn checked(
        network: Hash,
        source_id: u64,
        control_id: u64,
        source: &SourceVersionExpected,
    ) -> Result<Self> {
        source
            .statement()
            .reaudit()
            .map_err(|_| Error::WrongDomain)?;
        if source_id == control_id {
            return Err(Error::WrongDomain);
        }
        let d = Self {
            network,
            source_id,
            control_id,
            source: source.clone(),
        };
        if d.encode().len() > MAX_DESCRIPTOR_BYTES {
            return Err(Error::ResourceLimit);
        }
        Ok(d)
    }
    pub fn source(&self) -> &SourceVersionExpected {
        &self.source
    }
    pub fn network(&self) -> Hash {
        self.network
    }
    pub fn database(&self) -> [u8; 16] {
        self.source.statement().heads[0][8..24].try_into().unwrap()
    }
    pub fn control_id(&self) -> u64 {
        self.control_id
    }
    pub fn id(&self) -> Hash {
        let mut h = Sha256::new();
        h.update(b"DCS/WORD-JOURNAL/application/v1");
        h.update(self.encode());
        h.finalize().into()
    }
    pub fn encode(&self) -> Vec<u8> {
        let s = self.source.statement();
        let mut out =
            Vec::with_capacity(HEADER + 8 + s.packets.iter().map(Vec::len).sum::<usize>());
        out.extend(b"DCSWAD01");
        out.extend(contract_digest());
        out.extend(self.network);
        out.extend(self.source_id.to_le_bytes());
        out.extend(self.control_id.to_le_bytes());
        out.extend(source::statement::encode_digest(s.key_commitment));
        out.extend(self.source.state_commitment());
        for head in s.heads {
            out.extend(head);
        }
        for packet in &s.packets {
            out.extend((packet.len() as u32).to_le_bytes());
            out.extend(packet);
        }
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_DESCRIPTOR_BYTES {
            return Err(Error::ResourceLimit);
        }
        if bytes.len() < HEADER + 8
            || &bytes[..8] != b"DCSWAD01"
            || bytes[8..40] != contract_digest()
        {
            return Err(Error::InvalidEncoding);
        }
        let raw_heads: [[u8; 112]; 2] = [
            bytes[152..264].try_into().unwrap(),
            bytes[264..376].try_into().unwrap(),
        ];
        let mut at = HEADER;
        let mut images: [Vec<u8>; 2] = core::array::from_fn(|i| raw_heads[i].to_vec());
        for image in &mut images {
            let n = bytes.get(at..at + 4).ok_or(Error::InvalidEncoding)?;
            let n = u32::from_le_bytes(n.try_into().unwrap()) as usize;
            at += 4;
            let end = at.checked_add(n).ok_or(Error::ResourceLimit)?;
            image.extend_from_slice(bytes.get(at..end).ok_or(Error::InvalidEncoding)?);
            at = end;
        }
        if at != bytes.len() {
            return Err(Error::InvalidEncoding);
        }
        let heads: [_; 2] = core::array::from_fn(|i| {
            compact_store::Commitment::decode(&raw_heads[i], source::statement::limits())
        });
        let [a, b] = heads;
        let (a, b) = (
            a.map_err(|_| Error::InvalidEncoding)?,
            b.map_err(|_| Error::InvalidEncoding)?,
        );
        let source = SourceVersionExpected::checked(
            [&images[0], &images[1]],
            [&a, &b],
            bytes[88..120].try_into().unwrap(),
            bytes[120..152].try_into().unwrap(),
        )
        .map_err(|_| Error::WrongDomain)?;
        let d = Self::checked(
            bytes[40..72].try_into().unwrap(),
            u64::from_le_bytes(bytes[72..80].try_into().unwrap()),
            u64::from_le_bytes(bytes[80..88].try_into().unwrap()),
            &source,
        )?;
        if d.encode() != bytes {
            return Err(Error::InvalidEncoding);
        }
        Ok(d)
    }
    pub fn initial_shards(&self) -> Vec<ShardState> {
        let [data, index] = self.source.statement().heads;
        let mut s = vec![
            ShardState {
                id: self.source_id,
                heads: HeadPair { data, index },
            },
            ShardState {
                id: self.control_id,
                heads: Control::Pending.heads(self),
            },
        ];
        s.sort_unstable_by_key(|s| s.id);
        s
    }
    pub(super) fn control(&self, shards: &[ShardState]) -> Result<Control> {
        if shards.len() != 2 || shards[0].id >= shards[1].id {
            return Err(Error::InvalidTransition);
        }
        let original = self.initial_shards();
        let source = shards
            .iter()
            .find(|s| s.id == self.source_id)
            .ok_or(Error::InvalidTransition)?;
        if source != original.iter().find(|s| s.id == self.source_id).unwrap() {
            return Err(Error::WrongDomain);
        }
        let control = shards
            .iter()
            .find(|s| s.id == self.control_id)
            .ok_or(Error::InvalidTransition)?;
        Control::decode(self, control.heads)
    }
}
pub struct Application {
    descriptor: Descriptor,
    genesis: Hash,
}
impl Application {
    pub fn new(descriptor: Descriptor, genesis: &Genesis) -> Result<Self> {
        genesis.validate()?;
        if genesis.network_id != descriptor.network
            || genesis.database != descriptor.database()
            || genesis.application_commitment != descriptor.id()
            || genesis.initial_shards != descriptor.initial_shards()
        {
            return Err(Error::WrongDomain);
        }
        Ok(Self {
            descriptor,
            genesis: genesis.id()?,
        })
    }
    pub fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }
    pub fn id(&self) -> Hash {
        self.descriptor.id()
    }
    pub fn genesis(&self) -> Hash {
        self.genesis
    }
}
