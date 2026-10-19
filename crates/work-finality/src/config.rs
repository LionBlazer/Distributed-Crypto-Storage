use crate::{
    Election, EpochSet, Error, GENESIS_HEADER_BYTES, Hash, MAX_GENESIS_BYTES, MAX_TICKETS,
    MAX_VALIDATORS, Result, SEED_BYTES, TICKET_BYTES, WorkTicket, election, hash, profile_digest,
    wire::{self, Reader},
};

const SEED_MAGIC: &[u8; 8] = b"DCSWFS01";
const GENESIS_MAGIC: &[u8; 8] = b"DCSWFG01";

/// Explicit lowerable resource limits; there is no production default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub(crate) tickets: u32,
    pub(crate) validators: u32,
}
impl Limits {
    pub fn new(max_tickets: u32, max_validators: u32) -> Result<Self> {
        if max_tickets == 0
            || max_tickets as usize > MAX_TICKETS
            || max_validators == 0
            || max_validators as usize > MAX_VALIDATORS
            || max_validators > max_tickets
        {
            return Err(Error::InvalidConfig);
        }
        Ok(Self {
            tickets: max_tickets,
            validators: max_validators,
        })
    }
    pub fn max_tickets(self) -> usize {
        self.tickets as usize
    }
    pub fn max_validators(self) -> usize {
        self.validators as usize
    }
}

/// Pre-work immutable configuration. It excludes tickets, roster and Genesis id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkSeed {
    domain: Hash,
    bootstrap_challenge: Hash,
    target: Hash,
    limits: Limits,
}
impl NetworkSeed {
    /// `target` is a full unsigned big-endian SHA256d target, explicit even in tests.
    pub fn new(
        domain: Hash,
        bootstrap_challenge: Hash,
        target: Hash,
        limits: Limits,
    ) -> Result<Self> {
        if target == [0; 32] {
            return Err(Error::InvalidConfig);
        }
        Ok(Self {
            domain,
            bootstrap_challenge,
            target,
            limits,
        })
    }
    pub fn domain(&self) -> Hash {
        self.domain
    }
    pub fn target(&self) -> Hash {
        self.target
    }
    pub fn limits(&self) -> Limits {
        self.limits
    }
    pub fn bootstrap_challenge(&self) -> Hash {
        self.bootstrap_challenge
    }
    pub fn id(&self) -> Hash {
        hash(b"dcs/work-finality/seed/v1", &[&self.encode()])
    }
    pub fn bootstrap_election(&self) -> Election {
        Election::bootstrap(self)
    }
    pub fn encode(&self) -> [u8; SEED_BYTES] {
        let mut bytes = [0; SEED_BYTES];
        bytes[..8].copy_from_slice(SEED_MAGIC);
        bytes[8..40].copy_from_slice(&profile_digest());
        bytes[40..72].copy_from_slice(&self.domain);
        bytes[72..104].copy_from_slice(&self.bootstrap_challenge);
        bytes[104..136].copy_from_slice(&self.target);
        bytes[136..140].copy_from_slice(&self.limits.tickets.to_le_bytes());
        bytes[140..144].copy_from_slice(&self.limits.validators.to_le_bytes());
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SEED_BYTES {
            return Err(Error::InvalidEncoding);
        }
        let mut reader = Reader::new(bytes);
        reader.header(SEED_MAGIC)?;
        let domain = reader.array()?;
        let challenge = reader.array()?;
        let target = reader.array()?;
        let limits = Limits::new(reader.u32()?, reader.u32()?)?;
        reader.end()?;
        let seed = Self::new(domain, challenge, target, limits)?;
        if seed.encode() != bytes {
            return Err(Error::InvalidEncoding);
        }
        Ok(seed)
    }
}

/// Independently pinnable bootstrap configuration with actual checked work.
/// The initial roster is derived, never nominated by a responding peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Genesis {
    seed: NetworkSeed,
    tickets: Vec<WorkTicket>,
    id: Hash,
    initial: EpochSet,
}
impl Genesis {
    /// Tickets are sorted by PoW identity. Signature bytes never identify work.
    /// Checking work does not prove an honest initial weight distribution.
    pub fn from_bootstrap(seed: NetworkSeed, tickets: Vec<WorkTicket>) -> Result<Self> {
        let election = seed.bootstrap_election();
        let tickets = election::canonical_tickets(&election, tickets)?;
        let bytes = Self::encode_parts(&seed, &tickets)?;
        let id = hash(b"dcs/work-finality/genesis/v1", &[&bytes]);
        let initial = election::derive_set(&election, id, &tickets)?;
        Ok(Self {
            seed,
            tickets,
            id,
            initial,
        })
    }
    pub fn id(&self) -> Hash {
        self.id
    }
    pub fn seed(&self) -> &NetworkSeed {
        &self.seed
    }
    pub fn initial_set(&self) -> &EpochSet {
        &self.initial
    }
    pub fn bootstrap_tickets(&self) -> &[WorkTicket] {
        &self.tickets
    }

    /// This creates a work context only. The caller must separately establish
    /// challenge finality, the election window and old-to-new quorum handoff.
    pub fn election(&self, epoch: u64, challenge: Hash) -> Result<Election> {
        if epoch == 0 {
            return Err(Error::InvalidConfig);
        }
        Ok(Election::successor(&self.seed, self.id, epoch, challenge))
    }
    /// Derived weights are mathematical evidence, not an activated configuration.
    pub fn derive_epoch_set(
        &self,
        epoch: u64,
        challenge: Hash,
        tickets: Vec<WorkTicket>,
    ) -> Result<EpochSet> {
        let election = self.election(epoch, challenge)?;
        let tickets = election::canonical_tickets(&election, tickets)?;
        election::derive_set(&election, self.id, &tickets)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        Self::encode_parts(&self.seed, &self.tickets)
    }
    fn encode_parts(seed: &NetworkSeed, tickets: &[WorkTicket]) -> Result<Vec<u8>> {
        let size = wire::length(
            GENESIS_HEADER_BYTES,
            tickets.len(),
            TICKET_BYTES,
            MAX_GENESIS_BYTES,
        )?;
        let count = u32::try_from(tickets.len()).map_err(|_| Error::ResourceLimit)?;
        let mut bytes = Vec::with_capacity(size);
        bytes.extend_from_slice(GENESIS_MAGIC);
        bytes.extend_from_slice(&profile_digest());
        bytes.extend_from_slice(&seed.encode());
        bytes.extend_from_slice(&count.to_le_bytes());
        for ticket in tickets {
            bytes.extend_from_slice(&ticket.encode());
        }
        Ok(bytes)
    }
    /// The expected id must come from outside the responding peer's packet.
    pub fn decode(bytes: &[u8], independently_pinned_id: Hash) -> Result<Self> {
        if bytes.len() > MAX_GENESIS_BYTES {
            return Err(Error::ResourceLimit);
        }
        let mut reader = Reader::new(bytes);
        reader.header(GENESIS_MAGIC)?;
        let seed = NetworkSeed::decode(&reader.array::<SEED_BYTES>()?)?;
        let count = reader.u32()? as usize;
        if count == 0 || count > seed.limits.max_tickets() || count > MAX_TICKETS {
            return Err(Error::ResourceLimit);
        }
        let size = wire::length(GENESIS_HEADER_BYTES, count, TICKET_BYTES, MAX_GENESIS_BYTES)?;
        if size != bytes.len() {
            return Err(Error::InvalidEncoding);
        }
        if hash(b"dcs/work-finality/genesis/v1", &[bytes]) != independently_pinned_id {
            return Err(Error::WrongDomain);
        }
        // All remote sizes and the independent identity are checked before allocation.
        let mut tickets = Vec::with_capacity(count);
        for _ in 0..count {
            tickets.push(WorkTicket::parse(&reader.array::<TICKET_BYTES>()?)?);
        }
        reader.end()?;
        let genesis = Self::from_bootstrap(seed, tickets)?;
        if genesis.id != independently_pinned_id || genesis.encode()? != bytes {
            return Err(Error::InvalidEncoding);
        }
        Ok(genesis)
    }
}
