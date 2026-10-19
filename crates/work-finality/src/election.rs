use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey};
use sha2::{Digest, Sha256};

use crate::{
    Error, Hash, Limits, NetworkSeed, Result, TICKET_BYTES, hash, profile_digest,
    wire::{self, Reader},
};

const TICKET_MAGIC: &[u8; 8] = b"DCSWFT01";

/// A fixed-target work context. A successor challenge is not a finality receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Election {
    kind: u8,
    scope: Hash,
    epoch: u64,
    challenge: Hash,
    target: Hash,
    limits: Limits,
}
impl Election {
    pub(crate) fn bootstrap(seed: &NetworkSeed) -> Self {
        Self {
            kind: 0,
            scope: seed.id(),
            epoch: 0,
            challenge: seed.bootstrap_challenge(),
            target: seed.target(),
            limits: seed.limits(),
        }
    }
    pub(crate) fn successor(
        seed: &NetworkSeed,
        network: Hash,
        epoch: u64,
        challenge: Hash,
    ) -> Self {
        Self {
            kind: 1,
            scope: network,
            epoch,
            challenge,
            target: seed.target(),
            limits: seed.limits(),
        }
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn scope_id(&self) -> Hash {
        self.scope
    }
    pub fn challenge(&self) -> Hash {
        self.challenge
    }
    pub fn target(&self) -> Hash {
        self.target
    }
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// SHA256d includes the exact election, target, public key and nonce.
    /// Each accepted unique solution has one fixed-difficulty work unit.
    pub fn work_hash(&self, public_key: Hash, nonce: u64) -> Hash {
        let first = hash(
            b"dcs/work-finality/ticket-pow/v1",
            &[
                &[self.kind],
                &self.scope,
                &self.epoch.to_le_bytes(),
                &self.challenge,
                &self.target,
                &public_key,
                &nonce.to_le_bytes(),
            ],
        );
        Sha256::digest(first).into()
    }
    pub fn permits(&self, public_key: Hash, nonce: u64) -> bool {
        self.work_hash(public_key, nonce) <= self.target
    }
}

/// Public PoW solution and strict possession signature. It owns no secret key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkTicket {
    kind: u8,
    scope: Hash,
    epoch: u64,
    challenge: Hash,
    public_key: Hash,
    nonce: u64,
    signature: [u8; 64],
}
impl WorkTicket {
    /// Signs only a nonce which satisfies the independently selected target.
    pub fn sign(election: &Election, key: &SigningKey, nonce: u64) -> Result<Self> {
        let public_key = key.verifying_key().to_bytes();
        wire::key(public_key)?;
        if !election.permits(public_key, nonce) {
            return Err(Error::InvalidWork);
        }
        let id = election.work_hash(public_key, nonce);
        let signature = key.sign(&possession_message(id)).to_bytes();
        Ok(Self {
            kind: election.kind,
            scope: election.scope,
            epoch: election.epoch,
            challenge: election.challenge,
            public_key,
            nonce,
            signature,
        })
    }
    /// Bounded local mining helper. It does not choose a production target or
    /// schedule network work. Exhaustion never wraps the nonce or loops forever.
    pub fn mine(
        election: &Election,
        key: &SigningKey,
        start_nonce: u64,
        max_attempts: u64,
    ) -> Result<Self> {
        let public_key = key.verifying_key().to_bytes();
        wire::key(public_key)?;
        let mut nonce = start_nonce;
        for attempt in 0..max_attempts {
            if election.permits(public_key, nonce) {
                return Self::sign(election, key, nonce);
            }
            if attempt.checked_add(1).ok_or(Error::ArithmeticOverflow)? < max_attempts {
                nonce = nonce.checked_add(1).ok_or(Error::MiningExhausted)?;
            }
        }
        Err(Error::MiningExhausted)
    }
    pub fn public_key(&self) -> Hash {
        self.public_key
    }
    pub fn nonce(&self) -> u64 {
        self.nonce
    }
    /// Identifies the work, not the signature. This MUST be the deduplication key.
    pub fn pow_id(&self, election: &Election) -> Result<Hash> {
        self.require_context(election)?;
        Ok(election.work_hash(self.public_key, self.nonce))
    }
    fn require_context(&self, election: &Election) -> Result<()> {
        if self.kind != election.kind
            || self.scope != election.scope
            || self.epoch != election.epoch
            || self.challenge != election.challenge
        {
            return Err(Error::WrongDomain);
        }
        Ok(())
    }
    pub fn verify(&self, election: &Election) -> Result<()> {
        let id = self.pow_id(election)?;
        if id > election.target {
            return Err(Error::InvalidWork);
        }
        wire::key(self.public_key)?
            .verify_strict(
                &possession_message(id),
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| Error::InvalidSignature)
    }
    pub fn encode(&self) -> [u8; TICKET_BYTES] {
        let mut bytes = [0; TICKET_BYTES];
        bytes[..8].copy_from_slice(TICKET_MAGIC);
        bytes[8..40].copy_from_slice(&profile_digest());
        bytes[40] = self.kind;
        bytes[41..73].copy_from_slice(&self.scope);
        bytes[73..81].copy_from_slice(&self.epoch.to_le_bytes());
        bytes[81..113].copy_from_slice(&self.challenge);
        bytes[113..145].copy_from_slice(&self.public_key);
        bytes[145..153].copy_from_slice(&self.nonce.to_le_bytes());
        bytes[153..].copy_from_slice(&self.signature);
        bytes
    }
    pub fn decode(election: &Election, bytes: &[u8]) -> Result<Self> {
        let ticket = Self::parse(bytes)?;
        ticket.verify(election)?;
        Ok(ticket)
    }
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != TICKET_BYTES {
            return Err(Error::InvalidEncoding);
        }
        let mut reader = Reader::new(bytes);
        reader.header(TICKET_MAGIC)?;
        let kind = reader.byte()?;
        if kind > 1 {
            return Err(Error::InvalidEncoding);
        }
        let ticket = Self {
            kind,
            scope: reader.array()?,
            epoch: reader.u64()?,
            challenge: reader.array()?,
            public_key: reader.array()?,
            nonce: reader.u64()?,
            signature: reader.array()?,
        };
        reader.end()?;
        if ticket.encode() != bytes {
            return Err(Error::InvalidEncoding);
        }
        Ok(ticket)
    }
}

fn possession_message(pow_id: Hash) -> Hash {
    hash(b"dcs/work-finality/ticket-possession/v1", &[&pow_id])
}

/// Exactly counted fixed-target work units, not a self-declared hashpower claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorWeight {
    public_key: Hash,
    work_units: u64,
}
impl ValidatorWeight {
    pub fn public_key(&self) -> Hash {
        self.public_key
    }
    pub fn work_units(&self) -> u64 {
        self.work_units
    }
}

/// An immutable, checked mathematical election result. It is NOT an activated
/// authority set, finalized configuration, availability or honesty proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochSet {
    network: Hash,
    epoch: u64,
    challenge: Hash,
    ticket_root: Hash,
    id: Hash,
    validators: Vec<ValidatorWeight>,
    total: u64,
    limits: Limits,
}
impl EpochSet {
    pub fn network_id(&self) -> Hash {
        self.network
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn challenge(&self) -> Hash {
        self.challenge
    }
    pub fn ticket_root(&self) -> Hash {
        self.ticket_root
    }
    pub fn id(&self) -> Hash {
        self.id
    }
    pub fn total_work_units(&self) -> u64 {
        self.total
    }
    pub fn validators(&self) -> &[ValidatorWeight] {
        &self.validators
    }
    pub fn limits(&self) -> Limits {
        self.limits
    }
    pub fn weight(&self, public_key: Hash) -> Option<u64> {
        self.validators
            .binary_search_by_key(&public_key, |v| v.public_key)
            .ok()
            .map(|i| self.validators[i].work_units)
    }
}

pub(crate) fn canonical_tickets(
    election: &Election,
    mut tickets: Vec<WorkTicket>,
) -> Result<Vec<WorkTicket>> {
    if tickets.is_empty() || tickets.len() > election.limits.max_tickets() {
        return Err(Error::ResourceLimit);
    }
    for ticket in &tickets {
        ticket.verify(election)?;
    }
    // Context was checked above. Neither sorting nor duplicate detection includes
    // signature bytes: alternative valid Ed25519 signatures cannot mint work.
    tickets.sort_by_key(|t| election.work_hash(t.public_key, t.nonce));
    for pair in tickets.windows(2) {
        if election.work_hash(pair[0].public_key, pair[0].nonce)
            == election.work_hash(pair[1].public_key, pair[1].nonce)
        {
            return Err(Error::DuplicateTicket);
        }
    }
    Ok(tickets)
}

pub(crate) fn derive_set(
    election: &Election,
    network: Hash,
    tickets: &[WorkTicket],
) -> Result<EpochSet> {
    if tickets.is_empty() || tickets.len() > election.limits.max_tickets() {
        return Err(Error::ResourceLimit);
    }
    let mut weights = BTreeMap::<Hash, u64>::new();
    let mut ticket_hash = Sha256::new();
    ticket_hash.update(b"dcs/work-finality/ticket-set/v1");
    ticket_hash.update(profile_digest());
    ticket_hash.update([election.kind]);
    ticket_hash.update(election.scope);
    ticket_hash.update(election.epoch.to_le_bytes());
    ticket_hash.update(election.challenge);
    ticket_hash.update(election.target);
    ticket_hash.update((tickets.len() as u64).to_le_bytes());
    let mut previous = None;
    let mut total = 0u64;
    for ticket in tickets {
        let id = ticket.pow_id(election)?;
        if previous.is_some_and(|p| p >= id) {
            return Err(Error::DuplicateTicket);
        }
        previous = Some(id);
        // The checked constructor always calls canonical_tickets first.
        ticket_hash.update(id);
        if !weights.contains_key(&ticket.public_key)
            && weights.len() >= election.limits.max_validators()
        {
            return Err(Error::ResourceLimit);
        }
        let count = weights.entry(ticket.public_key).or_default();
        *count = count.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
        total = total.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
    }
    let ticket_root: Hash = ticket_hash.finalize().into();
    let validators: Vec<_> = weights
        .into_iter()
        .map(|(public_key, work_units)| ValidatorWeight {
            public_key,
            work_units,
        })
        .collect();
    let mut h = Sha256::new();
    h.update(b"dcs/work-finality/epoch-set/v1");
    h.update(profile_digest());
    h.update(network);
    h.update(election.epoch.to_le_bytes());
    h.update(election.challenge);
    h.update(ticket_root);
    h.update(total.to_le_bytes());
    h.update((validators.len() as u64).to_le_bytes());
    for validator in &validators {
        h.update(validator.public_key);
        h.update(validator.work_units.to_le_bytes());
    }
    Ok(EpochSet {
        network,
        epoch: election.epoch,
        challenge: election.challenge,
        ticket_root,
        id: h.finalize().into(),
        validators,
        total,
        limits: election.limits,
    })
}
