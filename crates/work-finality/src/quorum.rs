use ed25519_dalek::{Signature, Signer, SigningKey};

use crate::{
    CERTIFICATE_HEADER_BYTES, ENDORSEMENT_BYTES, EpochSet, Error, Hash, MAX_CERTIFICATE_BYTES,
    Result, VOTE_BYTES, hash, profile_digest,
    wire::{self, Reader},
};

const VOTE_MAGIC: &[u8; 8] = b"DCSWFV01";
const CERTIFICATE_MAGIC: &[u8; 8] = b"DCSWFQ01";

/// Tendermint vote steps. A quorum of either kind is signature evidence only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Prevote,
    Precommit,
}
impl Step {
    fn byte(self) -> u8 {
        match self {
            Self::Prevote => 1,
            Self::Precommit => 2,
        }
    }
    fn parse(byte: u8) -> Result<Self> {
        match byte {
            1 => Ok(Self::Prevote),
            2 => Ok(Self::Precommit),
            _ => Err(Error::InvalidEncoding),
        }
    }
}

/// All independently expected signed metadata. Slot/round/step/value are not
/// checked against a consensus state machine by this mathematical library.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VoteContext {
    network: Hash,
    journal: Hash,
    set: Hash,
    epoch: u64,
    slot: u64,
    round: u64,
    step: Step,
    value: Option<Hash>,
}
impl VoteContext {
    pub fn new(
        set: &EpochSet,
        journal_genesis: Hash,
        slot: u64,
        round: u64,
        step: Step,
        value: Option<Hash>,
    ) -> Result<Self> {
        if slot == 0 {
            return Err(Error::InvalidConfig);
        }
        Ok(Self {
            network: set.network_id(),
            journal: journal_genesis,
            set: set.id(),
            epoch: set.epoch(),
            slot,
            round,
            step,
            value,
        })
    }
    pub fn network_id(self) -> Hash {
        self.network
    }
    pub fn journal_genesis(self) -> Hash {
        self.journal
    }
    pub fn set_id(self) -> Hash {
        self.set
    }
    pub fn epoch(self) -> u64 {
        self.epoch
    }
    pub fn slot(self) -> u64 {
        self.slot
    }
    pub fn round(self) -> u64 {
        self.round
    }
    pub fn step(self) -> Step {
        self.step
    }
    pub fn value(self) -> Option<Hash> {
        self.value
    }
    fn require_set(self, set: &EpochSet) -> Result<()> {
        if self.network != set.network_id() || self.set != set.id() || self.epoch != set.epoch() {
            return Err(Error::WrongDomain);
        }
        Ok(())
    }
    fn message(self) -> Hash {
        let (flag, value) = match self.value {
            None => (0, [0; 32]),
            Some(value) => (1, value),
        };
        hash(
            b"dcs/work-finality/vote/v1",
            &[
                &self.network,
                &self.journal,
                &self.set,
                &self.epoch.to_le_bytes(),
                &self.slot.to_le_bytes(),
                &self.round.to_le_bytes(),
                &[self.step.byte()],
                &[flag],
                &value,
            ],
        )
    }
    fn write_fields(self, bytes: &mut [u8]) {
        bytes[40..72].copy_from_slice(&self.network);
        bytes[72..104].copy_from_slice(&self.journal);
        bytes[104..136].copy_from_slice(&self.set);
        bytes[136..144].copy_from_slice(&self.epoch.to_le_bytes());
        bytes[144..152].copy_from_slice(&self.slot.to_le_bytes());
        bytes[152..160].copy_from_slice(&self.round.to_le_bytes());
        bytes[160] = self.step.byte();
    }
    fn read_fields(reader: &mut Reader<'_>, value: Option<Hash>) -> Result<Self> {
        let context = Self {
            network: reader.array()?,
            journal: reader.array()?,
            set: reader.array()?,
            epoch: reader.u64()?,
            slot: reader.u64()?,
            round: reader.u64()?,
            step: Step::parse(reader.byte()?)?,
            value,
        };
        if context.slot == 0 {
            return Err(Error::InvalidEncoding);
        }
        Ok(context)
    }
}

/// Public signed vote. This type supplies no anti-double-vote or WAL policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedVote {
    context: VoteContext,
    public_key: Hash,
    signature: [u8; 64],
}
impl SignedVote {
    /// Stateless signing only. A production signer must persist its vote lock
    /// before exposing a signature and must validate the application separately.
    pub fn sign(context: VoteContext, key: &SigningKey) -> Result<Self> {
        let public_key = key.verifying_key().to_bytes();
        wire::key(public_key)?;
        Ok(Self {
            context,
            public_key,
            signature: key.sign(&context.message()).to_bytes(),
        })
    }
    pub fn context(&self) -> VoteContext {
        self.context
    }
    pub fn public_key(&self) -> Hash {
        self.public_key
    }
    pub fn verify(&self, set: &EpochSet, expected: &VoteContext) -> Result<()> {
        expected.require_set(set)?;
        if self.context != *expected {
            return Err(Error::MixedVotes);
        }
        if set.weight(self.public_key).is_none() {
            return Err(Error::UnknownSigner);
        }
        verify_signature(self.public_key, self.signature, *expected)
    }
    pub fn encode(&self) -> [u8; VOTE_BYTES] {
        let mut bytes = [0; VOTE_BYTES];
        bytes[..8].copy_from_slice(VOTE_MAGIC);
        bytes[8..40].copy_from_slice(&profile_digest());
        self.context.write_fields(&mut bytes);
        match self.context.value {
            None => {
                bytes[161] = 0;
            }
            Some(value) => {
                bytes[161] = 1;
                bytes[162..194].copy_from_slice(&value);
            }
        }
        bytes[194..226].copy_from_slice(&self.public_key);
        bytes[226..].copy_from_slice(&self.signature);
        bytes
    }
    pub fn decode_and_verify(set: &EpochSet, expected: &VoteContext, bytes: &[u8]) -> Result<Self> {
        if bytes.len() != VOTE_BYTES {
            return Err(Error::InvalidEncoding);
        }
        let mut reader = Reader::new(bytes);
        reader.header(VOTE_MAGIC)?;
        let mut context = VoteContext::read_fields(&mut reader, None)?;
        let flag = reader.byte()?;
        let value = reader.array()?;
        context.value = match flag {
            0 if value == [0; 32] => None,
            1 => Some(value),
            _ => return Err(Error::InvalidEncoding),
        };
        let vote = Self {
            context,
            public_key: reader.array()?,
            signature: reader.array()?,
        };
        reader.end()?;
        vote.verify(set, expected)?;
        if vote.encode() != bytes {
            return Err(Error::InvalidEncoding);
        }
        Ok(vote)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Endorsement {
    public_key: Hash,
    signature: [u8; 64],
}

/// Strictly more than two thirds of checked fixed-target work signed one exact
/// non-nil context. This is NOT a commit decision, a FinalizedHead, an activated
/// epoch, or evidence that a candidate/proof/SQL result was valid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumCertificate {
    context: VoteContext,
    endorsements: Vec<Endorsement>,
    signed_work_units: u64,
}
impl QuorumCertificate {
    pub fn assemble(set: &EpochSet, expected: &VoteContext, votes: &[SignedVote]) -> Result<Self> {
        expected.require_set(set)?;
        if expected.value.is_none() {
            return Err(Error::NilValue);
        }
        check_count(set, votes.len())?;
        for vote in votes {
            vote.verify(set, expected)?;
        }
        let mut endorsements: Vec<_> = votes
            .iter()
            .map(|v| Endorsement {
                public_key: v.public_key,
                signature: v.signature,
            })
            .collect();
        endorsements.sort_by_key(|v| v.public_key);
        let signed_work_units = checked_weight(set, *expected, &endorsements)?;
        Ok(Self {
            context: *expected,
            endorsements,
            signed_work_units,
        })
    }
    pub fn context(&self) -> VoteContext {
        self.context
    }
    pub fn signer_count(&self) -> usize {
        self.endorsements.len()
    }
    pub fn signed_work_units(&self) -> u64 {
        self.signed_work_units
    }
    /// Recheck actual signatures and weights; cached totals never grant authority.
    pub fn verify(&self, set: &EpochSet, expected: &VoteContext) -> Result<()> {
        if self.context != *expected {
            return Err(Error::MixedVotes);
        }
        let signed = checked_weight(set, *expected, &self.endorsements)?;
        if signed != self.signed_work_units {
            return Err(Error::InvalidEncoding);
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let size = wire::length(
            CERTIFICATE_HEADER_BYTES,
            self.endorsements.len(),
            ENDORSEMENT_BYTES,
            MAX_CERTIFICATE_BYTES,
        )?;
        let count = u32::try_from(self.endorsements.len()).map_err(|_| Error::ResourceLimit)?;
        let mut bytes = vec![0; CERTIFICATE_HEADER_BYTES];
        bytes.reserve(size - CERTIFICATE_HEADER_BYTES);
        bytes[..8].copy_from_slice(CERTIFICATE_MAGIC);
        bytes[8..40].copy_from_slice(&profile_digest());
        self.context.write_fields(&mut bytes);
        bytes[161..193].copy_from_slice(&self.context.value.ok_or(Error::NilValue)?);
        bytes[193..197].copy_from_slice(&count.to_le_bytes());
        for endorsement in &self.endorsements {
            bytes.extend_from_slice(&endorsement.public_key);
            bytes.extend_from_slice(&endorsement.signature);
        }
        Ok(bytes)
    }
    pub fn decode_and_verify(set: &EpochSet, expected: &VoteContext, bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_CERTIFICATE_BYTES {
            return Err(Error::ResourceLimit);
        }
        expected.require_set(set)?;
        if expected.value.is_none() {
            return Err(Error::NilValue);
        }
        let mut reader = Reader::new(bytes);
        reader.header(CERTIFICATE_MAGIC)?;
        let mut context = VoteContext::read_fields(&mut reader, None)?;
        context.value = Some(reader.array()?);
        let count = reader.u32()? as usize;
        check_count(set, count)?;
        let size = wire::length(
            CERTIFICATE_HEADER_BYTES,
            count,
            ENDORSEMENT_BYTES,
            MAX_CERTIFICATE_BYTES,
        )?;
        if size != bytes.len() {
            return Err(Error::InvalidEncoding);
        }
        if context != *expected {
            return Err(Error::MixedVotes);
        }
        // Exact length and every remote count are bounded before Vec allocation.
        let mut endorsements = Vec::with_capacity(count);
        for _ in 0..count {
            endorsements.push(Endorsement {
                public_key: reader.array()?,
                signature: reader.array()?,
            });
        }
        reader.end()?;
        let signed_work_units = checked_weight(set, context, &endorsements)?;
        let certificate = Self {
            context,
            endorsements,
            signed_work_units,
        };
        if certificate.encode()? != bytes {
            return Err(Error::InvalidEncoding);
        }
        Ok(certificate)
    }
}

fn check_count(set: &EpochSet, count: usize) -> Result<()> {
    if count == 0 || count > set.limits().max_validators() || count > set.validators().len() {
        return Err(Error::ResourceLimit);
    }
    wire::length(
        CERTIFICATE_HEADER_BYTES,
        count,
        ENDORSEMENT_BYTES,
        MAX_CERTIFICATE_BYTES,
    )?;
    Ok(())
}
fn verify_signature(public_key: Hash, signature: [u8; 64], context: VoteContext) -> Result<()> {
    wire::key(public_key)?
        .verify_strict(&context.message(), &Signature::from_bytes(&signature))
        .map_err(|_| Error::InvalidSignature)
}
fn checked_weight(
    set: &EpochSet,
    context: VoteContext,
    endorsements: &[Endorsement],
) -> Result<u64> {
    context.require_set(set)?;
    if context.value.is_none() {
        return Err(Error::NilValue);
    }
    check_count(set, endorsements.len())?;
    let mut previous = None;
    let mut signed = 0u64;
    for endorsement in endorsements {
        if previous.is_some_and(|key| key >= endorsement.public_key) {
            return Err(Error::DuplicateSigner);
        }
        previous = Some(endorsement.public_key);
        let weight = set
            .weight(endorsement.public_key)
            .ok_or(Error::UnknownSigner)?;
        verify_signature(endorsement.public_key, endorsement.signature, context)?;
        signed = signed
            .checked_add(weight)
            .ok_or(Error::ArithmeticOverflow)?;
    }
    let lhs = u128::from(signed)
        .checked_mul(3)
        .ok_or(Error::ArithmeticOverflow)?;
    let rhs = u128::from(set.total_work_units())
        .checked_mul(2)
        .ok_or(Error::ArithmeticOverflow)?;
    if lhs <= rhs {
        return Err(Error::NoQuorum);
    }
    Ok(signed)
}
