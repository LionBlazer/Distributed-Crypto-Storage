use super::{
    Context, Error, MAX_INPUT_BYTES, Result,
    codec::{self, Reader},
};
use crate::{Hash, QuorumCertificate, SignedVote, Step, hash};
use ed25519_dalek::{Signature, Signer, SigningKey};

const PROPOSAL_HEADER: usize = 8 + 32 + 8 + 32 + 8 + 32 + 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoundStep {
    Propose,
    Prevote,
    Precommit,
}
impl RoundStep {
    pub(crate) fn index(self) -> usize {
        match self {
            Self::Propose => 0,
            Self::Prevote => 1,
            Self::Precommit => 2,
        }
    }
    pub(crate) fn parse(byte: u8) -> Result<Self> {
        match byte {
            0 => Ok(Self::Propose),
            1 => Ok(Self::Prevote),
            2 => Ok(Self::Precommit),
            _ => Err(Error::InvalidEncoding),
        }
    }
}
/// A local timer token. It is effective only at the exact current slot/round/step;
/// the transport/clock owner must wait its full duration before delivering it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeout {
    pub(crate) slot: u64,
    pub(crate) round: u64,
    pub(crate) step: RoundStep,
    pub(crate) duration_ms: u64,
}
impl Timeout {
    pub fn slot(self) -> u64 {
        self.slot
    }
    pub fn round(self) -> u64 {
        self.round
    }
    pub fn step(self) -> RoundStep {
        self.step
    }
    pub fn duration_ms(self) -> u64 {
        self.duration_ms
    }
    pub(crate) fn new(ctx: &Context, round: u64, step: RoundStep) -> Result<Self> {
        Ok(Self {
            slot: ctx.slot(),
            round,
            step,
            duration_ms: ctx.rules().timeout_ms(round, step)?,
        })
    }
}

/// Signed public proposal plus an actual earlier PREVOTE quorum, if any. This
/// is untrusted application input until the captured verifier checks its value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    context: Hash,
    round: u64,
    value: Vec<u8>,
    value_id: Hash,
    pol: Option<QuorumCertificate>,
    public_key: Hash,
    signature: [u8; 64],
}
impl Proposal {
    pub fn round(&self) -> u64 {
        self.round
    }
    pub fn value(&self) -> &[u8] {
        &self.value
    }
    pub fn value_id(&self) -> Hash {
        self.value_id
    }
    pub fn pol(&self) -> Option<&QuorumCertificate> {
        self.pol.as_ref()
    }
    pub(crate) fn sign(
        ctx: &Context,
        round: u64,
        value: Vec<u8>,
        pol: Option<QuorumCertificate>,
        key: &SigningKey,
    ) -> Result<Self> {
        let mut proposal = Self {
            context: ctx.id(),
            round,
            value_id: ctx.value_id(&value)?,
            value,
            pol,
            public_key: key.verifying_key().to_bytes(),
            signature: [0; 64],
        };
        if ctx.proposer(round)? != proposal.public_key {
            return Err(Error::WrongProposer);
        }
        proposal.check_pol(ctx)?;
        proposal.signature = key.sign(&proposal.message()?).to_bytes();
        Ok(proposal)
    }
    fn message(&self) -> Result<Hash> {
        let pol = match &self.pol {
            None => Vec::new(),
            Some(qc) => qc.encode()?,
        };
        Ok(hash(
            b"dcs/work-finality/consensus-proposal/v1",
            &[
                &self.context,
                &self.round.to_le_bytes(),
                &self.value_id,
                &(pol.len() as u64).to_le_bytes(),
                &pol,
            ],
        ))
    }
    fn check_pol(&self, ctx: &Context) -> Result<()> {
        if let Some(pol) = &self.pol {
            let round = pol.context().round();
            if round >= self.round {
                return Err(Error::InvalidProposal);
            }
            pol.verify(
                ctx.set(),
                &ctx.vote(round, Step::Prevote, Some(self.value_id))?,
            )?;
        }
        Ok(())
    }
    pub fn verify(&self, ctx: &Context) -> Result<()> {
        if self.context != ctx.id() || self.value_id != ctx.value_id(&self.value)? {
            return Err(Error::WrongContext);
        }
        if ctx.proposer(self.round)? != self.public_key {
            return Err(Error::WrongProposer);
        }
        self.check_pol(ctx)?;
        crate::wire::key(self.public_key)?
            .verify_strict(&self.message()?, &Signature::from_bytes(&self.signature))
            .map_err(|_| Error::InvalidProposal)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(PROPOSAL_HEADER + 8 + self.value.len());
        bytes.extend_from_slice(b"DCSWFP01");
        bytes.extend_from_slice(&self.context);
        bytes.extend_from_slice(&self.round.to_le_bytes());
        bytes.extend_from_slice(&self.value_id);
        let pol_round = self
            .pol
            .as_ref()
            .map_or(u64::MAX, |pol| pol.context().round());
        bytes.extend_from_slice(&pol_round.to_le_bytes());
        bytes.extend_from_slice(&self.public_key);
        bytes.extend_from_slice(&self.signature);
        codec::blob(&mut bytes, &self.value, super::MAX_VALUE_BYTES)?;
        let pol = match &self.pol {
            None => Vec::new(),
            Some(qc) => qc.encode()?,
        };
        codec::blob(&mut bytes, &pol, crate::MAX_CERTIFICATE_BYTES)?;
        if bytes.len() > MAX_INPUT_BYTES - 5 {
            return Err(Error::ResourceLimit);
        }
        Ok(bytes)
    }
    pub fn decode(ctx: &Context, bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_INPUT_BYTES - 5 {
            return Err(Error::ResourceLimit);
        }
        let mut r = Reader::new(bytes);
        if r.array::<8>()? != *b"DCSWFP01" {
            return Err(Error::InvalidEncoding);
        }
        let context = r.array()?;
        let round = r.u64()?;
        let value_id = r.array()?;
        let pol_round = r.u64()?;
        let public_key = r.array()?;
        let signature = r.array()?;
        let value = r.blob(ctx.rules().max_value_bytes())?;
        let pol_bytes = r.blob(crate::MAX_CERTIFICATE_BYTES)?;
        r.end()?;
        if context != ctx.id()
            || value_id != ctx.value_id(value)?
            || ctx.proposer(round)? != public_key
        {
            return Err(Error::WrongContext);
        }
        let pol = if pol_round == u64::MAX {
            if !pol_bytes.is_empty() {
                return Err(Error::InvalidEncoding);
            }
            None
        } else {
            if pol_round >= round {
                return Err(Error::InvalidProposal);
            }
            Some(QuorumCertificate::decode_and_verify(
                ctx.set(),
                &ctx.vote(pol_round, Step::Prevote, Some(value_id))?,
                pol_bytes,
            )?)
        };
        // All remote lengths, EOF and context are checked before owning value bytes.
        let result = Self {
            context,
            round,
            value: value.to_vec(),
            value_id,
            pol,
            public_key,
            signature,
        };
        result.verify(ctx)?;
        if result.encode()? != bytes {
            return Err(Error::InvalidEncoding);
        }
        Ok(result)
    }
}

/// Inputs are untrusted; constructing this enum never bypasses verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    Propose(Vec<u8>),
    Proposal(Proposal),
    Vote(SignedVote),
    Certificate {
        value: Vec<u8>,
        certificate: QuorumCertificate,
    },
    Timeout(Timeout),
}
impl Input {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut b = Vec::new();
        match self {
            Self::Propose(value) => {
                b.push(1);
                codec::blob(&mut b, value, super::MAX_VALUE_BYTES)?;
            }
            Self::Proposal(proposal) => {
                b.push(2);
                codec::blob(&mut b, &proposal.encode()?, MAX_INPUT_BYTES - 5)?;
            }
            Self::Vote(vote) => {
                b.push(3);
                b.extend_from_slice(&vote.encode());
            }
            Self::Certificate { value, certificate } => {
                b.push(4);
                codec::blob(&mut b, value, super::MAX_VALUE_BYTES)?;
                b.extend_from_slice(&certificate.context().round().to_le_bytes());
                b.push(match certificate.context().step() {
                    Step::Prevote => 1,
                    Step::Precommit => 2,
                });
                codec::blob(&mut b, &certificate.encode()?, crate::MAX_CERTIFICATE_BYTES)?;
            }
            Self::Timeout(timeout) => {
                b.push(5);
                b.extend_from_slice(&timeout.slot.to_le_bytes());
                b.extend_from_slice(&timeout.round.to_le_bytes());
                b.push(timeout.step.index() as u8);
                b.extend_from_slice(&timeout.duration_ms.to_le_bytes());
            }
        }
        if b.len() > MAX_INPUT_BYTES {
            return Err(Error::ResourceLimit);
        }
        Ok(b)
    }
    /// Remote inputs are only signed proposals/votes/certificates. Local timer
    /// firing and local proposal requests are never accepted from wire bytes.
    pub fn decode(ctx: &Context, bytes: &[u8]) -> Result<Self> {
        if matches!(bytes.first(), Some(1 | 5)) {
            return Err(Error::InvalidEncoding);
        }
        Self::decode_record(ctx, bytes)
    }
    pub(crate) fn decode_record(ctx: &Context, bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_INPUT_BYTES {
            return Err(Error::ResourceLimit);
        }
        let mut r = Reader::new(bytes);
        let input = match r.byte()? {
            1 => {
                let raw = r.blob(ctx.rules().max_value_bytes())?;
                // Exact outer length before allocating an owned descriptor.
                if raw.len().checked_add(5) != Some(bytes.len()) {
                    return Err(Error::InvalidEncoding);
                }
                Self::Propose(raw.to_vec())
            }
            2 => {
                let raw = r.blob(MAX_INPUT_BYTES - 5)?;
                if raw.len().checked_add(5) != Some(bytes.len()) {
                    return Err(Error::InvalidEncoding);
                }
                Self::Proposal(Proposal::decode(ctx, raw)?)
            }
            3 => {
                let raw = r.take(crate::VOTE_BYTES)?;
                let mut fields = Reader::new(raw.get(144..194).ok_or(Error::InvalidEncoding)?);
                let slot = fields.u64()?;
                let round = fields.u64()?;
                let step = match fields.byte()? {
                    1 => Step::Prevote,
                    2 => Step::Precommit,
                    _ => return Err(Error::InvalidEncoding),
                };
                let flag = fields.byte()?;
                let value = fields.array()?;
                let value = match flag {
                    0 if value == [0; 32] => None,
                    1 => Some(value),
                    _ => return Err(Error::InvalidEncoding),
                };
                if slot != ctx.slot() {
                    return Err(Error::WrongContext);
                }
                Self::Vote(SignedVote::decode_and_verify(
                    ctx.set(),
                    &ctx.vote(round, step, value)?,
                    raw,
                )?)
            }
            4 => {
                let value = r.blob(ctx.rules().max_value_bytes())?;
                let round = r.u64()?;
                let step = match r.byte()? {
                    1 => Step::Prevote,
                    2 => Step::Precommit,
                    _ => return Err(Error::InvalidEncoding),
                };
                let raw = r.blob(crate::MAX_CERTIFICATE_BYTES)?;
                if 18usize
                    .checked_add(value.len())
                    .and_then(|n| n.checked_add(raw.len()))
                    != Some(bytes.len())
                {
                    return Err(Error::InvalidEncoding);
                }
                let certificate = QuorumCertificate::decode_and_verify(
                    ctx.set(),
                    &ctx.vote(round, step, Some(ctx.value_id(value)?))?,
                    raw,
                )?;
                Self::Certificate {
                    value: value.to_vec(),
                    certificate,
                }
            }
            5 => Self::Timeout(Timeout {
                slot: r.u64()?,
                round: r.u64()?,
                step: RoundStep::parse(r.byte()?)?,
                duration_ms: r.u64()?,
            }),
            _ => return Err(Error::InvalidEncoding),
        };
        r.end()?;
        if input.encode()? != bytes {
            return Err(Error::InvalidEncoding);
        }
        Ok(input)
    }
}

/// Protocol decision only. No production application adapter or finality floor
/// installation exists here. The actual QC and descriptor remain inspectable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub(crate) context: Hash,
    pub(crate) value: Vec<u8>,
    pub(crate) certificate: QuorumCertificate,
}
impl Decision {
    /// Stable agreed-value identity. Different genuine quorum subsets, signature
    /// encodings or commit rounds for this same slot/value MUST NOT split the
    /// following slot's vote domain.
    pub fn semantic_id(&self) -> Hash {
        hash(
            b"dcs/work-finality/semantic-decision/v1",
            &[
                &self.context,
                &(self.value.len() as u64).to_le_bytes(),
                &self.value,
            ],
        )
    }
    pub fn context_id(&self) -> Hash {
        self.context
    }
    pub fn value(&self) -> &[u8] {
        &self.value
    }
    pub fn certificate(&self) -> &QuorumCertificate {
        &self.certificate
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Proposal(Proposal),
    Vote(SignedVote),
    Certificate {
        value: Vec<u8>,
        certificate: QuorumCertificate,
    },
    Schedule(Timeout),
    Decided(Decision),
}
pub(crate) fn encode_actions(actions: &[Action]) -> Result<Vec<u8>> {
    if actions.len() > super::MAX_ACTIONS {
        return Err(Error::ResourceLimit);
    }
    let mut b = vec![actions.len() as u8];
    for action in actions {
        match action {
            Action::Proposal(p) => {
                b.push(1);
                codec::blob(&mut b, &p.encode()?, MAX_INPUT_BYTES)?;
            }
            Action::Vote(v) => {
                b.push(2);
                b.extend_from_slice(&v.encode());
            }
            Action::Certificate { value, certificate } => {
                b.push(3);
                codec::blob(
                    &mut b,
                    &Input::Certificate {
                        value: value.clone(),
                        certificate: certificate.clone(),
                    }
                    .encode()?,
                    MAX_INPUT_BYTES,
                )?;
            }
            Action::Schedule(t) => {
                b.push(4);
                b.extend_from_slice(&t.slot.to_le_bytes());
                b.extend_from_slice(&t.round.to_le_bytes());
                b.push(t.step.index() as u8);
                b.extend_from_slice(&t.duration_ms.to_le_bytes());
            }
            Action::Decided(d) => {
                b.push(5);
                b.extend_from_slice(&d.context);
                codec::blob(&mut b, &d.value, super::MAX_VALUE_BYTES)?;
                codec::blob(
                    &mut b,
                    &d.certificate.encode()?,
                    crate::MAX_CERTIFICATE_BYTES,
                )?;
            }
        }
    }
    Ok(b)
}
