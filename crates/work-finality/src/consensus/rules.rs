use super::{
    Error, MAX_INPUT_BYTES, MAX_RECORD_BYTES, MAX_ROUND, MAX_SHARED_BYTES, MAX_VALUE_BYTES, Result,
};
use crate::{EpochSet, Genesis, Hash, hash, profile_digest};

/// Distinct from the unchanged ticket/vote/QC mathematical profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsensusRulesId(Hash);
impl ConsensusRulesId {
    pub fn to_bytes(self) -> Hash {
        self.0
    }
    pub fn as_bytes(&self) -> &Hash {
        &self.0
    }
}

/// Consensus semantics and bounds pinned BEFORE bootstrap work. No defaults.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rules {
    application: Hash,
    value_bytes: u32,
    max_round: u64,
    timeouts_ms: [u64; 3],
    timeout_delta_ms: u64,
    wal_bytes: u64,
}
impl Rules {
    pub fn new(
        application: Hash,
        value_bytes: u32,
        max_round: u64,
        timeouts_ms: [u64; 3],
        timeout_delta_ms: u64,
        wal_bytes: u64,
    ) -> Result<Self> {
        if value_bytes == 0
            || value_bytes as usize > MAX_VALUE_BYTES
            || max_round > MAX_ROUND
            || timeouts_ms.contains(&0)
            || timeout_delta_ms == 0
            || !(MAX_RECORD_BYTES as u64..=MAX_SHARED_BYTES).contains(&wal_bytes)
        {
            return Err(Error::InvalidConfig);
        }
        for base in timeouts_ms {
            base.checked_add(
                max_round
                    .checked_mul(timeout_delta_ms)
                    .ok_or(Error::InvalidConfig)?,
            )
            .ok_or(Error::InvalidConfig)?;
        }
        Ok(Self {
            application,
            value_bytes,
            max_round,
            timeouts_ms,
            timeout_delta_ms,
            wal_bytes,
        })
    }
    pub fn id(&self) -> ConsensusRulesId {
        let mut fields = Vec::new();
        fields.extend_from_slice(&self.application);
        fields.extend_from_slice(&self.value_bytes.to_le_bytes());
        fields.extend_from_slice(&self.max_round.to_le_bytes());
        for value in self.timeouts_ms {
            fields.extend_from_slice(&value.to_le_bytes());
        }
        fields.extend_from_slice(&self.timeout_delta_ms.to_le_bytes());
        fields.extend_from_slice(&self.wal_bytes.to_le_bytes());
        ConsensusRulesId(hash(b"dcs/work-finality/consensus-rules/v1", &[
            &profile_digest(), &fields,
            b"arxiv1807.04938v3/algorithm1/bounded-single-slot/certified-descriptor-commit",
            b"single-slot/initial-set-only/weighted-proposer-(slot-1+round)%total",
            b"proposal-pol-older/lockRound<=polRound-or-same/late-valid-no-second-precommit",
            b"nil-never-unlocks/strict2of3/any-unique-step/future1of3-same-round-latest-per-key/no-relative-round-cutoff",
            b"old-same-slot-commit/app-before-vote-and-decision/no-slot-advance",
            b"vote-domain=SHA256(dcs/work-finality/consensus-vote-instance/v1,ContextId)/including-nil-ANY-and-future",
            b"DCSWFP01/input-tags1..5/action-tags1..5/u32le-lengths/strict-eof",
            b"DCSWFW01/DCSWFR01/hash-chain/exact-output-replay/fsync-before-return/poison-no-truncate",
            &(MAX_INPUT_BYTES as u64).to_le_bytes(), &(MAX_RECORD_BYTES as u64).to_le_bytes(),
            &MAX_SHARED_BYTES.to_le_bytes(), &(super::MAX_ACTIONS as u64).to_le_bytes(),
            &(super::MAX_TRACKED_FILES as u64).to_le_bytes(),
        ]))
    }
    /// Supply this as NetworkSeed::domain before mining any bootstrap tickets.
    pub fn seed_domain(&self, public_network_tag: Hash) -> Hash {
        hash(
            b"dcs/work-finality/consensus-seed/v1",
            &[self.id().as_bytes(), &public_network_tag],
        )
    }
    pub fn max_value_bytes(&self) -> usize {
        self.value_bytes as usize
    }
    pub fn max_wal_bytes(&self) -> u64 {
        self.wal_bytes
    }
    pub(crate) fn max_round(&self) -> u64 {
        self.max_round
    }
    pub(crate) fn timeout_ms(&self, round: u64, step: super::RoundStep) -> Result<u64> {
        if round > self.max_round {
            return Err(Error::ResourceLimit);
        }
        self.timeouts_ms[step.index()]
            .checked_add(
                round
                    .checked_mul(self.timeout_delta_ms)
                    .ok_or(Error::ResourceLimit)?,
            )
            .ok_or(Error::ResourceLimit)
    }
}

/// Immutable independently selected context. Only the checked bootstrap roster
/// is activated by this stage; successor-set math is deliberately insufficient.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context {
    rules: Rules,
    network: Hash,
    journal: Hash,
    set: EpochSet,
    slot: u64,
    previous: Hash,
}
impl Context {
    pub fn new(
        rules: Rules,
        public_network_tag: Hash,
        genesis: &Genesis,
        journal_genesis: Hash,
        slot: u64,
        previous_decision: Hash,
    ) -> Result<Self> {
        if slot == 0
            || genesis.seed().domain() != rules.seed_domain(public_network_tag)
            || genesis.initial_set().epoch() != 0
        {
            return Err(Error::WrongContext);
        }
        Ok(Self {
            rules,
            network: genesis.id(),
            journal: journal_genesis,
            set: genesis.initial_set().clone(),
            slot,
            previous: previous_decision,
        })
    }
    pub fn rules(&self) -> &Rules {
        &self.rules
    }
    pub fn set(&self) -> &EpochSet {
        &self.set
    }
    pub fn slot(&self) -> u64 {
        self.slot
    }
    pub fn network_id(&self) -> Hash {
        self.network
    }
    pub fn journal_genesis(&self) -> Hash {
        self.journal
    }
    pub fn previous_decision(&self) -> Hash {
        self.previous
    }
    pub fn id(&self) -> Hash {
        hash(
            b"dcs/work-finality/consensus-context/v1",
            &[
                self.rules.id().as_bytes(),
                &self.network,
                &self.journal,
                &self.set.id(),
                &self.set.epoch().to_le_bytes(),
                &self.slot.to_le_bytes(),
                &self.previous,
            ],
        )
    }
    pub fn value_id(&self, value: &[u8]) -> Result<Hash> {
        if value.is_empty() || value.len() > self.rules.max_value_bytes() {
            return Err(Error::ResourceLimit);
        }
        Ok(hash(
            b"dcs/work-finality/consensus-value/v1",
            &[&self.id(), &(value.len() as u64).to_le_bytes(), value],
        ))
    }
    pub fn proposer(&self, round: u64) -> Result<Hash> {
        if round > self.rules.max_round {
            return Err(Error::ResourceLimit);
        }
        let position = (u128::from(self.slot - 1) + u128::from(round))
            % u128::from(self.set.total_work_units());
        let mut end = 0u128;
        for validator in self.set.validators() {
            end += u128::from(validator.work_units());
            if position < end {
                return Ok(validator.public_key());
            }
        }
        Err(Error::InvalidConfig)
    }
    pub(crate) fn vote(
        &self,
        round: u64,
        step: crate::Step,
        value: Option<Hash>,
    ) -> Result<crate::VoteContext> {
        if round > self.rules.max_round {
            return Err(Error::ResourceLimit);
        }
        Ok(crate::VoteContext::new(
            &self.set,
            hash(
                b"dcs/work-finality/consensus-vote-instance/v1",
                &[&self.id()],
            ),
            self.slot,
            round,
            step,
            value,
        )?)
    }
    pub(crate) fn check_vote(&self, vote: &crate::SignedVote) -> Result<()> {
        let raw = vote.context();
        vote.verify(&self.set, &self.vote(raw.round(), raw.step(), raw.value())?)?;
        Ok(())
    }
    pub(crate) fn verify_application<V: ApplicationVerifier>(
        &self,
        verifier: &V,
        value: &[u8],
    ) -> Result<Hash> {
        let id = self.value_id(value)?;
        verifier
            .verify(&ApplicationContext { context: self }, value)
            .map_err(|_| Error::ApplicationRejected)?;
        Ok(id)
    }
}

/// The integration must validate actual candidate proof/source/authorization and
/// the correct parent under these immutable pins. A TLS sender or DTO cannot
/// supply this result. Reopening calls it again, including for old decisions.
pub trait ApplicationVerifier {
    fn verify(
        &self,
        context: &ApplicationContext<'_>,
        descriptor: &[u8],
    ) -> std::result::Result<(), ApplicationError>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApplicationError;
pub struct ApplicationContext<'a> {
    context: &'a Context,
}
impl ApplicationContext<'_> {
    pub fn consensus(&self) -> &Context {
        self.context
    }
}
