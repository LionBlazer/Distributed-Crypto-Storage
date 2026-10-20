use super::{
    Action, ApplicationVerifier, Context, Decision, Error, Input, Proposal, Result, RoundStep,
    Timeout,
};
use crate::{Hash, QuorumCertificate, SignedVote, Step};
use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;

#[derive(Clone, PartialEq, Eq)]
struct Valid {
    round: u64,
    value: Vec<u8>,
    pol: QuorumCertificate,
}
#[derive(Clone, PartialEq, Eq)]
struct Lock {
    round: u64,
    id: Hash,
}

/// Private machine. Only DurableVoter can publish any action from it.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Machine {
    round: u64,
    step: RoundStep,
    proposal: Option<Proposal>,
    own_proposal: Option<Proposal>,
    prevotes: BTreeMap<Hash, SignedVote>,
    precommits: BTreeMap<Hash, SignedVote>,
    // One highest authenticated future round per key, across BOTH vote steps.
    future: BTreeMap<Hash, SignedVote>,
    current_pol: Option<(Vec<u8>, QuorumCertificate)>,
    valid: Option<Valid>,
    locked: Option<Lock>,
    own_prevote: Option<SignedVote>,
    own_precommit: Option<SignedVote>,
    prevote_timer: bool,
    precommit_timer: bool,
    decision: Option<Decision>,
}
impl Machine {
    pub(crate) fn new() -> Self {
        Self {
            round: 0,
            step: RoundStep::Propose,
            proposal: None,
            own_proposal: None,
            prevotes: BTreeMap::new(),
            precommits: BTreeMap::new(),
            future: BTreeMap::new(),
            current_pol: None,
            valid: None,
            locked: None,
            own_prevote: None,
            own_precommit: None,
            prevote_timer: false,
            precommit_timer: false,
            decision: None,
        }
    }
    pub(crate) fn round(&self) -> u64 {
        self.round
    }
    pub(crate) fn step(&self) -> RoundStep {
        self.step
    }
    pub(crate) fn lock(&self) -> Option<(u64, Hash)> {
        self.locked.as_ref().map(|l| (l.round, l.id))
    }
    pub(crate) fn valid(&self) -> Option<(u64, Hash)> {
        self.valid.as_ref().map(|v| {
            (
                v.round,
                v.pol.context().value().expect("non-nil checked POL"),
            )
        })
    }
    pub(crate) fn decision(&self) -> Option<&Decision> {
        self.decision.as_ref()
    }
    pub(crate) fn outbound(&self) -> Vec<Action> {
        let mut actions = Vec::new();
        if let Some(p) = &self.own_proposal {
            actions.push(Action::Proposal(p.clone()));
        }
        if let Some(v) = &self.own_prevote {
            actions.push(Action::Vote(v.clone()));
        }
        if let Some(v) = &self.own_precommit {
            actions.push(Action::Vote(v.clone()));
        }
        if let Some(valid) = &self.valid {
            actions.push(Action::Certificate {
                value: valid.value.clone(),
                certificate: valid.pol.clone(),
            });
        }
        if let Some(d) = &self.decision {
            actions.push(Action::Decided(d.clone()));
        }
        actions
    }
    pub(crate) fn timer(&self, ctx: &Context) -> Result<Timeout> {
        if self.decision.is_some()
            || (self.step == RoundStep::Prevote && !self.prevote_timer)
            || (self.step == RoundStep::Precommit && !self.precommit_timer)
        {
            return Err(Error::Stale);
        }
        Timeout::new(ctx, self.round, self.step)
    }
    pub(crate) fn apply<V: ApplicationVerifier>(
        &mut self,
        ctx: &Context,
        verifier: &V,
        key: &SigningKey,
        input: &Input,
    ) -> Result<Vec<Action>> {
        if self.decision.is_some() {
            return Err(Error::Stale);
        }
        let mut out = Vec::new();
        match input {
            Input::Propose(value) => {
                if self.step != RoundStep::Propose || self.own_proposal.is_some() {
                    return Err(Error::Stale);
                }
                if ctx.proposer(self.round)? != key.verifying_key().to_bytes() {
                    return Err(Error::WrongProposer);
                }
                let (value, pol) = if let Some(valid) = &self.valid {
                    (valid.value.clone(), Some(valid.pol.clone()))
                } else {
                    (value.clone(), None)
                };
                ctx.verify_application(verifier, &value)?;
                let proposal = Proposal::sign(ctx, self.round, value, pol, key)?;
                self.own_proposal = Some(proposal.clone());
                out.push(Action::Proposal(proposal.clone()));
                self.receive_proposal(ctx, verifier, key, &proposal, &mut out)?;
            }
            Input::Proposal(proposal) => {
                // An authenticated byte-identical remote retry adds no protocol
                // evidence. Return from the WHOLE apply: even drive must not
                // emit an action or turn this no-op into a new admission check.
                proposal.verify(ctx)?;
                if proposal.round() != self.round {
                    return Err(Error::Stale);
                }
                if self.proposal.as_ref() == Some(proposal) {
                    return Ok(Vec::new());
                }
                self.receive_proposal(ctx, verifier, key, proposal, &mut out)?
            }
            Input::Vote(vote) => {
                ctx.check_vote(vote)?;
                let round = vote.context().round();
                if round < self.round {
                    return Err(Error::Stale);
                }
                if round > self.round {
                    let key = vote.public_key();
                    if self
                        .future
                        .get(&key)
                        .is_none_or(|old| old.context().round() < round)
                    {
                        self.future.insert(key, vote.clone());
                    }
                    // Never add powers across rounds or steps. A signer occurs once.
                    let weight = self
                        .future
                        .values()
                        .filter(|v| v.context().round() == round)
                        .try_fold(0u64, |sum, v| {
                            sum.checked_add(
                                ctx.set()
                                    .weight(v.public_key())
                                    .ok_or(Error::WrongContext)?,
                            )
                            .ok_or(Error::ResourceLimit)
                        })?;
                    if u128::from(weight) * 3 > u128::from(ctx.set().total_work_units()) {
                        self.start_round(ctx, round, &mut out)?;
                    }
                } else {
                    self.add_vote(ctx, vote.clone())?;
                }
            }
            Input::Certificate { value, certificate } => {
                let raw = certificate.context();
                let id = ctx.value_id(value)?;
                certificate.verify(ctx.set(), &ctx.vote(raw.round(), raw.step(), Some(id))?)?;
                if raw.step() == Step::Prevote {
                    // Authenticate even a stale/future POL, but do not replay
                    // application proofs for a round this machine cannot use.
                    if raw.round() != self.round {
                        return Err(Error::Stale);
                    }
                    if self
                        .current_pol
                        .as_ref()
                        .is_some_and(|(old_value, _)| old_value == value)
                    {
                        // The first event for these exact value bytes already
                        // ran drive before durable publication. This QC adds no
                        // map entries and cannot replace that retained POL.
                        return Ok(Vec::new());
                    }
                }
                // PRECOMMIT always retains the full application check, even
                // for an older allowed round of this same slot.
                ctx.verify_application(verifier, value)?;
                match raw.step() {
                    Step::Precommit => self.decide(ctx, value, certificate, &mut out)?,
                    Step::Prevote => {
                        if let Some((_, old)) = &self.current_pol {
                            if old.context().value() != Some(id) {
                                return Err(Error::Equivocation);
                            }
                        } else {
                            self.current_pol = Some((value.clone(), certificate.clone()));
                        }
                    }
                }
            }
            Input::Timeout(timeout) => {
                if *timeout != self.timer(ctx)? {
                    return Err(Error::Stale);
                }
                match self.step {
                    RoundStep::Propose => self.cast(ctx, key, Step::Prevote, None, &mut out)?,
                    RoundStep::Prevote => {
                        if !self.prevote_timer {
                            return Err(Error::Stale);
                        }
                        self.cast(ctx, key, Step::Precommit, None, &mut out)?;
                    }
                    RoundStep::Precommit => {
                        if !self.precommit_timer {
                            return Err(Error::Stale);
                        }
                        let round = self.round.checked_add(1).ok_or(Error::ResourceLimit)?;
                        self.start_round(ctx, round, &mut out)?;
                    }
                }
            }
        }
        self.drive(ctx, verifier, key, &mut out)?;
        if out.len() > super::MAX_ACTIONS {
            return Err(Error::ResourceLimit);
        }
        Ok(out)
    }
    fn receive_proposal<V: ApplicationVerifier>(
        &mut self,
        ctx: &Context,
        verifier: &V,
        key: &SigningKey,
        proposal: &Proposal,
        out: &mut Vec<Action>,
    ) -> Result<()> {
        proposal.verify(ctx)?;
        if proposal.round() != self.round {
            return Err(Error::Stale);
        }
        ctx.verify_application(verifier, proposal.value())?;
        if let Some(old) = &self.proposal {
            if old != proposal {
                return Err(Error::Equivocation);
            }
            return Ok(());
        }
        self.proposal = Some(proposal.clone());
        if self.step == RoundStep::Propose {
            let permitted = match (&self.locked, proposal.pol()) {
                (None, _) => true,
                (Some(lock), Some(pol)) => {
                    lock.id == proposal.value_id() || lock.round <= pol.context().round()
                }
                (Some(lock), None) => lock.id == proposal.value_id(),
            };
            self.cast(
                ctx,
                key,
                Step::Prevote,
                permitted.then_some(proposal.value_id()),
                out,
            )?;
        }
        Ok(())
    }
    fn add_vote(&mut self, ctx: &Context, vote: SignedVote) -> Result<()> {
        let votes = match vote.context().step() {
            Step::Prevote => &mut self.prevotes,
            Step::Precommit => &mut self.precommits,
        };
        if let Some(old) = votes.get(&vote.public_key()) {
            if old.context() != vote.context() {
                return Err(Error::Equivocation);
            }
            return Ok(()); // alternative valid signatures cannot add weight
        }
        if votes.len() >= ctx.set().validators().len() {
            return Err(Error::ResourceLimit);
        }
        votes.insert(vote.public_key(), vote);
        Ok(())
    }
    fn cast(
        &mut self,
        ctx: &Context,
        key: &SigningKey,
        step: Step,
        value: Option<Hash>,
        out: &mut Vec<Action>,
    ) -> Result<()> {
        let own = match step {
            Step::Prevote => &mut self.own_prevote,
            Step::Precommit => &mut self.own_precommit,
        };
        if own.is_some() {
            return Err(Error::Equivocation);
        }
        let vote = SignedVote::sign(ctx.vote(self.round, step, value)?, key)?;
        *own = Some(vote.clone());
        self.step = match step {
            Step::Prevote => RoundStep::Prevote,
            Step::Precommit => RoundStep::Precommit,
        };
        self.add_vote(ctx, vote.clone())?;
        out.push(Action::Vote(vote));
        Ok(())
    }
    fn start_round(&mut self, ctx: &Context, round: u64, out: &mut Vec<Action>) -> Result<()> {
        if round <= self.round || round > ctx.rules().max_round() {
            return Err(Error::ResourceLimit);
        }
        self.round = round;
        self.step = RoundStep::Propose;
        self.proposal = None;
        self.own_proposal = None;
        self.own_prevote = None;
        self.own_precommit = None;
        self.current_pol = None;
        self.prevotes.clear();
        self.precommits.clear();
        self.prevote_timer = false;
        self.precommit_timer = false;
        let current: Vec<_> = self
            .future
            .values()
            .filter(|v| v.context().round() == round)
            .cloned()
            .collect();
        self.future.retain(|_, v| v.context().round() > round);
        for vote in current {
            self.add_vote(ctx, vote)?;
        }
        // Locks and valid POL are intentionally preserved across timeouts/jumps.
        out.push(Action::Schedule(Timeout::new(
            ctx,
            round,
            RoundStep::Propose,
        )?));
        Ok(())
    }
    fn drive<V: ApplicationVerifier>(
        &mut self,
        ctx: &Context,
        verifier: &V,
        key: &SigningKey,
        out: &mut Vec<Action>,
    ) -> Result<()> {
        if self.decision.is_some() {
            return Ok(());
        }
        if let Some(proposal) = self.proposal.clone() {
            if let Some(qc) = quorum(
                ctx,
                self.round,
                Step::Precommit,
                Some(proposal.value_id()),
                &self.precommits,
            )? {
                ctx.verify_application(verifier, proposal.value())?;
                out.push(Action::Certificate {
                    value: proposal.value().to_vec(),
                    certificate: qc.clone(),
                });
                self.decide(ctx, proposal.value(), &qc, out)?;
                return Ok(());
            }
            let pol = if let Some((_, qc)) = &self.current_pol {
                (qc.context().value() == Some(proposal.value_id())).then(|| qc.clone())
            } else {
                quorum(
                    ctx,
                    self.round,
                    Step::Prevote,
                    Some(proposal.value_id()),
                    &self.prevotes,
                )?
            };
            if let Some(pol) = pol {
                if self.valid.as_ref().is_none_or(|old| old.round < self.round) {
                    self.valid = Some(Valid {
                        round: self.round,
                        value: proposal.value().to_vec(),
                        pol: pol.clone(),
                    });
                    out.push(Action::Certificate {
                        value: proposal.value().to_vec(),
                        certificate: pol,
                    });
                }
                // A late POL can update validValue after a nil precommit, but
                // cannot cause a second precommit or silently replace a lock.
                if self.step == RoundStep::Prevote {
                    self.locked = Some(Lock {
                        round: self.round,
                        id: proposal.value_id(),
                    });
                    self.cast(ctx, key, Step::Precommit, Some(proposal.value_id()), out)?;
                }
            }
        }
        if self.step == RoundStep::Prevote {
            if quorum_weight(ctx, &self.prevotes, Some(None))? {
                self.cast(ctx, key, Step::Precommit, None, out)?;
            } else if !self.prevote_timer && quorum_weight(ctx, &self.prevotes, None)? {
                self.prevote_timer = true;
                out.push(Action::Schedule(Timeout::new(
                    ctx,
                    self.round,
                    RoundStep::Prevote,
                )?));
            }
        }
        if self.step == RoundStep::Precommit
            && !self.precommit_timer
            && quorum_weight(ctx, &self.precommits, None)?
        {
            self.precommit_timer = true;
            out.push(Action::Schedule(Timeout::new(
                ctx,
                self.round,
                RoundStep::Precommit,
            )?));
        }
        // Locally casting a precommit can itself complete the quorum (including
        // a one-key mathematical test roster). Do not wait for another input.
        if let Some(proposal) = self.proposal.clone()
            && let Some(qc) = quorum(
                ctx,
                self.round,
                Step::Precommit,
                Some(proposal.value_id()),
                &self.precommits,
            )?
        {
            ctx.verify_application(verifier, proposal.value())?;
            out.push(Action::Certificate {
                value: proposal.value().to_vec(),
                certificate: qc.clone(),
            });
            self.decide(ctx, proposal.value(), &qc, out)?;
        }
        Ok(())
    }
    fn decide(
        &mut self,
        ctx: &Context,
        value: &[u8],
        qc: &QuorumCertificate,
        out: &mut Vec<Action>,
    ) -> Result<()> {
        if qc.context().step() != Step::Precommit {
            return Err(Error::InvalidProposal);
        }
        let decision = Decision {
            context: ctx.id(),
            value: value.to_vec(),
            certificate: qc.clone(),
        };
        self.decision = Some(decision.clone());
        out.push(Action::Decided(decision));
        Ok(())
    }
}

fn quorum_weight(
    ctx: &Context,
    votes: &BTreeMap<Hash, SignedVote>,
    filter: Option<Option<Hash>>,
) -> Result<bool> {
    let mut weight = 0u64;
    for vote in votes
        .values()
        .filter(|v| filter.is_none_or(|value| v.context().value() == value))
    {
        weight = weight
            .checked_add(
                ctx.set()
                    .weight(vote.public_key())
                    .ok_or(Error::WrongContext)?,
            )
            .ok_or(Error::ResourceLimit)?;
    }
    Ok(u128::from(weight) * 3 > u128::from(ctx.set().total_work_units()) * 2)
}
fn quorum(
    ctx: &Context,
    round: u64,
    step: Step,
    value: Option<Hash>,
    votes: &BTreeMap<Hash, SignedVote>,
) -> Result<Option<QuorumCertificate>> {
    if !quorum_weight(ctx, votes, Some(value))? {
        return Ok(None);
    }
    let matching: Vec<_> = votes
        .values()
        .filter(|v| v.context().value() == value)
        .cloned()
        .collect();
    Ok(Some(QuorumCertificate::assemble(
        ctx.set(),
        &ctx.vote(round, step, value)?,
        &matching,
    )?))
}
