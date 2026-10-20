//! PUBLIC, NON-SECRET keys and real local filesystem/signature tests. These are
//! protocol-kernel scenarios, not independently running DCS peers or SQL proofs.
use super::{
    Action, ApplicationContext, ApplicationError, ApplicationVerifier, Context, DurableVoter,
    Error, Input, MAX_RECORD_BYTES, MAX_SHARED_BYTES, Proposal, RoundStep, Rules, wal::Fault,
};
use crate::{
    Election, Genesis, Hash, Limits, NetworkSeed, QuorumCertificate, SignedVote, Step, WorkTicket,
};
use ed25519_dalek::SigningKey;
use protocol_storage::{ByteBudget, ControlFile, ParticipantQuota};
use std::{
    fs,
    io::Write,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
struct TicketApplication {
    election: Election,
    network: Hash,
}
impl ApplicationVerifier for TicketApplication {
    fn verify(
        &self,
        ctx: &ApplicationContext<'_>,
        bytes: &[u8],
    ) -> std::result::Result<(), ApplicationError> {
        if ctx.consensus().network_id() != self.network {
            return Err(ApplicationError);
        }
        WorkTicket::decode(&self.election, bytes)
            .map(|_| ())
            .map_err(|_| ApplicationError)
    }
}
struct Fixture {
    genesis: Genesis,
    context: Context,
    application: TicketApplication,
    keys: Vec<SigningKey>,
    a: Vec<u8>,
    b: Vec<u8>,
}
fn fixture() -> Fixture {
    let rules = rules();
    let mut keys: Vec<_> = (1..=4).map(|n| SigningKey::from_bytes(&[n; 32])).collect();
    keys.sort_by_key(|k| k.verifying_key().to_bytes());
    let seed = NetworkSeed::new(
        rules.seed_domain([3; 32]),
        [4; 32],
        [255; 32],
        Limits::new(16, 4).unwrap(),
    )
    .unwrap();
    let election = seed.bootstrap_election();
    let tickets = keys
        .iter()
        .map(|k| WorkTicket::sign(&election, k, 0).unwrap())
        .collect();
    let genesis = Genesis::from_bootstrap(seed, tickets).unwrap();
    let a = WorkTicket::sign(&election, &keys[0], 77)
        .unwrap()
        .encode()
        .to_vec();
    let b = WorkTicket::sign(&election, &keys[0], 78)
        .unwrap()
        .encode()
        .to_vec();
    let application = TicketApplication {
        election,
        network: genesis.id(),
    };
    let context = Context::new(rules, [3; 32], &genesis, [5; 32], 1, [6; 32]).unwrap();
    Fixture {
        genesis,
        context,
        application,
        keys,
        a,
        b,
    }
}
fn rules() -> Rules {
    Rules::new(
        [2; 32],
        2048,
        32,
        [100, 200, 300],
        10,
        MAX_RECORD_BYTES as u64,
    )
    .unwrap()
}
impl Fixture {
    fn key(&self, n: usize) -> SigningKey {
        SigningKey::from_bytes(&self.keys[n].to_bytes())
    }
    fn proposal(&self, round: u64, value: &[u8], pol: Option<QuorumCertificate>) -> Proposal {
        let proposer = self.context.proposer(round).unwrap();
        let key = self
            .keys
            .iter()
            .find(|k| k.verifying_key().to_bytes() == proposer)
            .unwrap();
        Proposal::sign(&self.context, round, value.to_vec(), pol, key).unwrap()
    }
    fn vote(&self, n: usize, round: u64, step: Step, value: Option<&[u8]>) -> SignedVote {
        let value = value.map(|v| self.context.value_id(v).unwrap());
        SignedVote::sign(
            self.context.vote(round, step, value).unwrap(),
            &self.keys[n],
        )
        .unwrap()
    }
    fn qc(&self, round: u64, step: Step, value: &[u8]) -> QuorumCertificate {
        let expected = self
            .context
            .vote(round, step, Some(self.context.value_id(value).unwrap()))
            .unwrap();
        let votes: Vec<_> = (0..3)
            .map(|n| self.vote(n, round, step, Some(value)))
            .collect();
        QuorumCertificate::assemble(self.context.set(), &expected, &votes).unwrap()
    }
    fn create(
        &self,
        files: &OwnedFiles,
        name: &str,
        n: usize,
        budget: &ByteBudget,
    ) -> DurableVoter<TicketApplication> {
        DurableVoter::create_new(
            files.path(name),
            self.context.clone(),
            self.application.clone(),
            self.key(n),
            budget,
        )
        .unwrap()
    }
}

static NEXT: AtomicU64 = AtomicU64::new(0);
struct OwnedFiles {
    parent: PathBuf,
    directory: PathBuf,
    name: std::ffi::OsString,
}
impl OwnedFiles {
    fn new() -> Self {
        let parent = std::env::temp_dir().canonicalize().unwrap();
        let mut made = None;
        for _ in 0..64 {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let t = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let name = format!("dcs-public-finality-{}-{t}-{n}", std::process::id());
            let path = parent.join(&name);
            match fs::create_dir(&path) {
                Ok(()) => {
                    made = Some((path.canonicalize().unwrap(), std::ffi::OsString::from(name)));
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("create PUBLIC test directory: {e}"),
            }
        }
        let (directory, name) = made.expect("bounded unique directory allocation");
        assert_eq!(directory.parent(), Some(parent.as_path()));
        assert_eq!(directory.file_name(), Some(name.as_os_str()));
        Self {
            parent,
            directory,
            name,
        }
    }
    fn path(&self, name: &str) -> PathBuf {
        assert!(std::path::Path::new(name).components().count() == 1);
        self.directory.join(name)
    }
}
impl Drop for OwnedFiles {
    fn drop(&mut self) {
        let Ok(actual) = self.directory.canonicalize() else {
            return;
        };
        if actual != self.directory
            || actual.parent() != Some(self.parent.as_path())
            || actual.file_name() != Some(self.name.as_os_str())
        {
            return;
        }
        if let Ok(entries) = fs::read_dir(&actual) {
            for entry in entries.flatten() {
                if entry.file_type().is_ok_and(|t| t.is_file()) {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
        let _ = fs::remove_dir(actual); // non-recursive; never follows a nested link
    }
}

fn lock_and_enter_round_one(f: &Fixture, voter: &mut DurableVoter<TicketApplication>) {
    voter
        .handle(Input::Proposal(f.proposal(0, &f.a, None)))
        .unwrap();
    for n in 0..3 {
        voter
            .handle(Input::Vote(f.vote(n, 0, Step::Prevote, Some(&f.a))))
            .unwrap();
    }
    assert_eq!(voter.locked(), Some((0, f.context.value_id(&f.a).unwrap())));
    // ANY has three distinct keys, but A only has two. The fourth key's delayed
    // A precommit can still legitimately complete the old-round commit later.
    voter
        .handle(Input::Vote(f.vote(1, 0, Step::Precommit, None)))
        .unwrap();
    voter
        .handle(Input::Vote(f.vote(2, 0, Step::Precommit, Some(&f.a))))
        .unwrap();
    voter
        .handle(Input::Timeout(voter.timeout().unwrap()))
        .unwrap();
    assert_eq!(voter.round(), 1);
}

#[test]
fn complete_rules_are_bound_before_work_and_old_or_changed_domains_cannot_start_a_signer() {
    let f = fixture();
    let old = NetworkSeed::new([3; 32], [4; 32], [255; 32], Limits::new(4, 4).unwrap()).unwrap();
    let ticket = WorkTicket::sign(&old.bootstrap_election(), &f.keys[0], 0).unwrap();
    let old = Genesis::from_bootstrap(old, vec![ticket]).unwrap();
    assert!(matches!(
        Context::new(rules(), [3; 32], &old, [5; 32], 1, [6; 32]),
        Err(Error::WrongContext)
    ));
    let changed = Rules::new(
        [2; 32],
        2048,
        31,
        [100, 200, 300],
        10,
        MAX_RECORD_BYTES as u64,
    )
    .unwrap();
    assert_ne!(rules().id(), changed.id());
    assert_ne!(rules().seed_domain([3; 32]), changed.seed_domain([3; 32]));
    assert!(
        Rules::new(
            [2; 32],
            2048,
            32,
            [u64::MAX, 200, 300],
            10,
            MAX_RECORD_BYTES as u64
        )
        .is_err()
    );
}

#[test]
fn application_rejection_precedes_any_signature_or_wal_growth() {
    let f = fixture();
    let files = OwnedFiles::new();
    let budget = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
    let mut voter = f.create(&files, "signer", 0, &budget);
    let mut bad = f.a.clone();
    *bad.last_mut().unwrap() ^= 1;
    let proposal = f.proposal(0, &bad, None); // genuinely signed proposer, invalid work possession
    proposal.verify(&f.context).unwrap();
    let before = voter.file_bytes();
    assert!(matches!(
        voter.handle(Input::Proposal(proposal)),
        Err(Error::ApplicationRejected)
    ));
    assert_eq!(voter.file_bytes(), before);
    assert!(voter.outbound().unwrap().is_empty());
    assert_eq!(voter.locked(), None);
    voter
        .handle(Input::Proposal(f.proposal(0, &f.a, None)))
        .unwrap();
    assert!(
        voter
            .outbound()
            .unwrap()
            .iter()
            .any(|a| matches!(a, Action::Vote(_)))
    );
    assert!(matches!(voter.timeout(), Err(Error::Stale))); // no ANY quorum yet
}

#[test]
fn nil_and_timeouts_preserve_locks_and_conflicting_unjustified_proposals_get_nil() {
    let f = fixture();
    let files = OwnedFiles::new();
    let budget = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
    let mut voter = f.create(&files, "signer", 0, &budget);
    let old_timeout = voter.timeout().unwrap();
    lock_and_enter_round_one(&f, &mut voter);
    let before = voter.file_bytes();
    assert!(matches!(
        voter.handle(Input::Timeout(old_timeout)),
        Err(Error::Stale)
    ));
    assert_eq!(voter.file_bytes(), before);
    let locked = voter.locked();
    let out = voter
        .handle(Input::Proposal(f.proposal(1, &f.b, None)))
        .unwrap();
    assert!(out.iter().any(|a| matches!(a, Action::Vote(v) if v.context().step() == Step::Prevote && v.context().value().is_none())));
    for n in 0..3 {
        voter
            .handle(Input::Vote(f.vote(n, 1, Step::Prevote, None)))
            .unwrap();
    }
    assert_eq!(voter.step(), RoundStep::Precommit);
    assert_eq!(voter.locked(), locked);
    for n in 0..3 {
        voter
            .handle(Input::Vote(f.vote(n, 1, Step::Precommit, None)))
            .unwrap();
    }
    voter
        .handle(Input::Timeout(voter.timeout().unwrap()))
        .unwrap();
    assert_eq!(voter.round(), 2);
    assert_eq!(voter.locked(), locked);
    assert!(voter.decision().is_none());
}

#[test]
fn late_pol_updates_valid_value_without_a_second_precommit() {
    let f = fixture();
    let files = OwnedFiles::new();
    let budget = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
    let mut voter = f.create(&files, "signer", 0, &budget);
    voter
        .handle(Input::Proposal(f.proposal(0, &f.a, None)))
        .unwrap();
    voter
        .handle(Input::Vote(f.vote(1, 0, Step::Prevote, Some(&f.b))))
        .unwrap();
    voter
        .handle(Input::Vote(f.vote(2, 0, Step::Prevote, Some(&f.a))))
        .unwrap();
    let out = voter
        .handle(Input::Timeout(voter.timeout().unwrap()))
        .unwrap();
    let first = out
        .iter()
        .find_map(|a| match a {
            Action::Vote(v) if v.context().step() == Step::Precommit => Some(v.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(first.context().value(), None);
    let out = voter
        .handle(Input::Vote(f.vote(3, 0, Step::Prevote, Some(&f.a))))
        .unwrap();
    assert!(out.iter().any(|a| matches!(a, Action::Certificate { certificate, .. } if certificate.context().step() == Step::Prevote)));
    assert!(
        !out.iter()
            .any(|a| matches!(a, Action::Vote(v) if v.context().step() == Step::Precommit))
    );
    assert_eq!(voter.valid(), Some((0, f.context.value_id(&f.a).unwrap())));
    assert_eq!(voter.locked(), None);
    assert!(voter.outbound().unwrap().contains(&Action::Vote(first)));
    let persisted = voter.outbound().unwrap();
    drop(voter);
    let reopened = DurableVoter::open_existing(
        files.path("signer"),
        f.context.clone(),
        f.application.clone(),
        f.key(0),
        &budget,
    )
    .unwrap();
    assert_eq!(
        reopened.valid(),
        Some((0, f.context.value_id(&f.a).unwrap()))
    );
    assert!(matches!(reopened.timeout(), Err(Error::Stale)));
    assert_eq!(reopened.locked(), None);
    assert_eq!(reopened.outbound().unwrap(), persisted);
}

#[test]
fn future_round_weight_never_mixes_rounds_steps_or_duplicate_keys() {
    let f = fixture();
    let files = OwnedFiles::new();
    let budget = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
    let mut voter = f.create(&files, "signer", 0, &budget);
    voter
        .handle(Input::Vote(f.vote(1, 2, Step::Prevote, None)))
        .unwrap();
    voter
        .handle(Input::Vote(f.vote(1, 2, Step::Precommit, None)))
        .unwrap();
    voter
        .handle(Input::Vote(f.vote(2, 3, Step::Precommit, None)))
        .unwrap();
    assert_eq!(voter.round(), 0);
    let before = voter.file_bytes();
    let too_far = SignedVote::sign(
        crate::VoteContext::new(
            f.context.set(),
            f.context.journal_genesis(),
            1,
            33,
            Step::Prevote,
            None,
        )
        .unwrap(),
        &f.keys[3],
    )
    .unwrap();
    assert!(matches!(
        voter.handle(Input::Vote(too_far)),
        Err(Error::ResourceLimit)
    ));
    assert_eq!(voter.file_bytes(), before);
    voter
        .handle(Input::Vote(f.vote(3, 2, Step::Prevote, None)))
        .unwrap();
    assert_eq!(voter.round(), 2); // two keys in EXACT round two, not two messages by one key
    assert_eq!(voter.locked(), None);
    voter
        .handle(Input::Vote(f.vote(0, 30, Step::Prevote, None)))
        .unwrap();
    assert_eq!(voter.round(), 2);
    voter
        .handle(Input::Vote(f.vote(1, 30, Step::Precommit, None)))
        .unwrap();
    assert_eq!(voter.round(), 30); // bounded evidence must not impose a relative catch-up cutoff
}

#[test]
fn genuine_older_pol_permits_reproposal_but_same_or_future_round_pol_does_not() {
    let f = fixture();
    let files = OwnedFiles::new();
    let budget = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
    let mut voter = f.create(&files, "signer", 0, &budget);
    lock_and_enter_round_one(&f, &mut voter);
    // A round-one POL is actual signatures, never a nominated validRound integer.
    let pol = f.qc(1, Step::Prevote, &f.b);
    assert!(Proposal::sign(&f.context, 1, f.b.clone(), Some(pol.clone()), &f.keys[1]).is_err());
    voter
        .handle(Input::Vote(f.vote(1, 2, Step::Prevote, None)))
        .unwrap();
    voter
        .handle(Input::Vote(f.vote(2, 2, Step::Prevote, None)))
        .unwrap();
    let out = voter
        .handle(Input::Proposal(f.proposal(2, &f.b, Some(pol))))
        .unwrap();
    assert!(out.iter().any(|a| matches!(a, Action::Vote(v) if v.context().step() == Step::Prevote && v.context().value() == Some(f.context.value_id(&f.b).unwrap()))));
}

#[test]
fn old_same_slot_commit_is_checked_and_persisted_after_advancing_round() {
    let f = fixture();
    let files = OwnedFiles::new();
    let budget = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
    let mut voter = f.create(&files, "signer", 0, &budget);
    lock_and_enter_round_one(&f, &mut voter);
    let expected = f
        .context
        .vote(0, Step::Precommit, Some(f.context.value_id(&f.a).unwrap()))
        .unwrap();
    let votes: Vec<_> = [0, 2, 3]
        .into_iter()
        .map(|n| f.vote(n, 0, Step::Precommit, Some(&f.a)))
        .collect();
    let qc = QuorumCertificate::assemble(f.context.set(), &expected, &votes).unwrap();
    let out = voter
        .handle(Input::Certificate {
            value: f.a.clone(),
            certificate: qc.clone(),
        })
        .unwrap();
    assert!(
        out.iter()
            .any(|a| matches!(a, Action::Decided(d) if d.value() == f.a && d.certificate() == &qc))
    );
    assert_eq!(voter.decision().unwrap().certificate().context().round(), 0);
    let length = voter.file_bytes();
    drop(voter);
    let reopened = DurableVoter::open_existing(
        files.path("signer"),
        f.context.clone(),
        f.application.clone(),
        f.key(0),
        &budget,
    )
    .unwrap();
    assert_eq!(reopened.file_bytes(), length);
    assert_eq!(reopened.decision().unwrap().value(), f.a);
    assert_eq!(reopened.decision().unwrap().certificate(), &qc);
    assert_eq!(
        reopened.locked(),
        Some((0, f.context.value_id(&f.a).unwrap()))
    );
    assert_eq!(
        reopened.valid(),
        Some((0, f.context.value_id(&f.a).unwrap()))
    );
}

#[test]
fn nil_mixed_context_and_wrong_value_certificates_never_decide() {
    let f = fixture();
    let files = OwnedFiles::new();
    let budget = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
    let mut voter = f.create(&files, "signer", 0, &budget);
    let qc = f.qc(0, Step::Precommit, &f.a);
    let before = voter.file_bytes();
    assert!(
        voter
            .handle(Input::Certificate {
                value: f.b.clone(),
                certificate: qc.clone()
            })
            .is_err()
    );
    let mut encoded = Input::Certificate {
        value: f.a.clone(),
        certificate: qc,
    }
    .encode()
    .unwrap();
    *encoded.last_mut().unwrap() ^= 1;
    assert!(voter.handle_bytes(&encoded).is_err());
    let nil_votes: Vec<_> = (0..3)
        .map(|n| f.vote(n, 0, Step::Precommit, None))
        .collect();
    assert!(
        QuorumCertificate::assemble(
            f.context.set(),
            &f.context.vote(0, Step::Precommit, None).unwrap(),
            &nil_votes
        )
        .is_err()
    );
    assert_eq!(voter.file_bytes(), before);
    assert!(voter.decision().is_none());
}

#[test]
fn signer_file_is_exclusive_open_only_and_replays_exact_lost_ack_signatures() {
    let f = fixture();
    let files = OwnedFiles::new();
    let budget = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
    assert!(
        DurableVoter::open_existing(
            files.path("missing"),
            f.context.clone(),
            f.application.clone(),
            f.key(0),
            &budget
        )
        .is_err()
    );
    let mut voter = f.create(&files, "signer", 0, &budget);
    assert!(
        DurableVoter::open_existing(
            files.path("signer"),
            f.context.clone(),
            f.application.clone(),
            f.key(0),
            &budget
        )
        .is_err()
    );
    voter.inject(Fault::AfterSync);
    assert!(matches!(
        voter.handle(Input::Proposal(f.proposal(0, &f.a, None))),
        Err(Error::Io(_))
    ));
    assert!(voter.is_poisoned());
    assert!(matches!(voter.outbound(), Err(Error::Poisoned)));
    drop(voter);
    let mut reopened = DurableVoter::open_existing(
        files.path("signer"),
        f.context.clone(),
        f.application.clone(),
        f.key(0),
        &budget,
    )
    .unwrap();
    let votes = reopened.outbound().unwrap();
    let expected = f.vote(0, 0, Step::Prevote, Some(&f.a));
    assert!(votes.contains(&Action::Vote(expected.clone())));
    expected
        .verify(f.context.set(), &expected.context())
        .unwrap();
    let before = reopened.file_bytes();
    let out = reopened
        .handle(Input::Proposal(f.proposal(0, &f.a, None)))
        .unwrap();
    assert!(!out.iter().any(|a| matches!(a, Action::Vote(_))));
    assert_eq!(reopened.file_bytes(), before);
    assert_eq!(reopened.outbound().unwrap(), votes);
}

#[test]
fn designated_local_proposer_persists_the_actual_proposal_and_other_members_cannot_propose() {
    let f = fixture();
    let files = OwnedFiles::new();
    let budget = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
    let mut wrong = f.create(&files, "wrong", 1, &budget);
    let bytes = wrong.file_bytes();
    assert!(matches!(
        wrong.handle(Input::Propose(f.a.clone())),
        Err(Error::WrongProposer)
    ));
    assert_eq!(wrong.file_bytes(), bytes);
    let mut proposer = f.create(&files, "proposer", 0, &budget);
    let out = proposer.handle(Input::Propose(f.a.clone())).unwrap();
    let proposal = out
        .iter()
        .find_map(|a| match a {
            Action::Proposal(p) => Some(p.clone()),
            _ => None,
        })
        .unwrap();
    proposal.verify(&f.context).unwrap();
    assert_eq!(proposal.value(), f.a);
    let persisted = proposer.outbound().unwrap();
    assert!(matches!(
        proposer.handle(Input::Propose(f.b.clone())),
        Err(Error::Stale)
    ));
    drop(proposer);
    let reopened = DurableVoter::open_existing(
        files.path("proposer"),
        f.context.clone(),
        f.application.clone(),
        f.key(0),
        &budget,
    )
    .unwrap();
    assert_eq!(reopened.outbound().unwrap(), persisted);
    drop(reopened);
    assert!(matches!(
        DurableVoter::open_existing(
            files.path("proposer"),
            f.context.clone(),
            f.application.clone(),
            f.key(1),
            &budget
        ),
        Err(Error::WrongContext)
    ));
}

#[test]
fn repeated_genuine_votes_do_not_consume_the_wal_quota_or_add_weight() {
    let f = fixture();
    let files = OwnedFiles::new();
    let budget = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
    let mut voter = f.create(&files, "signer", 0, &budget);
    let vote = f.vote(1, 0, Step::Prevote, None);
    voter.handle(Input::Vote(vote.clone())).unwrap();
    let length = voter.file_bytes();
    for _ in 0..16 {
        assert!(voter.handle(Input::Vote(vote.clone())).unwrap().is_empty());
    }
    assert_eq!(voter.file_bytes(), length);
    assert_eq!(budget.used().unwrap(), length);
    assert_eq!(voter.step(), RoundStep::Propose);
}

#[test]
fn three_owned_signers_decide_only_after_actual_prevote_and_precommit_quorums() {
    let f = fixture();
    let files = OwnedFiles::new();
    let budget = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
    let mut voters: Vec<_> = (0..3)
        .map(|n| f.create(&files, &format!("signer-{n}"), n, &budget))
        .collect();
    let out = voters[0].handle(Input::Propose(f.a.clone())).unwrap();
    let proposal = out
        .into_iter()
        .find_map(|a| match a {
            Action::Proposal(p) => Some(p),
            _ => None,
        })
        .unwrap();
    for voter in voters.iter_mut().skip(1) {
        voter.handle(Input::Proposal(proposal.clone())).unwrap();
    }
    let prevotes: Vec<_> = voters
        .iter()
        .flat_map(|v| v.outbound().unwrap())
        .filter_map(|a| match a {
            Action::Vote(v) if v.context().step() == Step::Prevote => Some(v),
            _ => None,
        })
        .collect();
    assert_eq!(prevotes.len(), 3);
    for voter in &mut voters {
        assert!(voter.decision().is_none());
        for vote in &prevotes {
            voter.handle(Input::Vote(vote.clone())).unwrap();
        }
        assert!(voter.locked().is_some());
        assert!(voter.decision().is_none());
        let before = voter.file_bytes();
        assert!(matches!(
            voter.handle(Input::Proposal(f.proposal(0, &f.b, None))),
            Err(Error::Equivocation)
        ));
        assert_eq!(voter.file_bytes(), before);
    }
    let precommits: Vec<_> = voters
        .iter()
        .flat_map(|v| v.outbound().unwrap())
        .filter_map(|a| match a {
            Action::Vote(v) if v.context().step() == Step::Precommit => Some(v),
            _ => None,
        })
        .collect();
    assert_eq!(precommits.len(), 3);
    for (n, voter) in voters.iter_mut().enumerate() {
        for vote in precommits
            .iter()
            .filter(|v| v.public_key() != f.keys[n].verifying_key().to_bytes())
        {
            voter.handle(Input::Vote(vote.clone())).unwrap();
        }
        let decision = voter.decision().unwrap();
        assert_eq!(decision.value(), f.a);
        decision
            .certificate()
            .verify(
                f.context.set(),
                &f.context
                    .vote(0, Step::Precommit, Some(f.context.value_id(&f.a).unwrap()))
                    .unwrap(),
            )
            .unwrap();
    }
}

#[test]
fn partial_writes_and_sync_errors_poison_without_truncating_or_publishing() {
    let f = fixture();
    let files = OwnedFiles::new();
    for (n, fault) in [Fault::Partial(3), Fault::Partial(96), Fault::BeforeSync]
        .into_iter()
        .enumerate()
    {
        let budget = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
        let name = format!("fault-{n}");
        let mut voter = f.create(&files, &name, 0, &budget);
        let old_length = voter.file_bytes();
        voter.inject(fault);
        assert!(matches!(
            voter.handle(Input::Proposal(f.proposal(0, &f.a, None))),
            Err(Error::Io(_))
        ));
        assert!(voter.is_poisoned());
        assert!(matches!(
            voter.handle(Input::Timeout(voter.timeout().unwrap_or(super::Timeout {
                slot: 1,
                round: 0,
                step: RoundStep::Propose,
                duration_ms: 100
            }))),
            Err(Error::Poisoned)
        ));
        drop(voter);
        let length = fs::metadata(files.path(&name)).unwrap().len();
        assert!(length > old_length);
        if matches!(fault, Fault::Partial(_)) {
            // Use a fresh accounting owner on restart. Torn tail is still a hard
            // error and its exact bytes remain, without set_len/recovery fallback.
            let restart_budget = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
            assert!(matches!(
                DurableVoter::open_existing(
                    files.path(&name),
                    f.context.clone(),
                    f.application.clone(),
                    f.key(0),
                    &restart_budget
                ),
                Err(Error::CorruptWal)
            ));
            assert_eq!(fs::metadata(files.path(&name)).unwrap().len(), length);
        }
    }
}

#[test]
fn corrupt_tail_and_replay_application_failure_are_strict_without_repair() {
    let f = fixture();
    let files = OwnedFiles::new();
    let budget = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
    let mut voter = f.create(&files, "signer", 0, &budget);
    voter
        .handle(Input::Proposal(f.proposal(0, &f.a, None)))
        .unwrap();
    drop(voter);
    let original = fs::read(files.path("signer")).unwrap();
    let mut changed_app = f.application.clone();
    changed_app.network = [99; 32];
    assert!(matches!(
        DurableVoter::open_existing(
            files.path("signer"),
            f.context.clone(),
            changed_app,
            f.key(0),
            &budget
        ),
        Err(Error::CorruptWal)
    ));
    assert_eq!(fs::read(files.path("signer")).unwrap(), original);
    let mut bad_checksum = original.clone();
    let last_checksum = bad_checksum.len() - 13;
    bad_checksum[last_checksum] ^= 1;
    let mut copy = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(files.path("checksum"))
        .unwrap();
    copy.write_all(&bad_checksum).unwrap();
    copy.sync_all().unwrap();
    drop(copy);
    assert!(matches!(
        DurableVoter::open_existing(
            files.path("checksum"),
            f.context.clone(),
            f.application.clone(),
            f.key(0),
            &budget
        ),
        Err(Error::CorruptWal)
    ));
    assert_eq!(fs::read(files.path("checksum")).unwrap(), bad_checksum);
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(files.path("signer"))
        .unwrap();
    file.write_all(&[0xff; 4]).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let corrupted = fs::read(files.path("signer")).unwrap();
    let restart = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
    assert!(matches!(
        DurableVoter::open_existing(
            files.path("signer"),
            f.context.clone(),
            f.application.clone(),
            f.key(0),
            &restart
        ),
        Err(Error::CorruptWal)
    ));
    assert_eq!(fs::read(files.path("signer")).unwrap(), corrupted);
}

#[test]
fn actual_wal_and_external_bytes_share_one_quota_and_drop_does_not_forget_the_file() {
    let f = fixture();
    let files = OwnedFiles::new();
    let budget = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
    let voter = f.create(&files, "signer", 0, &budget);
    let wal = voter.file_bytes();
    drop(voter);
    let original = fs::read(files.path("signer")).unwrap();
    let mut voter = DurableVoter::open_existing(
        files.path("signer"),
        f.context.clone(),
        f.application.clone(),
        f.key(0),
        &budget,
    )
    .unwrap();
    let mut external = budget.reserve(MAX_SHARED_BYTES - wal).unwrap();
    assert!(matches!(
        voter.handle(Input::Proposal(f.proposal(0, &f.a, None))),
        Err(Error::ResourceLimit)
    ));
    assert!(!voter.is_poisoned());
    assert!(voter.outbound().unwrap().is_empty());
    assert_eq!(voter.file_bytes(), wal);
    drop(voter);
    assert_eq!(fs::read(files.path("signer")).unwrap(), original);
    external.resize(0).unwrap();
    let mut voter = DurableVoter::open_existing(
        files.path("signer"),
        f.context.clone(),
        f.application.clone(),
        f.key(0),
        &budget,
    )
    .unwrap();
    voter
        .handle(Input::Proposal(f.proposal(0, &f.a, None)))
        .unwrap();
    let length = voter.file_bytes();
    drop(voter);
    assert_eq!(budget.used().unwrap(), length);
    let reopened = DurableVoter::open_existing(
        files.path("signer"),
        f.context.clone(),
        f.application.clone(),
        f.key(0),
        &budget,
    )
    .unwrap();
    assert_eq!(budget.used().unwrap(), reopened.file_bytes());
}

#[test]
fn genuine_votes_from_a_different_previous_anchor_never_start_timers_or_future_jumps() {
    let f = fixture();
    let foreign = Context::new(
        f.context.rules().clone(),
        [3; 32],
        &f.genesis,
        f.context.journal_genesis(),
        f.context.slot(),
        [0x77; 32],
    )
    .unwrap();
    assert_eq!(foreign.set(), f.context.set());
    assert_ne!(foreign.id(), f.context.id());
    let files = OwnedFiles::new();
    let budget = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
    let mut voter = f.create(&files, "signer", 0, &budget);
    let original_length = voter.file_bytes();
    for round in [0, 9] {
        for step in [Step::Prevote, Step::Precommit] {
            for value in [None, Some(foreign.value_id(&f.a).unwrap())] {
                for key in &f.keys {
                    let vote =
                        SignedVote::sign(foreign.vote(round, step, value).unwrap(), key).unwrap();
                    foreign.check_vote(&vote).unwrap();
                    assert!(f.context.check_vote(&vote).is_err());
                    let input = Input::Vote(vote);
                    assert!(voter.handle_bytes(&input.encode().unwrap()).is_err());
                    assert!(voter.handle(input).is_err());
                    assert_eq!(voter.file_bytes(), original_length);
                    assert!(voter.outbound().unwrap().is_empty());
                    assert_eq!(voter.round(), 0);
                    assert_eq!(voter.step(), RoundStep::Propose);
                }
            }
        }
    }
}

#[test]
fn bounded_codecs_reject_oversize_counts_truncation_trailing_and_signature_changes() {
    let f = fixture();
    let proposal = f.proposal(0, &f.a, None);
    let wire = Input::Proposal(proposal.clone()).encode().unwrap();
    assert_eq!(
        Input::decode(&f.context, &wire).unwrap(),
        Input::Proposal(proposal)
    );
    for length in [0, 1, 4, wire.len() - 1] {
        assert!(Input::decode(&f.context, &wire[..length]).is_err());
    }
    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(Input::decode(&f.context, &trailing).is_err());
    let mut bomb = wire.clone();
    bomb[1..5].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        Input::decode(&f.context, &bomb),
        Err(Error::ResourceLimit)
    ));
    let mut bad = wire;
    *bad.last_mut().unwrap() ^= 1;
    assert!(Input::decode(&f.context, &bad).is_err());
    assert!(Input::decode(&f.context, &Input::Propose(f.a.clone()).encode().unwrap()).is_err());
    let timeout = super::Timeout::new(&f.context, 0, RoundStep::Propose).unwrap();
    assert!(Input::decode(&f.context, &Input::Timeout(timeout).encode().unwrap()).is_err());
}

fn multi_fixture() -> Fixture {
    let mut f = fixture();
    let rules = Rules::multi_slot(
        [2; 32],
        2048,
        32,
        [100, 200, 300],
        10,
        MAX_RECORD_BYTES as u64,
    )
    .unwrap();
    assert_ne!(rules.id(), f.context.rules().id());
    let seed = NetworkSeed::new(
        rules.seed_domain([3; 32]),
        [4; 32],
        [255; 32],
        Limits::new(16, 4).unwrap(),
    )
    .unwrap();
    let election = seed.bootstrap_election();
    let tickets = f
        .keys
        .iter()
        .map(|k| WorkTicket::sign(&election, k, 0).unwrap())
        .collect();
    f.genesis = Genesis::from_bootstrap(seed, tickets).unwrap();
    f.context = Context::new(rules, [3; 32], &f.genesis, [5; 32], 1, [6; 32]).unwrap();
    f.application = TicketApplication {
        election: election.clone(),
        network: f.genesis.id(),
    };
    f.a = WorkTicket::sign(&election, &f.keys[0], 77)
        .unwrap()
        .encode()
        .to_vec();
    f.b = WorkTicket::sign(&election, &f.keys[0], 78)
        .unwrap()
        .encode()
        .to_vec();
    f
}

#[test]
fn distinct_actual_quorum_subsets_and_rounds_have_one_semantic_successor() {
    let f = multi_fixture();
    let first = f.qc(0, Step::Precommit, &f.a);
    let expected = f
        .context
        .vote(7, Step::Precommit, Some(f.context.value_id(&f.a).unwrap()))
        .unwrap();
    let other_votes: Vec<_> = (1..4)
        .map(|i| f.vote(i, 7, Step::Precommit, Some(&f.a)))
        .collect();
    let other = QuorumCertificate::assemble(f.context.set(), &expected, &other_votes).unwrap();
    assert_ne!(first.encode().unwrap(), other.encode().unwrap());
    let a = f
        .context
        .verify_commit(&f.a, 0, &first.encode().unwrap())
        .unwrap();
    let b = f
        .context
        .verify_commit(&f.a, 7, &other.encode().unwrap())
        .unwrap();
    assert_eq!(a.semantic_id(), b.semantic_id());
    let next = f.context.after_decision(&a).unwrap();
    assert_eq!(next, f.context.after_decision(&b).unwrap());
    assert_eq!(next.previous_decision(), a.semantic_id());
    assert_eq!(next.slot(), 2);
    assert!(
        f.context
            .verify_commit(&f.b, 0, &first.encode().unwrap())
            .is_err()
    );
    assert!(fixture().context.after_decision(&a).is_err());
}

#[test]
fn multi_slot_signer_advances_only_its_durable_decision_and_replays_two_slots() {
    let f = multi_fixture();
    let files = OwnedFiles::new();
    let budget = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
    let mut voter = f.create(&files, "multi", 0, &budget);
    assert!(matches!(voter.advance(), Err(Error::Stale)));
    voter
        .handle(Input::Certificate {
            value: f.a.clone(),
            certificate: f.qc(0, Step::Precommit, &f.a),
        })
        .unwrap();
    let first = voter.decision().unwrap().semantic_id();
    voter.advance().unwrap();
    let next = voter.context().clone();
    assert_eq!(next.slot(), 2);
    assert_eq!(next.previous_decision(), first);
    assert!(voter.locked().is_none());
    assert!(voter.valid().is_none());
    assert_eq!(voter.round(), 0);
    assert!(voter.outbound().unwrap().is_empty());
    let length = voter.file_bytes();
    for step in [Step::Prevote, Step::Precommit] {
        for value in [None, Some(f.a.as_slice())] {
            assert!(
                voter
                    .handle(Input::Vote(f.vote(0, 0, step, value)))
                    .is_err()
            );
        }
    }
    assert_eq!(voter.file_bytes(), length);
    assert!(
        DurableVoter::create_new(
            files.path("wrong-start"),
            next.clone(),
            f.application.clone(),
            f.key(0),
            &budget
        )
        .is_err()
    );
    let expected = next
        .vote(3, Step::Precommit, Some(next.value_id(&f.b).unwrap()))
        .unwrap();
    let votes: Vec<_> = f.keys[..3]
        .iter()
        .map(|key| SignedVote::sign(expected, key).unwrap())
        .collect();
    let qc = QuorumCertificate::assemble(next.set(), &expected, &votes).unwrap();
    voter
        .handle(Input::Certificate {
            value: f.b.clone(),
            certificate: qc,
        })
        .unwrap();
    voter.advance().unwrap();
    let final_context = voter.context().clone();
    assert_eq!(final_context.slot(), 3);
    drop(voter);
    let reopened = DurableVoter::open_existing(
        files.path("multi"),
        f.context.clone(),
        f.application.clone(),
        f.key(0),
        &budget,
    )
    .unwrap();
    assert_eq!(reopened.context(), &final_context);
    assert!(reopened.decision().is_none());
    assert!(reopened.outbound().unwrap().is_empty());
}

#[test]
fn multi_slot_lost_advance_ack_replays_but_partial_advance_never_repairs_or_restarts() {
    let f = multi_fixture();
    let files = OwnedFiles::new();
    let budget = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
    for (name, fault) in [("lost", Fault::AfterSync), ("torn", Fault::Partial(7))] {
        let mut voter = f.create(&files, name, 0, &budget);
        voter
            .handle(Input::Certificate {
                value: f.a.clone(),
                certificate: f.qc(0, Step::Precommit, &f.a),
            })
            .unwrap();
        let next = f.context.after_decision(voter.decision().unwrap()).unwrap();
        voter.inject(fault);
        assert!(matches!(voter.advance(), Err(Error::Io(_))));
        assert!(voter.is_poisoned());
        assert!(voter.outbound().is_err());
        assert!(voter.decision().is_none());
        drop(voter);
        let bytes = fs::read(files.path(name)).unwrap();
        // A fresh process budget registers the ACTUAL uncertain physical extent.
        let reopened = DurableVoter::open_existing(
            files.path(name),
            f.context.clone(),
            f.application.clone(),
            f.key(0),
            &ByteBudget::new(MAX_SHARED_BYTES).unwrap(),
        );
        if name == "lost" {
            assert_eq!(reopened.unwrap().context(), &next);
        } else {
            assert!(matches!(reopened, Err(Error::CorruptWal)));
        }
        assert_eq!(fs::read(files.path(name)).unwrap(), bytes);
    }
}

/// Owns only a newly created PUBLIC test namespace, including fixed child dirs.
struct ParticipantFiles {
    files: OwnedFiles,
}
impl ParticipantFiles {
    fn new() -> Self {
        Self {
            files: OwnedFiles::new(),
        }
    }
    fn root(&self) -> PathBuf {
        self.files.path("participant")
    }
}
impl Drop for ParticipantFiles {
    fn drop(&mut self) {
        let root = self.root();
        for directory in [
            root.join("control"),
            root.join("depot"),
            root.join("custody"),
            root,
        ] {
            if !fs::symlink_metadata(&directory).is_ok_and(|metadata| metadata.file_type().is_dir())
                || directory.canonicalize().ok().as_ref() != Some(&directory)
            {
                continue;
            }
            if let Ok(entries) = fs::read_dir(&directory) {
                for entry in entries
                    .take(protocol_storage::MAX_TRACKED_FILES + 2)
                    .flatten()
                {
                    if entry.file_type().is_ok_and(|kind| kind.is_file()) {
                        let _ = fs::remove_file(entry.path());
                    }
                }
            }
            let _ = fs::remove_dir(directory); // non-recursive, never follows links
        }
    }
}

#[test]
fn participant_wal_precharges_its_header_before_creating_any_file() {
    let f = multi_fixture();
    let files = ParticipantFiles::new();
    // The actual namespace header needs 136 bytes; this leaves one byte less
    // than the actual fixed WAL header (144), without relaxing either limit.
    let quota = ParticipantQuota::create_new(files.root(), [71; 32], 136 + 143).unwrap();
    let path = quota.control_file([72; 32], ControlFile::Wal);
    let result = DurableVoter::create_new(
        &path,
        f.context.clone(),
        f.application.clone(),
        f.key(0),
        &quota.control_budget(),
    );
    assert!(matches!(result, Err(Error::ResourceLimit)));
    assert!(!path.exists());
    assert_eq!(quota.usage().unwrap().total_bytes(), 136);
    assert_eq!(quota.usage().unwrap().tracked_files(), 2);
    assert!(quota.depot_budget().reserve(1).is_ok());
}

#[test]
fn participant_wal_write_and_advance_failures_stop_all_classes_until_strict_reopen() {
    let f = multi_fixture();
    for advancing in [false, true] {
        for fault in [Fault::Partial(7), Fault::BeforeSync, Fault::AfterSync] {
            let files = ParticipantFiles::new();
            let quota = ParticipantQuota::create_new(files.root(), [71; 32], 1_000_000).unwrap();
            let control = quota.control_budget();
            let depot = quota.depot_budget();
            let custody = quota.custody_budget();
            let path = quota.control_file([72; 32], ControlFile::Wal);
            let mut voter = DurableVoter::create_new(
                &path,
                f.context.clone(),
                f.application.clone(),
                f.key(0),
                &control,
            )
            .unwrap();
            if advancing {
                voter
                    .handle(Input::Certificate {
                        value: f.a.clone(),
                        certificate: f.qc(0, Step::Precommit, &f.a),
                    })
                    .unwrap();
            }
            let before = voter.file_bytes();
            voter.inject(fault);
            let result = if advancing {
                voter.advance()
            } else {
                voter
                    .handle(Input::Certificate {
                        value: f.a.clone(),
                        certificate: f.qc(0, Step::Precommit, &f.a),
                    })
                    .map(|_| ())
            };
            assert!(matches!(result, Err(Error::Io(_))));
            assert!(voter.is_poisoned());
            assert!(voter.outbound().is_err());
            assert!(voter.decision().is_none());
            for result in [control.reserve(1), depot.reserve(1), custody.reserve(1)] {
                assert!(matches!(result, Err(protocol_storage::Error::Poisoned)));
            }
            let charged = quota.usage().unwrap().total_bytes();
            drop(voter);
            // Windows prevents even a read through another descriptor while
            // the WAL lock is held; inspect the physical bytes after Drop.
            let bytes = fs::read(&path).unwrap();
            assert!(bytes.len() as u64 > before);
            assert!(charged >= 136 + bytes.len() as u64);
            drop(quota);
            // Even after the parent handle disappears, every descendant budget
            // retains the exclusive namespace lock and conservative accounting.
            assert!(ParticipantQuota::open_existing(files.root(), [71; 32], 1_000_000).is_err());
            drop(control);
            drop(depot);
            drop(custody);
            let reopened =
                ParticipantQuota::open_existing(files.root(), [71; 32], 1_000_000).unwrap();
            assert_eq!(
                reopened.usage().unwrap().total_bytes(),
                136 + bytes.len() as u64
            );
            let voter = DurableVoter::open_existing(
                &path,
                f.context.clone(),
                f.application.clone(),
                f.key(0),
                &reopened.control_budget(),
            );
            if matches!(fault, Fault::Partial(_)) {
                assert!(matches!(voter, Err(Error::CorruptWal)));
            } else {
                let voter = voter.unwrap();
                assert_eq!(voter.context().slot(), if advancing { 2 } else { 1 });
                assert_eq!(voter.decision().is_some(), !advancing);
            }
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
    }
}

#[test]
fn participant_wal_extent_changes_poison_the_shared_namespace_before_any_action() {
    let f = multi_fixture();
    let files = ParticipantFiles::new();
    let quota = ParticipantQuota::create_new(files.root(), [71; 32], 1_000_000).unwrap();
    let path = quota.control_file([72; 32], ControlFile::Wal);
    let mut voter = DurableVoter::create_new(
        &path,
        f.context.clone(),
        f.application.clone(),
        f.key(0),
        &quota.control_budget(),
    )
    .unwrap();
    // A locked Windows file rejects another descriptor's write. The test-only
    // hook changes the actual owned file, rather than mocking metadata/errors.
    voter.append_unaccounted_for_test().unwrap();
    assert!(matches!(
        voter.handle(Input::Propose(f.a.clone())),
        Err(Error::CorruptWal)
    ));
    assert!(voter.outbound().is_err());
    assert!(matches!(
        quota.depot_budget().reserve(1),
        Err(protocol_storage::Error::Poisoned)
    ));
    assert!(matches!(
        quota.custody_budget().reserve(1),
        Err(protocol_storage::Error::Poisoned)
    ));
}

#[derive(Clone)]
struct CountedTicketApplication {
    actual: TicketApplication,
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}
impl ApplicationVerifier for CountedTicketApplication {
    fn verify(
        &self,
        ctx: &ApplicationContext<'_>,
        bytes: &[u8],
    ) -> std::result::Result<(), ApplicationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        // Count the actual pinned work/signature verifier, never AcceptAll.
        self.actual.verify(ctx, bytes)
    }
}
fn counted_ticket_application(
    f: &Fixture,
) -> (
    CountedTicketApplication,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    (
        CountedTicketApplication {
            actual: f.application.clone(),
            calls: calls.clone(),
        },
        calls,
    )
}

#[test]
fn exact_authenticated_remote_proposal_retries_do_not_recheck_or_change_the_owned_wal() {
    let f = fixture();
    let files = OwnedFiles::new();
    let path = files.path("proposal-noop");
    let budget = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
    let (application, calls) = counted_ticket_application(&f);
    let mut voter = DurableVoter::create_new(
        &path,
        f.context.clone(),
        application.clone(),
        f.key(1),
        &budget,
    )
    .unwrap();
    let proposal = f.proposal(0, &f.a, None);
    proposal.verify(&f.context).unwrap();
    let initial = voter.handle(Input::Proposal(proposal.clone())).unwrap();
    assert!(initial.iter().any(|a| matches!(a, Action::Vote(_))));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let persisted = voter.outbound().unwrap();
    let length = voter.file_bytes();
    let used = budget.used().unwrap();
    drop(voter);
    // Read only after releasing the exclusive Windows file lock.
    let exact_wal = fs::read(&path).unwrap();
    let mut voter =
        DurableVoter::open_existing(&path, f.context.clone(), application, f.key(1), &budget)
            .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let encoded = Input::Proposal(proposal.clone()).encode().unwrap();

    // Direct enum inputs and the canonical remote decoder both hit the no-op.
    for _ in 0..16 {
        assert!(
            voter
                .handle(Input::Proposal(proposal.clone()))
                .unwrap()
                .is_empty()
        );
        assert!(voter.handle_bytes(&encoded).unwrap().is_empty());
    }

    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(voter.context(), &f.context);
    assert_eq!(voter.round(), 0);
    assert_eq!(voter.step(), RoundStep::Prevote);
    assert_eq!(voter.locked(), None);
    assert_eq!(voter.valid(), None);
    assert!(voter.decision().is_none());
    assert!(matches!(voter.timeout(), Err(Error::Stale)));
    assert_eq!(voter.outbound().unwrap(), persisted);
    assert_eq!(voter.file_bytes(), length);
    assert_eq!(budget.used().unwrap(), used);
    drop(voter);
    assert_eq!(fs::read(&path).unwrap(), exact_wal);
}

#[test]
fn local_propose_checks_actual_application_once_and_recovery_revalidates_original_signed_actions() {
    let f = fixture();
    let files = OwnedFiles::new();
    let path = files.path("local-propose-once");
    let budget = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
    let (application, calls) = counted_ticket_application(&f);
    let mut voter = DurableVoter::create_new(
        &path,
        f.context.clone(),
        application.clone(),
        f.key(0),
        &budget,
    )
    .unwrap();
    let initial_bytes = voter.file_bytes();
    let initial_used = budget.used().unwrap();

    let actions = voter.handle(Input::Propose(f.a.clone())).unwrap();

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let [Action::Proposal(proposal), Action::Vote(vote)] = actions.as_slice() else {
        panic!("One actual signed proposal precedes its actual non-nil prevote");
    };
    proposal.verify(&f.context).unwrap();
    assert_eq!(proposal.value(), f.a);
    vote.verify(
        f.context.set(),
        &f.context
            .vote(0, Step::Prevote, Some(proposal.value_id()))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(vote.public_key(), f.keys[0].verifying_key().to_bytes());
    assert_eq!(voter.outbound().unwrap(), actions);
    assert_eq!(voter.step(), RoundStep::Prevote);
    assert_eq!(voter.locked(), None);
    assert_eq!(voter.valid(), None);
    assert!(voter.decision().is_none());
    assert!(voter.file_bytes() > initial_bytes);
    assert!(budget.used().unwrap() > initial_used);
    drop(voter);
    let original_wal = fs::read(&path).unwrap();

    // This same-call reduction is not a stored application-success flag.
    // Reopen still invokes the actual captured verifier on the original value.
    let mut rejecting = application.clone();
    rejecting.actual.network = [99; 32];
    assert!(matches!(
        DurableVoter::open_existing(&path, f.context.clone(), rejecting, f.key(0), &budget),
        Err(Error::CorruptWal)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(fs::read(&path).unwrap(), original_wal);
    let reopened =
        DurableVoter::open_existing(&path, f.context.clone(), application, f.key(0), &budget)
            .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(reopened.outbound().unwrap(), actions);
    assert_eq!(reopened.step(), RoundStep::Prevote);
    drop(reopened);
    assert_eq!(fs::read(&path).unwrap(), original_wal);
}

#[test]
fn local_reproposal_checks_the_actual_retained_valid_value_once_not_the_unused_caller_value() {
    let f = fixture();
    let files = OwnedFiles::new();
    let budget = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
    let (application, calls) = counted_ticket_application(&f);
    let mut voter = DurableVoter::create_new(
        files.path("local-valid-reproposal"),
        f.context.clone(),
        application,
        f.key(1),
        &budget,
    )
    .unwrap();
    voter
        .handle(Input::Proposal(f.proposal(0, &f.a, None)))
        .unwrap();
    for n in [0, 2] {
        voter
            .handle(Input::Vote(f.vote(n, 0, Step::Prevote, Some(&f.a))))
            .unwrap();
    }
    let locked = Some((0, f.context.value_id(&f.a).unwrap()));
    assert_eq!(voter.locked(), locked);
    assert_eq!(voter.valid(), locked);
    for n in [0, 2] {
        voter
            .handle(Input::Vote(f.vote(n, 0, Step::Precommit, None)))
            .unwrap();
    }
    voter
        .handle(Input::Timeout(voter.timeout().unwrap()))
        .unwrap();
    assert_eq!(voter.round(), 1);
    assert_eq!(
        f.context.proposer(1).unwrap(),
        f.keys[1].verifying_key().to_bytes()
    );
    let before = calls.load(Ordering::SeqCst);
    let mut unused = f.b.clone();
    *unused.last_mut().unwrap() ^= 1;
    assert!(WorkTicket::decode(&f.application.election, &unused).is_err());

    let actions = voter.handle(Input::Propose(unused)).unwrap();

    assert_eq!(calls.load(Ordering::SeqCst), before + 1);
    let [Action::Proposal(proposal), Action::Vote(vote)] = actions.as_slice() else {
        panic!("The real older POL reproposal precedes its own same-value prevote");
    };
    proposal.verify(&f.context).unwrap();
    assert_eq!(proposal.value(), f.a);
    assert_eq!(proposal.pol().unwrap().context().round(), 0);
    vote.verify(
        f.context.set(),
        &f.context
            .vote(1, Step::Prevote, Some(proposal.value_id()))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(voter.locked(), locked);
    assert_eq!(voter.valid(), locked);
    assert_eq!(voter.step(), RoundStep::Prevote);
    assert!(voter.decision().is_none());
}

#[test]
fn invalid_local_or_authenticated_remote_application_publishes_no_proposal_vote_or_wal_record() {
    let f = fixture();
    let files = OwnedFiles::new();
    let path = files.path("invalid-local-propose");
    let budget = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
    let (application, calls) = counted_ticket_application(&f);
    let voter = DurableVoter::create_new(
        &path,
        f.context.clone(),
        application.clone(),
        f.key(0),
        &budget,
    )
    .unwrap();
    drop(voter); // Read only after releasing the exclusive Windows file lock.
    let original_wal = fs::read(&path).unwrap();
    let mut voter = DurableVoter::open_existing(
        &path,
        f.context.clone(),
        application.clone(),
        f.key(0),
        &budget,
    )
    .unwrap();
    let initial_bytes = voter.file_bytes();
    let initial_used = budget.used().unwrap();
    let initial_timer = voter.timeout().unwrap();
    let mut invalid = f.a.clone();
    *invalid.last_mut().unwrap() ^= 1;
    assert!(WorkTicket::decode(&f.application.election, &invalid).is_err());

    assert!(matches!(
        voter.handle(Input::Propose(invalid.clone())),
        Err(Error::ApplicationRejected)
    ));

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(voter.outbound().unwrap().is_empty());
    assert_eq!(voter.file_bytes(), initial_bytes);
    assert_eq!(budget.used().unwrap(), initial_used);
    assert_eq!(voter.context(), &f.context);
    assert_eq!(voter.round(), 0);
    assert_eq!(voter.step(), RoundStep::Propose);
    assert_eq!(voter.locked(), None);
    assert_eq!(voter.valid(), None);
    assert!(voter.decision().is_none());
    assert_eq!(voter.timeout().unwrap(), initial_timer);

    // A genuine proposer signature/POL is not application correctness. The
    // external path must still invoke the actual verifier and reject this work.
    let remote = f.proposal(0, &invalid, None);
    remote.verify(&f.context).unwrap();
    assert!(matches!(
        voter.handle(Input::Proposal(remote)),
        Err(Error::ApplicationRejected)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(voter.outbound().unwrap().is_empty());
    assert_eq!(voter.file_bytes(), initial_bytes);
    assert_eq!(budget.used().unwrap(), initial_used);
    assert_eq!(voter.context(), &f.context);
    assert_eq!(voter.round(), 0);
    assert_eq!(voter.step(), RoundStep::Propose);
    assert_eq!(voter.locked(), None);
    assert_eq!(voter.valid(), None);
    assert!(voter.decision().is_none());
    assert_eq!(voter.timeout().unwrap(), initial_timer);
    drop(voter);
    assert_eq!(fs::read(&path).unwrap(), original_wal);
    let reopened =
        DurableVoter::open_existing(&path, f.context.clone(), application, f.key(0), &budget)
            .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(reopened.outbound().unwrap().is_empty());
    assert_eq!(reopened.step(), RoundStep::Propose);
    drop(reopened);
    assert_eq!(fs::read(&path).unwrap(), original_wal);
}

#[test]
fn first_prevote_quota_refusal_never_publishes_a_same_value_noop() {
    let f = fixture();
    let files = OwnedFiles::new();
    let path = files.path("first-pol-quota");
    let budget = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
    let (application, calls) = counted_ticket_application(&f);
    let mut voter = DurableVoter::create_new(
        &path,
        f.context.clone(),
        application.clone(),
        f.key(3),
        &budget,
    )
    .unwrap();
    let original = f.qc(0, Step::Prevote, &f.a);
    let expected = f
        .context
        .vote(0, Step::Prevote, Some(f.context.value_id(&f.a).unwrap()))
        .unwrap();
    let votes: Vec<_> = [0, 2, 3]
        .into_iter()
        .map(|n| f.vote(n, 0, Step::Prevote, Some(&f.a)))
        .collect();
    let alternate = QuorumCertificate::assemble(f.context.set(), &expected, &votes).unwrap();
    alternate.verify(f.context.set(), &expected).unwrap();
    assert_ne!(alternate, original);
    let header_bytes = voter.file_bytes();
    let header_used = budget.used().unwrap();
    let full = budget.reserve(MAX_SHARED_BYTES - header_used).unwrap();

    // Both genuine QCs reach the actual app check, then the REAL file quota
    // refuses the first record. A prepared clone is never the retained POL.
    for certificate in [original.clone(), alternate.clone()] {
        assert!(matches!(
            voter.handle(Input::Certificate {
                value: f.a.clone(),
                certificate,
            }),
            Err(Error::ResourceLimit)
        ));
        assert!(!voter.is_poisoned());
        assert_eq!(voter.file_bytes(), header_bytes);
        assert_eq!(fs::metadata(&path).unwrap().len(), header_bytes);
        assert_eq!(budget.used().unwrap(), MAX_SHARED_BYTES);
        assert_eq!(voter.step(), RoundStep::Propose);
        assert_eq!(voter.locked(), None);
        assert_eq!(voter.valid(), None);
        assert!(voter.outbound().unwrap().is_empty());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    drop(full);
    assert_eq!(budget.used().unwrap(), header_used);

    assert!(
        voter
            .handle(Input::Certificate {
                value: f.a.clone(),
                certificate: alternate.clone(),
            })
            .unwrap()
            .is_empty()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert!(voter.file_bytes() > header_bytes);
    let admitted_bytes = voter.file_bytes();
    let admitted_used = budget.used().unwrap();
    assert!(
        voter
            .handle(Input::Certificate {
                value: f.a.clone(),
                certificate: original,
            })
            .unwrap()
            .is_empty()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(voter.file_bytes(), admitted_bytes);
    assert_eq!(budget.used().unwrap(), admitted_used);
    let out = voter
        .handle(Input::Proposal(f.proposal(0, &f.a, None)))
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    assert!(out.iter().any(|a| matches!(a,
        Action::Certificate { certificate, .. } if certificate == &alternate
    )));
    let locked = Some((0, f.context.value_id(&f.a).unwrap()));
    assert_eq!(voter.locked(), locked);
    let persisted = voter.outbound().unwrap();
    drop(voter);
    let exact_wal = fs::read(&path).unwrap();
    let reopened =
        DurableVoter::open_existing(&path, f.context.clone(), application, f.key(3), &budget)
            .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 6);
    assert_eq!(reopened.locked(), locked);
    assert_eq!(reopened.outbound().unwrap(), persisted);
    drop(reopened);
    assert_eq!(fs::read(&path).unwrap(), exact_wal);
}

#[test]
fn first_prevote_lost_sync_ack_requires_recovery_before_same_value_noop() {
    let f = fixture();
    let files = OwnedFiles::new();
    let path = files.path("first-pol-lost-ack");
    let budget = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
    let (application, calls) = counted_ticket_application(&f);
    let mut voter = DurableVoter::create_new(
        &path,
        f.context.clone(),
        application.clone(),
        f.key(3),
        &budget,
    )
    .unwrap();
    let original = f.qc(0, Step::Prevote, &f.a);
    let expected = f
        .context
        .vote(0, Step::Prevote, Some(f.context.value_id(&f.a).unwrap()))
        .unwrap();
    let votes: Vec<_> = [0, 2, 3]
        .into_iter()
        .map(|n| f.vote(n, 0, Step::Prevote, Some(&f.a)))
        .collect();
    let alternate = QuorumCertificate::assemble(f.context.set(), &expected, &votes).unwrap();
    alternate.verify(f.context.set(), &expected).unwrap();
    assert_ne!(alternate, original);
    voter.inject(Fault::AfterSync);
    assert!(matches!(
        voter.handle(Input::Certificate {
            value: f.a.clone(),
            certificate: original.clone(),
        }),
        Err(Error::Io(_))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(voter.is_poisoned());
    assert!(matches!(voter.outbound(), Err(Error::Poisoned)));
    assert!(fs::metadata(&path).unwrap().len() > voter.file_bytes());
    let charged = budget.used().unwrap();
    assert!(matches!(
        voter.handle(Input::Certificate {
            value: f.a.clone(),
            certificate: alternate.clone(),
        }),
        Err(Error::Poisoned)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(budget.used().unwrap(), charged);
    drop(voter);
    let lost_ack_record = fs::read(&path).unwrap();

    // Reconstruct actual retained bytes with a fresh process budget. The first
    // durable POL MUST call the real app verifier again during this recovery.
    let recovered_budget = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
    let mut reopened = DurableVoter::open_existing(
        &path,
        f.context.clone(),
        application.clone(),
        f.key(3),
        &recovered_budget,
    )
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let length = reopened.file_bytes();
    let used = recovered_budget.used().unwrap();
    assert_eq!(length, lost_ack_record.len() as u64);
    assert!(
        reopened
            .handle(Input::Certificate {
                value: f.a.clone(),
                certificate: alternate,
            })
            .unwrap()
            .is_empty()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(reopened.file_bytes(), length);
    assert_eq!(recovered_budget.used().unwrap(), used);
    assert!(reopened.outbound().unwrap().is_empty());
    assert_eq!(reopened.locked(), None);
    let out = reopened
        .handle(Input::Proposal(f.proposal(0, &f.a, None)))
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert!(out.iter().any(|a| matches!(a,
        Action::Certificate { certificate, .. } if certificate == &original
    )));
    let persisted = reopened.outbound().unwrap();
    let locked = Some((0, f.context.value_id(&f.a).unwrap()));
    assert_eq!(reopened.locked(), locked);
    drop(reopened);
    let exact_wal = fs::read(&path).unwrap();
    assert!(exact_wal.starts_with(&lost_ack_record));
    let recovered = DurableVoter::open_existing(
        &path,
        f.context.clone(),
        application,
        f.key(3),
        &recovered_budget,
    )
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 5);
    assert_eq!(recovered.outbound().unwrap(), persisted);
    assert_eq!(recovered.locked(), locked);
    drop(recovered);
    assert_eq!(fs::read(&path).unwrap(), exact_wal);
}

#[test]
fn altered_proposals_and_invalid_authentication_never_use_the_exact_remote_noop() {
    let f = fixture();
    let files = OwnedFiles::new();
    let budget = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
    let (application, calls) = counted_ticket_application(&f);
    let mut voter = DurableVoter::create_new(
        files.path("proposal-auth"),
        f.context.clone(),
        application,
        f.key(0),
        &budget,
    )
    .unwrap();
    // Real same-round future weight enters round one without an app proposal.
    for n in [1, 2] {
        voter
            .handle(Input::Vote(f.vote(n, 1, Step::Prevote, None)))
            .unwrap();
    }
    assert_eq!(voter.round(), 1);
    let proposal = f.proposal(1, &f.a, None);
    voter.handle(Input::Proposal(proposal.clone())).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let length = voter.file_bytes();
    let used = budget.used().unwrap();
    let persisted = voter.outbound().unwrap();
    let timer = voter.timeout().unwrap();

    // Same value and round, but a different genuine POL/signature: full Eq is
    // essential. Both proposals authenticate independently before the Act.
    let with_pol = f.proposal(1, &f.a, Some(f.qc(0, Step::Prevote, &f.a)));
    with_pol.verify(&f.context).unwrap();
    assert_ne!(with_pol, proposal);
    assert!(matches!(
        voter.handle(Input::Proposal(with_pol.clone())),
        Err(Error::Equivocation)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let different = f.proposal(1, &f.b, None);
    different.verify(&f.context).unwrap();
    WorkTicket::decode(&f.application.election, &f.b).unwrap();
    assert!(matches!(
        voter.handle(Input::Proposal(different)),
        Err(Error::Equivocation)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    let mut bad_ticket = f.a.clone();
    *bad_ticket.last_mut().unwrap() ^= 1;
    let signed_bad_ticket = f.proposal(1, &bad_ticket, None);
    signed_bad_ticket.verify(&f.context).unwrap();
    assert!(matches!(
        voter.handle(Input::Proposal(signed_bad_ticket)),
        Err(Error::ApplicationRejected)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 4);

    let foreign_context = Context::new(rules(), [3; 32], &f.genesis, [5; 32], 1, [77; 32]).unwrap();
    let foreign_key = f
        .keys
        .iter()
        .find(|key| key.verifying_key().to_bytes() == foreign_context.proposer(1).unwrap())
        .unwrap();
    let foreign = Proposal::sign(&foreign_context, 1, f.a.clone(), None, foreign_key).unwrap();
    foreign.verify(&foreign_context).unwrap();
    assert!(matches!(
        voter.handle(Input::Proposal(foreign)),
        Err(Error::WrongContext)
    ));
    for round in [0, 2] {
        let other_round = f.proposal(round, &f.a, None);
        other_round.verify(&f.context).unwrap();
        assert!(matches!(
            voter.handle(Input::Proposal(other_round)),
            Err(Error::Stale)
        ));
    }
    let mut bad_signature = proposal.encode().unwrap();
    // DCSWFP01, Context32, round8, value32, POL-round8, proposer32.
    bad_signature[8 + 32 + 8 + 32 + 8 + 32] ^= 1;
    assert!(Proposal::decode(&f.context, &bad_signature).is_err());
    let mut bad_pol = with_pol.encode().unwrap();
    *bad_pol.last_mut().unwrap() ^= 1;
    assert!(Proposal::decode(&f.context, &bad_pol).is_err());
    let mut trailing = Input::Proposal(proposal).encode().unwrap();
    trailing.push(0);
    assert!(voter.handle_bytes(&trailing).is_err());

    assert_eq!(calls.load(Ordering::SeqCst), 4);
    assert_eq!(voter.context(), &f.context);
    assert_eq!(voter.round(), 1);
    assert_eq!(voter.step(), RoundStep::Prevote);
    assert_eq!(voter.locked(), None);
    assert_eq!(voter.valid(), None);
    assert!(voter.decision().is_none());
    assert_eq!(voter.timeout().unwrap(), timer);
    assert_eq!(voter.outbound().unwrap(), persisted);
    assert_eq!(voter.file_bytes(), length);
    assert_eq!(budget.used().unwrap(), used);
}

#[test]
fn remote_proposal_noop_preserves_local_signing_locked_wal_replay_and_stale_after_decision() {
    let f = fixture();
    let files = OwnedFiles::new();
    let path = files.path("proposal-locked-replay");
    let budget = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
    let (application, calls) = counted_ticket_application(&f);
    let mut voter = DurableVoter::create_new(
        &path,
        f.context.clone(),
        application.clone(),
        f.key(0),
        &budget,
    )
    .unwrap();
    let initial = voter.handle(Input::Propose(f.a.clone())).unwrap();
    // Owner-local Propose checks the actual application once before signing;
    // only that same apply's own receive/prevote path shares the result.
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let proposal = initial
        .iter()
        .find_map(|action| match action {
            Action::Proposal(p) => Some(p.clone()),
            _ => None,
        })
        .unwrap();
    for n in [1, 2] {
        voter
            .handle(Input::Vote(f.vote(n, 0, Step::Prevote, Some(&f.a))))
            .unwrap();
    }
    let locked = Some((0, f.context.value_id(&f.a).unwrap()));
    assert_eq!(voter.locked(), locked);
    assert_eq!(voter.valid(), locked);
    assert_eq!(voter.step(), RoundStep::Precommit);
    let persisted = voter.outbound().unwrap();
    let length = voter.file_bytes();
    let used = budget.used().unwrap();
    drop(voter);
    let exact_old_records = fs::read(&path).unwrap();
    let mut voter = DurableVoter::open_existing(
        &path,
        f.context.clone(),
        application.clone(),
        f.key(0),
        &budget,
    )
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(voter.outbound().unwrap(), persisted);
    assert_eq!(voter.locked(), locked);
    assert_eq!(voter.valid(), locked);
    assert!(
        voter
            .handle(Input::Proposal(proposal.clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(voter.outbound().unwrap(), persisted);
    assert_eq!(voter.locked(), locked);
    assert_eq!(voter.valid(), locked);
    assert_eq!(voter.file_bytes(), length);
    assert_eq!(budget.used().unwrap(), used);
    drop(voter);
    assert_eq!(fs::read(&path).unwrap(), exact_old_records);

    let mut voter = DurableVoter::open_existing(
        &path,
        f.context.clone(),
        application.clone(),
        f.key(0),
        &budget,
    )
    .unwrap();
    voter
        .handle(Input::Certificate {
            value: f.a.clone(),
            certificate: f.qc(0, Step::Precommit, &f.a),
        })
        .unwrap();
    let decision = voter.decision().unwrap().clone();
    let decided_actions = voter.outbound().unwrap();
    let before_stale = calls.load(Ordering::SeqCst);
    let decided_bytes = voter.file_bytes();
    let decided_used = budget.used().unwrap();
    // The original decision guard must win over the exact-duplicate branch.
    assert!(matches!(
        voter.handle(Input::Proposal(proposal)),
        Err(Error::Stale)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), before_stale);
    assert_eq!(voter.file_bytes(), decided_bytes);
    assert_eq!(budget.used().unwrap(), decided_used);
    drop(voter);
    let exact_decided_wal = fs::read(&path).unwrap();
    assert!(exact_decided_wal.starts_with(&exact_old_records));
    let before_replay = calls.load(Ordering::SeqCst);
    let reopened =
        DurableVoter::open_existing(&path, f.context.clone(), application, f.key(0), &budget)
            .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), before_replay + 2);
    assert_eq!(reopened.decision(), Some(&decision));
    assert_eq!(reopened.outbound().unwrap(), decided_actions);
    assert_eq!(reopened.locked(), locked);
    assert_eq!(reopened.valid(), locked);
    drop(reopened);
    assert_eq!(fs::read(&path).unwrap(), exact_decided_wal);
}

#[test]
fn exact_current_prevote_qc_retries_do_not_replay_or_hide_new_evidence() {
    let f = fixture();
    let files = OwnedFiles::new();
    let path = files.path("prevote-noop");
    let budget = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
    let (application, calls) = counted_ticket_application(&f);
    let mut voter = DurableVoter::create_new(
        &path,
        f.context.clone(),
        application.clone(),
        f.key(3),
        &budget,
    )
    .unwrap();
    let certificate = f.qc(0, Step::Prevote, &f.a);
    let input = Input::Certificate {
        value: f.a.clone(),
        certificate: certificate.clone(),
    };
    assert!(voter.handle(input.clone()).unwrap().is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let length = voter.file_bytes();
    let used = budget.used().unwrap();
    let timer = voter.timeout().unwrap();
    drop(voter);
    let first_pol_record = fs::read(&path).unwrap();
    let mut voter = DurableVoter::open_existing(
        &path,
        f.context.clone(),
        application.clone(),
        f.key(3),
        &budget,
    )
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let encoded = input.encode().unwrap();
    for _ in 0..16 {
        assert!(voter.handle(input.clone()).unwrap().is_empty());
        assert!(voter.handle_bytes(&encoded).unwrap().is_empty());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(voter.context(), &f.context);
    assert_eq!(voter.round(), 0);
    assert_eq!(voter.step(), RoundStep::Propose);
    assert_eq!(voter.timeout().unwrap(), timer);
    assert_eq!(voter.locked(), None);
    assert_eq!(voter.valid(), None);
    assert!(voter.outbound().unwrap().is_empty());
    assert_eq!(voter.file_bytes(), length);
    assert_eq!(budget.used().unwrap(), used);

    // Another genuine signer subset adds no new protocol facts for these exact
    // current value bytes. The original independently verified QC stays stored.
    let expected = f
        .context
        .vote(0, Step::Prevote, Some(f.context.value_id(&f.a).unwrap()))
        .unwrap();
    let votes: Vec<_> = [0, 2, 3]
        .into_iter()
        .map(|n| f.vote(n, 0, Step::Prevote, Some(&f.a)))
        .collect();
    let alternate = QuorumCertificate::assemble(f.context.set(), &expected, &votes).unwrap();
    alternate.verify(f.context.set(), &expected).unwrap();
    assert_ne!(alternate, certificate);
    assert!(
        voter
            .handle(Input::Certificate {
                value: f.a.clone(),
                certificate: alternate.clone(),
            })
            .unwrap()
            .is_empty()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(matches!(
        voter.handle(Input::Certificate {
            value: f.b.clone(),
            certificate: f.qc(0, Step::Prevote, &f.b),
        }),
        Err(Error::Equivocation)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(voter.file_bytes(), length);
    assert_eq!(budget.used().unwrap(), used);

    // The first POL ran drive without a proposal. A NEW genuine proposal must
    // still introduce that missing evidence and produce the actual lock/vote.
    let out = voter
        .handle(Input::Proposal(f.proposal(0, &f.a, None)))
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    assert!(
        out.iter()
            .any(|a| matches!(a, Action::Vote(v) if v.context().step() == Step::Precommit))
    );
    let locked = Some((0, f.context.value_id(&f.a).unwrap()));
    assert_eq!(voter.locked(), locked);
    assert_eq!(voter.valid(), locked);
    assert_eq!(voter.step(), RoundStep::Precommit);
    assert!(out.iter().any(|a| matches!(a,
        Action::Certificate { certificate: retained, .. } if retained == &certificate
    )));
    let persisted = voter.outbound().unwrap();
    let locked_length = voter.file_bytes();
    let locked_used = budget.used().unwrap();
    assert!(
        voter
            .handle(Input::Certificate {
                value: f.a.clone(),
                certificate: alternate.clone(),
            })
            .unwrap()
            .is_empty()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    assert_eq!(voter.outbound().unwrap(), persisted);
    assert_eq!(voter.locked(), locked);
    assert_eq!(voter.valid(), locked);
    assert_eq!(voter.file_bytes(), locked_length);
    assert_eq!(budget.used().unwrap(), locked_used);
    drop(voter);
    let locked_records = fs::read(&path).unwrap();
    assert!(locked_records.starts_with(&first_pol_record));
    let mut reopened =
        DurableVoter::open_existing(&path, f.context.clone(), application, f.key(3), &budget)
            .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 6);
    let used = budget.used().unwrap();
    let length = reopened.file_bytes();
    assert!(reopened.handle(input).unwrap().is_empty());
    assert!(
        reopened
            .handle(Input::Certificate {
                value: f.a.clone(),
                certificate: alternate,
            })
            .unwrap()
            .is_empty()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 6);
    assert_eq!(reopened.outbound().unwrap(), persisted);
    assert_eq!(reopened.locked(), locked);
    assert_eq!(reopened.valid(), locked);
    assert_eq!(reopened.file_bytes(), length);
    assert_eq!(budget.used().unwrap(), used);
    drop(reopened);
    assert_eq!(fs::read(&path).unwrap(), locked_records);
}

#[test]
fn noncurrent_prevote_is_authenticated_without_app_replay_but_old_precommit_stays_fresh() {
    let f = multi_fixture();
    let files = OwnedFiles::new();
    let path = files.path("certificate-rounds");
    let budget = ByteBudget::new(MAX_SHARED_BYTES).unwrap();
    let (application, calls) = counted_ticket_application(&f);
    let mut voter = DurableVoter::create_new(
        &path,
        f.context.clone(),
        application.clone(),
        f.key(0),
        &budget,
    )
    .unwrap();
    for n in [1, 2] {
        voter
            .handle(Input::Vote(f.vote(n, 1, Step::Prevote, None)))
            .unwrap();
    }
    assert_eq!(voter.round(), 1);
    let length = voter.file_bytes();
    let used = budget.used().unwrap();
    let timer = voter.timeout().unwrap();
    for round in [0, 2] {
        let input = Input::Certificate {
            value: f.a.clone(),
            certificate: f.qc(round, Step::Prevote, &f.a),
        };
        assert!(matches!(voter.handle(input.clone()), Err(Error::Stale)));
        assert!(matches!(
            voter.handle_bytes(&input.encode().unwrap()),
            Err(Error::Stale)
        ));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let foreign_context = Context::new(
        f.context.rules().clone(),
        [3; 32],
        &f.genesis,
        [5; 32],
        1,
        [88; 32],
    )
    .unwrap();
    let foreign_vote = foreign_context
        .vote(
            1,
            Step::Prevote,
            Some(foreign_context.value_id(&f.a).unwrap()),
        )
        .unwrap();
    let foreign_votes: Vec<_> = f.keys[..3]
        .iter()
        .map(|key| SignedVote::sign(foreign_vote, key).unwrap())
        .collect();
    let foreign =
        QuorumCertificate::assemble(foreign_context.set(), &foreign_vote, &foreign_votes).unwrap();
    foreign
        .verify(foreign_context.set(), &foreign_vote)
        .unwrap();
    assert!(
        voter
            .handle(Input::Certificate {
                value: f.a.clone(),
                certificate: foreign
            })
            .is_err()
    );
    assert!(
        voter
            .handle(Input::Certificate {
                value: f.b.clone(),
                certificate: f.qc(1, Step::Prevote, &f.a),
            })
            .is_err()
    );
    let mut bad_signature = Input::Certificate {
        value: f.a.clone(),
        certificate: f.qc(1, Step::Prevote, &f.a),
    }
    .encode()
    .unwrap();
    *bad_signature.last_mut().unwrap() ^= 1;
    assert!(voter.handle_bytes(&bad_signature).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(voter.context(), &f.context);
    assert_eq!(voter.round(), 1);
    assert_eq!(voter.step(), RoundStep::Propose);
    assert_eq!(voter.timeout().unwrap(), timer);
    assert_eq!(voter.locked(), None);
    assert_eq!(voter.valid(), None);
    assert!(voter.decision().is_none());
    assert!(voter.outbound().unwrap().is_empty());
    assert_eq!(voter.file_bytes(), length);
    assert_eq!(budget.used().unwrap(), used);

    // A real older-round quorum is still insufficient for an invalid work
    // application. Only the actual application verifier may reject this value.
    let mut bad_ticket = f.a.clone();
    *bad_ticket.last_mut().unwrap() ^= 1;
    assert!(matches!(
        voter.handle(Input::Certificate {
            certificate: f.qc(0, Step::Precommit, &bad_ticket),
            value: bad_ticket,
        }),
        Err(Error::ApplicationRejected)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(voter.decision().is_none());
    assert_eq!(voter.file_bytes(), length);
    assert_eq!(budget.used().unwrap(), used);

    let out = voter
        .handle(Input::Certificate {
            value: f.a.clone(),
            certificate: f.qc(0, Step::Precommit, &f.a),
        })
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(out.iter().any(|a| matches!(a, Action::Decided(_))));
    let decision = voter.decision().unwrap().clone();
    assert_eq!(decision.certificate().context().round(), 0);
    voter.advance().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    let next = voter.context().clone();
    assert_eq!(next.slot(), 2);
    assert_eq!(next.previous_decision(), decision.semantic_id());
    let used = budget.used().unwrap();
    drop(voter);
    let exact_wal = fs::read(&path).unwrap();

    // Recovery still executes the actual application, not a stored QC receipt.
    let mut rejecting = application.clone();
    rejecting.actual.network = [99; 32];
    assert!(matches!(
        DurableVoter::open_existing(&path, f.context.clone(), rejecting, f.key(0), &budget,),
        Err(Error::CorruptWal)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    assert_eq!(fs::read(&path).unwrap(), exact_wal);
    let reopened =
        DurableVoter::open_existing(&path, f.context.clone(), application, f.key(0), &budget)
            .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 6);
    assert_eq!(reopened.context(), &next);
    assert!(reopened.decision().is_none());
    assert!(reopened.outbound().unwrap().is_empty());
    assert_eq!(budget.used().unwrap(), used);
    drop(reopened);
    assert_eq!(fs::read(&path).unwrap(), exact_wal);
}
