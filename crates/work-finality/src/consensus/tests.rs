//! PUBLIC, NON-SECRET keys and real local filesystem/signature tests. These are
//! protocol-kernel scenarios, not independently running DCS peers or SQL proofs.
use super::{
    Action, ApplicationContext, ApplicationError, ApplicationVerifier, ByteBudget, Context,
    DurableVoter, Error, Input, MAX_RECORD_BYTES, MAX_SHARED_BYTES, Proposal, RoundStep, Rules,
    wal::Fault,
};
use crate::{
    Election, Genesis, Hash, Limits, NetworkSeed, QuorumCertificate, SignedVote, Step, WorkTicket,
};
use ed25519_dalek::SigningKey;
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
