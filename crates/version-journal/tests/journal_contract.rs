//! Public deterministic fixtures are non-secret. Easy work tests protocol behavior;
//! it provides no claim about an adequately funded permissionless deployment.
use std::cell::Cell;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::SigningKey;
use num_bigint::BigUint;
use version_journal::{
    AuthorizedTransition, Body, DurableJournal, Error, Freshness, Genesis, Hash, HeadPair, Header,
    Journal, ProtocolProfile, RejectUnprovedTransitions, ShardState, ShardUpdate, Target,
    TransitionStatement, TransitionVerifier, hash,
};

fn target(first: u8) -> Target {
    let mut bytes = [255; 32];
    bytes[0] = first;
    Target(bytes)
}
fn genesis() -> Genesis {
    Genesis {
        network_id: [1; 32],
        database: [2; 16],
        owner: SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes(),
        application_commitment: [4; 32],
        timestamp: 1000,
        profile: ProtocolProfile {
            initial_target: target(31),
            pow_limit: target(127),
            block_spacing_secs: 10,
            retarget_interval: 2,
            max_future_secs: 60,
            confirmation_depth: 1,
            max_headers: 128,
            max_shards: 8,
            max_updates: 8,
            max_body_bytes: 4096,
            max_request_bytes: 256,
            max_proof_bytes: 1024,
            max_journal_bytes: 1024 * 1024,
        },
        initial_shards: vec![ShardState {
            id: 7,
            heads: HeadPair {
                data: [5; 112],
                index: [6; 112],
            },
        }],
    }
}
fn empty_block(journal: &Journal, parent: Hash, timestamp: u64) -> (Header, Vec<u8>) {
    let body = Body::Empty.encode(journal.profile()).unwrap();
    let mut header = journal.candidate(parent, &Body::Empty, timestamp).unwrap();
    header.mine(100_000).unwrap();
    (header, body)
}
fn add_empty(journal: &mut Journal, parent: Hash, timestamp: u64) -> Hash {
    let (header, body) = empty_block(journal, parent, timestamp);
    journal
        .import_block(header, &body, 10_000, &RejectUnprovedTransitions)
        .unwrap()
        .block
}
fn signed_transition(journal: &Journal) -> Body {
    let old = journal.genesis().initial_shards[0].heads;
    let mut transition = AuthorizedTransition {
        parent: journal.genesis_id(),
        request: b"encrypted request fixture".to_vec(),
        updates: vec![ShardUpdate {
            id: 7,
            old,
            new: HeadPair {
                data: [8; 112],
                index: [9; 112],
            },
        }],
        // Deliberately invalid proof bytes, used only for rejection tests.
        proof: b"invalid proof fixture".to_vec(),
        owner_signature: [0; 64],
    };
    transition.sign(journal.genesis_id(), &SigningKey::from_bytes(&[3; 32]));
    Body::Transition(transition)
}

#[test]
fn full_width_targets_measure_exact_work_without_overflow() {
    assert_eq!(Target([255; 32]).work().unwrap(), BigUint::from(1u8));
    assert_eq!(target(127).work().unwrap(), BigUint::from(2u8));
    assert_eq!(target(31).work().unwrap(), BigUint::from(8u8));
    let mut minimum = [0; 32];
    minimum[31] = 1;
    assert_eq!(
        Target(minimum).work().unwrap(),
        BigUint::from(1u8) << 255usize
    );
    assert_eq!(Target([0; 32]).work(), Err(Error::InvalidTarget));
    assert!(Target(minimum).permits([0; 32]));
    assert!(!Target(minimum).permits([255; 32]));
}

#[test]
fn shorter_higher_work_branch_reorganizes_the_longer_chain() {
    let mut journal = Journal::new(genesis()).unwrap();
    let root = journal.genesis_id();
    let mut slow = root;
    for time in [1040, 1080, 1120, 1160, 1200] {
        slow = add_empty(&mut journal, slow, time);
    }
    let old_confirmed = journal.resolve(Freshness::LatestConfirmed).unwrap();
    assert_eq!(old_confirmed.height, 4);
    assert_eq!(journal.cumulative_work(slow).unwrap(), BigUint::from(22u8));

    let fast_one = add_empty(&mut journal, root, 1001);
    let fast_two = add_empty(&mut journal, fast_one, 1002);
    let (header, body) = empty_block(&journal, fast_two, 1003);
    let outcome = journal
        .import_block(header, &body, 10_000, &RejectUnprovedTransitions)
        .unwrap();

    assert_eq!(journal.best_validated().height, 3);
    assert_eq!(
        journal.cumulative_work(outcome.block).unwrap(),
        BigUint::from(48u8)
    );
    let reorg = outcome.reorganization.unwrap();
    assert_eq!(reorg.common_ancestor, root);
    assert_eq!(reorg.detached.len(), 5);
    assert_eq!(reorg.attached, vec![fast_one, fast_two, outcome.block]);
    assert_eq!(
        journal.resolve(Freshness::AtLeast(old_confirmed)),
        Err(Error::Reorganized)
    );
    let confirmed = journal.resolve(Freshness::LatestConfirmed).unwrap();
    assert_eq!(confirmed.block, fast_two);
    assert_eq!(
        journal.resolve(Freshness::Exact(confirmed)).unwrap(),
        confirmed
    );
}

#[test]
fn retarget_is_branch_local_and_clamped_in_both_directions() {
    let mut journal = Journal::new(genesis()).unwrap();
    let root = journal.genesis_id();
    let fast1 = add_empty(&mut journal, root, 1001);
    let fast2 = add_empty(&mut journal, fast1, 1002);
    let slow1 = add_empty(&mut journal, root, 1040);
    let slow2 = add_empty(&mut journal, slow1, 1080);
    assert_eq!(
        journal.next_target(fast2).unwrap().work().unwrap(),
        BigUint::from(32u8)
    );
    let mut exact_four_times = target(127);
    exact_four_times.0[31] = 252;
    assert_eq!(journal.next_target(slow2).unwrap(), exact_four_times);

    let (mut header, body) = empty_block(&journal, fast2, 1003);
    header.target = target(31);
    header.nonce = 0;
    header.mine(100_000).unwrap();
    assert_eq!(
        journal.import_block(header, &body, 10_000, &RejectUnprovedTransitions),
        Err(Error::InvalidTarget)
    );
}

#[test]
fn invalid_work_and_median_or_future_timestamps_are_rejected() {
    let mut journal = Journal::new(genesis()).unwrap();
    let (valid, body) = empty_block(&journal, journal.genesis_id(), 1001);
    let mut wrong_work = valid.clone();
    while wrong_work.target.permits(wrong_work.id()) {
        wrong_work.nonce += 1;
    }
    assert_eq!(
        journal.import_block(wrong_work, &body, 1001, &RejectUnprovedTransitions),
        Err(Error::InvalidWork)
    );
    for timestamp in [1000, 1062] {
        let mut wrong_time = valid.clone();
        wrong_time.timestamp = timestamp;
        wrong_time.nonce = 0;
        wrong_time.mine(100_000).unwrap();
        assert_eq!(
            journal.import_block(wrong_time, &body, 1001, &RejectUnprovedTransitions),
            Err(Error::InvalidTimestamp)
        );
    }
    assert_eq!(journal.header_count(), 0);
}

#[test]
fn unconfirmed_write_tokens_cannot_silently_fall_back_to_ancestors() {
    let mut journal = Journal::new(genesis()).unwrap();
    let root = journal.genesis_id();
    let one = add_empty(&mut journal, root, 1001);
    let token = journal.best_validated();
    assert_eq!(
        journal.resolve(Freshness::AtLeast(token)),
        Err(Error::Unconfirmed)
    );
    assert_eq!(
        journal.resolve(Freshness::Exact(token)),
        Err(Error::Unconfirmed)
    );
    add_empty(&mut journal, one, 1010);
    assert_eq!(journal.resolve(Freshness::AtLeast(token)).unwrap(), token);
    let mut forged = token;
    forged.state_root[0] ^= 1;
    assert_eq!(
        journal.resolve(Freshness::AtLeast(forged)),
        Err(Error::InvalidTransition)
    );
    let mut other_network = token;
    other_network.genesis[0] ^= 1;
    assert_eq!(
        journal.resolve(Freshness::Exact(other_network)),
        Err(Error::WrongDomain)
    );
}

#[test]
fn a_heavier_header_with_an_unavailable_body_blocks_freshness() {
    let mut journal = Journal::new(genesis()).unwrap();
    let root = journal.genesis_id();
    let one = add_empty(&mut journal, root, 1001);
    let (header, body) = empty_block(&journal, one, 1010);
    let id = journal.import_header(header, 10_000).unwrap();
    assert_eq!(journal.best_validated().block, one);
    assert_eq!(
        journal.resolve(Freshness::LatestConfirmed),
        Err(Error::BodyUnavailable)
    );
    journal
        .import_body(id, &body, &RejectUnprovedTransitions)
        .unwrap();
    assert_eq!(
        journal.resolve(Freshness::LatestConfirmed).unwrap().block,
        one
    );
}

#[test]
fn uncommitted_wrong_body_cannot_poison_a_valid_header() {
    let mut journal = Journal::new(genesis()).unwrap();
    let (header, body) = empty_block(&journal, journal.genesis_id(), 1001);
    let id = journal.import_header(header, 10_000).unwrap();
    assert_eq!(
        journal.import_body(id, b"wrong bytes", &RejectUnprovedTransitions),
        Err(Error::InvalidBody)
    );
    assert_eq!(journal.best_header(), id);
    assert_eq!(
        journal
            .import_body(id, &body, &RejectUnprovedTransitions)
            .unwrap()
            .block,
        id
    );
    assert_eq!(
        journal.import_body(id, b"wrong bytes", &RejectUnprovedTransitions),
        Err(Error::InvalidBody)
    );
}

struct RejectAndInspect {
    calls: Cell<usize>,
}
impl TransitionVerifier for RejectAndInspect {
    fn verify(&self, statement: TransitionStatement<'_>) -> version_journal::Result<()> {
        self.calls.set(self.calls.get() + 1);
        assert_eq!(statement.application_commitment, [4; 32]);
        assert_eq!(statement.request, b"encrypted request fixture");
        assert_eq!(statement.previous_shards[0].heads, statement.updates[0].old);
        assert_eq!(statement.next_shards[0].heads, statement.updates[0].new);
        Err(Error::RejectedComputationProof)
    }
}

#[test]
fn a_valid_owner_signature_and_work_never_substitute_for_a_computation_proof() {
    let mut journal = Journal::new(genesis()).unwrap();
    let body = signed_transition(&journal);
    let wire = body.encode(journal.profile()).unwrap();
    let mut header = journal
        .candidate(journal.genesis_id(), &body, 1001)
        .unwrap();
    header.mine(100_000).unwrap();
    let verifier = RejectAndInspect {
        calls: Cell::new(0),
    };

    assert_eq!(
        journal.import_block(header.clone(), &wire, 10_000, &verifier),
        Err(Error::RejectedComputationProof)
    );
    assert_eq!(verifier.calls.get(), 1);
    assert_eq!(journal.header_count(), 0);
    assert_eq!(journal.best_validated(), journal.genesis_head());
    assert_eq!(
        journal.import_block(header, &wire, 10_000, &RejectUnprovedTransitions),
        Err(Error::MissingComputationProof)
    );
}

#[test]
fn unauthorized_or_replayed_transitions_never_reach_the_proof_backend() {
    let mut journal = Journal::new(genesis()).unwrap();
    let verifier = RejectAndInspect {
        calls: Cell::new(0),
    };
    let mut body = signed_transition(&journal);
    let Body::Transition(transition) = &mut body else {
        unreachable!()
    };
    transition.owner_signature[0] ^= 1;
    let mut header = journal
        .candidate(journal.genesis_id(), &body, 1001)
        .unwrap();
    header.mine(100_000).unwrap();
    let wire = body.encode(journal.profile()).unwrap();
    assert_eq!(
        journal.import_block(header, &wire, 10_000, &verifier),
        Err(Error::Unauthorized)
    );
    assert_eq!(verifier.calls.get(), 0);

    let body = signed_transition(&journal);
    let root = journal.genesis_id();
    let child = add_empty(&mut journal, root, 1001);
    assert_eq!(
        journal.candidate(child, &body, 1002),
        Err(Error::InvalidTransition)
    );
    let Body::Transition(transition) = body else {
        unreachable!()
    };
    let mut changed_domain = genesis();
    changed_domain.network_id[0] ^= 1;
    assert_ne!(
        transition.signing_message(journal.genesis_id()),
        transition.signing_message(changed_domain.id().unwrap())
    );
}

#[test]
fn canonical_decoders_reject_trailing_bytes_and_hostile_lengths() {
    let genesis = genesis();
    let genesis_wire = genesis.encode().unwrap();
    assert_eq!(Genesis::decode(&genesis_wire).unwrap(), genesis);
    let mut trailing = genesis_wire;
    trailing.push(0);
    assert_eq!(Genesis::decode(&trailing), Err(Error::InvalidEncoding));
    let mut empty = Body::Empty.encode(&genesis.profile).unwrap();
    empty.push(0);
    assert_eq!(
        Body::decode(&empty, &genesis.profile),
        Err(Error::InvalidEncoding)
    );
    let journal = Journal::new(genesis).unwrap();
    let mut transition = signed_transition(&journal)
        .encode(journal.profile())
        .unwrap();
    transition[41..45].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        Body::decode(&transition, journal.profile()),
        Err(Error::ResourceLimit)
    );
    let (header, _) = empty_block(&journal, journal.genesis_id(), 1001);
    assert_eq!(Header::decode(&header.encode()).unwrap(), header);
    let mut wire = header.encode().to_vec();
    wire.push(0);
    assert_eq!(Header::decode(&wire), Err(Error::InvalidEncoding));
}

#[test]
fn pinned_profiles_cannot_be_changed_midchain_and_caps_preserve_existing_bodies() {
    let mut pinned = genesis();
    pinned.profile.max_headers = 2;
    let mut journal = Journal::new(pinned).unwrap();
    let root = journal.genesis_id();
    let one = add_empty(&mut journal, root, 1001);
    let (header, body) = empty_block(&journal, one, 1010);
    let two = journal.import_header(header, 10_000).unwrap();
    journal
        .import_body(two, &body, &RejectUnprovedTransitions)
        .unwrap();
    let (header, body) = empty_block(&journal, two, 1020);
    assert_eq!(
        journal.import_block(header, &body, 10_000, &RejectUnprovedTransitions),
        Err(Error::ResourceLimit)
    );
    assert_eq!(journal.header_count(), 2);
    assert_eq!(
        journal.resolve(Freshness::LatestConfirmed).unwrap().block,
        one
    );
    let mut other = journal.genesis().clone();
    other.application_commitment[0] ^= 1;
    assert_ne!(other.id().unwrap(), journal.genesis_id());
}

struct TempPath(PathBuf);
impl TempPath {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Self(std::env::temp_dir().join(format!(
            "dcs-journal-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
}
impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn durable_reopen_revalidates_the_same_work_and_requires_the_pinned_genesis() {
    let path = TempPath::new();
    let pinned = genesis();
    let mut durable = DurableJournal::create(&path.0, pinned.clone()).unwrap();
    let root = durable.journal().genesis_id();
    let (one, body) = empty_block(durable.journal(), root, 1001);
    let one = durable
        .append_block(one, &body, 10_000, &RejectUnprovedTransitions)
        .unwrap()
        .block;
    let (two, body) = empty_block(durable.journal(), one, 1010);
    durable
        .append_block(two, &body, 10_000, &RejectUnprovedTransitions)
        .unwrap();
    let accepted = durable
        .journal()
        .resolve(Freshness::LatestConfirmed)
        .unwrap();
    let bytes = durable.disk_bytes();
    drop(durable);

    let reopened =
        DurableJournal::open(&path.0, pinned.clone(), 10_000, &RejectUnprovedTransitions).unwrap();
    assert_eq!(reopened.disk_bytes(), bytes);
    assert_eq!(
        reopened
            .journal()
            .resolve(Freshness::LatestConfirmed)
            .unwrap(),
        accepted
    );
    assert_eq!(reopened.journal().validated_blocks().len(), 2);
    drop(reopened);
    let mut wrong = pinned;
    wrong.profile.initial_target = target(15);
    assert!(matches!(
        DurableJournal::open(&path.0, wrong, 10_000, &RejectUnprovedTransitions),
        Err(Error::WrongDomain)
    ));
}

#[test]
fn durable_unproved_mutation_changes_neither_file_nor_published_head() {
    let path = TempPath::new();
    let durable = DurableJournal::create(&path.0, genesis()).unwrap();
    drop(durable);
    let initial = std::fs::read(&path.0).unwrap();
    let mut durable =
        DurableJournal::open(&path.0, genesis(), 10_000, &RejectUnprovedTransitions).unwrap();
    let body = signed_transition(durable.journal());
    let wire = body.encode(durable.journal().profile()).unwrap();
    let mut header = durable
        .journal()
        .candidate(durable.journal().genesis_id(), &body, 1001)
        .unwrap();
    header.mine(100_000).unwrap();
    assert_eq!(
        durable.append_block(header, &wire, 10_000, &RejectUnprovedTransitions),
        Err(Error::MissingComputationProof)
    );
    assert_eq!(
        durable.journal().best_validated(),
        durable.journal().genesis_head()
    );
    drop(durable);
    assert_eq!(std::fs::read(&path.0).unwrap(), initial);
}

#[test]
fn incomplete_or_tampered_durable_records_fail_closed() {
    let path = TempPath::new();
    let pinned = genesis();
    let mut durable = DurableJournal::create(&path.0, pinned.clone()).unwrap();
    let (header, body) = empty_block(durable.journal(), durable.journal().genesis_id(), 1001);
    durable
        .append_block(header, &body, 10_000, &RejectUnprovedTransitions)
        .unwrap();
    drop(durable);
    let clean = std::fs::read(&path.0).unwrap();
    OpenOptions::new()
        .append(true)
        .open(&path.0)
        .unwrap()
        .write_all(&[1, 2])
        .unwrap();
    assert!(matches!(
        DurableJournal::open(&path.0, pinned.clone(), 10_000, &RejectUnprovedTransitions),
        Err(Error::CorruptJournal)
    ));
    let mut tampered = clean;
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    std::fs::write(&path.0, tampered).unwrap();
    assert!(matches!(
        DurableJournal::open(&path.0, pinned, 10_000, &RejectUnprovedTransitions),
        Err(Error::CorruptJournal)
    ));
}

#[test]
fn a_second_durable_owner_cannot_open_the_same_journal_until_drop() {
    let path = TempPath::new();
    let pinned = genesis();
    let owner = DurableJournal::create(&path.0, pinned.clone()).unwrap();
    assert!(matches!(
        DurableJournal::open(&path.0, pinned.clone(), 10_000, &RejectUnprovedTransitions),
        Err(Error::JournalLocked)
    ));
    drop(owner);
    assert!(DurableJournal::open(&path.0, pinned, 10_000, &RejectUnprovedTransitions).is_ok());
}

#[test]
fn owner_authorization_binds_proof_bytes_and_the_genesis_domain() {
    let mut journal = Journal::new(genesis()).unwrap();
    for wrong_domain in [false, true] {
        let mut body = signed_transition(&journal);
        let Body::Transition(transition) = &mut body else {
            unreachable!()
        };
        if wrong_domain {
            transition.sign([99; 32], &SigningKey::from_bytes(&[3; 32]));
        } else {
            transition.proof[0] ^= 1;
        }
        let wire = body.encode(journal.profile()).unwrap();
        let mut header = journal
            .candidate(journal.genesis_id(), &body, 1001)
            .unwrap();
        header.mine(100_000).unwrap();
        assert_eq!(
            journal.import_block(header, &wire, 10_000, &RejectUnprovedTransitions),
            Err(Error::Unauthorized)
        );
    }
}

#[test]
fn header_commits_exact_body_and_rejects_invented_state_roots() {
    let mut journal = Journal::new(genesis()).unwrap();
    let (mut header, body) = empty_block(&journal, journal.genesis_id(), 1001);
    assert_eq!(header.body_hash, hash(&body));
    header.state_root[0] ^= 1;
    header.nonce = 0;
    header.mine(100_000).unwrap();
    let id = journal.import_header(header, 10_000).unwrap();
    assert_eq!(
        journal.import_body(id, &body, &RejectUnprovedTransitions),
        Err(Error::InvalidTransition)
    );
    assert_eq!(journal.best_header(), journal.genesis_id());
    assert_eq!(journal.best_validated(), journal.genesis_head());
}
