//! Explicitly NONSECRET Word owners and real durable weighted voters.
use super::*;
use crate::joint::history::tests::{Directory, keys};
use ed25519_dalek::SigningKey;
use p3_field::PrimeCharacteristicRing;
use protocol_storage::ParticipantQuota;
use registry200_joint::word::{
    Application, Control, Descriptor, Evidence, MAX_EVIDENCE_BYTES, REQUEST_BYTES, Request,
};
use registry200_proof::{Val, registry_progress::word as math, source};
use std::{collections::VecDeque, sync::OnceLock, time::Instant};
use version_journal::{AuthorizedTransition, Body, Genesis, ProtocolProfile, ShardUpdate, Target};
use work_finality::consensus::{Action, MAX_RECORD_BYTES, Rules};
use work_finality::{Genesis as WorkGenesis, Limits, NetworkSeed, WorkTicket};
use zeroize::Zeroizing;
fn hash(fields: &[Val]) -> [Val; 4] {
    let mut state = [Val::ZERO; 12];
    let mut scratch = [Val::ZERO; bfv_hiding_stark::poseidon::WIDTH];
    for block in fields.as_chunks::<8>().0 {
        state[..8].copy_from_slice(block);
        state = bfv_hiding_stark::poseidon::write(&mut scratch, state);
    }
    state[..4].try_into().unwrap()
}
fn words(b: &[u8]) -> Vec<Val> {
    source::statement::words(b).collect()
}
fn owner() -> SigningKey {
    SigningKey::from_bytes(&[0x81; 32])
}
struct Fixture {
    descriptor: Descriptor,
    plain: [u8; 2348],
    source: Vec<u8>,
}
fn fixture() -> &'static Fixture {
    static PUBLIC: OnceLock<Fixture> = OnceLock::new();
    PUBLIC.get_or_init(|| {
        let owner =
            compact_store::Owner::from_key([0x42; 16], [0x73; 16], Zeroizing::new([0x71; 32]));
        let data = [255, 0, 0, 0, 255, 255, 255, 0, 1, 128, 255, 0];
        let stored = owner
            .seal(
                compact_store::Layout {
                    schema: source::DATA_SCHEMA,
                    row_width: 3,
                    rows_per_page: 256,
                    row_count: 4,
                },
                &data,
                source::statement::limits(),
            )
            .unwrap();
        let suffix: Vec<_> =
            include_str!("../../../registry200-joint/tests/fixtures/index-v3-four-row-suffix.hex")
                .lines()
                .filter(|l| !l.starts_with('#'))
                .flat_map(str::split_whitespace)
                .map(|w| u8::from_str_radix(w, 16).unwrap())
                .collect();
        let mut index = stored.commitment().encode().to_vec();
        index.extend(suffix);
        let indexed = owner
            .seal(
                compact_store::Layout {
                    schema: source::INDEX_SCHEMA,
                    row_width: 1,
                    rows_per_page: 4096,
                    row_count: 2336,
                },
                &index,
                source::statement::limits(),
            )
            .unwrap();
        let key = source::commitment::digest(&source::commitment::key_fields(
            &stored.commitment().encode(),
            [0x71; 32],
            [Val::ONE; 4],
        ));
        let make = |state| {
            source::version::SourceVersionExpected::checked(
                [&stored.encode(), &indexed.encode()],
                [stored.commitment(), indexed.commitment()],
                source::statement::encode_digest(key),
                state,
            )
            .unwrap()
        };
        let mut plain = [0; 2348];
        plain[..12].copy_from_slice(&data);
        plain[12..].copy_from_slice(&index);
        let preliminary = make([0; 32]);
        let state = source::commitment::digest(&source::commitment::opening_fields(
            preliminary.statement(),
            [Val::TWO; 4],
            &plain,
        ));
        let e = make(source::statement::encode_digest(state));
        let source = source::version::prove(
            &e,
            &source::circuit::Witness::new(
                [0x71; 32],
                [Val::ONE; 4],
                [Val::TWO; 4],
                [255, 0, 255, 128],
            ),
        )
        .unwrap()
        .into_bytes();
        Fixture {
            descriptor: Descriptor::checked([0x77; 32], 11, 12, &e).unwrap(),
            plain,
            source,
        }
    })
}
fn genesis(d: &Descriptor) -> Genesis {
    Genesis {
        network_id: d.network(),
        database: d.database(),
        owner: owner().verifying_key().to_bytes(),
        application_commitment: d.id(),
        timestamp: 100,
        profile: ProtocolProfile {
            initial_target: Target([255; 32]),
            pow_limit: Target([255; 32]),
            block_spacing_secs: 1,
            retarget_interval: 8,
            max_future_secs: 30,
            confirmation_depth: 1,
            max_headers: 64,
            max_shards: 2,
            max_updates: 1,
            max_body_bytes: version_journal::MAX_BODY_BYTES as u32,
            max_request_bytes: REQUEST_BYTES as u32,
            max_proof_bytes: MAX_EVIDENCE_BYTES as u32,
            max_journal_bytes: version_journal::MAX_JOURNAL_BYTES,
        },
        initial_shards: d.initial_shards(),
    }
}
fn opening(f: &Fixture) -> math::SourceOpening {
    math::SourceOpening::checked(Zeroizing::new(f.plain.to_vec()), Zeroizing::new([2; 4])).unwrap()
}
fn enrollment_and_empty(f: &Fixture, a: &Application) -> ([Val; 4], [Val; 208]) {
    let zero = [Val::ZERO; 4];
    let context = math::Expected::checked(
        f.descriptor.source(),
        math::Role::Control,
        a.genesis(),
        [0; 32],
        zero,
        math::Claims {
            old: zero,
            command: zero,
            statement: zero,
            next: zero,
            result: zero,
            blind_sql: [Val::ZERO; 8],
        },
    )
    .unwrap();
    let mut enrollment = context.enrollment_header().to_vec();
    enrollment.extend(words(&f.plain[124..156]));
    enrollment.extend([Val::TWO, Val::ONE]);
    enrollment.extend(words(&[0x41; 32]));
    enrollment.push(Val::TWO);
    enrollment.extend(words(&[0x42; 32]));
    enrollment.extend([Val::from_u8(3); 4]);
    assert_eq!(enrollment.len(), 64);
    let enrollment = hash(&enrollment);
    let mut bank = [Val::ZERO; 208];
    bank[..33].copy_from_slice(context.registry_header());
    bank[33..37].copy_from_slice(&enrollment);
    bank[37..45].copy_from_slice(&words(&f.plain[124..156]));
    bank[45..77].copy_from_slice(&words(&f.plain[2220..2348]));
    bank[77..80].copy_from_slice(&[Val::TWO, Val::from_u8(4), Val::TWO]);
    bank[190..194].fill(Val::from_u8(6));
    (enrollment, bank)
}
fn boot(f: &Fixture, a: &Application, parent: Hash) -> (Request, Evidence, [Val; 208]) {
    let (enrollment, bank) = enrollment_and_empty(f, a);
    let root = hash(&bank);
    let e =
        math::bootstrap::Expected::checked(f.descriptor.source(), a.genesis(), enrollment, root)
            .unwrap();
    let input = math::bootstrap::PrivateInputs::checked(
        &e,
        opening(f),
        Zeroizing::new([[0x41; 32], [0x42; 32]]),
        Zeroizing::new([[3; 4], [6; 4]]),
    )
    .unwrap();
    let child = math::bootstrap::prove(&e, input, &f.source).unwrap();
    (
        Request::bootstrap(a, parent, [1; 32], enrollment, root),
        Evidence::bootstrap(&f.source, child.as_bytes()).unwrap(),
        bank,
    )
}
fn begin(f: &Fixture, a: &Application, parent: Hash, old: [Val; 208]) -> (Request, Evidence) {
    let enrollment = old[33..37].try_into().unwrap();
    let controllers: [[_; 8]; 2] = [
        words(&[0x41; 32]).try_into().unwrap(),
        words(&[0x42; 32]).try_into().unwrap(),
    ];
    let mut next = old;
    next[80] = Val::ONE;
    next[82] = Val::ONE;
    next[84] = Val::ONE;
    next[85] = Val::ONE;
    next[87] = Val::ONE;
    next[88..96].copy_from_slice(&controllers[0]);
    next[96] = Val::ONE;
    next[99..107].copy_from_slice(&words(&parent));
    let mut c = math::Claims {
        old: hash(&old),
        next: hash(&next),
        command: [Val::ZERO; 4],
        statement: [Val::ZERO; 4],
        result: [Val::ZERO; 4],
        blind_sql: [Val::ZERO; 8],
    };
    let m = math::Expected::checked(
        f.descriptor.source(),
        math::Role::Control,
        a.genesis(),
        parent,
        enrollment,
        c,
    )
    .unwrap();
    let mut cmd = math::command_header().to_vec();
    cmd.extend(m.context());
    cmd.extend(c.old);
    cmd.push(Val::ZERO);
    cmd.extend([Val::ONE, Val::ZERO]);
    cmd.push(Val::ONE);
    cmd.extend(controllers[0]);
    cmd.extend([Val::ZERO; 2 + 2 + 8 + 5 + 8]);
    cmd.extend(words(&parent));
    cmd.push(Val::ZERO);
    cmd.extend([Val::from_u8(4); 4]);
    cmd.push(Val::ZERO);
    assert_eq!(cmd.len(), 160);
    c.command = hash(&cmd);
    let mut result = math::result_header().to_vec();
    result.extend(m.context());
    result.extend(c.old);
    result.extend(c.next);
    result.extend(c.statement);
    result.extend([Val::TWO, Val::ONE]);
    result.extend([Val::ONE, Val::ZERO]);
    result.extend([Val::ZERO; 2 + 4 + 4 + 4 + 4 + 4 + 2 + 1 + 2 + 2]);
    result.extend([Val::from_u8(5); 4]);
    result.extend([Val::ZERO; 6]);
    assert_eq!(result.len(), 160);
    c.result = hash(&result);
    let m = math::Expected::checked(
        f.descriptor.source(),
        math::Role::Control,
        a.genesis(),
        parent,
        enrollment,
        c,
    )
    .unwrap();
    let input = math::PrivateInputs::new(
        opening(f),
        math::RegistryOpening::new(controllers, [old, next]),
        math::CommandInput {
            id: 1,
            principal: 1,
            ..Default::default()
        },
        math::WalkInput::default(),
        Zeroizing::new([0; 32]),
        [
            [Val::from_u8(3); 4],
            [Val::from_u8(4); 4],
            [Val::from_u8(5); 4],
        ],
    );
    let p = math::prove(&m, input).unwrap();
    (
        Request::control(a, parent, [2; 32], enrollment, c).unwrap(),
        Evidence::control(p.as_bytes()).unwrap(),
    )
}
fn binding() -> Binding {
    let f = fixture();
    let r = Rules::multi_slot(
        profile_digest(),
        CANDIDATE_BYTES as u32,
        32,
        [100, 200, 300],
        10,
        MAX_RECORD_BYTES as u64,
    )
    .unwrap();
    let seed = NetworkSeed::new(
        r.seed_domain(f.descriptor.network()),
        [10; 32],
        [255; 32],
        Limits::new(16, 4).unwrap(),
    )
    .unwrap();
    let tickets = keys()
        .iter()
        .map(|k| WorkTicket::sign(&seed.bootstrap_election(), k, 0).unwrap())
        .collect();
    let work = WorkGenesis::from_bootstrap(seed, tickets).unwrap();
    Binding::new(
        f.descriptor.network(),
        r,
        work,
        genesis(&f.descriptor),
        f.descriptor.clone(),
        &f.source,
    )
    .unwrap()
}
const LOCAL: Hash = [0xc7; 32];
const CAPACITY: u64 = 10_000_000_000;
struct Member {
    actor: DurableFinality,
    quota: ParticipantQuota,
    directory: Directory,
}
fn members(b: &Binding) -> Vec<Member> {
    keys()
        .into_iter()
        .map(|key| {
            let directory = Directory::new();
            let quota = ParticipantQuota::create_new(directory.root(), LOCAL, CAPACITY).unwrap();
            let actor = DurableFinality::create_participant(&quota, b.clone(), key).unwrap();
            Member {
                actor,
                quota,
                directory,
            }
        })
        .collect()
}
fn restart(members: &mut Vec<Member>, at: usize, b: &Binding) {
    let Member {
        actor,
        quota,
        directory,
    } = members.remove(at);
    drop(actor);
    drop(quota);
    let quota = ParticipantQuota::open_existing(directory.root(), LOCAL, CAPACITY).unwrap();
    let actor = DurableFinality::open_participant(&quota, b.clone(), keys().remove(at)).unwrap();
    members.insert(
        at,
        Member {
            actor,
            quota,
            directory,
        },
    );
}
fn block(
    b: &Binding,
    parent: Hash,
    height: u64,
    r: &Request,
    e: &Evidence,
    before: Control,
) -> CandidateBlock {
    let d = b.application_descriptor();
    let after = Control::Active {
        enrollment: r.enrollment(),
        registry: r.claims().next,
    };
    let mut t = AuthorizedTransition {
        parent,
        request: r.encode(),
        updates: vec![ShardUpdate {
            id: d.control_id(),
            old: before.heads(d),
            new: after.heads(d),
        }],
        proof: e.as_bytes().to_vec(),
        owner_signature: [0; 64],
    };
    t.sign(b.journal_genesis().id().unwrap(), &owner());
    let body = Body::Transition(t)
        .encode(&b.journal_genesis().profile)
        .unwrap();
    let mut shards = d.initial_shards();
    shards
        .iter_mut()
        .find(|s| s.id == d.control_id())
        .unwrap()
        .heads = after.heads(d);
    let mut h = version_journal::Header {
        genesis: b.journal_genesis().id().unwrap(),
        parent,
        height,
        timestamp: 100 + height,
        target: b.journal_genesis().profile.initial_target,
        body_hash: version_journal::hash(&body),
        state_root: version_journal::state_root(&shards),
        nonce: 0,
    };
    h.mine(16).unwrap();
    CandidateBlock::new(h, body).unwrap()
}
fn empty(b: &Binding) -> CandidateBlock {
    let g = b.journal_genesis();
    let body = Body::Empty.encode(&g.profile).unwrap();
    let mut h = version_journal::Header {
        genesis: g.id().unwrap(),
        parent: g.id().unwrap(),
        height: 1,
        timestamp: 101,
        target: g.profile.initial_target,
        body_hash: version_journal::hash(&body),
        state_root: version_journal::state_root(&g.initial_shards),
        nonce: 0,
    };
    h.mine(16).unwrap();
    CandidateBlock::new(h, body).unwrap()
}
fn imports(members: &mut [Member], b: &CandidateBlock) -> Vec<Candidate> {
    members
        .iter_mut()
        .map(|m| {
            m.actor
                .import_candidate(b.header().clone(), b.body())
                .unwrap()
        })
        .collect()
}
fn frames(actions: Vec<Action>) -> Vec<Vec<u8>> {
    use work_finality::consensus::Input;
    actions
        .into_iter()
        .filter_map(|a| match a {
            Action::Proposal(p) => Some(Input::Proposal(p)),
            Action::Vote(v) => Some(Input::Vote(v)),
            Action::Certificate { value, certificate } => {
                Some(Input::Certificate { value, certificate })
            }
            Action::Schedule(_) | Action::Decided(_) => None,
        })
        .map(|i| i.encode().unwrap())
        .collect()
}
fn relay(members: &mut [Member], active: &[usize], slot: u64, initial: Vec<(usize, Vec<Action>)>) {
    let mut queue = VecDeque::new();
    for (sender, actions) in initial {
        for bytes in frames(actions) {
            for &receiver in active {
                if receiver != sender {
                    queue.push_back((receiver, bytes.clone()));
                }
            }
        }
    }
    let mut delivered = 0;
    while let Some((receiver, bytes)) = queue.pop_front() {
        delivered += 1;
        assert!(delivered < 512, "bounded one-round traffic");
        match members[receiver].actor.receive(&bytes) {
            Ok(actions) => {
                for bytes in frames(actions) {
                    for &next in active {
                        if next != receiver {
                            queue.push_back((next, bytes.clone()));
                        }
                    }
                }
            }
            Err(Error::Consensus(
                work_finality::consensus::Error::Stale
                | work_finality::consensus::Error::WrongContext
                | work_finality::consensus::Error::Evidence(work_finality::Error::MixedVotes),
            )) if members[receiver].actor.context().unwrap().slot() != slot => {}
            Err(e) => panic!(
                "real voter {receiver} rejected live traffic: {e:?}; slot={} expected={slot} tag={}",
                members[receiver].actor.context().unwrap().slot(),
                bytes[0]
            ),
        }
    }
}
fn start_round(members: &mut [Member], candidates: &[Candidate], active: &[usize]) -> usize {
    let context = members[0].actor.context().unwrap();
    let slot = context.slot();
    let proposer = context.proposer(0).unwrap();
    let leader = keys()
        .iter()
        .position(|k| k.verifying_key().to_bytes() == proposer)
        .unwrap();
    assert!(active.contains(&leader));
    let actions = members[leader].actor.propose(&candidates[leader]).unwrap();
    relay(members, active, slot, vec![(leader, actions)]);
    leader
}
#[test]
fn real_word_bootstrap_begin_quorum_restart_and_no_quorum_no_finalization() {
    let began = Instant::now();
    let b = binding();
    let f = fixture();
    let a = Application::new(f.descriptor.clone(), b.journal_genesis()).unwrap();
    let mut voters = members(&b);
    let parent = b.journal_genesis().id().unwrap();
    let (r, e, bank) = boot(f, &a, parent);
    let boot_block = block(&b, parent, 1, &r, &e, Control::Pending);
    let cs = imports(&mut voters, &boot_block);
    assert!(
        voters
            .iter()
            .all(|m| m.actor.finalized_parent().unwrap().is_none())
    );
    start_round(&mut voters, &cs, &[0, 1, 2, 3]);
    for m in &voters {
        let p = m.actor.finalized_parent().unwrap().unwrap();
        assert_eq!(p.slot(), 1);
        assert_eq!(p.head().block, boot_block.header().id());
        assert_eq!(m.actor.context().unwrap().slot(), 2);
    }
    let (r, e) = begin(f, &a, boot_block.header().id(), bank);
    let before = Control::Active {
        enrollment: r.enrollment(),
        registry: r.claims().old,
    };
    let begin_block = block(&b, boot_block.header().id(), 2, &r, &e, before);
    // A fresh valid owner signature/header cannot replace damaged native Word.
    let mut bad = e.as_bytes()[24..].to_vec();
    *bad.last_mut().unwrap() ^= 1;
    let bad = Evidence::control(&bad).unwrap();
    let bad = block(&b, boot_block.header().id(), 2, &r, &bad, before);
    let used = voters[0].quota.usage().unwrap();
    assert!(
        voters[0]
            .actor
            .import_candidate(bad.header().clone(), bad.body())
            .is_err()
    );
    assert_eq!(voters[0].quota.usage().unwrap(), used);
    assert!(!voters[0].actor.has_candidate(bad.header().id()).unwrap());
    let candidates = imports(&mut voters, &begin_block);
    let leader_key = voters[0].actor.context().unwrap().proposer(0).unwrap();
    let leader = keys()
        .iter()
        .position(|k| k.verifying_key().to_bytes() == leader_key)
        .unwrap();
    let other = (leader + 1) % 4;
    start_round(&mut voters, &candidates, &[leader, other]);
    assert!(voters.iter().all(|m| m.actor.context().unwrap().slot() == 2
        && m.actor.finalized_parent().unwrap().unwrap().slot() == 1));
    restart(&mut voters, leader, &b);
    assert_eq!(voters[leader].actor.context().unwrap().slot(), 2);
    let mut conflicting = r.encode();
    conflicting[80] ^= 1;
    let conflicting = Request::decode(&conflicting).unwrap();
    let conflicting = block(&b, boot_block.header().id(), 2, &conflicting, &e, before);
    let conflicting = voters[leader]
        .actor
        .import_candidate(conflicting.header().clone(), conflicting.body())
        .unwrap();
    assert!(
        voters[leader].actor.propose(&conflicting).is_err(),
        "reopened signer must retain its original proposal/lock"
    );
    let out = voters
        .iter()
        .enumerate()
        .map(|(i, m)| (i, m.actor.outbound().unwrap()))
        .collect();
    let receiving = Instant::now();
    relay(&mut voters, &[0, 1, 2, 3], 2, out);
    for m in &voters {
        let p = m.actor.finalized_parent().unwrap().unwrap();
        assert_eq!(p.slot(), 2);
        assert_eq!(p.head().block, begin_block.header().id());
        assert_eq!(m.actor.context().unwrap().slot(), 3);
        assert_eq!(
            p.control(),
            Control::Active {
                enrollment: r.enrollment(),
                registry: r.claims().next
            }
        );
    }
    let qc = voters[1].actor.checkpoint_after(1).unwrap().unwrap();
    let decoded = Checkpoint::decode(&qc.encode()).unwrap();
    assert!(crate::progress::Checkpoint::decode(&qc.encode()).is_err());
    assert!(crate::progress::Candidate::decode(&qc.candidate().encode()).is_err());
    let used = voters[0].quota.usage().unwrap();
    voters[0].actor.receive_checkpoint(&decoded).unwrap();
    assert_eq!(voters[0].quota.usage().unwrap(), used);
    restart(&mut voters, 0, &b);
    assert_eq!(voters[0].actor.context().unwrap().slot(), 3);
    assert_eq!(
        voters[0]
            .actor
            .finalized_parent()
            .unwrap()
            .unwrap()
            .head()
            .block,
        begin_block.header().id()
    );
    eprintln!(
        "word_durable local_remaining_begin_votes_duplicate_and_reopen_ms={:.3} whole_test_ms={:.3} sql_accepted=false",
        receiving.elapsed().as_secs_f64() * 1000.,
        began.elapsed().as_secs_f64() * 1000.
    );
}
#[test]
fn word_floor_ack_loss_recovers_and_partial_tail_is_never_repaired() {
    let b = binding();
    let mut voters = members(&b);
    let block = empty(&b);
    let cs = imports(&mut voters, &block);
    start_round(&mut voters, &cs, &[0, 1, 2, 3]);
    let qc = voters[0].actor.checkpoint_after(0).unwrap().unwrap();
    for fault in [
        crate::store::Fault::AfterSync,
        crate::store::Fault::Partial(9),
    ] {
        let directory = Directory::new();
        let quota = ParticipantQuota::create_new(directory.root(), LOCAL, CAPACITY).unwrap();
        let key = keys().remove(0);
        let mut actor = DurableFinality::create_participant(&quota, b.clone(), key).unwrap();
        actor
            .import_candidate(block.header().clone(), block.body())
            .unwrap();
        let paths = crate::participant::Paths::participant(
            &quota,
            crate::pins::Pins::Word(&b),
            keys().remove(0).verifying_key().to_bytes(),
        );
        actor.engine.inject_floor_fault_for_test(fault);
        assert!(actor.receive_checkpoint(&qc).is_err());
        assert!(actor.outbound().is_err());
        assert!(actor.finalized_parent().is_err());
        assert!(quota.depot_budget().reserve(1).is_err());
        drop(actor);
        drop(quota);
        let exact = std::fs::read(&paths.floor).unwrap();
        let quota = ParticipantQuota::open_existing(directory.root(), LOCAL, CAPACITY).unwrap();
        let reopened = DurableFinality::open_participant(&quota, b.clone(), keys().remove(0));
        match fault {
            crate::store::Fault::AfterSync => {
                let actor = reopened.unwrap();
                assert_eq!(actor.context().unwrap().slot(), 2);
                assert_eq!(
                    actor.finalized_parent().unwrap().unwrap().head().block,
                    block.header().id()
                );
                drop(actor);
            }
            crate::store::Fault::Partial(_) => assert!(matches!(
                reopened,
                Err(Error::Durable(crate::Error::CorruptFloor))
            )),
        }
        assert_eq!(std::fs::read(&paths.floor).unwrap(), exact);
        drop(quota);
    }
}
