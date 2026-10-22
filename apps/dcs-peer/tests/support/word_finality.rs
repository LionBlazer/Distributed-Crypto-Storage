//! PUBLIC NONSECRET inputs for genuine Word/native/QC process checks only.
use ed25519_dalek::SigningKey;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use registry200_finality::{
    CandidateBlock,
    word::{Binding, CANDIDATE_BYTES, Hash, profile_digest},
};
use registry200_joint::word::{
    Application, Control, Descriptor, Evidence, MAX_EVIDENCE_BYTES, OperationId, REQUEST_BYTES,
    Request,
};
use registry200_proof::{Val, registry_progress::word as math, source};
use std::sync::OnceLock;
use version_journal::{AuthorizedTransition, Body, Genesis, ProtocolProfile, ShardUpdate, Target};
use work_finality::{
    Genesis as WorkGenesis, Limits, NetworkSeed, WorkTicket,
    consensus::{MAX_RECORD_BYTES, Rules},
};
use zeroize::Zeroizing;
pub fn keys() -> Vec<SigningKey> {
    let mut k: Vec<_> = (1..=4).map(|n| SigningKey::from_bytes(&[n; 32])).collect();
    k.sort_by_key(|k| k.verifying_key().to_bytes());
    k
}
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
pub struct Fixture {
    pub descriptor: Descriptor,
    plain: [u8; 2348],
    pub source: Vec<u8>,
}
pub fn fixture() -> &'static Fixture {
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
        let suffix: Vec<_> = include_str!(
            "../../../../crates/registry200-joint/tests/fixtures/index-v3-four-row-suffix.hex"
        )
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
pub fn binding() -> Binding {
    let f = fixture();
    let r = Rules::multi_slot(
        profile_digest(),
        CANDIDATE_BYTES as u32,
        32,
        [1000, 1500, 2000],
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

pub fn bootstrap(b: &Binding) -> (CandidateBlock, [Val; 208]) {
    let app = Application::new(b.application_descriptor().clone(), b.journal_genesis()).unwrap();
    let parent = b.journal_genesis().id().unwrap();
    let (r, e, bank) = boot(fixture(), &app, parent);
    (block(b, parent, 1, &r, &e, Control::Pending), bank)
}
pub fn begin(b: &Binding, old: [Val; 208], parent: Hash) -> CandidateBlock {
    let f = fixture();
    let app = Application::new(b.application_descriptor().clone(), b.journal_genesis()).unwrap();
    let enrollment = old[33..37].try_into().unwrap();
    let zero = [Val::ZERO; 4];
    let draft = math::Expected::checked(
        f.descriptor.source(),
        math::Role::Control,
        app.genesis(),
        parent,
        enrollment,
        math::Claims {
            old: hash(&old),
            command: zero,
            statement: zero,
            next: zero,
            result: zero,
            blind_sql: [Val::ZERO; 8],
        },
    )
    .unwrap();
    let prepared = math::prepare_transition(
        &draft,
        math::TransitionMaterial {
            source: opening(f),
            registry: math::CurrentRegistry::new(
                [
                    words(&[0x41; 32]).try_into().unwrap(),
                    words(&[0x42; 32]).try_into().unwrap(),
                ],
                Zeroizing::new(old.map(|v| v.as_canonical_u64())),
                Zeroizing::new([6; 4]),
            )
            .unwrap(),
            command: math::CommandInput {
                op: 0,
                principal: 1,
                id: 1,
                ..Default::default()
            },
            walk: Default::default(),
            mask: Zeroizing::new([0; 32]),
            salts: [
                [Val::from_u8(3); 4],
                [Val::from_u8(4); 4],
                [Val::from_u8(5); 4],
            ],
        },
    )
    .unwrap();
    let (expected, inputs, _) = prepared.into_parts();
    let child = math::Prover::new(math::Role::Control)
        .unwrap()
        .produce(&expected, inputs)
        .unwrap();
    let r = Request::control(&app, parent, [2; 32], enrollment, expected.claims()).unwrap();
    let e = Evidence::control(child.as_bytes()).unwrap();
    block(
        b,
        parent,
        2,
        &r,
        &e,
        Control::Active {
            enrollment,
            registry: hash(&old),
        },
    )
}
pub fn check(j: &mut version_journal::Journal, b: &Binding, block: &CandidateBlock) {
    let app = Application::new(b.application_descriptor().clone(), b.journal_genesis()).unwrap();
    let verifier = registry200_joint::word::Verifier::new(
        b.application_descriptor().clone(),
        b.journal_genesis(),
        &fixture().source,
    )
    .unwrap();
    let Body::Transition(body) = Body::decode(block.body(), &b.journal_genesis().profile).unwrap()
    else {
        panic!("Expected real owner transition")
    };
    let request = Request::decode(&body.request).unwrap();
    let id = OperationId::new(&app, &request, &body.proof).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (pending, _) = verifier
        .prepare_import(j, block.header().clone(), block.body(), now, id)
        .unwrap();
    let _ = pending.commit();
}
pub fn corrupt(b: &Binding, block: &CandidateBlock) -> CandidateBlock {
    let Body::Transition(mut body) =
        Body::decode(block.body(), &b.journal_genesis().profile).unwrap()
    else {
        panic!("Expected owner transition")
    };
    *body.proof.last_mut().unwrap() ^= 1;
    body.sign(b.journal_genesis().id().unwrap(), &owner());
    let bytes = Body::Transition(body)
        .encode(&b.journal_genesis().profile)
        .unwrap();
    let mut header = block.header().clone();
    header.body_hash = version_journal::hash(&bytes);
    header.nonce = 0;
    header.mine(16).unwrap();
    CandidateBlock::new(header, bytes).unwrap()
}
