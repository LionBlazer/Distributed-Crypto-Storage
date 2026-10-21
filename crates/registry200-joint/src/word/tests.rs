//! Explicitly NONSECRET owner inputs; real Source/Word, signatures and Journal I/O.
use super::*;
use ed25519_dalek::SigningKey;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use registry200_proof::{Val, registry_progress::word as math, source};
use std::{sync::OnceLock, time::Instant};
use version_journal::{
    AuthorizedTransition, Body, Genesis, Journal, ProtocolProfile, ShardUpdate, Target,
};
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
        let suffix: Vec<_> = include_str!("../../tests/fixtures/index-v3-four-row-suffix.hex")
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
fn candidate(
    j: &Journal,
    a: &Application,
    r: &Request,
    e: &Evidence,
    before: Control,
    key: &SigningKey,
) -> (version_journal::Header, Vec<u8>) {
    let after = Control::Active {
        enrollment: r.enrollment(),
        registry: r.claims().next,
    };
    let d = a.descriptor();
    let mut t = AuthorizedTransition {
        parent: r.parent(),
        request: r.encode(),
        updates: vec![ShardUpdate {
            id: d.control_id(),
            old: before.heads(d),
            new: after.heads(d),
        }],
        proof: e.as_bytes().to_vec(),
        owner_signature: [0; 64],
    };
    t.sign(a.genesis(), key);
    let body = Body::Transition(t);
    let mut header = j
        .candidate(r.parent(), &body, 101 + j.header_count() as u64)
        .unwrap();
    header.mine(4).unwrap();
    (header, body.encode(&genesis(d).profile).unwrap())
}
#[test]
fn full_descriptor_and_frames_reject_foreign_state_noncanonical_fields_and_predicate_lane() {
    let f = fixture();
    let bytes = f.descriptor.encode();
    assert_eq!(Descriptor::decode(&bytes).unwrap().encode(), bytes);
    assert!(crate::progress::Descriptor::decode(&bytes).is_err());
    assert!(registry200_journal::ApplicationDescriptor::decode(&bytes).is_err());
    let mut shards = f.descriptor.initial_shards();
    shards[0].heads.data[111] ^= 1;
    assert!(f.descriptor.control(&shards).is_err());
    for at in [8, 40, 72, 88, 120, 152, 264, 376] {
        let mut other = bytes.clone();
        other[at] ^= 1;
        if let Ok(d) = Descriptor::decode(&other) {
            assert_ne!(d.id(), f.descriptor.id());
            assert!(Application::new(d, &genesis(&f.descriptor)).is_err());
        }
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(Descriptor::decode(&trailing).is_err());
    let g = genesis(&f.descriptor);
    let a = Application::new(f.descriptor.clone(), &g).unwrap();
    let r = Request::bootstrap(&a, g.id().unwrap(), [3; 32], [Val::ONE; 4], [Val::TWO; 4]);
    let wire = r.encode();
    assert_eq!(wire.len(), REQUEST_BYTES);
    assert_eq!(Request::decode(&wire).unwrap().encode(), wire);
    for at in [0, 8, 9, 112] {
        let mut bad = wire.clone();
        if at == 112 {
            bad[112..120].copy_from_slice(&Val::ORDER_U64.to_le_bytes());
        } else {
            bad[at] = 2;
        }
        assert!(Request::decode(&bad).is_err());
    }
    assert!(Evidence::control(&[]).is_err());
    let e = Evidence::control(b"unproved").unwrap();
    let mut bad = e.into_bytes();
    bad[8] = 2;
    assert!(Evidence::split(Lane::Control, &bad).is_err());
    let mut oversized = Evidence::control(b"unproved").unwrap().into_bytes();
    oversized[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        Evidence::split(Lane::Control, &oversized),
        Err(Error::ResourceLimit)
    ));
    let s = f.descriptor.source().statement();
    let heads: [_; 2] = core::array::from_fn(|i| {
        compact_store::Commitment::decode(&s.heads[i], source::statement::limits()).unwrap()
    });
    let images: [Vec<_>; 2] =
        core::array::from_fn(|i| s.heads[i].iter().chain(&s.packets[i]).copied().collect());
    let mut state = s.open_commitment;
    state[3] += Val::ONE;
    let foreign = source::version::SourceVersionExpected::checked(
        [&images[0], &images[1]],
        [&heads[0], &heads[1]],
        source::statement::encode_digest(s.key_commitment),
        source::statement::encode_digest(state),
    )
    .unwrap();
    assert_eq!(foreign.version_id(), f.descriptor.source().version_id());
    let foreign = Descriptor::checked(f.descriptor.network(), 11, 12, &foreign).unwrap();
    assert_ne!(foreign.id(), f.descriptor.id());
    assert!(Verifier::new(foreign.clone(), &g, &f.source).is_err());
    let authorized_foreign = genesis(&foreign);
    assert!(matches!(
        Verifier::new(foreign, &authorized_foreign, &f.source),
        Err(Error::RejectedComputationProof)
    ));
}
#[test]
fn actual_source_bootstrap_begin_and_owner_journal_handoff_are_required() {
    let f = fixture();
    let g = genesis(&f.descriptor);
    let a = Application::new(f.descriptor.clone(), &g).unwrap();
    let mut journal = Journal::new(g.clone()).unwrap();
    assert!(Verifier::new(f.descriptor.clone(), &g, &[]).is_err());
    let verifier = Verifier::new(f.descriptor.clone(), &g, &f.source).unwrap();
    let parent = journal.genesis_head();
    let (r, e, bank) = boot(f, &a, parent.block);
    let id = OperationId::new(&a, &r, e.as_bytes()).unwrap();
    let (h, b) = candidate(&journal, &a, &r, &e, Control::Pending, &owner());
    let count = journal.header_count();
    let (pending, checked) = verifier
        .prepare_import(&mut journal, h.clone(), &b, 200, id)
        .unwrap();
    assert!(checked.bootstrap().is_some());
    drop(pending);
    assert_eq!(journal.header_count(), count);
    let (pending, _) = verifier
        .prepare_import(&mut journal, h.clone(), &b, 200, id)
        .unwrap();
    pending.commit();
    let wrong = SigningKey::from_bytes(&[0x82; 32]);
    let (unauthorized_header, unauthorized) = candidate(
        &Journal::new(g.clone()).unwrap(),
        &a,
        &r,
        &e,
        Control::Pending,
        &wrong,
    );
    assert!(matches!(
        verifier.check_block(&journal, &unauthorized_header, &unauthorized, 200, id),
        Err(Error::Unauthorized)
    ));
    let (r, e) = begin(f, &a, h.id(), bank);
    let id = OperationId::new(&a, &r, e.as_bytes()).unwrap();
    let before = Control::Active {
        enrollment: r.enrollment(),
        registry: r.claims().old,
    };
    let (h, b) = candidate(&journal, &a, &r, &e, before, &owner());
    for field in [112, 144, 176] {
        let mut changed = r.encode();
        let value = u64::from_le_bytes(changed[field..field + 8].try_into().unwrap());
        changed[field..field + 8].copy_from_slice(&(value + 1).to_le_bytes());
        let changed = Request::decode(&changed).unwrap();
        let changed_id = OperationId::new(&a, &changed, e.as_bytes()).unwrap();
        let (changed_h, changed_b) = candidate(&journal, &a, &changed, &e, before, &owner());
        let failure = verifier.check_block(&journal, &changed_h, &changed_b, 200, changed_id);
        assert!(matches!(
            failure,
            Err(Error::InvalidTransition | Error::RejectedComputationProof)
        ));
    }
    let began = Instant::now();
    let checked = verifier.check_block(&journal, &h, &b, 200, id).unwrap();
    assert!(checked.control().is_some());
    eprintln!(
        "word_journal_begin native_word_and_owner_header_ms={:.3} sql_accepted=false",
        began.elapsed().as_secs_f64() * 1000.
    );
    let mut forged = e.as_bytes()[24..].to_vec();
    *forged.last_mut().unwrap() ^= 1;
    let forged = Evidence::control(&forged).unwrap();
    let bad_id = OperationId::new(&a, &r, forged.as_bytes()).unwrap();
    let (bad_h, bad_b) = candidate(&journal, &a, &r, &forged, before, &owner());
    assert!(
        verifier
            .check_block(&journal, &bad_h, &bad_b, 200, bad_id)
            .is_err()
    );
    let mut other = r.encode();
    other[80] ^= 1;
    let other = Request::decode(&other).unwrap();
    let other = OperationId::new(&a, &other, e.as_bytes()).unwrap();
    assert!(verifier.check_block(&journal, &h, &b, 200, other).is_err());
    let (pending, checked) = verifier
        .prepare_import(&mut journal, h.clone(), &b, 200, id)
        .unwrap();
    assert_eq!(checked.operation_id(), id);
    pending.commit();
    assert!(verifier.check_block(&journal, &h, &b, 200, id).is_ok());
}
