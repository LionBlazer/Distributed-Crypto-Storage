//! PUBLIC NONSECRET private witnesses, with actual Canonical Source and lifecycle proofs.
use super::{
    PreparedWitness,
    circuit::{
        Witness, commitment,
        model::{Command, Operation, Registry},
    },
    prove,
    statement::{self, Expected, Phase},
};
use crate::{
    Val,
    admission::{self, CanonicalSource},
    source, wire,
};
use bfv_hiding_stark::{Config, codec};
use compact_store::{Layout, Owner};
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::Proof;
use std::sync::OnceLock;
use zeroize::Zeroizing;

struct Fixture {
    source: CanonicalSource,
    mathematical: Witness,
    source_bytes: Vec<u8>,
}
fn fixture() -> &'static Fixture {
    static PUBLIC: OnceLock<Fixture> = OnceLock::new();
    PUBLIC.get_or_init(|| {
        let key = [0x71; 32]; // Explicit PUBLIC NONSECRET test key, not a key getter.
        let owner = Owner::from_key([0x42; 16], [0x73; 16], Zeroizing::new(key));
        let limits = source::statement::limits();
        let data = [255, 0, 0, 0, 255, 255, 255, 0, 1, 128, 255, 0];
        let stored = owner
            .seal(
                Layout {
                    schema: source::DATA_SCHEMA,
                    row_width: 3,
                    rows_per_page: 256,
                    row_count: 4,
                },
                &data,
                limits,
            )
            .unwrap();
        let suffix: Vec<u8> =
            include_str!("../../../compact-query/tests/fixtures/index-v3-four-row-suffix.hex")
                .lines()
                .filter(|l| !l.starts_with('#'))
                .flat_map(str::split_whitespace)
                .map(|x| u8::from_str_radix(x, 16).unwrap())
                .collect();
        assert_eq!(suffix.len(), 2224);
        let mut index = stored.commitment().encode().to_vec();
        index.extend(suffix);
        let indexed = owner
            .seal(
                Layout {
                    schema: source::INDEX_SCHEMA,
                    row_width: 1,
                    rows_per_page: 4096,
                    row_count: 2336,
                },
                &index,
                limits,
            )
            .unwrap();
        let key_root = source::commitment::digest(&source::commitment::key_fields(
            &stored.commitment().encode(),
            key,
            [Val::ONE; 4],
        ));
        let mut claim = source::Statement::checked_relation(
            source::Relation::CanonicalIndex,
            [&stored.encode(), &indexed.encode()],
            [stored.commitment(), indexed.commitment()],
            [0x83; 32],
            source::statement::encode_digest(key_root),
            [0; 32],
        )
        .unwrap();
        let mut plain = [0; 2348];
        plain[..12].copy_from_slice(&data);
        plain[12..].copy_from_slice(&index);
        claim.open_commitment = source::commitment::digest(&source::commitment::opening_fields(
            &claim,
            [Val::TWO; 4],
            &plain,
        ));
        let source = CanonicalSource::checked_claim(&claim).unwrap();
        let source_bytes = {
            let witness = source::circuit::Witness::new(
                key,
                [Val::ONE; 4],
                [Val::TWO; 4],
                [255, 0, 255, 128],
            );
            source::prove(&source, &witness).unwrap().into_bytes()
        };
        let mathematical = Witness {
            plain,
            controllers: [[0x41; 32], [0x42; 32]],
            salts: [
                [Val::TWO; 4],
                [Val::from_u8(3); 4],
                [Val::from_u8(4); 4],
                [Val::from_u8(5); 4],
                [Val::from_u8(6); 4],
                [Val::from_u8(7); 4],
            ],
            old: Registry::default(),
            command: None,
        };
        drop(owner);
        drop(stored);
        drop(indexed);
        Fixture {
            source,
            mathematical,
            source_bytes,
        }
    })
}
fn bootstrap(f: &Fixture) -> Expected {
    let mut e = Expected::bootstrap(f.source.claim(), [0xa7; 32], [0xb7; 32], [0; 32]).unwrap();
    e.enrollment = source::commitment::digest(&commitment::enrollment_fields(&e, &f.mathematical));
    e
}

#[test]
fn actual_source_first_bootstrap_and_begin_roundtrip_without_prover_state() {
    let f = fixture();
    let initial = bootstrap(f);
    let checked = admission::Expected::checked_claim(&initial).unwrap();
    let prepared = PreparedWitness::new(&checked, f.mathematical.clone()).unwrap();
    let evidence = prove(&checked, &prepared, &f.source_bytes).unwrap();
    drop(prepared);
    let boot = wire::verify_claim(&initial, evidence.as_bytes()).unwrap();
    assert_eq!(boot.values(), evidence.statement().values());
    let mut mathematical = f.mathematical.clone();
    mathematical.salts[2] = mathematical.salts[4];
    mathematical.command = Some(Command::control(Operation::Begin, 1, 1, 0));
    let mut e = Expected::transition(
        f.source.claim(),
        initial.genesis,
        initial.parent,
        statement::encoded(initial.enrollment),
        statement::encoded(boot.next),
        [0; 32],
    )
    .unwrap();
    let command = statement::digest(&commitment::command_fields(
        &e,
        &mathematical,
        mathematical.command.as_ref().unwrap(),
    ));
    e.phase = Phase::Transition {
        old: boot.next,
        command,
    };
    let checked = admission::Expected::checked_claim(&e).unwrap();
    let expected = mathematical.statement(&e).unwrap();
    let prepared = PreparedWitness::new(&checked, mathematical).unwrap();
    let evidence = prove(&checked, &prepared, &f.source_bytes).unwrap();
    drop(prepared);
    let (claimed, bytes) = evidence.into_parts();
    assert_eq!(claimed.values(), expected.values());
    let verified = wire::verify_claim(&e, &bytes).unwrap();
    assert_eq!(verified.values(), expected.values());
    let frame = wire::frame::Frame::parse(wire::frame::Role::Transition, &bytes).unwrap();
    assert_eq!(frame.source, f.source_bytes);
    assert!(!frame.child.is_empty());
    // These actual mathematical proofs use labels, not a signed/admitted Journal history.
}

#[test]
fn prepared_witness_matches_complete_expected_before_any_source_backend() {
    let f = fixture();
    let original = bootstrap(f);
    let checked = admission::Expected::checked_claim(&original).unwrap();
    let prepared = PreparedWitness::new(&checked, f.mathematical.clone()).unwrap();
    for case in 0..7 {
        let mut e = original.clone();
        match case {
            0 => e.genesis[31] ^= 1,
            1 => e.parent[31] ^= 1,
            2 => e.enrollment[3] += Val::ONE,
            3 => e.source.request[31] ^= 1,
            4 => e.source.open_commitment[3] += Val::ONE,
            5 => e.source.key_commitment[3] += Val::ONE,
            _ => {
                e.phase = Phase::Transition {
                    old: [Val::ZERO; 4],
                    command: [Val::ZERO; 4],
                }
            }
        }
        let different = admission::Expected::checked_claim(&e).unwrap();
        assert!(
            matches!(
                prove(&different, &prepared, &[]),
                Err(wire::Error::Proof(crate::BackendError::Shape))
            ),
            "complete context {case}"
        );
    }
    let mut wrong = f.mathematical.clone();
    wrong.plain[2347] ^= 1;
    assert!(PreparedWitness::new(&checked, wrong).is_err());
    let mut wrong = f.mathematical.clone();
    wrong.controllers[1][31] ^= 1;
    assert!(PreparedWitness::new(&checked, wrong).is_err());
    let mut bad = original;
    bad.source.packets[1].pop();
    assert!(admission::Expected::checked_claim(&bad).is_err());
}

#[test]
fn canonical_bad_source_and_resource_bombs_fail_before_lifecycle_proving() {
    let f = fixture();
    let e = bootstrap(f);
    let checked = admission::Expected::checked_claim(&e).unwrap();
    let prepared = PreparedWitness::new(&checked, f.mathematical.clone()).unwrap();
    let backend = crate::fixed::Backend::source(f.source.claim()).unwrap();
    let mut proof: Proof<Config> = codec::decode(
        &f.source_bytes,
        &backend.shape,
        wire::MAX_SEQUENCE_ELEMENTS,
        wire::SOURCE_SLOTS,
    )
    .unwrap();
    let mut roots = proof.commitments.trace.roots().to_vec();
    roots[0][0] += Val::ONE;
    proof.commitments.trace = p3_symmetric::MerkleCap::new(roots);
    let damaged =
        crate::coefficient_encoding::wire::encode_source(f.source.claim(), &proof).unwrap();
    assert!(matches!(
        prove(&checked, &prepared, &damaged),
        Err(wire::Error::Proof(crate::BackendError::Verification) | wire::Error::Verification)
    ));
    assert!(matches!(
        prove(&checked, &prepared, &[]),
        Err(wire::Error::ResourceLimit)
    ));
    assert!(matches!(
        prove(
            &checked,
            &prepared,
            &vec![0; wire::frame::MAX_SOURCE_BYTES + 1]
        ),
        Err(wire::Error::ResourceLimit)
    ));
    assert!(prove(&checked, &prepared, &[0xff; 9]).is_err());
}

#[test]
fn mathematical_writer_bounds_private_geometry_without_granting_authority() {
    let f = fixture();
    let e = bootstrap(f);
    let claim = f.mathematical.statement(&e).unwrap();
    let mut wrong = f.mathematical.clone();
    wrong.old.transactions = vec![
        super::circuit::model::Transaction {
            id: 1,
            principal: 1,
            sequence: 1,
            failed: false,
            snapshot: [0; 32],
            held: [0; 4],
            savepoints: Vec::new()
        };
        3
    ];
    assert!(matches!(
        wrong.trace(&claim),
        Err(crate::BackendError::Shape)
    ));
    let mut wrong = f.mathematical.clone();
    wrong.command = Some(Command::control(Operation::Begin, 1, 0, 0));
    assert!(matches!(
        wrong.trace(&claim),
        Err(crate::BackendError::Shape)
    ));
    // Low-level mathematical field changes remain possible for AIR attacks;
    // only the consuming PreparedWitness is bound to a complete Expected.
    let mut foreign = claim;
    foreign.next[3] += Val::ONE;
    assert!(f.mathematical.trace(&foreign).is_ok());
}
