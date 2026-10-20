//! PUBLIC NONSECRET inputs. Only bootstrap cases claim genuine new-role proofs.
use super::*;
use crate::{admission::CanonicalSource, lifecycle::circuit::commitment, source};
use compact_store::{Layout, Owner};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::OnceLock,
};

pub(in crate::registry_progress) struct Fixture {
    pub(in crate::registry_progress) source: CanonicalSource,
    pub(in crate::registry_progress) plain: [u8; 2348],
    pub(in crate::registry_progress) source_bytes: Vec<u8>,
}
pub(in crate::registry_progress) fn fixture() -> &'static Fixture {
    static PUBLIC: OnceLock<Fixture> = OnceLock::new();
    PUBLIC.get_or_init(|| {
        let key = [0x71; 32]; // PUBLIC test authority, not exported production material.
        let owner = Owner::from_key([0x42; 16], [0x73; 16], Zeroizing::new(key));
        let data = [0, 1, 0, 1, 2, 0, 128, 3, 0, 255, 4, 0];
        let stored = owner
            .seal(
                Layout {
                    schema: source::DATA_SCHEMA,
                    row_width: 3,
                    rows_per_page: 256,
                    row_count: 4,
                },
                &data,
                source::statement::limits(),
            )
            .unwrap();
        // Explicit test-only fixed v3 index grammar. The actual Source AIR,
        // rather than this builder, proves bucket counts, postings and all IDs.
        let mut index = vec![0; 2336];
        index[..112].copy_from_slice(&stored.commitment().encode());
        index[112..144].fill(0x31);
        let ages = [0u8, 1, 128, 255];
        let mut count = 0u32;
        for age in 0..256 {
            let present = ages.contains(&(age as u8));
            index[144 + 4 * age..148 + 4 * age].copy_from_slice(&u32::from(present).to_le_bytes());
            index[1168 + 4 * age..1172 + 4 * age].copy_from_slice(&count.to_le_bytes());
            if present {
                index[2196 + count as usize] =
                    ages.iter().position(|a| usize::from(*a) == age).unwrap() as u8;
                count += 1;
            }
        }
        index[2192..2196].copy_from_slice(&count.to_le_bytes());
        for i in 0..4 {
            index[2208 + 32 * i] = i as u8 + 1;
        }
        let indexed = owner
            .seal(
                Layout {
                    schema: source::INDEX_SCHEMA,
                    row_width: 1,
                    rows_per_page: 4096,
                    row_count: 2336,
                },
                &index,
                source::statement::limits(),
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
        let witness = source::circuit::Witness::new(key, [Val::ONE; 4], [Val::TWO; 4], ages);
        let source_bytes = source::prove(&source, &witness).unwrap().into_bytes();
        Fixture {
            source,
            plain,
            source_bytes,
        }
    })
}
pub(in crate::registry_progress) fn expected(f: &Fixture) -> BootstrapExpected {
    let legacy = crate::lifecycle::statement::Expected::bootstrap(
        f.source.claim(),
        [0xa7; 32],
        [0xb7; 32],
        [0; 32],
    )
    .unwrap();
    let enrollment = source::commitment::digest(&commitment::enrollment_fields_opening(
        &legacy,
        &f.plain[124..156].try_into().unwrap(),
        &[[0x41; 32], [0x42; 32]],
        [Val::from_u8(3); 4],
    ));
    BootstrapExpected::new(
        &f.source,
        legacy.genesis,
        legacy.parent,
        source::statement::encode_digest(enrollment),
    )
    .unwrap()
}
fn witness(f: &Fixture, e: &BootstrapExpected) -> BootstrapWitness {
    BootstrapWitness::new(
        e,
        Zeroizing::new(f.plain),
        Zeroizing::new([[0x41; 32], [0x42; 32]]),
        Zeroizing::new([[2; 4], [3; 4], [6; 4]]),
    )
    .unwrap()
}
fn reject_trace(s: &BootstrapStatement, trace: RowMajorMatrix<Val>) {
    let backend = Backend::new(s).unwrap();
    if let Ok(Ok(proof)) = catch_unwind(AssertUnwindSafe(|| backend.prove(trace))) {
        assert!(
            backend.verify(&proof).is_err(),
            "repaired false Registry208 bootstrap accepted"
        );
    }
}
/// Recompute every actual Poseidon witness and every checkpoint. A submitted
/// forged field is not disguised by an incoherent permutation or a stale root.
fn refresh(
    s: &BootstrapStatement,
    trace: &mut RowMajorMatrix<Val>,
    forged: Option<(usize, Val)>,
) -> [Val; 4] {
    let air = air::BootstrapAir::new(s);
    let mut checkpoint = [Val::ZERO; 12];
    let mut root = [Val::ZERO; 4];
    for (r, row) in trace
        .values
        .as_chunks_mut::<WIDTH>()
        .0
        .iter_mut()
        .enumerate()
    {
        row[air::CHECKPOINT..air::WORDS].copy_from_slice(&checkpoint);
        let mut input = [Val::ZERO; 12];
        if let Some((stream, block)) = air::absorb(r) {
            for (slot, value) in input[..8].iter_mut().enumerate() {
                let f = block * 8 + slot;
                *value = air.field(row, stream, f, slot);
                if matches!(stream, air::Stream::Registry)
                    && let Some((at, v)) = forged
                    && f == at
                {
                    *value = v;
                }
            }
            if !air::reset(r) {
                input[8..].copy_from_slice(&checkpoint[8..]);
            }
        }
        let output = crate::poseidon::write(&mut row[..air::CHECKPOINT], input);
        if air::absorb(r).is_some() {
            checkpoint = output;
        }
        if r == 118 {
            root.copy_from_slice(&output[..4]);
        }
    }
    root
}

#[test]
fn genuine_source_and_new_empty_registry208_bootstrap_roundtrip() {
    let f = fixture();
    let e = expected(f);
    let w = witness(f, &e);
    let evidence = prove_bootstrap(&e, &w, &f.source_bytes).unwrap();
    let (statement, bytes) = evidence.into_parts();
    drop(w);
    assert_eq!(statement.values().len(), 803);
    let checked = verify_bootstrap(&e, &statement, &f.source_bytes, &bytes).unwrap();
    assert_eq!(checked.statement().values(), statement.values());
    let root = State::default()
        .root(&e, &f.plain, &[[0x41; 32], [0x42; 32]], [6; 4])
        .unwrap();
    assert_eq!(statement.next(), source::statement::encode_digest(root));
    // New domain and 208 fields cannot alias the original empty Registry200.
    let table = f.plain[124..156].try_into().unwrap();
    let ids = core::array::from_fn(|i| f.plain[2220 + 32 * i..2252 + 32 * i].try_into().unwrap());
    let old = commitment::registry_fields_opening(
        &e.legacy(),
        &table,
        &ids,
        &[[0x41; 32], [0x42; 32]],
        &crate::lifecycle::circuit::model::Registry::default(),
        [Val::from_u8(6); 4],
    );
    assert_ne!(root, crate::lifecycle::statement::digest(&old));
    assert_eq!(
        payload(&statement, &bytes).unwrap().len() + HEADER,
        bytes.len()
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(payload(&statement, &trailing), Err(Error::Encoding));
    let mut namespace = bytes.clone();
    namespace[8] = 2;
    assert_eq!(payload(&statement, &namespace), Err(Error::Shape));
    let mut corrupted = bytes;
    *corrupted.last_mut().unwrap() ^= 1;
    assert!(verify_bootstrap(&e, &statement, &f.source_bytes, &corrupted).is_err());
}

#[test]
fn complete_expected_and_genuine_source_are_required_before_child_work() {
    let f = fixture();
    let e = expected(f);
    let w = witness(f, &e);
    for n in 0..6 {
        let mut other = e.clone();
        match n {
            0 => other.genesis[31] ^= 1,
            1 => other.parent[31] ^= 1,
            2 => other.enrollment[3] += Val::ONE,
            3 => {
                other.source = {
                    let mut claim = f.source.claim().clone();
                    claim.request[31] ^= 1;
                    CanonicalSource::checked_claim(&claim).unwrap()
                }
            }
            4 => {
                other.source = {
                    let mut claim = f.source.claim().clone();
                    claim.key_commitment[3] += Val::ONE;
                    CanonicalSource::checked_claim(&claim).unwrap()
                }
            }
            _ => {
                other.source = {
                    let mut claim = f.source.claim().clone();
                    claim.open_commitment[3] += Val::ONE;
                    CanonicalSource::checked_claim(&claim).unwrap()
                }
            }
        }
        assert!(matches!(
            prove_bootstrap(&other, &w, &[]),
            Err(Error::Proof(BackendError::Shape))
        ));
    }
    assert!(matches!(
        prove_bootstrap(&e, &w, &[]),
        Err(Error::Prerequisite)
    ));
    let backend = crate::fixed::Backend::source(f.source.claim()).unwrap();
    let mut proof: Proof<Config> = codec::decode(
        &f.source_bytes,
        &backend.shape,
        crate::wire::MAX_SEQUENCE_ELEMENTS,
        crate::wire::SOURCE_SLOTS,
    )
    .unwrap();
    let mut roots = proof.commitments.trace.roots().to_vec();
    roots[0][0] += Val::ONE;
    proof.commitments.trace = p3_symmetric::MerkleCap::new(roots);
    let malformed =
        crate::coefficient_encoding::wire::encode_source(f.source.claim(), &proof).unwrap();
    assert!(matches!(
        prove_bootstrap(&e, &w, &malformed),
        Err(Error::Prerequisite)
    ));
    let mut plain = f.plain;
    plain[2347] ^= 1;
    assert!(
        BootstrapWitness::new(
            &e,
            Zeroizing::new(plain),
            Zeroizing::new([[0x41; 32], [0x42; 32]]),
            Zeroizing::new([[2; 4], [3; 4], [6; 4]])
        )
        .is_err()
    );
    assert!(
        BootstrapWitness::new(
            &e,
            Zeroizing::new(f.plain),
            Zeroizing::new([[0x41; 32], [0x42; 32]]),
            Zeroizing::new([[2; 4], [3; 4], [Val::ORDER_U64; 4]])
        )
        .is_err()
    );
}

#[test]
fn repaired_roots_cannot_insert_progress_revision_or_padding_into_bootstrap() {
    let f = fixture();
    let e = expected(f);
    let w = witness(f, &e);
    let statement = w.statement();
    for field in [80, 82, 84, 194, 195, 199, 203, 204, 207] {
        let mut trace = w.trace();
        let mut false_claim = statement.clone();
        false_claim.next = refresh(statement, &mut trace, Some((field, Val::ONE)));
        assert_ne!(false_claim.next, statement.next);
        reject_trace(&false_claim, trace);
    }
    // All 32 ID words, including last ordinal/last word, must come from Source.
    let mut trace = w.trace();
    for row in trace.values.as_chunks_mut::<WIDTH>().0 {
        row[air::IDS + 31] += Val::ONE;
    }
    let mut false_claim = statement.clone();
    false_claim.next = refresh(statement, &mut trace, None);
    assert_ne!(false_claim.next, statement.next);
    reject_trace(&false_claim, trace);
}
