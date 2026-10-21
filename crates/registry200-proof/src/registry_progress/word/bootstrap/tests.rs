//! Bounded explicitly NONSECRET inputs; actual Source/EMPTY native proof boundaries.
use super::*;
use crate::registry_progress::{bootstrap_air as air, word_inventory::owner};
use bfv_hiding_stark::{Challenge, Config};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::default_goldilocks_poseidon2_12;
use p3_symmetric::Permutation;
use p3_uni_stark::Proof;
use std::{sync::OnceLock, time::Instant};
struct Fixture {
    expected: Expected,
    plain: [u8; 2348],
    source: Vec<u8>,
    bank: [Val; 208],
}
fn fixture() -> &'static Fixture {
    static PUBLIC: OnceLock<Fixture> = OnceLock::new();
    PUBLIC.get_or_init(|| {
        // Reuse the original public Begin example's independently serialized
        // EMPTY old bank, not this module's early opening check or trace writer.
        let (m, p) = owner::public_case(false);
        let expected = Expected::checked(&m.source, [0xa7; 32], m.enrollment, m.old).unwrap();
        assert_eq!(expected.registry_header(), &m.registry_header);
        assert_eq!(expected.enrollment_header(), &m.enrollment_header);
        let mut plain = [0; 2348];
        for (out, word) in plain.as_chunks_mut::<4>().0.iter_mut().zip(p.source) {
            out.copy_from_slice(&(word.as_canonical_u64() as u32).to_le_bytes());
        }
        let source = source::version::prove(
            &m.source,
            &source::circuit::Witness::new(
                [0x71; 32],
                [Val::ONE; 4],
                [Val::TWO; 4],
                [0, 1, 128, 255],
            ),
        )
        .unwrap()
        .into_bytes();
        let mut state = [Val::ZERO; 12];
        for block in p.banks[0].as_chunks::<8>().0 {
            state[..8].copy_from_slice(block);
            default_goldilocks_poseidon2_12().permute_mut(&mut state);
        }
        assert_eq!(expected.root(), state[..4]);
        Fixture {
            expected,
            plain,
            source,
            bank: p.banks[0],
        }
    })
}
fn inputs(f: &Fixture) -> PrivateInputs {
    PrivateInputs::checked(
        &f.expected,
        SourceOpening::checked(Zeroizing::new(f.plain.to_vec()), Zeroizing::new([2; 4])).unwrap(),
        Zeroizing::new([[0x41; 32], [0x42; 32]]),
        Zeroizing::new([[3; 4], [6; 4]]),
    )
    .unwrap()
}
fn reframe(e: &Expected, proof: &Proof<Config>) -> Vec<u8> {
    let backend = backend::Backend::new(e).unwrap();
    let child = codec::serialize(proof, &backend.shape, MAX_PROOF_BYTES).unwrap();
    let mut out = header(e, child.len()).unwrap();
    out.extend(child);
    out
}
#[test]
fn genuine_state_version_and_word_empty_root_verify_without_granting_currentness() {
    let began = Instant::now();
    let f = fixture();
    let e = &f.expected;
    let proof = prove(e, inputs(f), &f.source).unwrap();
    let receiving = Instant::now();
    let checked = verify(e, &f.source, proof.as_bytes()).unwrap();
    let receive = receiving.elapsed();
    assert_eq!(checked.expected().binding(), e.binding());
    assert_eq!(checked.expected().root(), e.root());
    assert_eq!(e.values().len(), PUBLIC_VALUES);
    assert_eq!(&f.bank[190..194], &[Val::from_u8(6); 4]);
    for field in (80..190).chain(194..208) {
        assert_eq!(f.bank[field], Val::ZERO);
    }
    assert_ne!(
        profile_digest(),
        crate::registry_progress::bootstrap_profile_digest()
    );
    assert_ne!(profile_digest(), super::super::wire_profile_digest());
    eprintln!(
        "word_empty_bootstrap source_bytes={} child_bytes={} receive_source_and_child_ms={:.3} whole_owner_setup_prove_receive_ms={:.3} sql_accepted=false",
        f.source.len(),
        proof.as_bytes().len(),
        receive.as_secs_f64() * 1000.,
        began.elapsed().as_secs_f64() * 1000.
    );
    // Continue with a real original Word Begin proof over exactly this EMPTY
    // root. The historical bootstrap result still supplies no current-head lease.
    let (m, mut p) = owner::public_case(false);
    assert_eq!(
        checked.expected().source().statement().values(),
        m.source.statement().values()
    );
    assert_eq!(checked.expected().root(), m.old);
    let word = WordExpected::checked(
        &m.source,
        Role::Control,
        [0xa7; 32],
        [0xb7; 32],
        m.enrollment,
        Claims {
            old: m.old,
            command: m.command,
            statement: m.statement,
            next: m.next,
            result: m.result,
            blind_sql: m.blind_sql,
        },
    )
    .unwrap();
    let input = super::super::PrivateInputs::new(
        SourceOpening::checked(Zeroizing::new(f.plain.to_vec()), Zeroizing::new([2; 4])).unwrap(),
        super::super::RegistryOpening::new(p.controllers, p.banks),
        core::mem::take(&mut p.command),
        core::mem::take(&mut p.walk),
        Zeroizing::new(p.mask),
        p.salts,
    );
    let word_proof = super::super::prove(&word, input).unwrap();
    let checked_word = super::super::verify(&word, word_proof.as_bytes()).unwrap();
    assert_eq!(
        checked_word.expected().claims().old,
        checked.expected().root()
    );
    assert_ne!(
        checked_word.expected().claims().next,
        checked.expected().root()
    );
    assert!(super::super::verify(&word, proof.as_bytes()).is_err());
    assert!(verify(e, &f.source, word_proof.as_bytes()).is_err());
}
#[test]
fn owner_openings_require_the_original_source_controllers_and_empty_root() {
    let f = fixture();
    for n in 0..5 {
        let mut plain = f.plain;
        let mut controllers = [[0x41; 32], [0x42; 32]];
        let mut salts = [[3; 4], [6; 4]];
        match n {
            0 => plain[2347] ^= 1,
            1 => controllers[1][31] ^= 1,
            2 => controllers[0].fill(0),
            3 => salts[0][3] = Val::ORDER_U64,
            _ => salts[1][3] += 1,
        }
        assert!(
            PrivateInputs::checked(
                &f.expected,
                SourceOpening::checked(Zeroizing::new(plain.to_vec()), Zeroizing::new([2; 4]))
                    .unwrap(),
                Zeroizing::new(controllers),
                Zeroizing::new(salts),
            )
            .is_err(),
            "opening variant {n}"
        );
    }
}
#[test]
fn receiving_rejects_missing_or_damaged_source_child_and_repaired_foreign_metadata() {
    let f = fixture();
    let e = &f.expected;
    assert!(matches!(prove(e, inputs(f), &[]), Err(Error::Prerequisite)));
    let proof = prove(e, inputs(f), &f.source).unwrap();
    let bytes = proof.as_bytes();
    assert!(matches!(verify(e, &[], bytes), Err(Error::Prerequisite)));
    let source_backend = crate::fixed::Backend::source_version(e.source()).unwrap();
    let mut damaged = codec::decode(
        &f.source,
        &source_backend.shape,
        crate::wire::MAX_SEQUENCE_ELEMENTS,
        crate::wire::SOURCE_SLOTS,
    )
    .unwrap();
    damaged.opened_values.trace_local[0] += Challenge::ONE;
    let damaged = codec::serialize(
        &damaged,
        &source_backend.shape,
        source::version::MAX_CERTIFICATE_BYTES,
    )
    .unwrap();
    assert!(matches!(
        verify(e, &damaged, bytes),
        Err(Error::Prerequisite)
    ));
    assert!(matches!(
        prove(e, inputs(f), &damaged),
        Err(Error::Prerequisite)
    ));
    let b = backend::Backend::new(e).unwrap();
    let native = codec::decode(
        payload(e, bytes).unwrap(),
        &b.shape,
        16_384,
        16 * 1024 * 1024,
    )
    .unwrap();
    let mut damaged = codec::decode(
        payload(e, bytes).unwrap(),
        &b.shape,
        16_384,
        16 * 1024 * 1024,
    )
    .unwrap();
    damaged.opened_values.trace_local[0] += Challenge::ONE;
    assert!(matches!(
        verify(e, &f.source, &reframe(e, &damaged)),
        Err(Error::Backend(crate::BackendError::Verification))
    ));
    // A coherent repaired wire binding is not a native proof under another claim.
    for field in 0..3 {
        let mut enrollment = e.enrollment();
        let mut root = e.root();
        let mut genesis = [0xa7; 32];
        match field {
            0 => genesis[31] ^= 1,
            1 => enrollment[3] += Val::ONE,
            _ => root[3] += Val::ONE,
        }
        let other = Expected::checked(e.source(), genesis, enrollment, root).unwrap();
        assert_ne!(other.binding(), e.binding());
        assert!(matches!(
            verify(&other, &f.source, bytes),
            Err(Error::Binding)
        ));
        assert!(matches!(
            verify(&other, &f.source, &reframe(&other, &native)),
            Err(Error::Backend(crate::BackendError::Verification))
        ));
    }
    // C_state is deliberately absent from version_id; the COMPLETE expectation is bound.
    let s = e.source().statement();
    let images: [Vec<u8>; 2] =
        core::array::from_fn(|i| s.heads[i].iter().chain(&s.packets[i]).copied().collect());
    let heads: [_; 2] = core::array::from_fn(|i| {
        compact_store::Commitment::decode(&s.heads[i], source::statement::limits()).unwrap()
    });
    let mut state = s.open_commitment;
    state[3] += Val::ONE;
    let foreign = SourceVersionExpected::checked(
        [&images[0], &images[1]],
        [&heads[0], &heads[1]],
        source::statement::encode_digest(s.key_commitment),
        source::statement::encode_digest(state),
    )
    .unwrap();
    assert_eq!(foreign.version_id(), e.source().version_id());
    let foreign = Expected::checked(&foreign, [0xa7; 32], e.enrollment(), e.root()).unwrap();
    assert_ne!(foreign.binding(), e.binding());
    assert!(matches!(
        verify(&foreign, &f.source, &reframe(&foreign, &native)),
        Err(Error::Prerequisite)
    ));
    for n in 0..7 {
        let mut malformed = bytes.to_vec();
        match n {
            0 => malformed.clear(),
            1 => malformed.push(0),
            2 => malformed[0] ^= 1,
            3 => malformed[9] = 1,
            4 => malformed[116] = 1,
            5 => malformed[112..116].copy_from_slice(&u32::MAX.to_le_bytes()),
            _ => {
                malformed.push(0);
                let len = (malformed.len() - HEADER_BYTES) as u32;
                malformed[112..116].copy_from_slice(&len.to_le_bytes());
            }
        }
        assert!(
            verify(e, &f.source, &malformed).is_err(),
            "framing variant {n}"
        );
    }
}
// Recompute every actual Poseidon checkpoint after a malicious witness/root edit.
fn refresh(
    backend: &backend::Backend,
    trace: &mut p3_matrix::dense::RowMajorMatrix<Val>,
    forged: Option<usize>,
) -> [Val; 4] {
    let mut checkpoint = [Val::ZERO; 12];
    let mut root = [Val::ZERO; 4];
    for (r, row) in trace
        .values
        .as_chunks_mut::<{ backend::WIDTH }>()
        .0
        .iter_mut()
        .enumerate()
    {
        row[air::CHECKPOINT..air::WORDS].copy_from_slice(&checkpoint);
        let mut input = [Val::ZERO; 12];
        if let Some((stream, block)) = air::absorb(r) {
            for (slot, value) in input[..8].iter_mut().enumerate() {
                let field = block * 8 + slot;
                *value = backend.air.field(row, stream, field, slot);
                if matches!(stream, air::Stream::Registry) && forged == Some(field) {
                    *value = Val::ONE;
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
fn native_relation_rejects_inserted_locks_progress_padding_and_foreign_last_source_id() {
    let f = fixture();
    let e = &f.expected;
    let w = inputs(f);
    let b = backend::Backend::new(e).unwrap();
    for field in [80, 82, 84, 194, 195, 199, 203, 204, 207, 76] {
        let mut trace = b.air.trace(&w.plain, &w.controllers, &w.salts);
        let root = refresh(&b, &mut trace, Some(field));
        assert_ne!(root, e.root(), "repaired field {field}");
        let false_claim = Expected::checked(e.source(), [0xa7; 32], e.enrollment(), root).unwrap();
        let verifier = backend::Backend::new(&false_claim).unwrap();
        if let Ok(Ok(proof)) =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| verifier.prove(trace)))
        {
            assert!(
                verifier.verify(&proof).is_err(),
                "native forgery accepted at field {field}"
            );
        }
    }
    let mut trace = b.air.trace(&w.plain, &w.controllers, &w.salts);
    for row in trace.values.as_chunks_mut::<{ backend::WIDTH }>().0 {
        row[air::IDS + 31] += Val::ONE;
    }
    let root = refresh(&b, &mut trace, None);
    let false_claim = Expected::checked(e.source(), [0xa7; 32], e.enrollment(), root).unwrap();
    let verifier = backend::Backend::new(&false_claim).unwrap();
    if let Ok(Ok(proof)) =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| verifier.prove(trace)))
    {
        assert!(
            verifier.verify(&proof).is_err(),
            "foreign ordinal accepted after repaired root"
        );
    }
}
