//! PUBLIC NONSECRET fixtures. The real SDK proves both roles; no plaintext SQL executor.
use super::*;
use crate::{
    backend::Val,
    opening::{proof_codec, statement as source},
};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use registry200_proof::{
    admission::CanonicalSource,
    coefficient_encoding::{self as fixed, N, Role, SCALE, T, layout::*, statement::BfvBinding},
};
use std::{
    cell::Cell,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::OnceLock,
};
use zeroize::Zeroizing;
fn fixture() -> &'static fixture::Fixture {
    static F: OnceLock<fixture::Fixture> = OnceLock::new();
    F.get_or_init(|| fixture::genuine().unwrap())
}
struct Published {
    source: Vec<u8>,
    frames: [Vec<u8>; 2],
    statements: [Statement; 2],
}
fn published() -> &'static Published {
    static P: OnceLock<Published> = OnceLock::new();
    P.get_or_init(|| {
        let f = fixture();
        let b = Backend::new(&f.source_statement).unwrap();
        let proof = b
            .prove_with_trace(&f.source_statement, || {
                f.source_witness.trace(&f.source_statement)
            })
            .unwrap();
        b.verify(&f.source_statement, &proof).unwrap();
        let source = frame::source_bytes(&f.source_statement, &proof).unwrap();
        drop(b);
        let statements = [
            f.source_encoding.statement(&f.source),
            f.query_encoding.statement(&f.query),
        ];
        let frames = core::array::from_fn(|i| {
            let w = if i == 0 {
                &f.source_encoding
            } else {
                &f.query_encoding
            };
            let s = &statements[i];
            let child =
                prove_child_with_factory(&s.expected, s, Some(&proof), || w.trace(s)).unwrap();
            frame::encode_with_source(&s.expected, s, &source, &child).unwrap()
        });
        Published {
            source,
            frames,
            statements,
        }
    })
}
fn source_proof() -> Proof<Config> {
    let f = fixture();
    let b = Backend::new(&f.source_statement).unwrap();
    let shape = proof_codec::Topology::checked(11521, b.report.quotient_chunks).unwrap();
    proof_codec::decode(&published().source, &shape, 16384, 24 * 1024 * 1024).unwrap()
}
fn actual_source(f: &fixture::Fixture) -> Proof<Config> {
    let b = Backend::new(&f.source_statement).unwrap();
    let p = b
        .prove_with_trace(&f.source_statement, || {
            f.source_witness.trace(&f.source_statement)
        })
        .unwrap();
    b.verify(&f.source_statement, &p).unwrap();
    p
}
fn own_frame(e: &Expected, w: &trace::Witness, source: &Proof<Config>) -> (Statement, Vec<u8>) {
    let s = w.statement(e);
    let child = prove_child_with_factory(e, &s, Some(source), || w.trace(&s)).unwrap();
    let a = frame::source_bytes(e.source_claim(), source).unwrap();
    let bytes = frame::encode_with_source(e, &s, &a, &child).unwrap();
    require_complete(&s, &frame::decode_and_verify(e, &bytes).unwrap()).unwrap();
    (s, bytes)
}
fn reject_sdk(s: &Statement, t: RowMajorMatrix<Val>) {
    let b = Backend::new(s).unwrap();
    let p = catch_unwind(AssertUnwindSafe(|| b.prove_with_trace(s, || Ok(t))));
    if let Ok(Ok(p)) = p {
        assert!(
            b.verify(s, &p).is_err(),
            "coherently rebuilt false trace accepted"
        );
    }
}
fn field(t: &mut RowMajorMatrix<Val>, at: usize, v: Val) {
    let width = t.width;
    for row in t.values.chunks_exact_mut(width) {
        row[at] = v;
    }
}
fn bitfield(t: &mut RowMajorMatrix<Val>, at: usize, n: usize, v: u64) {
    let width = t.width;
    for row in t.values.chunks_exact_mut(width) {
        trace::bits(&mut row[at..at + n], v);
    }
}
fn raw_oracle(role: Role) -> Vec<u64> {
    let mut raw = vec![0; N];
    match role {
        Role::SourceAllOriginal => {
            for i in 0..4 {
                let age = usize::from(fixture::DATA[3 * i]);
                let amount =
                    u16::from_le_bytes(fixture::DATA[3 * i + 1..3 * i + 3].try_into().unwrap());
                for (f, v) in [1, age as u64, u64::from(amount)].into_iter().enumerate() {
                    raw[(3 * i + f) * 512 + age] = v;
                }
            }
        }
        Role::PrivateMask => {
            for (n, value) in raw.iter_mut().take(256).enumerate() {
                let age = 255 - n;
                *value = u64::from([0, 128, 255].contains(&age));
            }
        }
    }
    raw
}
#[test]
fn genuine_source_and_private_mask_all8192_match_actual_sdk_poly_and_formation_root() {
    use fhe::bfv::{BfvParameters, Encoding, Plaintext};
    use fhe_math::rq::{Poly, Representation, traits::TryConvertFrom};
    use fhe_traits::FheEncoder;
    let f = fixture();
    let p = published();
    // Parameters are taken from the real fixed Core setup, never a substitute field transform.
    let (_, setup) = bfv_query_core::Owner::generate(bfv_query_core::Geometry::Rows16).unwrap();
    let material = setup.relinearization_material().unwrap();
    use fhe_traits::Deserialize;
    let parameters =
        std::sync::Arc::new(BfvParameters::try_deserialize(material.parameters()).unwrap());
    for (i, (e, w)) in [
        (&f.source, &f.source_encoding),
        (&f.query, &f.query_encoding),
    ]
    .into_iter()
    .enumerate()
    {
        let s = frame::decode_and_verify(e, &p.frames[i]).unwrap();
        require_complete(&p.statements[i], &s).unwrap();
        let raw = raw_oracle(e.role());
        let plaintext = Plaintext::try_encode(&raw, Encoding::poly(), &parameters).unwrap();
        let poly = Poly::try_convert_from(
            &plaintext,
            parameters.context_at_level(0).unwrap(),
            false,
            Representation::PowerBasis,
        )
        .unwrap();
        let unscaled = poly.coefficients().row(0).to_vec();
        assert_eq!(unscaled, raw);
        for row in poly.coefficients().rows() {
            assert_eq!(row.to_vec(), raw);
        }
        let qmod = parameters
            .moduli()
            .iter()
            .fold(1u128, |v, q| v * u128::from(*q) % u128::from(T));
        assert_eq!(qmod, u128::from(SCALE));
        let expected: Vec<_> = unscaled.into_iter().map(|m| m * SCALE % T).collect();
        assert_eq!(&*w.coefficients(e.role()), &expected);
        assert_eq!(expected.len(), 8192);
        assert!(w.formation_opening(&s).is_ok());
        assert_eq!(s.values().len(), e.role().public_values());
        assert_eq!(s.values()[8..699], e.source_claim().values());
        assert_eq!(s.values()[707..740], e.bfv().key().public_values());
        assert!(p.frames[i].len() <= frame::MAX_FRAME);
    }
}
#[test]
fn empty_full_range_and_noncontiguous_hidden_masks_prove_complete_reversed_vectors() {
    let f = fixture();
    for (sql, truth) in [
        ("SELECT * FROM records WHERE FALSE", 0u8),
        ("SELECT * FROM records WHERE TRUE", 1),
        ("SELECT * FROM records WHERE age BETWEEN 3 AND 250", 2),
        ("SELECT * FROM records WHERE age IN (0, 7, 128, 255)", 3),
        (
            "SELECT * FROM records WHERE age = NULL OR age IN (7, 128)",
            4,
        ),
    ] {
        let compiled = compiler::CompiledPrivatePredicate::compile(
            sql,
            Zeroizing::new([0xB1; 32]),
            [0xA1; 32],
        )
        .unwrap();
        let mut source = f.source_statement.clone();
        source.request = compiled.query(&source, f.source.bfv());
        // A different exact SQL has a different q and requires a fresh genuine Source.
        let g = fixture::prepare(
            sql,
            [0xB1; 32],
            [0xA1; 32],
            f.source.bfv().clone(),
            fixture::DATA,
        )
        .unwrap();
        assert_eq!(source.request, g.source_statement.request);
        let gp = actual_source(&g);
        let (s, _) = own_frame(&g.query, &g.query_encoding, &gp);
        let words = g.query_encoding.coefficients(Role::PrivateMask);
        for n in 0..N {
            let age = 255usize.saturating_sub(n);
            let yes = n < 256
                && match truth {
                    0 => false,
                    1 => true,
                    2 => (3..=250).contains(&age),
                    3 => [0, 7, 128, 255].contains(&age),
                    _ => [7, 128].contains(&age),
                };
            assert_eq!(words[n], if yes { SCALE } else { 0 });
        }
        assert_eq!(
            s.values()[752..760],
            source::words(&g.query.sql_identity()).collect::<Vec<_>>()
        );
    }
}
#[test]
fn compiler_rejects_other_sql_roles_and_owns_private_blind_nonce_and_full_query() {
    let f = fixture();
    for sql in [
        "SELECT age FROM records",
        "SELECT amount, age FROM records",
        "SELECT * FROM records LIMIT 1",
        "SELECT * FROM records OFFSET 1",
        "SELECT * FROM records FOR UPDATE",
        "SELECT COUNT(*) FROM records",
        "UPDATE records SET amount = amount + 1",
    ] {
        assert!(
            compiler::CompiledPrivatePredicate::compile(
                sql,
                Zeroizing::new([0xB1; 32]),
                [0xA1; 32]
            )
            .is_err(),
            "{sql}"
        );
    }
    assert!(
        compiler::CompiledPrivatePredicate::compile(
            fixture::SQL,
            Zeroizing::new([0xA1; 32]),
            [0xA1; 32]
        )
        .is_err()
    );
    assert!(
        compiler::CompiledPrivatePredicate::compile(
            fixture::SQL,
            Zeroizing::new([0; 32]),
            [0xA1; 32]
        )
        .is_err()
    );
    let canonical = CanonicalSource::checked_claim(&f.source_statement).unwrap();
    for (sql, blind, nonce) in [
        (fixture::SQL, [0xB2; 32], [0xA1; 32]),
        (fixture::SQL, [0xB1; 32], [0xA2; 32]),
        (
            "SELECT * FROM records WHERE age < 9",
            [0xB1; 32],
            [0xA1; 32],
        ),
    ] {
        let c =
            compiler::CompiledPrivatePredicate::compile(sql, Zeroizing::new(blind), nonce).unwrap();
        assert_ne!(
            c.query(&f.source_statement, f.source.bfv()),
            f.source_statement.request
        );
        assert!(
            c.bind(&canonical, f.source.bfv().clone(), [Val::from_u8(23); 4])
                .is_err()
        );
    }
}
#[test]
fn source_values_ids_and_final_padding_remain_bound_in_coherently_rehashed_traces() {
    let f = fixture();
    let s = &published().statements[0];
    let original = f.source_encoding.coefficients(Role::SourceAllOriginal);
    for at in [DATA + 95, TABLE + 7, IDS + 31, SOURCE_SALT + 3] {
        let mut t = f.source_encoding.trace(s).unwrap();
        let v = t.values[at] + Val::ONE;
        field(&mut t, at, v);
        let mut claim = s.clone();
        claim.encoded = trace::refresh(&claim, &mut t, &original);
        reject_sdk(&claim, t);
    }
    // Every scaled-weight range cell is repaired for another LEGITIMATE u16 amount.
    // Only the immutable original Source amount -> scaled-weight equation must fail.
    let replacement = 256u64;
    let scaled = replacement * SCALE % T;
    let mut t = f.source_encoding.trace(s).unwrap();
    let at = weight(3, 1);
    bitfield(&mut t, at, 17, scaled);
    bitfield(&mut t, at + 17, 17, T - 1 - scaled);
    bitfield(&mut t, at + 34, 16, replacement * SCALE / T);
    let mut claim = s.clone();
    let mut words = original.to_vec();
    words[11 * 512 + 128] = scaled;
    claim.encoded = trace::refresh(&claim, &mut t, &words);
    reject_sdk(&claim, t);
    for omit in [true, false] {
        let mut words = original.to_vec();
        if omit {
            for lane in 9..12 {
                words[lane * 512 + 128] = 0;
            }
        } else {
            words[9 * 512 + 129] = words[9 * 512 + 128];
            words[9 * 512 + 128] = 0;
        }
        let mut t = f.source_encoding.trace(s).unwrap();
        let mut claim = s.clone();
        claim.encoded = trace::refresh(&claim, &mut t, &words);
        reject_sdk(&claim, t);
    }
    for n in [256, 5888, 8191] {
        let mut words = original.to_vec();
        words[n] = 1;
        let mut t = f.source_encoding.trace(s).unwrap();
        let mut claim = s.clone();
        claim.encoded = trace::refresh(&claim, &mut t, &words);
        reject_sdk(&claim, t);
    }
    let mut t = f.source_encoding.trace(s).unwrap();
    t.values[84 * SOURCE_WIDTH + WORDS + 32 * 7] = Val::ONE;
    let mut claim = s.clone();
    claim.encoded = trace::refresh(&claim, &mut t, &original);
    reject_sdk(&claim, t);
}
#[test]
fn query_mask_reversal_salts_and_last_coefficient_cannot_be_repaired_into_valid_claims() {
    let f = fixture();
    let s = &published().statements[1];
    let original = f.query_encoding.coefficients(Role::PrivateMask);
    for at in [MASK, MASK + 255, COMMAND_SALT + 3] {
        let mut t = f.query_encoding.trace(s).unwrap();
        let old = t.values[at];
        field(
            &mut t,
            at,
            if at < MASK + 256 {
                Val::ONE - old
            } else {
                old + Val::ONE
            },
        );
        let mut claim = s.clone();
        claim.encoded = trace::refresh(&claim, &mut t, &original);
        reject_sdk(&claim, t);
    }
    for n in [0, 255, 256, 8191] {
        let mut words = original.to_vec();
        words[n] = (words[n] + 1) % T;
        let mut t = f.query_encoding.trace(s).unwrap();
        let mut claim = s.clone();
        claim.encoded = trace::refresh(&claim, &mut t, &words);
        reject_sdk(&claim, t);
    }
    // Preserve the entire binary scaled shape and zero tail; only index reversal is false.
    for reverse in [false, true] {
        let mut words = original.to_vec();
        if reverse {
            words[..256].reverse();
        } else {
            words[..256].rotate_left(1);
        }
        assert_ne!(words.as_slice(), original.as_slice());
        assert!(words[..256].iter().all(|v| *v == 0 || *v == SCALE));
        assert!(words[256..].iter().all(|v| *v == 0));
        let mut t = f.query_encoding.trace(s).unwrap();
        let mut claim = s.clone();
        claim.encoded = trace::refresh(&claim, &mut t, &words);
        reject_sdk(&claim, t);
    }
    let mut t = f.query_encoding.trace(s).unwrap();
    let mut input: [Val; 12] = t.values[5 * QUERY_WIDTH + 3 * P2..5 * QUERY_WIDTH + 3 * P2 + 12]
        .try_into()
        .unwrap();
    input[7] = Val::ONE;
    let out = bfv_hiding_stark::poseidon::write(
        &mut t.values[5 * QUERY_WIDTH + 3 * P2..5 * QUERY_WIDTH + 4 * P2],
        input,
    );
    assert_ne!(&out[..4], &f.query.command());
    reject_sdk(s, t);
}
#[test]
fn full_independent_source_key33_and_setup_contexts_reject_before_child_factory() {
    let f = fixture();
    let p = published();
    let proof = source_proof();
    let called = Cell::new(0);
    let s = &p.statements[0];
    assert!(
        prove_child_with_factory(&f.source, s, None, || {
            called.set(1);
            Err(Error::Shape)
        })
        .is_err()
    );
    let mut malformed = source_proof();
    malformed.ood_pow_witness += Val::ONE;
    assert!(
        prove_child_with_factory(&f.source, s, Some(&malformed), || {
            called.set(1);
            Err(Error::Shape)
        })
        .is_err()
    );
    assert_eq!(called.get(), 0);
    drop(malformed);
    for case in 0..9 {
        let mut source = f.source_statement.clone();
        let mut key = f.source.bfv().key().clone();
        let mut setup = f.source.bfv().full_setup();
        match case {
            0 => source.request[31] ^= 1,
            1 => source.heads[0][111] ^= 1,
            2 => source.packets[1][2383] ^= 1,
            3 => setup[31] ^= 1,
            4 => key.expected.descriptor.key_domain[15] ^= 1,
            5 => key.expected.descriptor.key_epoch ^= 1 << 31,
            6 => key.expected.coefficients[3] += Val::ONE,
            7 => key.transformed[3] += Val::ONE,
            _ => key.expected.descriptor.public_setup_digest[31] ^= 1,
        };
        if let Ok(c) = CanonicalSource::checked_claim(&source) {
            let foreign = Expected::source(&c, BfvBinding::new(setup, key)).unwrap();
            assert!(frame::decode_and_verify(&foreign, &p.frames[0]).is_err());
            assert!(
                prove_child_with_factory(&foreign, s, Some(&proof), || {
                    called.set(1);
                    Err(Error::Shape)
                })
                .is_err()
            );
        } else {
            assert!([1, 2].contains(&case));
        }
        assert_eq!(called.get(), 0);
    }
    let mut wrong_db = f.source.bfv().key().clone();
    wrong_db.expected.descriptor.database[15] ^= 1;
    let canonical = CanonicalSource::checked_claim(&f.source_statement).unwrap();
    assert!(
        Expected::source(
            &canonical,
            BfvBinding::new(f.source.bfv().full_setup(), wrong_db)
        )
        .is_err()
    );
    let mut key = f.source.bfv().key().clone();
    key.transformed[3] += Val::ONE;
    let binding = BfvBinding::new(f.source.bfv().full_setup(), key);
    let compiled = compiler::CompiledPrivatePredicate::compile(
        fixture::SQL,
        Zeroizing::new([0xB1; 32]),
        [0xA1; 32],
    )
    .unwrap();
    assert_eq!(
        compiled.query(&f.source_statement, &binding),
        f.source_statement.request
    );
    let foreign =
        fixture::prepare(fixture::SQL, [0xB1; 32], [0xA1; 32], binding, fixture::DATA).unwrap();
    assert_eq!(
        foreign.source_statement.values(),
        f.source_statement.values()
    );
    let (fs, bytes) = own_frame(&foreign.source, &foreign.source_encoding, &proof);
    assert_ne!(
        fs.expected.encoding_context(),
        s.expected.encoding_context()
    );
    assert!(frame::decode_and_verify(&f.source, &bytes).is_err());
    assert!(
        prove_child_with_factory(&f.source, &fs, Some(&proof), || {
            called.set(1);
            Err(Error::Shape)
        })
        .is_err()
    );
    assert_eq!(called.get(), 0);
    let g = fixture::prepare(
        "SELECT * FROM records WHERE age = 7",
        [0xB1; 32],
        [0xA1; 32],
        f.source.bfv().clone(),
        fixture::DATA,
    )
    .unwrap();
    let gp = actual_source(&g);
    let (_, bytes) = own_frame(&g.query, &g.query_encoding, &gp);
    assert!(frame::decode_and_verify(&f.query, &bytes).is_err());
    assert!(
        prove_child_with_factory(&f.source, s, Some(&gp), || {
            called.set(1);
            Err(Error::Shape)
        })
        .is_err()
    );
    assert_eq!(called.get(), 0);
}
#[test]
fn equal_numeric_rows_with_new_full_rowid_keep_words_but_change_independent_source_binding() {
    let f = fixture();
    let mut suffix = crate::opening::fixture::canonical_suffix();
    suffix[2223] ^= 1;
    let other = fixture::prepare_with_suffix(
        fixture::SQL,
        [0xB1; 32],
        [0xA1; 32],
        f.source.bfv().clone(),
        fixture::DATA,
        suffix,
    )
    .unwrap();
    assert_ne!(other.source_statement.heads, f.source_statement.heads);
    assert_eq!(
        *other.source_encoding.coefficients(Role::SourceAllOriginal),
        *f.source_encoding.coefficients(Role::SourceAllOriginal)
    );
    let p = actual_source(&other);
    let (s, bytes) = own_frame(&other.source, &other.source_encoding, &p);
    assert_ne!(s.expected.encoding_context(), f.source.encoding_context());
    assert!(frame::decode_and_verify(&f.source, &bytes).is_err());
}
#[test]
fn distinct_roles_bounded_pair_and_real_nested_proof_damage_fail_closed() {
    let f = fixture();
    let p = published();
    let e = &f.query;
    let bytes = &p.frames[1];
    assert!(frame::decode_and_verify(&f.source, bytes).is_err());
    assert!(frame::decode_and_verify(e, &p.frames[0]).is_err());
    for at in [0, 8, 15, 47, 79, 111, 143, 175] {
        let mut bad = bytes.clone();
        bad[at] ^= 1;
        assert!(frame::decode_and_verify(e, &bad).is_err());
    }
    let mut alias = bytes.clone();
    alias[144..152].copy_from_slice(&0xffff_ffff_0000_0001u64.to_le_bytes());
    assert!(frame::Frame::parse(e, &alias).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(frame::Frame::parse(e, &trailing).is_err());
    assert!(frame::Frame::parse(e, &bytes[..183]).is_err());
    assert!(matches!(
        frame::Frame::parse(e, &vec![0; frame::MAX_FRAME + 1]),
        Err(frame::Error::ResourceLimit)
    ));
    for at in [176, 180] {
        let mut bad = bytes.clone();
        bad[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            frame::Frame::parse(e, &bad),
            Err(frame::Error::ResourceLimit)
        ));
    }
    let parsed = frame::Frame::parse(e, bytes).unwrap();
    let backend = Backend::new(&p.statements[1]).unwrap();
    let shape =
        proof_codec::Topology::checked(QUERY_WIDTH, backend.report.quotient_chunks).unwrap();
    let mut child: Proof<Config> =
        proof_codec::decode(parsed.child, &shape, 16384, 16 * 1024 * 1024).unwrap();
    child.ood_pow_witness += Val::ONE;
    assert!(proof_codec::serialize(&child, &shape, frame::MAX_CHILD).is_err());
    let raw = postcard::to_allocvec(&child).unwrap();
    let prefix = postcard::to_allocvec(&child.commitments).unwrap().len();
    let mut bomb = raw[..prefix].to_vec();
    bomb.extend([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1]);
    let bad = frame::join(e, parsed.encoded, parsed.source, &bomb).unwrap();
    assert!(matches!(
        frame::decode_and_verify(e, &bad),
        Err(frame::Error::ResourceLimit)
    ));
    child.ood_pow_witness = Val::ZERO;
    child.opened_values.trace_next = None;
    let raw = postcard::to_allocvec(&child).unwrap();
    let bad = frame::join(e, parsed.encoded, parsed.source, &raw).unwrap();
    assert!(frame::decode_and_verify(e, &bad).is_err());
    let mut bad_source = parsed.source.to_vec();
    bad_source[0] ^= 1;
    let bad = frame::join(e, parsed.encoded, &bad_source, parsed.child).unwrap();
    assert!(frame::decode_and_verify(e, &bad).is_err());
    assert_eq!(
        fixed::profile_digest(Role::SourceAllOriginal),
        crate::backend::profile_digest(Kind::SourceCoefficientEncoding)
    );
    assert_eq!(
        fixed::profile_digest(Role::PrivateMask),
        crate::backend::profile_digest(Kind::PrivateMaskCoefficientEncoding)
    );
    assert_ne!(
        crate::backend::profile_digest(Kind::SelectedEncoding),
        fixed::profile_digest(Role::SourceAllOriginal)
    );
}

#[test]
fn fresh_encoding_salts_prove_but_complete_statement_and_original_opening_do_not_replay() {
    let f = fixture();
    let p = published();
    let proof = source_proof();
    for (i, w) in [&f.source_encoding, &f.query_encoding]
        .into_iter()
        .enumerate()
    {
        let original = &p.statements[i];
        let mut trace = w.trace(original).unwrap();
        let at = if i == 0 {
            SOURCE_ENC_SALT + 3
        } else {
            QUERY_ENC_SALT + 3
        };
        let value = trace.values[at] + Val::ONE;
        field(&mut trace, at, value);
        let mut fresh = original.clone();
        fresh.encoded = trace::refresh(&fresh, &mut trace, &w.coefficients(fresh.expected.role()));
        assert_ne!(fresh.encoded, original.encoded);
        let child =
            prove_child_with_factory(&fresh.expected, &fresh, Some(&proof), || Ok(trace)).unwrap();
        let bytes = frame::encode_with_source(&fresh.expected, &fresh, &p.source, &child).unwrap();
        let decoded = frame::decode_and_verify(&fresh.expected, &bytes).unwrap();
        require_complete(&fresh, &decoded).unwrap();
        assert_eq!(fresh.producer_identity(), decoded.producer_identity());
        assert_ne!(original.producer_identity(), decoded.producer_identity());
        assert!(require_complete(original, &decoded).is_err());
        assert!(w.formation_opening(&decoded).is_err());
    }
}
