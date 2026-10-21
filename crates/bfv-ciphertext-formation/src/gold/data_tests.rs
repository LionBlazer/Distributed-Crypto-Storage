//! Public test rows; only this owner fixture holds its fresh guarded SDK secret.
use super::*;
use crate::gold::{
    self, evidence, program,
    relation::{ExpectedRef, RelationKind},
    setup, wire,
    witness::{hash_fields, pack_secret},
};
use bfv_hiding_stark::{Challenge, Val};
use fhe::bfv::{BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, Plaintext, SecretKey};
use fhe_traits::{FheEncoder, FheEncrypter, Serialize};
use p3_air::{BaseAir, check_all_constraints};
use p3_batch_stark::{BatchVerificationError, verify_batch};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::LookupError;
use std::{
    sync::{Arc, OnceLock},
    time::Instant,
};
use zeroize::Zeroizing;
struct Fixture {
    expected: Expected,
    words: Zeroizing<Vec<u64>>,
    secret: Zeroizing<Vec<i64>>,
    sdk: Zeroizing<Vec<u8>>,
    salts: [[u64; 4]; 2],
}
impl Fixture {
    fn new() -> Self {
        static PARAMS: OnceLock<Arc<BfvParameters>> = OnceLock::new();
        let p = PARAMS.get_or_init(|| {
            BfvParametersBuilder::new()
                .set_degree(N)
                .set_plaintext_modulus(T)
                .set_moduli(&Q)
                .set_variance(10)
                .build_arc()
                .unwrap()
        });
        let key = SecretKey::random(p, &mut rand::rng());
        let mut raw = Zeroizing::new(vec![0u64; N]);
        for (i, (age, amount)) in [(0usize, 65535u64), (1, 0), (128, 255), (255, 65534)]
            .into_iter()
            .enumerate()
        {
            raw[2 * i * 512 + age] = 256 + age as u64;
            raw[(2 * i + 1) * 512 + age] = amount;
        }
        let plain =
            Zeroizing::new(Plaintext::try_encode(raw.as_slice(), Encoding::poly(), p).unwrap());
        let ct: Ciphertext = key.try_encrypt(&*plain, &mut rand::rng()).unwrap();
        let request = Request::checked(
            [0x91; 32],
            Ciphertext::new(ct.iter().cloned().collect(), p)
                .unwrap()
                .to_bytes(),
        )
        .unwrap();
        let words = Zeroizing::new(raw.iter().map(|&v| v * SCALE % T).collect::<Vec<_>>());
        let secret = Zeroizing::new(fhe::proto::bfv::SecretKey::from(&key).coeffs);
        let sdk = Zeroizing::new(key.to_bytes());
        let contexts =
            core::array::from_fn(|r| core::array::from_fn(|i| Val::from_usize(211 + 16 * r + i)));
        let salts = [[19, 20, 21, 22], [23, 24, 25, 26]];
        let roots = [
            hash_fields(contexts[0], &salts[0], &words).unwrap(),
            hash_fields(contexts[1], &salts[1], &pack_secret(&secret).unwrap()).unwrap(),
        ];
        let expected = Expected::checked(request, [0x92; 64], contexts, roots).unwrap();
        Self {
            expected,
            words,
            secret,
            sdk,
            salts,
        }
    }
    fn prepared(&self) -> Prepared {
        self.prepare_with(&self.expected, self.words.clone(), self.sdk.clone())
    }
    fn prepare_with(
        &self,
        e: &Expected,
        w: Zeroizing<Vec<u64>>,
        s: Zeroizing<Vec<u8>>,
    ) -> Prepared {
        let c = e.contexts();
        let r = e.roots();
        Prepared::new(
            e,
            ScaledOpening::checked(c[0], r[0], w, Zeroizing::new(self.salts[0])).unwrap(),
            SecretOpening::checked(c[1], r[1], s, Zeroizing::new(self.salts[1])).unwrap(),
        )
        .unwrap()
    }
}
fn encode_secret(s: &[i64]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(vec![10, 128, 32]);
    for &x in s {
        assert!((-20..=20).contains(&x));
        out.push(((x << 1) ^ (x >> 63)) as u8);
    }
    out
}
fn varint(mut n: usize, out: &mut Vec<u8>) {
    while n >= 128 {
        out.push((n as u8 & 127) | 128);
        n >>= 7;
    }
    out.push(n as u8);
}
// Negative-only canonical input mutation, never a computation/proof oracle.
fn ciphertext(c0: &[Vec<u64>], a: &[Vec<u64>]) -> Vec<u8> {
    let mut out = Vec::new();
    for poly in [c0, a] {
        let mut packed = vec![0u8; N * 60 / 8];
        for b in 0..2 {
            assert_eq!(poly[b].len(), N);
            for (i, &coefficient) in poly[b].iter().enumerate() {
                assert!(coefficient < Q[b]);
                for j in 0..30 {
                    let at = b * N * 30 + i * 30 + j;
                    packed[at / 8] |= (((coefficient >> j) & 1) as u8) << (at % 8);
                }
            }
        }
        let mut p = vec![8, 2, 16];
        varint(N, &mut p);
        p.push(26);
        varint(packed.len(), &mut p);
        p.extend(packed);
        p.extend([32, 1]);
        out.push(10);
        varint(p.len(), &mut out);
        out.extend(p);
    }
    out
}
#[test]
fn data_request_and_prepared_reject_foreign_full_bindings() {
    let f = Fixture::new();
    let e = &f.expected;
    assert_eq!(
        Request::decode(e.request().bytes()).unwrap().bytes(),
        e.request().bytes()
    );
    assert_eq!(e.values().len(), 32);
    assert_eq!(
        e.request().ciphertext().len() + HEADER,
        e.request().bytes().len()
    );
    let mut extra = e.request().bytes().to_vec();
    extra.push(0);
    assert!(Request::decode(&extra).is_err());
    assert!(Request::checked([0; 32], vec![]).is_err());
    assert!(gold::Request::decode(e.request().bytes()).is_err());
    let mut two = e.request().ciphertext().to_vec();
    two.extend(e.request().ciphertext());
    assert!(Request::checked([1; 32], two).is_err());
    let other = Expected::checked(
        Request::checked([0x93; 32], e.request().ciphertext().to_vec()).unwrap(),
        [0x92; 64],
        e.contexts(),
        e.roots(),
    )
    .unwrap();
    assert!(matches!(
        f.prepared()
            .inner
            .require_expected(ExpectedRef::Data(&other)),
        Err(Error::Binding)
    ));
    let (pair, _) = gold::tests::fixture();
    assert!(matches!(
        f.prepared()
            .inner
            .require_expected(ExpectedRef::Pair(&pair)),
        Err(Error::Binding)
    ));
    assert_ne!(profile_digest(), gold::profile_digest());
    let k = RelationKind::Data;
    assert_eq!(
        (
            k.graph_rows(),
            k.range_first(),
            k.cw_first(0),
            k.cs_first(),
            k.padding_first()
        ),
        (2560, 2560, 4608, 5122, 5188)
    );
    assert_eq!(
        (
            k.vectors(),
            k.w_tag(0),
            k.cs_tag(),
            k.range().stride,
            k.range().bits
        ),
        (39, 39, 40, 9, 98)
    );
    let (air, a) = evidence::prescreen(ExpectedRef::Data(e)).unwrap();
    a.require_resources().unwrap();
    assert_eq!(air.num_public_values(), 32);
}
#[test]
fn actual_data_equations_reject_wrong_secret_shared_error_and_repaired_tail() {
    let f = Fixture::new();
    let e = &f.expected;
    // Repair Cs for a different bounded S; public A cannot absorb this in bounded E.
    assert!(
        e.request().input(1)[0]
            .iter()
            .any(|&a| a > 80 && a < Q[0] - 80)
    );
    let mut s = f.secret.clone();
    s[0] += if s[0] < 20 { 1 } else { -1 };
    let mut roots = e.roots();
    roots[1] = hash_fields(e.contexts()[1], &f.salts[1], &pack_secret(&s).unwrap()).unwrap();
    let other = Expected::checked(e.request().clone(), [0x92; 64], e.contexts(), roots).unwrap();
    evidence::prescreen(ExpectedRef::Data(&other)).unwrap();
    assert!(matches!(
        f.prepare_with(&other, f.words.clone(), encode_secret(&s))
            .inner
            .trace(ExpectedRef::Data(&other)),
        Err(Error::Arithmetic)
    ));
    // Q1-only c0[4095]+1 requires a different E, forbidden by the shared-E relation.
    let mut c = e.request().input(0).to_vec();
    c[1][N - 1] = (c[1][N - 1] + 1) % Q[1];
    let other = Expected::checked(
        Request::checked(e.request().nonce(), ciphertext(&c, e.request().input(1))).unwrap(),
        [0x92; 64],
        e.contexts(),
        e.roots(),
    )
    .unwrap();
    evidence::prescreen(ExpectedRef::Data(&other)).unwrap();
    assert!(matches!(
        f.prepare_with(&other, f.words.clone(), f.sdk.clone())
            .inner
            .trace(ExpectedRef::Data(&other)),
        Err(Error::Arithmetic)
    ));
    let mut w = f.words.clone();
    w[N - 1] = (w[N - 1] + 1) % T;
    let mut roots = e.roots();
    roots[0] = hash_fields(e.contexts()[0], &f.salts[0], &w).unwrap();
    let other = Expected::checked(e.request().clone(), [0x92; 64], e.contexts(), roots).unwrap();
    evidence::prescreen(ExpectedRef::Data(&other)).unwrap();
    assert!(matches!(
        f.prepare_with(&other, w, f.sdk.clone())
            .inner
            .trace(ExpectedRef::Data(&other)),
        Err(Error::Arithmetic)
    ));
}
#[test]
fn data_air_rejects_unused_bits_ports_padding_and_excluded_k_endpoint() {
    let f = Fixture::new();
    let e = ExpectedRef::Data(&f.expected);
    let (air, _) = evidence::prescreen(e).unwrap();
    let mut t = f.prepared().inner.trace(e).unwrap();
    assert!(check_all_constraints(&air, &t.0, f.expected.values(), Some(1)).is_ok());
    let k = RelationKind::Data;
    let width = program::WIDTH;
    for at in [
        k.range_first() * width + program::BITS + 196,
        k.range_first() * width + 19,
        k.padding_first() * width,
        k.padding_first() * width + 511,
    ] {
        let saved = t.0.values[at];
        t.0.values[at] = Val::ONE;
        assert!(!check_all_constraints(&air, &t.0, f.expected.values(), Some(1)).is_ok());
        t.0.values[at] = saved;
    }
    let at = k.range_first() * width;
    t.0.values[at + 2] = -Val::from_u32(524288);
    t.0.values[at + 7] = Val::ZERO;
    t.0.values[at + program::BITS + 24..at + program::BITS + 44].fill(Val::ZERO);
    assert!(!check_all_constraints(&air, &t.0, f.expected.values(), Some(1)).is_ok());
}
#[test]
fn genuine_single_data_native_proof_and_local_valid_false_wire_have_distinct_outcomes() {
    let f = Fixture::new();
    let e = &f.expected;
    let expected = ExpectedRef::Data(e);
    let began = Instant::now();
    let honest = prove(e, f.prepared()).unwrap();
    eprintln!(
        "core_gold_data phase=prove elapsed_ms={:.3} proof_bytes={}",
        began.elapsed().as_secs_f64() * 1000.,
        honest.as_bytes().len()
    );
    let began = Instant::now();
    let checked = verify(e, honest.as_bytes()).unwrap();
    eprintln!(
        "core_gold_data phase=cold_verify elapsed_ms={:.3}",
        began.elapsed().as_secs_f64() * 1000.
    );
    assert_eq!(checked.expected().values(), e.values());
    assert!(honest.as_bytes().len() <= MAX_EVIDENCE_BYTES);
    let (air, assessment) = evidence::prescreen(expected).unwrap();
    let mut proof = wire::decode(
        wire::payload(expected, honest.as_bytes()).unwrap(),
        &assessment,
    )
    .unwrap();
    proof.opened_values.instances[0]
        .base_opened_values
        .trace_local[0] += Challenge::ONE;
    let repaired = wire::encode(expected, &proof, &assessment).unwrap();
    drop(proof);
    assert!(matches!(verify(e, &repaired), Err(Error::Verification)));
    let other =
        Expected::checked(e.request().clone(), [0x94; 64], e.contexts(), e.roots()).unwrap();
    assert!(matches!(
        verify(&other, honest.as_bytes()),
        Err(Error::Binding)
    ));
    let mut extra = honest.as_bytes().to_vec();
    extra.push(0);
    assert!(verify(e, &extra).is_err());
    assert!(matches!(verify(e, &[]), Err(Error::Resource)));
    assert!(matches!(
        verify(e, &vec![0; MAX_EVIDENCE_BYTES + 1]),
        Err(Error::Resource)
    ));
    // A second genuine argument is deliberately false only at its internal wire.
    // Local equations and both final AS products are unchanged; LogUp must reject.
    let c = air.first_gate_coefficients();
    assert_eq!(c[0], Val::ONE);
    assert_eq!(c[2], Val::ONE);
    let data = setup::public_data(&air, expected, &assessment).unwrap();
    let mut t = f.prepared().inner.trace(expected).unwrap();
    t.0.values[0] += Val::ONE;
    t.0.values[2] += Val::ONE;
    t.0.values[3] += Val::ONE;
    assert!(
        check_all_constraints(&air, &t.0, e.values(), Some(1)).is_ok(),
        "local-only checks are not wire acceptance"
    );
    let attempt = evidence::prove_trace(expected, &air, &t.0, &data);
    drop(t);
    if cfg!(debug_assertions) {
        assert!(matches!(attempt, Err(Error::Proving)));
        return;
    }
    let mut bad = attempt.expect("release must genuinely prove the unbalanced DATA wire");
    let failure = verify_batch(
        &bfv_hiding_stark::config().unwrap(),
        core::slice::from_ref(&air),
        &bad,
        &[e.values().to_vec()],
        &data.common,
    )
    .unwrap_err();
    assert!(matches!(
        failure,
        BatchVerificationError::Lookup(LookupError::TerminalSumNonZero)
    ));
    bad.lookup_terminals[0].as_mut().unwrap().0 = Challenge::ZERO;
    let repaired = wire::encode(expected, &bad, &assessment).unwrap();
    drop(bad);
    drop(data);
    drop(air);
    assert!(matches!(verify(e, &repaired), Err(Error::Verification)));
    assert_eq!(
        verify(e, honest.as_bytes()).unwrap().expected().values(),
        e.values()
    );
}
