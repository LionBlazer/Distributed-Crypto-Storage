//! PUBLIC NONSECRET upstream encryption, full-size native CRT, and rebuilt SDK negatives.
use super::{air::*, ciphertext::*, statement::*, trace, *};
use crate::backend::{self, Backend, Val};
use crate::opening::poseidon;
use crate::primitive::PublicStatement;
use fhe::bfv::Ciphertext;
use fhe_math::{ntt::NttOperator, rq::Representation, zq::Modulus};
use fhe_traits::{DeserializeParametrized, Serialize};
use p3_air::{check_all_constraints, check_constraints};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

fn fixture() -> (Statement, Witness, KeyWitness) {
    fixture_with_noise_seed([0x45; 32])
}
fn fixture_with_noise_seed(seed: [u8; 32]) -> (Statement, Witness, KeyWitness) {
    public_fixture(
        [Val::from_u8(19); 4],
        [[Val::from_u8(7); 4], [Val::from_u8(11); 4]],
        0,
        seed,
    )
    .unwrap()
}
fn assert_distinct_public_ciphertexts(first: &Statement, second: &Statement) {
    // Actual upstream A uses its own OS entropy. These are checked attack preconditions,
    // not a claim that caller noise seeds deterministically select different A values.
    assert_eq!(
        first.expected.key().public_values(),
        second.expected.key().public_values()
    );
    assert_ne!(
        first.expected.ciphertext().bytes(),
        second.expected.ciphertext().bytes()
    );
    assert_ne!(
        first.expected.ciphertext().coefficients(),
        second.expected.ciphertext().coefficients()
    );
    let par = parameters();
    let a = Ciphertext::from_bytes(first.expected.ciphertext().bytes(), &par).unwrap();
    let b = Ciphertext::from_bytes(second.expected.ciphertext().bytes(), &par).unwrap();
    assert_ne!(a[0].coefficients(), b[0].coefficients());
}
fn valid(s: &Statement, w: &Witness) -> RowMajorMatrix<Val> {
    Backend::new(s).unwrap(); // symbolic/security gate before allocation
    let t = w.trace(s).unwrap();
    check_constraints(&s.air(), &t, &s.public_values());
    t
}
fn row(t: &RowMajorMatrix<Val>, r: usize) -> &[Val] {
    &t.values[r * WIDTH..(r + 1) * WIDTH]
}
fn row_mut(t: &mut RowMajorMatrix<Val>, r: usize) -> &mut [Val] {
    &mut t.values[r * WIDTH..(r + 1) * WIDTH]
}
fn finish_from(t: &mut RowMajorMatrix<Val>, from: usize, s: &Statement, w: &Witness) {
    let mut v = row(t, from)[..N].to_vec();
    let mut cp = row(t, from)[CHECKPOINT..CHECKPOINT + 12]
        .try_into()
        .unwrap();
    for physical in from..TRACE_HEIGHT {
        row_mut(t, physical).copy_from_slice(&trace::write_row(
            &v,
            &mut cp,
            w.salts,
            s.contexts(),
            physical,
        ));
        trace::advance(&mut v, physical, s.expected.ciphertext().evaluations());
    }
}
fn rebind_result(s: &mut Statement, t: &RowMajorMatrix<Val>, w: &Witness) {
    s.result = key_transform::trace::digest(s.contexts()[1], w.salts[1], &row(t, OUTPUT_ROW)[..N]);
}
fn reject_rebuilt(s: &Statement, t: RowMajorMatrix<Val>) {
    assert!(!check_all_constraints(&s.air(), &t, &s.public_values(), Some(1)).is_ok());
    let b = Backend::new(s).unwrap();
    if let Ok(p) = p3_uni_stark::prove(&b.config, &s.air(), t, &s.public_values()) {
        assert!(b.verify(s, &p).is_err());
    }
}
fn mul(a: u64, b: u64, q: u64) -> u64 {
    (u128::from(a) * u128::from(b) % u128::from(q)) as u64
}
fn pow(mut a: u64, mut n: u64, q: u64) -> u64 {
    let mut b = 1;
    while n != 0 {
        if n & 1 != 0 {
            b = mul(b, a, q);
        }
        a = mul(a, a, q);
        n >>= 1;
    }
    b
}
fn lift(x: i128) -> Val {
    if x < 0 {
        -Val::from_u64((-x) as u64)
    } else {
        Val::from_u64(x as u64)
    }
}
/// Independent prime-ring native transforms and a UNIQUE centered integer lift, not Gold FFT.
fn integer_oracle(a: &[u64], s: &[i8]) -> Vec<i128> {
    assert_eq!(a.len(), N);
    assert_eq!(s.len(), N);
    let primes = [MODULI[0], MODULI[2]];
    let residues: Vec<Vec<u64>> = primes
        .into_iter()
        .map(|q| {
            let modulus = Modulus::new(q).unwrap();
            let op = NttOperator::new(&modulus, N).unwrap();
            // Explicitly reduce original A to EACH prime: full-length Poly conversion does not.
            let mut a: Vec<_> = a.iter().map(|v| *v % q).collect();
            let mut s: Vec<_> = s
                .iter()
                .map(|v| {
                    if *v < 0 {
                        q - u64::from(v.unsigned_abs())
                    } else {
                        *v as u64
                    }
                })
                .collect();
            op.forward(&mut a);
            op.forward(&mut s);
            for (a, s) in a.iter_mut().zip(s) {
                *a = mul(*a, s, q);
            }
            op.backward(&mut a);
            a
        })
        .collect();
    let [p, q] = primes;
    let pq = i128::from(p) * i128::from(q);
    let inverse = pow(p % q, q - 2, q);
    let bound = N as i128 * 20 * i128::from(*a.iter().max().unwrap());
    assert!(pq > 2 * bound);
    residues[0]
        .iter()
        .zip(&residues[1])
        .map(|(&x, &y)| {
            let correction = mul((y + q - x % q) % q, inverse, q);
            let full = i128::from(x) + i128::from(p) * i128::from(correction);
            let centered = if full > pq / 2 { full - pq } else { full };
            assert!(centered.abs() <= bound);
            centered
        })
        .collect()
}

#[test]
fn upstream_key_serialization_fresh_encryption_and_both_canonical_ciphertexts_match() {
    // fixture() checks actual secret serialization/CBD replay and full SIMD decryption itself.
    let (s, _, _) = fixture();
    let par = parameters();
    let bytes = s.expected.ciphertext().bytes();
    let ct = Ciphertext::from_bytes(bytes, &par).unwrap();
    let unseeded = Ciphertext::new(ct.iter().cloned().collect(), &par)
        .unwrap()
        .to_bytes();
    assert!(bytes.len() <= 223281);
    assert!(unseeded.len() <= MAX_CANONICAL_UNSEEDED_BYTES);
    for basis in 0..5 {
        let seeded = CanonicalCiphertext::decode(&par.to_bytes(), bytes, basis).unwrap();
        let full = CanonicalCiphertext::decode(&par.to_bytes(), &unseeded, basis).unwrap();
        assert_eq!(seeded.coefficients(), full.coefficients());
        assert_eq!(seeded.evaluations(), full.evaluations());
        let alternate = Expected::new(
            s.expected.key().clone(),
            &par.to_bytes(),
            &unseeded,
            s.expected.request(),
            basis,
        )
        .unwrap();
        let original = Expected::new(
            s.expected.key().clone(),
            &par.to_bytes(),
            bytes,
            s.expected.request(),
            basis,
        )
        .unwrap();
        assert_ne!(
            Statement {
                expected: alternate,
                result: s.result
            }
            .contexts()[1],
            Statement {
                expected: original,
                result: s.result
            }
            .contexts()[1]
        );
    }
}
#[test]
fn canonical_decoder_rejects_wrong_parameters_caps_basis_and_noncanonical_full_wire() {
    let (s, _, _) = fixture();
    let par = parameters();
    let good = s.expected.ciphertext().bytes();
    let params = par.to_bytes();
    for wrong in [
        vec![],
        vec![0; MAX_PARAMETER_BYTES + 1],
        params.iter().copied().chain([0x28, 0]).collect(),
    ] {
        assert!(CanonicalCiphertext::decode(&wrong, good, 0).is_err());
    }
    assert!(CanonicalCiphertext::decode(&params, &vec![0; MAX_CIPHERTEXT_BYTES + 1], 0).is_err());
    assert!(CanonicalCiphertext::decode(&params, good, 5).is_err());
    // Unknown tag, duplicate level0, truncated late coefficient/seed, trailing incomplete varint.
    for bytes in [
        good.iter().copied().chain([0x20, 1]).collect::<Vec<_>>(),
        good.iter().copied().chain([0x18, 0]).collect(),
        good[..good.len() - 1].to_vec(),
        good.iter().copied().chain([0x80]).collect(),
    ] {
        assert!(CanonicalCiphertext::decode(&params, &bytes, 0).is_err());
    }
    let mut wrong = MODULI;
    wrong.swap(0, 1);
    let reordered = fhe::bfv::BfvParametersBuilder::new()
        .set_degree(N)
        .set_plaintext_modulus(PLAINTEXT)
        .set_moduli(&wrong)
        .set_variance(VARIANCE)
        .build_arc()
        .unwrap();
    assert!(CanonicalCiphertext::decode(&reordered.to_bytes(), good, 0).is_err());
}
#[test]
fn decoder_rejects_wrong_level_component_count_and_representation() {
    let (s, _, _) = fixture();
    let par = parameters();
    let ct = Ciphertext::from_bytes(s.expected.ciphertext().bytes(), &par).unwrap();
    let three = Ciphertext::new(vec![ct[0].clone(), ct[1].clone(), ct[1].clone()], &par).unwrap();
    assert!(CanonicalCiphertext::decode(&par.to_bytes(), &three.to_bytes(), 0).is_err());
    let mut low = ct.clone();
    low.switch_down().unwrap();
    assert!(CanonicalCiphertext::decode(&par.to_bytes(), &low.to_bytes(), 0).is_err());
    for repr in [Representation::PowerBasis, Representation::NttShoup] {
        let mut changed = ct.clone();
        changed[0].change_representation(repr);
        assert!(CanonicalCiphertext::decode(&par.to_bytes(), &changed.to_bytes(), 0).is_err());
    }
}
#[test]
fn all_five_bases_match_two_independent_native_prime_transforms_and_centered_crt() {
    let (s, w, key) = fixture();
    let par = parameters();
    for basis in 0..5 {
        let c =
            CanonicalCiphertext::decode(&par.to_bytes(), s.expected.ciphertext().bytes(), basis)
                .unwrap();
        let integers = integer_oracle(c.coefficients(), &key.coefficients);
        assert!(integers.iter().all(|v| v.abs() < (1i128 << 62)));
        let gold = trace::oracle(&w.evaluations, c.evaluations());
        assert!(gold.iter().copied().eq(integers.into_iter().map(lift)));
    }
}
#[test]
fn full8192_negacyclic_boundary_and_normalization_are_not_cyclic_or_bit_reversed() {
    let mut a = vec![0; N];
    a[N - 1] = MODULI[4] - 1;
    let mut s = vec![0i8; N];
    s[1] = 20;
    let integers = integer_oracle(&a, &s);
    assert_eq!(integers[0], -20 * i128::from(MODULI[4] - 1));
    assert!(integers[1..].iter().all(|v| *v == 0));
    let shat = key_transform::trace::oracle(
        &s.iter()
            .copied()
            .map(key_transform::signed)
            .collect::<Vec<_>>(),
    );
    let ahat =
        key_transform::trace::oracle(&a.iter().copied().map(Val::from_u64).collect::<Vec<_>>());
    assert!(
        trace::oracle(&shat, &ahat)
            .into_iter()
            .eq(integers.into_iter().map(lift))
    );
}
#[test]
fn full_vector_trace_preserves_exact_input_root_and_natural_integer_output() {
    let (s, w, key) = fixture();
    let t = valid(&s, &w);
    assert_eq!(
        key_transform::trace::digest(s.contexts()[0], w.salts[0], &w.evaluations),
        s.expected.key().transformed
    );
    assert_eq!(
        &row(&t, OUTPUT_ROW)[..N],
        trace::oracle(&w.evaluations, s.expected.ciphertext().evaluations())
    );
    let integers = integer_oracle(s.expected.ciphertext().coefficients(), &key.coefficients);
    assert!(
        row(&t, OUTPUT_ROW)[..N]
            .iter()
            .copied()
            .eq(integers.into_iter().map(lift))
    );
    assert_eq!(&row(&t, 205)[..N], &row(&t, 206)[..N]);
    assert_eq!(&row(&t, 426)[..N], &row(&t, 511)[..N]);
}
#[test]
fn genuine_composite_verifies_key_first_and_binds_full_expected_context() {
    let (s, w, key) = fixture();
    let mut proof = prove_with_trace(&s.expected, &s, &key, || w.trace(&s)).unwrap();
    verify(&s.expected, &s, &proof).unwrap();
    let retained = proof.key.take().unwrap();
    assert!(verify(&s.expected, &s, &proof).is_err());
    proof.key = Some(retained);
    for field in 0..5 {
        let mut expected_key = s.expected.key().clone();
        match field {
            0 => expected_key.expected.descriptor.database[0] ^= 1,
            1 => expected_key.expected.descriptor.key_epoch += 1,
            2 => expected_key.expected.coefficients[0] += Val::ONE,
            3 => expected_key.transformed[0] += Val::ONE,
            _ => {}
        }
        let request = if field == 4 {
            [0x73; 32]
        } else {
            s.expected.request()
        };
        let expected = Expected::new(
            expected_key,
            s.expected.ciphertext().parameter_bytes(),
            s.expected.ciphertext().bytes(),
            request,
            0,
        )
        .unwrap();
        assert!(verify(&expected, &s, &proof).is_err());
        let changed = Statement {
            expected,
            result: s.result,
        };
        assert!(
            Backend::new(&changed)
                .unwrap()
                .verify(&changed, &proof.convolution)
                .is_err()
        );
    }
}
#[test]
fn foreign_genuine_key_certificate_cannot_authorize_a_valid_child_proof() {
    let (s, w, key) = fixture();
    let child = Backend::new(&s)
        .unwrap()
        .prove_with_trace(&s, || w.trace(&s))
        .unwrap();
    let mut coeff = key.coefficients.clone();
    coeff[N - 1] = if coeff[N - 1] == 20 { 19 } else { 20 };
    let foreign = KeyWitness::new(coeff, key.salts[0], key.salts[1]).unwrap();
    let ks = foreign.statement(s.expected.key().expected.descriptor.clone());
    let kb = Backend::new(&ks).unwrap();
    let kp = kb.prove_with_trace(&ks, || foreign.trace(&ks)).unwrap();
    key_transform::verify(&ks.expected, &ks, &kp).unwrap();
    assert!(
        verify(
            &s.expected,
            &s,
            &CompositeProof {
                key: Some(kp),
                convolution: child
            }
        )
        .is_err()
    );
}
#[test]
fn independently_wrong_request_or_ciphertext_rejects_before_child_factory() {
    let (s, _, key) = fixture();
    // Constructor independently decodes another actual ciphertext; no A/digest injection path.
    let (other, _, _) = fixture_with_noise_seed([0x46; 32]);
    assert_distinct_public_ciphertexts(&s, &other);
    for case in 0..2 {
        let expected = Expected::new(
            s.expected.key().clone(),
            s.expected.ciphertext().parameter_bytes(),
            if case == 0 {
                s.expected.ciphertext().bytes()
            } else {
                other.expected.ciphertext().bytes()
            },
            if case == 0 {
                [0x99; 32]
            } else {
                s.expected.request()
            },
            0,
        )
        .unwrap();
        let called = std::cell::Cell::new(false);
        assert!(
            prove_with_trace(&expected, &s, &key, || {
                called.set(true);
                Err(Error::Shape)
            })
            .is_err()
        );
        assert!(!called.get());
    }
}
#[test]
fn b_only_seed_form_and_basis_changes_have_distinct_real_contexts_and_fail_replay() {
    let (s, w, _) = fixture();
    let b = Backend::new(&s).unwrap();
    let p = b.prove_with_trace(&s, || w.trace(&s)).unwrap();
    let par = parameters();
    let ct = Ciphertext::from_bytes(s.expected.ciphertext().bytes(), &par).unwrap();
    let mut b_changed = ct.clone();
    let (other, _, _) = fixture_with_noise_seed([0x46; 32]);
    assert_distinct_public_ciphertexts(&s, &other);
    let replacement = Ciphertext::from_bytes(other.expected.ciphertext().bytes(), &par).unwrap();
    b_changed[0] = replacement[0].clone();
    assert_ne!(b_changed[0].coefficients(), ct[0].coefficients());
    assert_eq!(b_changed[1], ct[1]);
    assert_eq!(
        fhe::proto::bfv::Ciphertext::from(&b_changed).seed,
        fhe::proto::bfv::Ciphertext::from(&ct).seed
    );
    let full = Ciphertext::new(ct.iter().cloned().collect(), &par).unwrap();
    for (bytes, basis) in [
        (b_changed.to_bytes(), 0),
        (full.to_bytes(), 0),
        (ct.to_bytes(), 4),
    ] {
        let changed = Statement {
            expected: Expected::new(
                s.expected.key().clone(),
                &par.to_bytes(),
                &bytes,
                s.expected.request(),
                basis,
            )
            .unwrap(),
            result: s.result,
        };
        assert_ne!(changed.contexts()[1], s.contexts()[1]);
        assert!(
            Backend::new(&changed)
                .unwrap()
                .verify(&changed, &p)
                .is_err()
        );
    }
}
#[test]
fn coherent_wrong_public_a_context_cannot_rebind_input_output_and_stages() {
    let (s, w, _) = fixture();
    let (other, _, _) = fixture_with_noise_seed([0x46; 32]);
    assert_distinct_public_ciphertexts(&s, &other);
    let wrong = Statement {
        expected: Expected::new(
            s.expected.key().clone(),
            s.expected.ciphertext().parameter_bytes(),
            other.expected.ciphertext().bytes(),
            s.expected.request(),
            0,
        )
        .unwrap(),
        result: s.result,
    };
    let mut t = valid(&s, &w);
    let mut changed = wrong;
    rebind_result(&mut changed, &t, &w);
    finish_from(&mut t, OUTPUT_ROW, &changed, &w);
    reject_rebuilt(&changed, t); // public multiplication link, not a constructor/replay rejection
}
#[test]
fn coherent_inverse_twiddle_order_and_normalization_changes_fail_raw_sdk() {
    let (s, w, _) = fixture();
    for at in [FIRST_STAGE, 211, SCALE_ROW, OUTPUT_ROW] {
        let mut changed = s.clone();
        let mut t = valid(&s, &w);
        if at == FIRST_STAGE {
            row_mut(&mut t, at)[..N].reverse();
        } else if at == OUTPUT_ROW {
            for v in &mut row_mut(&mut t, at)[..N] {
                *v *= Val::from_usize(N);
            }
        } else {
            row_mut(&mut t, at)[N - 1] += Val::ONE;
        }
        finish_from(&mut t, at, &changed, &w);
        rebind_result(&mut changed, &t, &w);
        finish_from(&mut t, OUTPUT_ROW, &changed, &w);
        reject_rebuilt(&changed, t);
    }
}
#[test]
fn coherent_last_input_coefficient_and_hash_phase_hold_cannot_open_original_shat() {
    let (s, w, _) = fixture();
    for at in [0, 1, 206, 426, 500] {
        let mut changed = s.clone();
        let mut t = valid(&s, &w);
        row_mut(&mut t, at)[N - 1] += Val::ONE;
        finish_from(&mut t, at, &changed, &w);
        if at <= OUTPUT_ROW {
            rebind_result(&mut changed, &t, &w);
            finish_from(&mut t, OUTPUT_ROW, &changed, &w);
        }
        reject_rebuilt(&changed, t);
    }
}
#[test]
fn partial_last_active_gadget_and_inactive_permutation_are_both_constrained() {
    let (s, w, _) = fixture();
    for (at, col) in [
        (205, P2 + poseidon::WIDTH),
        (426, P2 + poseidon::WIDTH),
        (500, P2 + poseidon::WIDTH + 12),
    ] {
        let mut t = valid(&s, &w);
        row_mut(&mut t, at)[col] += Val::ONE;
        reject_rebuilt(&s, t);
    }
}
#[test]
fn private_salt_copy_and_final_output_root_cannot_be_rebound_without_opening() {
    let (s, w, _) = fixture();
    let mut t = valid(&s, &w);
    row_mut(&mut t, OUTPUT_ROW)[SALTS + 4] += Val::ONE;
    reject_rebuilt(&s, t);
    let mut changed = s.clone();
    changed.result[3] += Val::ONE;
    reject_rebuilt(&changed, w.trace(&changed).unwrap());
}
#[test]
fn allocation_geometry_is_not_a_whole_process_memory_claim() {
    let estimate = backend::AllocationEstimate::for_width(WIDTH);
    assert_eq!(estimate.trace_bytes, 38715392);
    assert_eq!(estimate.masked_trace_bytes, 77471744);
    assert_eq!(estimate.main_lde_bytes, 619773952);
    assert_eq!(
        Statement {
            expected: fixture().0.expected,
            result: [Val::ZERO; 4]
        }
        .public_values()
        .len(),
        62
    );
}
