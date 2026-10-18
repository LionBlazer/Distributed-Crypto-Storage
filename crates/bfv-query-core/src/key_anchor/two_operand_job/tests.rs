//! PUBLIC NONSECRET fixtures. No private key, W, salt or predicate is logged/spooled.
use super::*;
use crate::{CoefficientRow, Geometry, HEAD_BYTES, PeerEvaluator, QueryContext};
use bfv_basis_convolution::{MODULI, N};
use bfv_hiding_stark::Val;
use fhe::bfv::Ciphertext;
use fhe_math::{
    ntt::NttOperator,
    rq::{Poly, Representation, traits::TryConvertFrom},
    zq::Modulus,
};
use fhe_traits::{DeserializeParametrized, Serialize};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_symmetric::Permutation;
use std::{
    fs,
    path::PathBuf,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

fn key_scope() -> KeyScope {
    KeyScope {
        database: [0x42; 16],
        bfv_key_domain: [0x71; 16],
        epoch: 1,
    }
}
fn query_context() -> QueryContext {
    QueryContext::new([0x81; 16], [0x82; HEAD_BYTES], [0x83; HEAD_BYTES])
}
const ROWS: [CoefficientRow; 4] = [
    CoefficientRow { age: 0, amount: 0 },
    CoefficientRow {
        age: 127,
        amount: 65535,
    },
    CoefficientRow {
        age: 128,
        amount: 256,
    },
    CoefficientRow {
        age: 255,
        amount: 1,
    },
];
fn mask() -> [u8; 32] {
    let mut bytes = [0; 32];
    for age in [0usize, 128, 255] {
        bytes[age / 8] |= 1 << (age % 8);
    }
    bytes
}
// Test input oracle only: the scope never sees rows or the private mask.
fn words(operand: Operand) -> Zeroizing<Vec<u64>> {
    let mut w = Zeroizing::new(vec![0; N]);
    match operand {
        Operand::Input0 => {
            for (i, row) in ROWS.iter().enumerate() {
                for (field, value) in [1, u64::from(row.age), u64::from(row.amount)]
                    .into_iter()
                    .enumerate()
                {
                    w[(3 * i + field) * 512 + usize::from(row.age)] = value;
                }
            }
        }
        Operand::Input1 => {
            let mask = mask();
            for age in 0..256 {
                w[255 - age] = u64::from((mask[age / 8] >> (age % 8)) & 1);
            }
        }
    }
    for value in w.iter_mut() {
        *value = *value * 78307 % 114689;
    }
    w
}
fn root(context: [u64; 8], salt: [u64; 4], values: &[u64]) -> [u64; 4] {
    let p = p3_goldilocks::default_goldilocks_poseidon2_12();
    let mut state = [Val::ZERO; 12];
    state[..8].copy_from_slice(&context.map(Val::from_u64));
    p.permute_mut(&mut state);
    state[..4].copy_from_slice(&salt.map(Val::from_u64));
    state[4..8].fill(Val::ZERO);
    p.permute_mut(&mut state);
    assert_eq!(values.len(), N);
    for block in values.as_chunks::<8>().0 {
        state[..8].copy_from_slice(&block.map(Val::from_u64));
        p.permute_mut(&mut state);
    }
    core::array::from_fn(|i| state[i].as_canonical_u64())
}
fn encoding(
    operand: Operand,
    key: &bfv_key_transform::Statement,
    q: [u8; 32],
    w: &[u64],
) -> EncodedCommitment {
    let mut h = Sha256::new();
    h.update(b"PUBLIC-NONSECRET/two-operand-test-context/v1");
    h.update([operand.index() as u8]);
    h.update(q);
    for word in key.public_values() {
        h.update(word.as_canonical_u64().to_le_bytes());
    }
    let context = bfv_basis_convolution::words(&h.finalize().into()).map(|v| v.as_canonical_u64());
    let salt = [37 + operand.index() as u64; 4];
    EncodedCommitment::new(
        [41 + operand.index() as u8; 32],
        context,
        root(context, salt, w),
    )
    .unwrap()
}
fn opening(operand: Operand, commitment: &EncodedCommitment) -> EncodedOpening {
    EncodedOpening::new(
        words(operand),
        [37 + operand.index() as u64; 4],
        commitment.clone(),
    )
    .unwrap()
}

struct PublicFiles {
    path: PathBuf,
    parent: PathBuf,
    name: String,
}
impl PublicFiles {
    fn new() -> Self {
        let parent = fs::canonicalize(std::env::temp_dir()).unwrap();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("dcs-two-operand-public-{}-{stamp}", std::process::id());
        let path = parent.join(&name);
        fs::create_dir(&path).unwrap();
        let checked = fs::canonicalize(&path).unwrap();
        assert_eq!(checked.parent(), Some(parent.as_path()));
        assert_eq!(checked.file_name(), Some(std::ffi::OsStr::new(&name)));
        assert_eq!(checked, path);
        Self {
            path: checked,
            parent,
            name,
        }
    }
    fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}
impl Drop for PublicFiles {
    fn drop(&mut self) {
        if let Ok(path) = fs::canonicalize(&self.path)
            && path == self.path
            && path.parent() == Some(self.parent.as_path())
            && path.file_name() == Some(std::ffi::OsStr::new(&self.name))
        {
            let _ = fs::remove_dir_all(path);
        }
    }
}
fn mul(a: u64, b: u64, q: u64) -> u64 {
    (u128::from(a) * u128::from(b) % u128::from(q)) as u64
}
fn pow(mut a: u64, mut e: u64, q: u64) -> u64 {
    let mut out = 1;
    while e != 0 {
        if e & 1 != 0 {
            out = mul(out, a, q);
        }
        a = mul(a, a, q);
        e >>= 1;
    }
    out
}
/// Two native prime transforms + unique centered CRT, independently of the Gold FFT.
fn integer_oracle(a: &[u64], secret: &[i8]) -> Vec<i128> {
    let primes = [MODULI[0], MODULI[2]];
    let residues: Vec<Vec<u64>> = primes
        .into_iter()
        .map(|q| {
            let modulus = Modulus::new(q).unwrap();
            let op = NttOperator::new(&modulus, N).unwrap();
            let mut a: Vec<_> = a.iter().map(|v| *v % q).collect();
            let mut s: Vec<_> = secret
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
fn raw_gold(value: i128) -> u64 {
    assert!(value.abs() < (1i128 << 62));
    if value < 0 {
        Val::ORDER_U64 - value.unsigned_abs() as u64
    } else {
        value as u64
    }
}
fn altered_expected(
    expected: &FormationExpected,
    key: &bfv_key_transform::Statement,
    q: [u8; 32],
    ciphertext: &[u8],
) -> FormationExpected {
    FormationExpected::new(
        expected.encoding().clone(),
        core::array::from_fn(|i| bfv_basis_convolution::Statement {
            expected: BasisExpected::new(
                key.clone(),
                expected.ciphertext().parameter_bytes(),
                ciphertext,
                q,
                i,
            )
            .unwrap(),
            result: expected.bases()[i].result,
        }),
    )
    .unwrap()
}
fn changed_b(owner: &Owner, bytes: &[u8]) -> Vec<u8> {
    let ct = Ciphertext::from_bytes(bytes, &owner.parameters).unwrap();
    let mut b = ct[0].clone();
    b.change_representation(Representation::PowerBasis);
    let mut values: Vec<_> = b.coefficients().iter().copied().collect();
    let at = 5 * N - 1;
    values[at] = (values[at] + 1) % MODULI[4];
    let mut b = Poly::try_convert_from(
        values,
        owner.parameters.context_at_level(0).unwrap(),
        false,
        Representation::PowerBasis,
    )
    .unwrap();
    b.change_representation(Representation::Ntt);
    Ciphertext::new(vec![b, ct[1].clone()], &owner.parameters)
        .unwrap()
        .to_bytes()
}

#[test]
fn one_key_forms_the_exact_prepared_two_operands_and_freshly_verifies_after_private_drop() {
    let full_started = Instant::now();
    let files = PublicFiles::new();
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let setup_bytes = setup.to_bytes().unwrap();
    let handle = owner.key_anchor(&setup, key_scope()).unwrap();
    let anchor = handle.public_anchor().clone();
    let mut scope = handle.two_operand_scope(&setup).unwrap();
    assert_eq!(scope.stage(), TwoOperandStage::AwaitingKey);
    assert!(scope.prove_next_basis().is_err());
    let key_started = Instant::now();
    fs::write(files.file("key"), scope.prove_key().unwrap().as_bytes()).unwrap();
    let key_ms = key_started.elapsed().as_secs_f64() * 1000.;
    let key = setup
        .verify_key_transform(&anchor, scope.key_evidence().unwrap().as_bytes())
        .unwrap()
        .statement()
        .clone();
    let key_pointer = scope.key_evidence().unwrap().as_bytes().as_ptr();
    let key_size = scope.key_evidence().unwrap().as_bytes().len();
    assert!(scope.material.witness.is_none());
    assert!(scope.prove_key().is_err());

    // q is an opaque public label; a caller compiler may derive it from stable KeyExpected29.
    let q = [0x91; 32];
    let original = owner
        .encrypt_original_coefficient_rows_for_experiment(&ROWS)
        .unwrap();
    let prepared = owner
        .prepare_private_coefficient_predicate_for_experiment(
            query_context(),
            q,
            &original,
            &mask(),
        )
        .unwrap();
    let ciphertexts = prepared.operand_ciphertexts().unwrap();
    let commitments: [EncodedCommitment; 2] = core::array::from_fn(|i| {
        encoding(
            if i == 0 {
                Operand::Input0
            } else {
                Operand::Input1
            },
            &key,
            q,
            &words(if i == 0 {
                Operand::Input0
            } else {
                Operand::Input1
            }),
        )
    });
    assert!(
        scope
            .bind_operands(
                q,
                [
                    OperandInput {
                        ciphertext: ciphertexts[0],
                        encoding: commitments[0].clone()
                    },
                    OperandInput {
                        ciphertext: &[],
                        encoding: commitments[1].clone()
                    },
                ]
            )
            .is_err()
    );
    assert_eq!(scope.stage(), TwoOperandStage::AwaitingOperands);
    scope
        .bind_operands(
            q,
            core::array::from_fn(|i| OperandInput {
                ciphertext: ciphertexts[i],
                encoding: commitments[i].clone(),
            }),
        )
        .unwrap();
    assert!(
        scope
            .bind_operands(
                q,
                core::array::from_fn(|i| OperandInput {
                    ciphertext: ciphertexts[i],
                    encoding: commitments[i].clone(),
                })
            )
            .is_err()
    );

    // A separately genuine same-stable29 Key control has a different fresh CsHat.
    let foreign_frame = handle.prove().unwrap();
    let foreign_key = setup
        .verify_key_transform(&anchor, foreign_frame.as_bytes())
        .unwrap()
        .statement()
        .clone();
    assert_eq!(foreign_key.expected, key.expected);
    assert_ne!(foreign_key.transformed, key.transformed);
    drop(foreign_frame);
    let secret = Zeroizing::new(fhe::proto::bfv::SecretKey::from(&owner.key).coeffs);
    let coefficients = Zeroizing::new(
        secret
            .iter()
            .map(|v| i8::try_from(*v).unwrap())
            .collect::<Vec<_>>(),
    );
    let mut s = Poly::try_convert_from(
        secret.as_slice(),
        owner.parameters.context_at_level(0).unwrap(),
        false,
        Representation::PowerBasis,
    )
    .unwrap();
    s.change_representation(Representation::Ntt);
    let mut saved_expected = Vec::with_capacity(2);
    let mut basis_sizes = [[0usize; 5]; 2];
    let mut basis_ms = [[0.0; 5]; 2];
    let mut formation_sizes = [0usize; 2];
    let mut formation_ms = [0.0; 2];
    let mut noise_roots = [[0u64; 4]; 2];
    for operand in [Operand::Input0, Operand::Input1] {
        let index = operand.index();
        let ct = Ciphertext::from_bytes(ciphertexts[index], &owner.parameters).unwrap();
        let mut a = ct[1].clone();
        a.change_representation(Representation::PowerBasis);
        let mut claims = Vec::with_capacity(5);
        for basis in 0..5 {
            assert_eq!(scope.stage(), TwoOperandStage::Basis { operand, basis });
            if index == 0 && basis == 0 {
                let last = scope.material.shat[N - 1];
                scope.material.shat[N - 1] = Val::ORDER_U64;
                assert!(scope.prove_next_basis().is_err());
                assert_eq!(scope.stage(), TwoOperandStage::Basis { operand, basis });
                scope.material.shat[N - 1] = last;
            }
            let integers = integer_oracle(&a.coefficients().row(basis).to_vec(), &coefficients);
            let native_values: Vec<_> = integers.into_iter().map(raw_gold).collect();
            let started = Instant::now();
            let frame = scope.prove_next_basis().unwrap();
            basis_ms[index][basis] = started.elapsed().as_secs_f64() * 1000.;
            basis_sizes[index][basis] = frame.as_bytes().len();
            let verified = setup
                .verify_basis_convolution(
                    &anchor,
                    q,
                    ciphertexts[index],
                    basis,
                    scope.key_evidence().unwrap().as_bytes(),
                    frame.as_bytes(),
                )
                .unwrap();
            let expected_root = root(
                verified.statement().contexts()[1].map(|v| v.as_canonical_u64()),
                scope.current.as_ref().unwrap().salts[basis],
                &native_values,
            );
            assert_eq!(
                verified.statement().result.map(|v| v.as_canonical_u64()),
                expected_root
            );
            claims.push(verified.statement().clone());
            fs::write(
                files.file(&format!("{index}-basis-{basis}")),
                frame.as_bytes(),
            )
            .unwrap();
            drop(frame);
        }
        let expected =
            FormationExpected::new(commitments[index].clone(), claims.try_into().ok().unwrap())
                .unwrap();
        let mut wrong_words = words(operand);
        wrong_words[N - 1] = (wrong_words[N - 1] + 1) % 114689;
        let salt = [37 + index as u64; 4];
        let wrong_commitment = EncodedCommitment::new(
            commitments[index].producer_identity(),
            commitments[index].context(),
            root(commitments[index].context(), salt, &wrong_words),
        )
        .unwrap();
        let wrong_opening = EncodedOpening::new(wrong_words, salt, wrong_commitment).unwrap();
        assert_eq!(
            wrong_opening.commitment().context(),
            commitments[index].context()
        );
        assert!(scope.begin_formation(wrong_opening).is_err());
        assert_eq!(scope.stage(), TwoOperandStage::AwaitingFormation(operand));
        scope
            .begin_formation(opening(operand, &commitments[index]))
            .unwrap();
        assert_eq!(scope.stage(), TwoOperandStage::FormationReady(operand));
        let frames: [Vec<u8>; 5] =
            core::array::from_fn(|i| fs::read(files.file(&format!("{index}-basis-{i}"))).unwrap());
        let bases = frames.each_ref().map(Vec::as_slice);
        for wrong in [
            altered_expected(&expected, &foreign_key, q, ciphertexts[index]),
            altered_expected(&expected, &key, [0x92; 32], ciphertexts[index]),
            altered_expected(&expected, &key, q, ciphertexts[1 - index]),
            altered_expected(&expected, &key, q, &changed_b(&owner, ciphertexts[index])),
        ] {
            assert!(matches!(
                scope.prove_formation(&wrong, bases),
                Err(Error::BindingMismatch)
            ));
            assert_eq!(scope.stage(), TwoOperandStage::FormationReady(operand));
        }
        for field in 0..3 {
            let old = expected.encoding();
            let mut producer = old.producer_identity();
            let mut context = old.context();
            let mut digest = old.root();
            match field {
                0 => producer[31] ^= 1,
                1 => context[7] ^= 1,
                _ => digest[3] ^= 1,
            }
            let wrong = FormationExpected::new(
                EncodedCommitment::new(producer, context, digest).unwrap(),
                expected.bases().clone(),
            )
            .unwrap();
            assert!(matches!(
                scope.prove_formation(&wrong, bases),
                Err(Error::BindingMismatch)
            ));
        }
        let mut missing = bases;
        missing[0] = &[];
        assert!(scope.prove_formation(&expected, missing).is_err());
        let mut reordered = bases;
        reordered.swap(0, 4);
        assert!(scope.prove_formation(&expected, reordered).is_err());
        assert_eq!(scope.stage(), TwoOperandStage::FormationReady(operand));

        // Actual SDK phase is independent of the Gold transform and fixes common e across Q5.
        let mut phase = &ct[1] * &s;
        phase += &ct[0];
        phase.change_representation(Representation::PowerBasis);
        let w = words(operand);
        let mut noise = Zeroizing::new(vec![0i8; N]);
        for (basis, modulus) in MODULI.into_iter().enumerate() {
            let q = i128::from(modulus);
            for (j, value) in noise.iter_mut().enumerate() {
                let e = (i128::from(phase.coefficients()[[basis, j]])
                    - i128::from(bfv_ciphertext_formation::DELTA[basis]) * i128::from(w[j]))
                .rem_euclid(q);
                let e = if e > q / 2 { e - q } else { e };
                assert!((-20..=20).contains(&e));
                if basis == 0 {
                    *value = e as i8;
                } else {
                    assert_eq!(i128::from(*value), e);
                }
            }
        }
        let statement = bfv_ciphertext_formation::Statement {
            expected: expected.clone(),
            full_setup_id: anchor.full_setup_id(),
            noise: [Val::ZERO; 4],
        };
        let signed: Vec<_> = noise.iter().map(|v| raw_gold(i128::from(*v))).collect();
        noise_roots[index] = root(
            statement.contexts()[6].map(|v| v.as_canonical_u64()),
            *scope.current.as_ref().unwrap().noise_salt,
            &signed,
        );
        let started = Instant::now();
        let frame = scope.prove_formation(&expected, bases).unwrap();
        formation_ms[index] = started.elapsed().as_secs_f64() * 1000.;
        formation_sizes[index] = frame.as_bytes().len();
        fs::write(files.file(&format!("{index}-formation")), frame.as_bytes()).unwrap();
        drop(frame);
        saved_expected.push(expected);
        assert!(scope.current.is_none());
        assert_eq!(
            scope.key_evidence().unwrap().as_bytes().as_ptr(),
            key_pointer
        );
        if index == 0 {
            assert_eq!(
                scope.stage(),
                TwoOperandStage::Basis {
                    operand: Operand::Input1,
                    basis: 0
                }
            );
            assert_eq!(scope.material.shat.len(), N);
            assert_eq!(
                scope.material.statement.public_values(),
                key.public_values()
            );
        }
    }
    assert_eq!(scope.stage(), TwoOperandStage::Complete);
    assert!(scope.material.shat.is_empty());
    assert!(scope.material.output_salt.iter().all(|v| *v == 0));
    assert!(
        scope.current.is_none() && scope.operands.is_none() && scope.material.witness.is_none()
    );
    assert_eq!(scope.key_evidence().unwrap().as_bytes().len(), key_size);
    assert!(scope.prove_next_basis().is_err());
    assert!(scope.prove_formation(&saved_expected[1], [&[]; 5]).is_err());
    scope.cancel();
    assert_eq!(scope.stage(), TwoOperandStage::Cancelled);
    assert!(scope.key_evidence().is_err());
    drop(scope);
    drop(s);
    drop(secret);
    drop(coefficients);
    drop(handle);
    let evaluated = PeerEvaluator::from_public_setup(&setup)
        .unwrap()
        .evaluate_private_coefficient_predicate_for_experiment(&prepared.request)
        .unwrap();
    assert_eq!(evaluated.ct_ct_multiplications, 1);
    let answer = owner
        .decrypt_private_coefficient_predicate_unverified_for_experiment(
            prepared.pending,
            &evaluated.output,
        )
        .unwrap();
    assert_eq!(
        answer.rows.iter().map(|r| r.present).collect::<Vec<_>>(),
        [true, false, true, true]
    );
    drop(owner);
    drop(setup);

    // No Owner, private scope or opening remains: fresh decode/check of every public component.
    let started = Instant::now();
    let fresh = PublicSetup::from_bytes(&setup_bytes).unwrap();
    let key_frame = fs::read(files.file("key")).unwrap();
    assert_eq!(
        fresh
            .verify_key_transform(&anchor, &key_frame)
            .unwrap()
            .statement()
            .public_values(),
        key.public_values()
    );
    for (index, expected) in saved_expected.iter().enumerate() {
        let frames: [Vec<u8>; 5] =
            core::array::from_fn(|i| fs::read(files.file(&format!("{index}-basis-{i}"))).unwrap());
        let frame = fs::read(files.file(&format!("{index}-formation"))).unwrap();
        let p = Prerequisites {
            key: &key_frame,
            bases: frames.each_ref().map(Vec::as_slice),
        };
        let verified = fresh
            .verify_ciphertext_formation(&anchor, expected, &p, &frame)
            .unwrap();
        assert_eq!(
            verified.statement().noise.map(|v| v.as_canonical_u64()),
            noise_roots[index]
        );
        for (i, component) in frames.iter().enumerate() {
            let checked = fresh
                .verify_basis_convolution(
                    &anchor,
                    q,
                    expected.ciphertext().bytes(),
                    i,
                    &key_frame,
                    component,
                )
                .unwrap();
            assert_eq!(
                checked.statement().public_values(),
                expected.bases()[i].public_values()
            );
        }
        let wrong_role = &saved_expected[1 - index];
        assert!(
            fresh
                .verify_ciphertext_formation(&anchor, wrong_role, &p, &frame)
                .is_err()
        );
        for at in [8, 40, 72, 104, 136] {
            let mut bad = frame.clone();
            bad[at] ^= 1;
            assert!(
                fresh
                    .verify_ciphertext_formation(&anchor, expected, &p, &bad)
                    .is_err()
            );
        }
    }
    println!(
        "{}",
        serde_json::json!({
            "stage":"actual_owner_two_operand_formation", "primary_components":13, "adversarial_key_components":1,
            "key_prove_and_public_spool_ms":key_ms, "basis_generation_ms":basis_ms, "formation_generation_ms":formation_ms,
            "fresh_setup_public_reads_verification_and_rejections_ms":started.elapsed().as_secs_f64()*1000.,
            "through_completion_ms":full_started.elapsed().as_secs_f64()*1000.,
            "key_frame_bytes":key_size, "basis_frame_bytes":basis_sizes, "formation_frame_bytes":formation_sizes,
            "native_coefficients_per_basis":8192, "same_prepared_operands":true,
            "sql_grant":false,"source_completeness_proven":false,"evaluation_key_consistency_proven":false,"composed_128_claim":false
        })
    );
}

#[test]
fn incomplete_and_cancelled_scopes_preserve_stage_and_reject_foreign_original_setup() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let handle = owner.key_anchor(&setup, key_scope()).unwrap();
    let mut foreign = setup.clone();
    foreign.rotation_keys.push(0);
    assert!(matches!(
        handle.two_operand_scope(&foreign),
        Err(Error::BindingMismatch)
    ));
    let mut scope = handle.two_operand_scope(&setup).unwrap();
    assert!(scope.key_evidence().is_err());
    assert!(scope.prove_next_basis().is_err());
    let commitment =
        EncodedCommitment::new([1; 32], [2; 8], root([2; 8], [3; 4], &vec![0; N])).unwrap();
    assert!(
        scope
            .bind_operands(
                [1; 32],
                core::array::from_fn(|_| OperandInput {
                    ciphertext: &[],
                    encoding: commitment.clone()
                })
            )
            .is_err()
    );
    assert!(
        scope
            .begin_formation(
                EncodedOpening::new(Zeroizing::new(vec![0; N]), [3; 4], commitment).unwrap()
            )
            .is_err()
    );
    assert_eq!(scope.stage(), TwoOperandStage::AwaitingKey);
    scope.cancel();
    assert_eq!(scope.stage(), TwoOperandStage::Cancelled);
    assert!(scope.material.shat.is_empty());
    assert!(scope.material.output_salt.iter().all(|v| *v == 0));
    assert!(scope.material.witness.is_none());
    assert!(scope.prove_key().is_err());
    assert!(scope.prove_next_basis().is_err());
    scope.cancel();
    assert_eq!(scope.stage(), TwoOperandStage::Cancelled);
}
