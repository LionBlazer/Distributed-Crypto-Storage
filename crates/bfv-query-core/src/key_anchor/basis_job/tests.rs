//! PUBLIC NONSECRET generated test keys/messages. No secret/vector/salt is printed or serialized.
use super::*;
use crate::Geometry;
use bfv_basis_convolution::{MODULI, N};
use bfv_hiding_stark::Val;
use fhe::bfv::{Ciphertext, Encoding, Plaintext};
use fhe_math::{ntt::NttOperator, rq::Representation, zq::Modulus};
use fhe_traits::{DeserializeParametrized, FheEncoder, FheEncrypter, Serialize};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_symmetric::Permutation;
use std::{
    fs,
    path::PathBuf,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

fn scope() -> KeyScope {
    KeyScope {
        database: [0x42; 16],
        bfv_key_domain: [0x71; 16],
        epoch: 1,
    }
}
struct PublicFiles {
    path: PathBuf,
    parent: PathBuf,
    name: String,
}
impl PublicFiles {
    fn new() -> Self {
        let parent = fs::canonicalize(std::env::temp_dir()).unwrap();
        assert!(parent.is_absolute());
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("dcs-owner-basis-public-{}-{stamp}", std::process::id());
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
        // Recheck the owned canonical immediate child before recursive cleanup.
        if let Ok(checked) = fs::canonicalize(&self.path)
            && checked == self.path
            && checked.parent() == Some(self.parent.as_path())
            && checked.file_name() == Some(std::ffi::OsStr::new(&self.name))
        {
            let _ = fs::remove_dir_all(checked);
        }
    }
}
fn ciphertext(owner: &Owner) -> Vec<u8> {
    let mut slots = vec![0u64; N];
    slots[0] = 1;
    slots[4096] = 65535;
    slots[8191] = 114688;
    let plaintext = Plaintext::try_encode(&slots, Encoding::simd(), &owner.parameters).unwrap();
    let value: Ciphertext = owner.key.try_encrypt(&plaintext, &mut rand::rng()).unwrap();
    // Canonical unseeded control makes a later B-only mutation leave SAME A and seed policy.
    Ciphertext::new(value.iter().cloned().collect(), &owner.parameters)
        .unwrap()
        .to_bytes()
}
fn native_context(
    key: &bfv_key_transform::Statement,
    parameters: &[u8],
    ciphertext: &[u8],
    request: [u8; 32],
    basis: usize,
) -> [Val; 8] {
    let domain = b"DCS/BFV-BASIS-NEGACYCLIC-RESIDUES/v1";
    let mut hash = Sha256::new();
    hash.update(b"DCS/BFV-BASIS-CONVOLUTION-CONTEXT/v1");
    hash.update((domain.len() as u32).to_le_bytes());
    hash.update(domain);
    hash.update(bfv_basis_convolution::profile_digest());
    for value in key.public_values() {
        hash.update(value.as_canonical_u64().to_le_bytes());
    }
    hash.update(request);
    hash.update((basis as u32).to_le_bytes());
    hash.update(MODULI[basis].to_le_bytes());
    hash.update(0u32.to_le_bytes());
    for bytes in [parameters, ciphertext] {
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    let bytes = hash.finalize();
    core::array::from_fn(|i| {
        Val::from_u32(u32::from_le_bytes(
            bytes[i * 4..i * 4 + 4].try_into().unwrap(),
        ))
    })
}
fn native_root(context: [Val; 8], salt: [u64; 4], values: &[Val]) -> [u64; 4] {
    assert_eq!(values.len(), N);
    let permutation = p3_goldilocks::default_goldilocks_poseidon2_12();
    let mut state = [Val::ZERO; 12];
    state[..8].copy_from_slice(&context);
    permutation.permute_mut(&mut state);
    state[..4].copy_from_slice(&salt.map(Val::from_u64));
    state[4..8].fill(Val::ZERO);
    permutation.permute_mut(&mut state);
    for row in values.as_chunks::<8>().0 {
        state[..8].copy_from_slice(row);
        permutation.permute_mut(&mut state);
    }
    core::array::from_fn(|i| state[i].as_canonical_u64())
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
fn actual_owner_emits_five_ordered_components_with_native8192_oracles_and_fresh_verification() {
    let files = PublicFiles::new();
    let started = Instant::now();
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let setup_bytes = setup.to_bytes().unwrap();
    let ciphertext = ciphertext(&owner);
    let generated_ms = started.elapsed().as_secs_f64() * 1000.0;
    let request = [0x61; 32];
    let preparing = Instant::now();
    let handle = owner.key_anchor(&setup, scope()).unwrap();
    let anchor = handle.public_anchor().clone();
    let mut job = handle.basis_job(&setup, request, &ciphertext).unwrap();
    let prepared_ms = preparing.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(job.stage(), BasisJobStage::AwaitingKey);
    assert!(matches!(job.prove_next_basis(), Err(Error::BasisJobStage)));
    let key_started = Instant::now();
    fs::write(files.file("key"), job.prove_key().unwrap().as_bytes()).unwrap();
    let key_ms = key_started.elapsed().as_secs_f64() * 1000.0;
    assert!(job.key_witness.is_none());
    assert!(matches!(job.prove_key(), Err(Error::BasisJobStage)));
    assert_eq!(job.stage(), BasisJobStage::Basis(0));
    // Independent unit-only read of the ACTUAL SDK Owner key, never an operational getter.
    let wide = Zeroizing::new(fhe::proto::bfv::SecretKey::from(&owner.key).coeffs);
    let coefficients = Zeroizing::new(
        wide.iter()
            .map(|v| i8::try_from(*v).unwrap())
            .collect::<Vec<_>>(),
    );
    drop(wide);
    let decoded = Ciphertext::from_bytes(&ciphertext, &owner.parameters).unwrap();
    let mut a = decoded[1].clone();
    a.change_representation(Representation::PowerBasis);
    let mut roots = [[0u64; 4]; 5];
    let mut sizes = [0usize; 5];
    let mut proving_ms = [0.0; 5];
    for basis in 0..5 {
        assert_eq!(job.stage(), BasisJobStage::Basis(basis));
        if basis == 2 {
            let last = job.shat[N - 1];
            job.shat[N - 1] = Val::ORDER_U64;
            assert!(job.prove_next_basis().is_err());
            assert_eq!(job.stage(), BasisJobStage::Basis(basis));
            job.shat[N - 1] = last;
        }
        let integers = integer_oracle(&a.coefficients().row(basis).to_vec(), &coefficients);
        assert!(integers.iter().all(|value| value.abs() < (1i128 << 62)));
        let values: Vec<_> = integers.into_iter().map(lift).collect();
        roots[basis] = native_root(
            native_context(
                &job.key_statement,
                &setup.parameters,
                &ciphertext,
                request,
                basis,
            ),
            job.salts[basis + 1],
            &values,
        );
        let started = Instant::now();
        let component = job.prove_next_basis().unwrap();
        proving_ms[basis] = started.elapsed().as_secs_f64() * 1000.0;
        sizes[basis] = component.as_bytes().len();
        fs::write(files.file(&basis.to_string()), component.as_bytes()).unwrap();
        drop(component); // only one returned public component/SDK proof exists at a time.
    }
    assert_eq!(job.stage(), BasisJobStage::Complete);
    assert!(matches!(job.prove_next_basis(), Err(Error::BasisJobStage)));
    drop(job);
    drop(coefficients);
    drop(a);
    drop(decoded);
    let mut other = handle.basis_job(&setup, request, &ciphertext).unwrap();
    fs::write(
        files.file("other-key"),
        other.prove_key().unwrap().as_bytes(),
    )
    .unwrap();
    other.cancel();
    assert_eq!(other.stage(), BasisJobStage::Cancelled);
    assert!(other.shat.is_empty());
    assert!(other.key_evidence.is_none());
    assert!(matches!(
        other.prove_next_basis(),
        Err(Error::BasisJobStage)
    ));
    drop(other);
    drop(handle);
    drop(owner);
    drop(setup);

    // All original private handles/witnesses/Owner are gone; fresh setup and proof decodes follow.
    let setup = PublicSetup::from_bytes(&setup_bytes).unwrap();
    let key = fs::read(files.file("key")).unwrap();
    let other_key = fs::read(files.file("other-key")).unwrap();
    let key_statement = setup.verify_key_transform(&anchor, &key).unwrap();
    let other_statement = setup.verify_key_transform(&anchor, &other_key).unwrap();
    assert_eq!(
        key_statement.statement().expected,
        other_statement.statement().expected
    );
    assert_ne!(
        key_statement.statement().transformed,
        other_statement.statement().transformed
    );
    let mut verification_ms = [0.0; 5];
    for basis in 0..5 {
        let component = fs::read(files.file(&basis.to_string())).unwrap();
        let started = Instant::now();
        let checked = setup
            .verify_basis_convolution(&anchor, request, &ciphertext, basis, &key, &component)
            .unwrap();
        verification_ms[basis] = started.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(checked.full_setup_id(), anchor.full_setup_id());
        assert_eq!(
            checked.statement().result.map(|v| v.as_canonical_u64()),
            roots[basis]
        );
        assert_eq!(
            checked.statement().expected.key().public_values(),
            key_statement.statement().public_values()
        );
        assert_eq!(
            checked.statement().expected.ciphertext().bytes(),
            ciphertext
        );
        assert_eq!(
            checked.statement().expected.ciphertext().parameter_bytes(),
            setup.parameters
        );
        assert_eq!(checked.statement().expected.request(), request);
        assert_eq!(checked.statement().expected.ciphertext().basis(), basis);
        if basis == 0 {
            assert!(
                setup
                    .verify_basis_convolution(
                        &anchor,
                        request,
                        &ciphertext,
                        0,
                        &other_key,
                        &component
                    )
                    .is_err()
            );
            for field in 0..6 {
                let mut foreign = anchor.clone();
                match field {
                    0 => foreign.scope.database[15] ^= 1,
                    1 => foreign.scope.bfv_key_domain[15] ^= 1,
                    2 => foreign.scope.epoch ^= 1 << 31,
                    3 => foreign.full_setup_id[31] ^= 1,
                    4 => foreign.parameter_digest[31] ^= 1,
                    _ => foreign.coefficients[3] ^= 1,
                }
                assert!(
                    setup
                        .verify_basis_convolution(
                            &foreign,
                            request,
                            &ciphertext,
                            0,
                            &key,
                            &component
                        )
                        .is_err()
                );
            }
            let mut foreign_request = request;
            foreign_request[31] ^= 1;
            let mut repaired = component.clone();
            repaired[235] ^= 1;
            assert!(
                setup
                    .verify_basis_convolution(
                        &anchor,
                        foreign_request,
                        &ciphertext,
                        0,
                        &key,
                        &repaired
                    )
                    .is_err()
            );
            let params = bfv_basis_convolution::parameters();
            let original = Ciphertext::from_bytes(&ciphertext, &params).unwrap();
            assert_ne!(original[0].coefficients(), original[1].coefficients());
            let changed = Ciphertext::new(vec![original[1].clone(), original[1].clone()], &params)
                .unwrap()
                .to_bytes();
            let changed_public =
                bfv_basis_convolution::CanonicalCiphertext::decode(&setup.parameters, &changed, 0)
                    .unwrap();
            let original_public = bfv_basis_convolution::CanonicalCiphertext::decode(
                &setup.parameters,
                &ciphertext,
                0,
            )
            .unwrap();
            assert_eq!(
                changed_public.coefficients(),
                original_public.coefficients()
            );
            assert_ne!(
                changed_public.b_coefficients(),
                original_public.b_coefficients()
            );
            let changed_expected = BasisExpected::new(
                key_statement.statement().clone(),
                &setup.parameters,
                &changed,
                request,
                0,
            )
            .unwrap();
            let mut repaired = component.clone();
            repaired[236..268].copy_from_slice(&changed_expected.ciphertext_binding());
            assert!(
                setup
                    .verify_basis_convolution(&anchor, request, &changed, 0, &key, &repaired)
                    .is_err()
            );
        }
        assert!(
            setup
                .verify_basis_convolution(
                    &anchor,
                    request,
                    &ciphertext,
                    (basis + 1) % 5,
                    &key,
                    &component
                )
                .is_err()
        );
    }
    println!(
        "{}",
        serde_json::json!({
            "stage":"actual_owner_five_basis_job", "owner_generate_ciphertext_ms":generated_ms,
            "anchor_job_ms":prepared_ms, "key_generation_ms":key_ms, "basis_generation_ms":proving_ms,
            "fresh_component_verification_ms":verification_ms, "key_frame_bytes":key.len(), "basis_frame_bytes":sizes,
            "basis_count":5, "native_coefficients_per_basis":8192, "sql_grant":false,
            "evaluation_key_consistency_proven":false, "composed_128_claim":false
        })
    );
}
#[test]
fn genuine_other_owner_component_verifies_under_its_pin_and_rejects_original_owner() {
    let (owner_a, setup_a) = Owner::generate(Geometry::Rows16).unwrap();
    let handle_a = owner_a.key_anchor(&setup_a, scope()).unwrap();
    let pin_a = handle_a.public_anchor().clone();
    let (owner_b, setup_b) = Owner::generate(Geometry::Rows16).unwrap();
    let ct = ciphertext(&owner_b);
    let handle_b = owner_b.key_anchor(&setup_b, scope()).unwrap();
    let pin_b = handle_b.public_anchor().clone();
    let mut job = handle_b.basis_job(&setup_b, [9; 32], &ct).unwrap();
    job.prove_key().unwrap();
    let basis = job.prove_next_basis().unwrap();
    setup_b
        .verify_basis_convolution(
            &pin_b,
            [9; 32],
            &ct,
            0,
            job.key_evidence().unwrap().as_bytes(),
            basis.as_bytes(),
        )
        .unwrap();
    assert!(
        setup_a
            .verify_basis_convolution(
                &pin_a,
                [9; 32],
                &ct,
                0,
                job.key_evidence().unwrap().as_bytes(),
                basis.as_bytes()
            )
            .is_err()
    );
    assert!(
        setup_b
            .verify_basis_convolution(
                &pin_a,
                [9; 32],
                &ct,
                0,
                job.key_evidence().unwrap().as_bytes(),
                basis.as_bytes()
            )
            .is_err()
    );
}
#[test]
fn complete_setup_and_public_wire_guards_precede_secret_copy_and_cancel_is_terminal() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let ct = ciphertext(&owner);
    let handle = owner.key_anchor(&setup, scope()).unwrap();
    let mut changed = PublicSetup::from_bytes(&setup.to_bytes().unwrap()).unwrap();
    changed.rotation_keys.push(0);
    assert!(matches!(
        handle.basis_job(&changed, [1; 32], &ct),
        Err(Error::BindingMismatch)
    ));
    for bytes in [&[][..], &ct[..ct.len() - 1]] {
        assert!(handle.basis_job(&setup, [1; 32], bytes).is_err());
    }
    let mut job = handle.basis_job(&setup, [1; 32], &ct).unwrap();
    assert!(matches!(job.key_evidence(), Err(Error::BasisJobStage)));
    job.cancel();
    job.cancel();
    assert_eq!(job.stage(), BasisJobStage::Cancelled);
    assert!(job.key_witness.is_none());
    assert!(job.shat.is_empty());
    assert!(job.salts.iter().flatten().all(|v| *v == 0));
    assert!(matches!(job.prove_key(), Err(Error::BasisJobStage)));
    assert!(matches!(job.prove_next_basis(), Err(Error::BasisJobStage)));
}
