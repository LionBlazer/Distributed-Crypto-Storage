//! Public nonsecret examples through the normal generated owner, not an SDK-secret fixture.
use super::*;
use lower::{data, query};
use std::time::Instant;

fn owner() -> Owner {
    Owner::generate([0xb1; 32], [11; 8]).unwrap()
}
fn words() -> Zeroizing<Vec<u64>> {
    let mut out = Zeroizing::new(vec![0; N]);
    for (i, (age, amount)) in [(0usize, 1u64), (1, 2), (128, 3), (255, 4)]
        .into_iter()
        .enumerate()
    {
        out[2 * i * 512 + age] = 256 + age as u64;
        out[(2 * i + 1) * 512 + age] = amount;
    }
    out
}
fn data_expected(owner: &Owner, original: &OriginatingData, salt: &[u64; 4]) -> data::Expected {
    let context = [51; 8];
    let root = original.commitment(context, salt).unwrap();
    data::Expected::checked(
        data::Request::checked([0xb2; 32], original.ciphertext().to_vec()).unwrap(),
        [0xb3; 64],
        [context.map(Val::from_u64), owner.key_expected().context()],
        [root.map(Val::from_u64), owner.key_expected().root()],
    )
    .unwrap()
}
fn statement(bits: &[u8; 32]) -> Zeroizing<[u64; 96]> {
    let mut words = Zeroizing::new([0; 96]);
    for (i, v) in words[..13].iter_mut().enumerate() {
        *v = 10 + i as u64;
    }
    for (i, block) in bits.as_chunks::<4>().0.iter().enumerate() {
        words[78 + i] = u32::from_le_bytes(*block) as u64;
    }
    words
}
fn statement_root(words: &[u64; 96]) -> [Val; 4] {
    use p3_goldilocks::default_goldilocks_poseidon2_12;
    use p3_symmetric::Permutation;
    let permutation = default_goldilocks_poseidon2_12();
    let mut state = [Val::ZERO; 12];
    for block in words.as_chunks::<8>().0 {
        state[..8].copy_from_slice(&block.map(Val::from_u64));
        permutation.permute_mut(&mut state);
    }
    let root = state[..4].try_into().unwrap();
    state.fill(Val::ZERO);
    root
}
fn query_expected(
    owner: &Owner,
    original: &OriginatingQuery,
    statement: &[u64; 96],
    salt: &[u64; 4],
) -> query::Expected {
    let request = original.public_request().formation_request().unwrap();
    let context = [71; 8];
    let root = owner.query_commitment(original, context, salt).unwrap();
    let core = data::Expected::checked(
        data::Request::checked(request.nonce(), request.ciphertexts()[1].to_vec()).unwrap(),
        [0xb4; 64],
        [context.map(Val::from_u64), owner.key_expected().context()],
        [root.map(Val::from_u64), owner.key_expected().root()],
    )
    .unwrap();
    query::Expected::checked(
        &core,
        statement_root(statement),
        core::array::from_fn(|i| Val::from_u64(statement[i])),
    )
    .unwrap()
}

#[test]
fn generated_key_custody_requires_independent_pins_aead_and_actual_cs_reopening() {
    let owner = owner();
    let expected = owner.key_expected().clone();
    // Explicit PUBLIC test custody keys; no participant secret is used.
    let key = CustodyKey::new(Zeroizing::new([0xd1; 32]));
    let identity = CustodyIdentity::checked([0xd2; 32]).unwrap();
    let record = owner.seal_key(&identity, &key).unwrap();
    assert_eq!(record.as_bytes().len(), KEY_RECORD_BYTES);
    let foreign = Owner::generate([0xb1; 32], [11; 8]).unwrap();
    assert!(matches!(
        Owner::restore_key(foreign.key_expected().clone(), &identity, &key, &record),
        Err(Error::Binding)
    ));
    assert!(matches!(
        Owner::restore_key(
            expected.clone(),
            &CustodyIdentity::checked([0xd3; 32]).unwrap(),
            &key,
            &record
        ),
        Err(Error::Binding)
    ));
    let wrong = CustodyKey::new(Zeroizing::new([0xd4; 32]));
    assert!(matches!(
        Owner::restore_key(expected.clone(), &identity, &wrong, &record),
        Err(Error::Authentication)
    ));
    let mut damaged = record.as_bytes().to_vec();
    *damaged.last_mut().unwrap() ^= 1;
    let damaged = EncryptedKey::from_bytes(&damaged).unwrap();
    assert!(matches!(
        Owner::restore_key(expected.clone(), &identity, &key, &damaged),
        Err(Error::Authentication)
    ));
    assert!(EncryptedKey::from_bytes(&record.as_bytes()[..KEY_RECORD_BYTES - 1]).is_err());
    let mut trailing = record.as_bytes().to_vec();
    trailing.push(0);
    assert!(EncryptedKey::from_bytes(&trailing).is_err());
    // The test repairs AEAD deliberately; a changed bounded SDK coefficient must still fail Cs.
    let mut plain = key_custody::open(&expected, &identity, &key, &record).unwrap();
    plain[3] = (plain[3] + 2) % 41;
    let repaired = key_custody::seal(&expected, &identity, &key, plain).unwrap();
    assert!(matches!(
        Owner::restore_key(expected.clone(), &identity, &key, &repaired),
        Err(Error::Binding)
    ));
    let restored = Owner::restore_key(expected.clone(), &identity, &key, &record).unwrap();
    assert_eq!(restored.key_expected().binding(), expected.binding());
}

#[test]
fn generated_restored_owner_proves_actual_data_and_fused_query_before_real_product_completion() {
    let started = Instant::now();
    let owner = owner();
    let key_expected = owner.key_expected().clone();
    let plain = words();
    let original = owner.originate_data(plain.clone()).unwrap();
    let data_salt = Zeroizing::new([13; 4]);
    let data = data_expected(&owner, &original, &data_salt);
    let identity = CustodyIdentity::checked([0xe1; 32]).unwrap();
    let key = CustodyKey::new(Zeroizing::new([0xe2; 32]));
    let record = owner.seal_key(&identity, &key).unwrap();
    drop(owner);
    let owner = Owner::restore_key(key_expected, &identity, &key, &record).unwrap();
    let prepared = owner.prepare_data(&original, &data, data_salt).unwrap();
    let data_started = Instant::now();

    let data_proof = data::prove_dense(&data, prepared).unwrap();
    let data_prove_ms = data_started.elapsed().as_secs_f64() * 1000.;
    let receive = Instant::now();
    let _checked_data = data::verify_dense(&data, data_proof.as_bytes()).unwrap();
    let data_verify_ms = receive.elapsed().as_secs_f64() * 1000.;
    let bits = [0x99; 32];
    let original_query = owner
        .originate(
            Mask256::new(bits),
            InputBinding::checked(super::tests::scope()).unwrap(),
            &data,
        )
        .unwrap();
    let statement = statement(&bits);
    let salt = Zeroizing::new([17; 4]);
    let query = query_expected(&owner, &original_query, &statement, &salt);
    let prepared = owner
        .prepare_query(&original_query, &query, statement, salt)
        .unwrap();
    let query_started = Instant::now();
    let query_proof = query::prove(&query, prepared).unwrap();
    let query_prove_ms = query_started.elapsed().as_secs_f64() * 1000.;
    let receive = Instant::now();
    let _checked_query = query::verify(&query, query_proof.as_bytes()).unwrap();
    let query_verify_ms = receive.elapsed().as_secs_f64() * 1000.;
    let response = Evaluator::new()
        .unwrap()
        .evaluate(original_query.public_request())
        .unwrap();
    let actual = owner.complete(&original_query, &response).unwrap();
    assert_eq!(
        actual.coefficients(),
        super::tests::oracle(&plain, &Mask256::new(bits)).as_slice()
    );
    let mut damaged = data_proof.as_bytes().to_vec();
    *damaged.last_mut().unwrap() ^= 1;
    assert!(data::verify_dense(&data, &damaged).is_err());
    let mut damaged = query_proof.as_bytes().to_vec();
    *damaged.last_mut().unwrap() ^= 1;
    assert!(query::verify(&query, &damaged).is_err());
    eprintln!(
        "gold_owner generated_native data_prove_ms={data_prove_ms:.3} data_verify_ms={data_verify_ms:.3} query_prove_ms={query_prove_ms:.3} query_verify_ms={query_verify_ms:.3} whole_test_ms={:.3} data_frame_bytes={} query_frame_bytes={} key_record_bytes={} Source=false Word=false freshness=false SQL=false security_assessed=false",
        started.elapsed().as_secs_f64() * 1000.,
        data_proof.as_bytes().len(),
        query_proof.as_bytes().len(),
        record.as_bytes().len()
    );
}

#[test]
fn original_data_query_key_mask_salt_and_nonce_are_mandatory_for_preparation() {
    let owner = owner();
    let original = owner.originate_data(words()).unwrap();
    let salt = Zeroizing::new([13; 4]);
    let data = data_expected(&owner, &original, &salt);
    assert!(
        owner
            .originate_data(Zeroizing::new(vec![0; N - 1]))
            .is_err()
    );
    assert!(owner.originate_data(Zeroizing::new(vec![T; N])).is_err());
    let foreign = Owner::generate([0xb1; 32], [11; 8]).unwrap();
    assert!(matches!(
        foreign.prepare_data(&original, &data, salt.clone()),
        Err(Error::Binding)
    ));
    let other = owner.originate_data(words()).unwrap();
    let other_expected = data_expected(&owner, &other, &salt);
    assert!(matches!(
        owner.prepare_data(&original, &other_expected, salt.clone()),
        Err(Error::Binding)
    ));
    assert!(matches!(
        owner.prepare_data(&original, &data, Zeroizing::new([14; 4])),
        Err(Error::Binding)
    ));
    owner
        .prepare_data(&original, &data, salt.clone())
        .unwrap()
        .check_private_consistency(&data)
        .unwrap();
    let bits = [0x99; 32];
    let original = owner
        .originate(
            Mask256::new(bits),
            InputBinding::checked(super::tests::scope()).unwrap(),
            &data,
        )
        .unwrap();
    let honest = statement(&bits);
    let qsalt = Zeroizing::new([17; 4]);
    let query = query_expected(&owner, &original, &honest, &qsalt);
    let mut wrong = honest.clone();
    wrong[78] ^= 1;
    assert!(matches!(
        owner.prepare_query(&original, &query, wrong, qsalt.clone()),
        Err(Error::Binding)
    ));
    assert!(matches!(
        owner.prepare_query(&original, &query, honest.clone(), Zeroizing::new([18; 4])),
        Err(Error::Binding)
    ));
    let core = query.core_expected();
    let request = data::Request::checked(
        [0x31; 32],
        original.public_request().query_ciphertext().to_vec(),
    )
    .unwrap();
    let bad = data::Expected::checked(request, [0x32; 64], core.contexts(), core.roots()).unwrap();
    let bad = query::Expected::checked(&bad, query.statement_root(), query.header()).unwrap();
    assert!(matches!(
        owner.prepare_query(&original, &bad, honest.clone(), qsalt.clone()),
        Err(Error::Binding)
    ));
    owner
        .prepare_query(&original, &query, honest, qsalt)
        .unwrap();
}

#[test]
fn originating_statement_requires_the_original_full_statement_mask_and_input_equations() {
    let owner = owner();
    let original_data = owner.originate_data(words()).unwrap();
    let data = data_expected(&owner, &original_data, &[13; 4]);
    let bits = [0x99; 32];
    let honest = statement(&bits);
    let mut scope = super::tests::scope();
    for (bytes, word) in scope
        .statement
        .as_chunks_mut::<8>()
        .0
        .iter_mut()
        .zip(statement_root(&honest))
    {
        *bytes = word.as_canonical_u64().to_le_bytes();
    }
    let original = owner
        .originate(
            Mask256::new(bits),
            InputBinding::checked(scope).unwrap(),
            &data,
        )
        .unwrap();

    let checked = owner.bind_statement(&original, honest.clone()).unwrap();
    assert_eq!(
        checked.root(),
        statement_root(&honest).map(|v| v.as_canonical_u64())
    );
    assert_eq!(
        checked.public_request().as_bytes(),
        original.public_request().as_bytes()
    );
    assert_eq!(checked.data_expected().binding(), data.binding());
    assert_eq!(checked.header(), core::array::from_fn(|i| honest[i]));
    // Same mask is insufficient: changing any other committed statement word fails too.
    for at in [0, 13, 77, 78, 85, 86, 94, 95] {
        let mut changed = honest.clone();
        changed[at] ^= 1;
        assert!(
            owner.bind_statement(&original, changed).is_err(),
            "word {at}"
        );
    }
    for (at, value) in [(78, 1u64 << 32), (94, Val::ORDER_U64)] {
        let mut changed = honest.clone();
        changed[at] = value;
        assert!(matches!(
            owner.bind_statement(&original, changed),
            Err(Error::Shape)
        ));
    }
    let foreign = Owner::generate([0xb9; 32], [19; 8]).unwrap();
    assert!(matches!(
        foreign.bind_statement(&original, honest.clone()),
        Err(Error::Binding)
    ));

    // Deliberate internal hostile construction: a well-formed ciphertext for a
    // different private mask, with the original public binding repaired. The
    // concrete input equations must reject it despite the correct Stmt96 root.
    let mut other = owner
        .originate(
            Mask256::new([0x66; 32]),
            original.request.binding().clone(),
            &data,
        )
        .unwrap();
    other.mask = Mask256::new(bits);
    assert!(matches!(
        owner.bind_statement(&other, honest),
        Err(Error::Arithmetic)
    ));
    // Actual certificate verification and original pair checks still precede completion.
    let response = Evaluator::new()
        .unwrap()
        .evaluate(checked.public_request())
        .unwrap();
    let expected = checked
        .public_request()
        .product_expected(response.output().to_vec())
        .unwrap();
    let product = product::check_arithmetic(&expected, response.certificate()).unwrap();
    let actual = checked.complete_checked_product(&owner, &product).unwrap();
    assert_eq!(
        actual.coefficients(),
        super::tests::oracle(&words(), &Mask256::new(bits)).as_slice()
    );
    assert!(matches!(
        checked.complete_checked_product(&foreign, &product),
        Err(Error::Binding)
    ));
}
