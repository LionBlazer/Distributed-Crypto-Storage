//! Public nonsecret source and explicit expected bank transitions, never an execution fallback.
use super::*;
use bfv_ciphertext_formation::gold::data;
use compact_store::{Layout, Owner as PageOwner};
use fhe_math::zq::Modulus;
use registry200_proof::{source, two_lane_encoding as encoding};
use std::time::Instant;

fn digest(words: &[Val]) -> [Val; 4] {
    assert!(words.len().is_multiple_of(8));
    let mut state = [Val::ZERO; 12];
    let mut scratch = [Val::ZERO; 248];
    for row in words.as_chunks::<8>().0 {
        state[..8].copy_from_slice(row);
        state = source::poseidon::write(&mut scratch, state);
    }
    scratch.fill(Val::ZERO);
    let root = state[..4].try_into().unwrap();
    state.fill(Val::ZERO);
    root
}
fn source_fixture() -> (source::version::SourceVersionExpected, Zeroizing<Vec<u8>>) {
    let owner = PageOwner::from_key([0x42; 16], [0x73; 16], Zeroizing::new([0x51; 32]));
    let values = [255, 0, 0, 0, 255, 255, 255, 0, 1, 128, 255, 0];
    let data = owner
        .seal(
            Layout {
                schema: source::DATA_SCHEMA,
                row_width: 3,
                rows_per_page: 256,
                row_count: 4,
            },
            &values,
            source::statement::limits(),
        )
        .unwrap();
    // Existing explicitly public input fixture; it is not a query answer.
    let mut index = data.commitment().encode().to_vec();
    index.extend(
        include_str!("../../../compact-query/tests/fixtures/index-v3-four-row-suffix.hex")
            .lines()
            .filter(|line| !line.starts_with('#'))
            .flat_map(str::split_whitespace)
            .map(|s| u8::from_str_radix(s, 16).unwrap()),
    );
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
    let images = [data.encode(), indexed.encode()];
    let heads = [data.commitment(), indexed.commitment()];
    let key = source::commitment::digest(&source::commitment::key_fields(
        &heads[0].encode(),
        [0x51; 32],
        [Val::ONE; 4],
    ));
    let draft = source::version::SourceVersionExpected::checked(
        [&images[0], &images[1]],
        heads,
        encode_digest(key),
        [0; 32],
    )
    .unwrap();
    let mut plain = Zeroizing::new(values.to_vec());
    plain.extend(index);
    let state = source::commitment::digest(&source::commitment::opening_fields(
        draft.statement(),
        [Val::TWO; 4],
        &plain,
    ));
    let source = source::version::SourceVersionExpected::checked(
        [&images[0], &images[1]],
        heads,
        encode_digest(key),
        encode_digest(state),
    )
    .unwrap();
    (source, plain)
}
fn claims(old: [Val; 4], next: [Val; 4], blind: [Val; 8]) -> word::Claims {
    word::Claims {
        old,
        next,
        command: [Val::ZERO; 4],
        statement: [Val::ZERO; 4],
        result: [Val::ZERO; 4],
        blind_sql: blind,
    }
}
fn expected(
    source: &source::version::SourceVersionExpected,
    enrollment: [Val; 4],
    claims: word::Claims,
) -> word::Expected {
    word::Expected::checked(
        source,
        word::Role::Predicate,
        [0xa7; 32],
        [0xa8; 32],
        enrollment,
        claims,
    )
    .unwrap()
}
fn banks(
    draft: &word::Expected,
    plain: &[u8],
    enrollment: [Val; 4],
    controllers: [[Val; 8]; 2],
) -> [[Val; 208]; 2] {
    let plain = source::statement::words(plain).collect::<Vec<_>>();
    let mut old = [Val::ZERO; 208];
    old[..33].copy_from_slice(draft.registry_header());
    old[33..37].copy_from_slice(&enrollment);
    old[37..45].copy_from_slice(&plain[31..39]);
    old[45..77].copy_from_slice(&plain[555..587]);
    old[77..80].copy_from_slice(&[Val::TWO, Val::from_u32(4), Val::TWO]);
    old[80] = Val::TWO;
    old[82] = Val::TWO;
    old[190..194].fill(Val::from_u32(6));
    for (slot, controller) in controllers.iter().enumerate() {
        let tx = &mut old[84 + 53 * slot..137 + 53 * slot];
        tx[0] = Val::ONE;
        tx[1] = Val::from_usize(slot + 1);
        tx[3] = Val::from_usize(slot + 1);
        tx[4..12].copy_from_slice(controller);
        tx[12] = Val::ONE;
        tx[15..23].copy_from_slice(&fields(&[0xa8; 32]));
    }
    // B holds row0. SQL age>=128 includes rows0/2/3, so SKIP chooses row2.
    old[137 + 23] = Val::from_u32(4);
    let mut next = old;
    next[80] = Val::from_u32(3);
    next[84 + 12] = Val::TWO;
    next[84 + 23 + 2] = Val::from_u32(4);
    [old, next]
}
#[test]
fn compiled_sql_requires_genuine_data_word_and_original_product_before_owner_completion() {
    let began = Instant::now();
    let (source, plain) = source_fixture();
    let key_binding = |cs| {
        encoding::statement::KeyBinding::new(
            source.statement().heads[0][8..24].try_into().unwrap(),
            [0x71; 16],
            1,
            [0x95; 32],
            encode_digest(cs),
        )
        .unwrap()
    };
    let owner = Owner::generate(
        [0x95; 32],
        installed::secret_context(&key_binding([Val::ZERO; 4])).map(|v| v.as_canonical_u64()),
    )
    .unwrap();
    let e = encoding::statement::Expected::source_version(
        &source,
        key_binding(owner.key_expected().root_words().map(Val::from_u64)),
    )
    .unwrap();
    let witness =
        encoding::circuit::Witness::source_version(&e, plain.clone(), [2; 4], [5; 4]).unwrap();
    let mut data_words = witness.coefficients();
    let modulus = Modulus::new(gold::T).unwrap();
    modulus.scalar_mul_vec(&mut data_words, modulus.inv(gold::SCALE).unwrap());
    let original_data = owner.originate_data(data_words.clone()).unwrap();
    let request = data::Request::checked([0x61; 32], original_data.ciphertext().to_vec()).unwrap();
    let data = installed::Expected::checked(&request, &witness.statement()).unwrap();
    let state = source::version::prove(
        &source,
        &source::circuit::Witness::new(
            [0x51; 32],
            [Val::ONE; 4],
            [Val::TWO; 4],
            [255, 0, 255, 128],
        ),
    )
    .unwrap()
    .into_bytes();
    let child = encoding::prove(&e, &witness, &state)
        .unwrap()
        .into_parts()
        .1;
    let frame = installed::prove_dense_prepared(
        &data,
        &request,
        installed::Prerequisites::checked(&state, &child).unwrap(),
        owner
            .prepare_data(&original_data, data.core_expected(), Zeroizing::new([5; 4]))
            .unwrap(),
    )
    .unwrap()
    .into_bytes();
    let retained = installed::verify_dense(
        &data,
        &request,
        installed::Prerequisites::checked(&state, &child).unwrap(),
        &frame,
    )
    .unwrap();
    drop((state, child, frame, witness));
    let producer = word::Prover::new(word::Role::Predicate).unwrap();
    let receiver = word::read::owner::Verifier::new().unwrap();
    let compiled = CompiledLockingSelect::compile(
        "SELECT age,amount FROM records WHERE age>=128 OFFSET 0 LIMIT 1 FOR UPDATE SKIP LOCKED",
    )
    .unwrap();
    let blind = compiled.blinded_sql();
    let controllers = [fields(&[0x41; 32]), fields(&[0x42; 32])];
    let draft = expected(
        &source,
        [Val::ZERO; 4],
        claims([Val::ZERO; 4], [Val::ZERO; 4], blind),
    );
    let mut enrollment = draft.enrollment_header().to_vec();
    let source_words = source::statement::words(&plain).collect::<Vec<_>>();
    enrollment.extend(&source_words[31..39]);
    enrollment.extend([Val::TWO, Val::ONE]);
    enrollment.extend(controllers[0]);
    enrollment.push(Val::TWO);
    enrollment.extend(controllers[1]);
    enrollment.extend([Val::from_u32(3); 4]);
    let enrollment = digest(&enrollment);
    let banks = banks(&draft, &plain, enrollment, controllers);
    let old = digest(&banks[0]);
    let next = digest(&banks[1]);
    let draft = expected(&source, enrollment, claims(old, next, blind));
    let prepared = compiled
        .prepare(
            draft.statement_domain(),
            Material {
                source: word::SourceOpening::checked(plain, Zeroizing::new([2; 4])).unwrap(),
                registry: word::RegistryOpening::new(controllers, banks),
                actor: Actor {
                    slot: 0,
                    principal: 1,
                    transaction: 1,
                },
                walk: word::WalkInput {
                    client: fields(&[0x47; 32]),
                    call: 1,
                    invocation: fields(&[0x48; 32]),
                    ..Default::default()
                },
                salts: Zeroizing::new([[3; 4], [4; 4], [5; 4]]),
            },
        )
        .unwrap();
    // Independently serialize the hand-specified command/result witnesses. No
    // production query evaluator or fixture answer feeds the actual FHE worker.
    let mut command = word::command_header().to_vec();
    command.extend(draft.context());
    command.extend(old);
    command.push(Val::ONE);
    command.extend([Val::ONE, Val::ZERO, Val::ONE]);
    command.extend(controllers[0]);
    command.extend([Val::TWO, Val::ZERO, Val::ONE, Val::ZERO]);
    command.extend([0, 0, 0, 0, u32::MAX, u32::MAX, u32::MAX, u32::MAX].map(Val::from_u32));
    command.extend([4, 2, 0, 1, 3].map(Val::from_u32));
    command.extend([Val::ZERO; 8 + 8 + 1]);
    command.extend([Val::from_u32(4); 4]);
    command.push(Val::ZERO);
    assert_eq!(command.len(), 160);
    let statement = prepared.statement_root();
    let mut result = word::result_header().to_vec();
    result.extend(draft.context());
    result.extend(old);
    result.extend(next);
    result.extend(statement);
    result.extend([
        Val::ZERO,
        Val::ONE,
        Val::ONE,
        Val::ZERO,
        Val::ZERO,
        Val::from_u32(3),
    ]);
    result.extend([0, 0, 1, 0, 0, 0, 1, 0].map(Val::from_u32));
    result.extend([Val::ZERO; 4 + 4 + 4 + 2 + 1]);
    result.extend([Val::ONE, Val::ZERO, Val::ONE, Val::ZERO]);
    result.extend([Val::from_u32(5); 4]);
    result.extend([Val::ZERO; 6]);
    assert_eq!(result.len(), 160);
    let mut claims = claims(old, next, blind);
    claims.command = digest(&command);
    claims.statement = statement;
    claims.result = digest(&result);
    let expected = expected(&source, enrollment, claims);
    let scope = InputScope {
        database: source.statement().heads[0][8..24].try_into().unwrap(),
        transaction: 1,
        call: 1,
        principal: 1,
        application: word::profile_digest(),
        genesis: [0xa7; 32],
        rules: word::wire_profile_digest(),
        context: Sha256::digest(expected.binding()).into(),
        parent: [0xa8; 32],
        client: [0x47; 32],
        controller: [0x41; 32],
        source_version: source.version_id(),
        data_admission: Sha256::digest(data.core_expected().binding()).into(),
        snapshot: [0xa8; 32],
        statement: encode_digest(statement),
        command: encode_digest(claims.command),
        attempt: [0x48; 32],
        nonce: [0xa9; 32],
    };
    let mut pending = prepared.originate(&owner, scope, &expected, &data).unwrap();
    let mut changed = claims;
    changed.next[0] += Val::ONE;
    let changed = word::Expected::checked(
        &source,
        word::Role::Predicate,
        [0xa7; 32],
        [0xa8; 32],
        enrollment,
        changed,
    )
    .unwrap();
    assert!(matches!(
        pending.prove(&owner, &producer, &changed),
        Err(Error::Binding)
    ));
    let proved = pending.prove(&owner, &producer, &expected).unwrap();
    let response = gold::Evaluator::new()
        .unwrap()
        .evaluate(proved.input().public_request())
        .unwrap();
    let checked = receiver
        .verify(
            proved.input(),
            &expected,
            &data,
            &retained,
            word::read::owner::Evidence {
                word: proved.word(),
                output: response.output(),
                product: response.certificate(),
            },
        )
        .unwrap();
    let completed = checked.complete(&owner).unwrap();
    // All4096 arithmetic is independently compared only after actual receiving.
    let mut oracle = Zeroizing::new(vec![0; gold::N]);
    for (i, &x) in data_words.iter().enumerate().filter(|(_, v)| **v != 0) {
        for j in 0..128 {
            let at = (i + j) % gold::N;
            oracle[at] = (oracle[at] + if i + j < gold::N { x } else { gold::T - x }) % gold::T;
        }
    }
    assert_eq!(completed.coefficients(), oracle.as_slice());
    let mut wrong = claims;
    wrong.next[0] += Val::ONE;
    let wrong = word::Expected::checked(
        &source,
        word::Role::Predicate,
        [0xa7; 32],
        [0xa8; 32],
        enrollment,
        wrong,
    )
    .unwrap();
    assert!(
        receiver
            .verify(
                proved.input(),
                &wrong,
                &data,
                &retained,
                word::read::owner::Evidence {
                    word: proved.word(),
                    output: response.output(),
                    product: response.certificate()
                }
            )
            .is_err()
    );
    let mut bad = proved.word().to_vec();
    *bad.last_mut().unwrap() ^= 1;
    assert!(
        receiver
            .verify(
                proved.input(),
                &expected,
                &data,
                &retained,
                word::read::owner::Evidence {
                    word: &bad,
                    output: response.output(),
                    product: response.certificate()
                }
            )
            .is_err()
    );
    drop(checked);
    drop(proved);
    assert!(matches!(
        pending.prove(&owner, &producer, &expected),
        Err(Error::Consumed)
    ));
    eprintln!(
        "word_sql_native whole_test_ms={:.3} actual_Source_DATA_Word_product=true sql_compiler=true owner_witness_supplied=true network=false SQL_accepted=false current_head=false finality=false locks_granted=false security_assessed=false",
        began.elapsed().as_secs_f64() * 1000.
    );
}
