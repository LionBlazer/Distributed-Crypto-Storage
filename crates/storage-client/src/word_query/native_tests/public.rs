//! Genuine public proofs from compiled SQL; plaintext fixtures are assertions only.
use super::*;

fn pending_sql(fixture: &InstalledFixture, nonce: u8) -> (PendingQuery, word::Expected) {
    let compiled = CompiledLockingSelect::compile(
        "SELECT age,amount FROM records WHERE age>=128 OFFSET 0 LIMIT 1 FOR UPDATE SKIP LOCKED",
    )
    .unwrap();
    let blind = compiled.blinded_sql();
    let controllers = [fields(&[0x41; 32]), fields(&[0x42; 32])];
    let draft = expected(
        &fixture.source,
        [Val::ZERO; 4],
        claims([Val::ZERO; 4], [Val::ZERO; 4], blind),
    );
    let source_words = source::statement::words(&fixture.plain).collect::<Vec<_>>();
    let mut enrollment = draft.enrollment_header().to_vec();
    enrollment.extend(&source_words[31..39]);
    enrollment.extend([Val::TWO, Val::ONE]);
    enrollment.extend(controllers[0]);
    enrollment.push(Val::TWO);
    enrollment.extend(controllers[1]);
    enrollment.extend([Val::from_u32(3); 4]);
    let enrollment = digest(&enrollment);
    let banks = banks(&draft, &fixture.plain, enrollment, controllers);
    let draft = expected(
        &fixture.source,
        enrollment,
        claims(digest(&banks[0]), [Val::ZERO; 4], blind),
    );
    let prepared = compiled
        .prepare_current(
            &draft,
            CurrentMaterial {
                source: word::SourceOpening::checked(fixture.plain.clone(), Zeroizing::new([2; 4]))
                    .unwrap(),
                registry: word::CurrentRegistry::new(
                    controllers,
                    Zeroizing::new(banks[0].map(|v| v.as_canonical_u64())),
                    Zeroizing::new([6; 4]),
                )
                .unwrap(),
                actor: Actor {
                    slot: 0,
                    principal: 1,
                    transaction: 1,
                },
                walk: word::WalkInput {
                    client: fields(&[0x47; 32]),
                    call: 1,
                    invocation: fields(&[nonce; 32]),
                    new_salt: [Val::from_u32(9); 4],
                    ..Default::default()
                },
                salts: Zeroizing::new([[3; 4], [4; 4], [5; 4]]),
            },
        )
        .unwrap();
    let (prepared, expected, opening) = prepared.into_parts();
    let (next, result) = opening.into_words();
    // Independent next-bank assertion: B keeps row0; this SKIP query locks row2.
    assert_eq!(*next, banks[1].map(|v| v.as_canonical_u64()));
    assert_eq!(
        word::result_root(&result).unwrap(),
        expected.claims().result
    );
    let scope = InputScope {
        database: fixture.source.statement().heads[0][8..24]
            .try_into()
            .unwrap(),
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
        source_version: fixture.source.version_id(),
        data_admission: Sha256::digest(fixture.data.core_expected().binding()).into(),
        snapshot: [0xa8; 32],
        statement: encode_digest(expected.claims().statement),
        command: encode_digest(expected.claims().command),
        attempt: [nonce; 32],
        nonce: [nonce; 32],
    };
    let pending = prepared
        .originate(&fixture.owner, scope, &expected, &fixture.data)
        .unwrap();
    (pending, expected)
}

fn public_read_expected(
    proved: &ProvedPublicQuery<'_>,
    word: &word::Expected,
    data: &installed::Expected,
    response: &gold::UnverifiedProduct,
) -> word::read::Expected {
    word::read::Expected::checked(
        word,
        data,
        &proved.public_request().formation_request().unwrap(),
        proved.query_expected().core_expected().roots()[0],
        response.output().to_vec(),
    )
    .unwrap()
}

// The receiving boundary has only public endpoints, proof bytes and its actually
// verified immutable DATA theorem. No owner, mask, SQL or private input premise.
fn public_receive<'a>(
    expected: &'a word::read::Expected,
    retained: &installed::VerifiedDataFormation,
    evidence: word::read::QueryEvidence<'_>,
) -> word::read::Result<word::read::ArithmeticCheckedRead<'a>> {
    word::read::Verifier::new(expected)?.verify_retained(retained, evidence)
}

#[test]
fn compiled_sql_public_proofs_bind_original_data_before_completion_and_share_single_use() {
    let began = Instant::now();
    let fixture = installed_fixture();
    let producer = word::Prover::new(word::Role::Predicate).unwrap();
    let evaluator = gold::Evaluator::new().unwrap();
    let (mut pending, expected) = pending_sql(&fixture, 0xb1);

    // Wrong original intent or complete DATA metadata must not consume witnesses.
    let mut changed_claims = expected.claims();
    changed_claims.next[0] += Val::ONE;
    let foreign_expected = word::Expected::checked(
        &fixture.source,
        word::Role::Predicate,
        expected.genesis(),
        expected.parent(),
        expected.statement_domain().enrollment,
        changed_claims,
    )
    .unwrap();
    assert!(matches!(
        pending.prove_public(&fixture.owner, &producer, &foreign_expected, &fixture.data),
        Err(Error::Binding)
    ));
    let foreign_request =
        data::Request::checked([0x62; 32], fixture.data.request().ciphertext().to_vec()).unwrap();
    let foreign_data =
        installed::Expected::checked(&foreign_request, fixture.data.source()).unwrap();
    assert_eq!(
        foreign_data.request().ciphertext(),
        fixture.data.request().ciphertext()
    );
    assert_ne!(
        foreign_data.core_expected().binding(),
        fixture.data.core_expected().binding()
    );
    assert!(matches!(
        pending.prove_public(&fixture.owner, &producer, &expected, &foreign_data),
        Err(Error::Binding)
    ));

    // The normal producer receives no caller-built Cw, mask, key or Query witness.
    let began_query = Instant::now();
    let proved = pending
        .prove_public(&fixture.owner, &producer, &expected, &fixture.data)
        .unwrap();
    let prove_ms = began_query.elapsed().as_secs_f64() * 1000.;
    assert_eq!(
        proved.query_expected().statement_root(),
        expected.claims().statement
    );
    let began_product = Instant::now();
    let response = evaluator.evaluate(proved.public_request()).unwrap();
    let product_ms = began_product.elapsed().as_secs_f64() * 1000.;
    let read = public_read_expected(&proved, &expected, &fixture.data, &response);
    let began_receive = Instant::now();
    let checked = public_receive(
        &read,
        &fixture.retained,
        word::read::QueryEvidence {
            word: proved.word(),
            query: proved.query(),
            product: response.certificate(),
        },
    )
    .unwrap();
    let receive_ms = began_receive.elapsed().as_secs_f64() * 1000.;
    let began_complete = Instant::now();
    let completed = proved.complete(&fixture.owner, &checked).unwrap();
    eprintln!(
        "word_sql_public_query from_prepared_original=true native_Word_Query_prove_ms={prove_ms:.3} SDK_product_certificate_ms={product_ms:.3} complete_public_receive_ms={receive_ms:.3} client_decrypt_ms={:.3} total_ms={:.3} Word_bytes={} Query_bytes={} product_bytes={} network=false SQL_accepted=false current_head=false finality=false locks_granted=false security_assessed=false",
        began_complete.elapsed().as_secs_f64() * 1000.,
        began_query.elapsed().as_secs_f64() * 1000.,
        proved.word().len(),
        proved.query().len(),
        response.certificate().len(),
    );

    // Full4096 assertion follows real public Word/Query/DATA/product checking.
    let mut oracle = Zeroizing::new(vec![0; gold::N]);
    for (i, &x) in fixture
        .data_words
        .iter()
        .enumerate()
        .filter(|(_, v)| **v != 0)
    {
        for j in 0..128 {
            let at = (i + j) % gold::N;
            oracle[at] = (oracle[at] + if i + j < gold::N { x } else { gold::T - x }) % gold::T;
        }
    }
    assert_eq!(completed.coefficients(), oracle.as_slice());

    let receiver = word::read::Verifier::new(&read).unwrap();
    let mut bad_query = proved.query().to_vec();
    *bad_query.last_mut().unwrap() ^= 1;
    assert!(
        receiver
            .verify_retained(
                &fixture.retained,
                word::read::QueryEvidence {
                    word: proved.word(),
                    query: &bad_query,
                    product: response.certificate(),
                },
            )
            .is_err()
    );
    assert!(
        receiver
            .verify_retained(
                &fixture.retained,
                word::read::QueryEvidence {
                    word: proved.word(),
                    query: &[],
                    product: response.certificate(),
                },
            )
            .is_err()
    );
    let foreign_read = public_read_expected(&proved, &foreign_expected, &fixture.data, &response);
    assert!(
        word::read::Verifier::new(&foreign_read)
            .unwrap()
            .verify_retained(
                &fixture.retained,
                word::read::QueryEvidence {
                    word: proved.word(),
                    query: proved.query(),
                    product: response.certificate(),
                },
            )
            .is_err()
    );

    // An independently valid receipt for another original query is still wrong.
    let (mut other, other_expected) = pending_sql(&fixture, 0xb2);
    let other_proved = other
        .prove_public(&fixture.owner, &producer, &other_expected, &fixture.data)
        .unwrap();
    let other_response = evaluator.evaluate(other_proved.public_request()).unwrap();
    let other_read = public_read_expected(
        &other_proved,
        &other_expected,
        &fixture.data,
        &other_response,
    );
    let other_checked = public_receive(
        &other_read,
        &fixture.retained,
        word::read::QueryEvidence {
            word: other_proved.word(),
            query: other_proved.query(),
            product: other_response.certificate(),
        },
    )
    .unwrap();
    assert!(proved.complete(&fixture.owner, &other_checked).is_err());
    assert!(
        other_proved
            .complete(&fixture.owner, &other_checked)
            .is_ok()
    );
    drop(other_checked);
    drop(other_proved);
    assert!(matches!(
        other.prove(&fixture.owner, &producer, &other_expected),
        Err(Error::Consumed)
    ));
    drop(checked);
    drop(proved);
    assert!(matches!(
        pending.prove_public(&fixture.owner, &producer, &expected, &fixture.data),
        Err(Error::Consumed)
    ));

    // The owner-private and transferable public routes share one consumption state.
    let (mut private, private_expected) = pending_sql(&fixture, 0xb3);
    drop(
        private
            .prove(&fixture.owner, &producer, &private_expected)
            .unwrap(),
    );
    assert!(matches!(
        private.prove_public(&fixture.owner, &producer, &private_expected, &fixture.data,),
        Err(Error::Consumed)
    ));

    let (mut failed, failed_expected) = pending_sql(&fixture, 0xb4);
    assert!(matches!(
        failed.prove_public_with_entropy(
            &fixture.owner,
            &producer,
            &failed_expected,
            &fixture.data,
            &mut |_| Err(Error::Entropy),
        ),
        Err(Error::Entropy)
    ));
    assert!(matches!(
        failed.prove_public(&fixture.owner, &producer, &failed_expected, &fixture.data),
        Err(Error::Consumed)
    ));

    for (byte, draws) in [(0, 4), (u8::MAX, 8)] {
        let (mut invalid_entropy, intent) = pending_sql(&fixture, 0xc0 + byte % 2);
        let mut calls = 0;
        assert!(matches!(
            invalid_entropy.prove_public_with_entropy(
                &fixture.owner,
                &producer,
                &intent,
                &fixture.data,
                &mut |bytes| {
                    calls += 1;
                    bytes.fill(byte);
                    Ok(())
                },
            ),
            Err(Error::Entropy)
        ));
        assert_eq!(calls, draws);
        assert!(matches!(
            invalid_entropy.prove(&fixture.owner, &producer, &intent),
            Err(Error::Consumed)
        ));
    }

    let foreign_owner = Owner::generate([0xbc; 32], [11; 8]).unwrap();
    let (mut foreign, foreign_owner_expected) = pending_sql(&fixture, 0xb5);
    assert!(
        foreign
            .prove_public(
                &foreign_owner,
                &producer,
                &foreign_owner_expected,
                &fixture.data,
            )
            .is_err()
    );
    assert!(matches!(
        foreign.prove_public(
            &fixture.owner,
            &producer,
            &foreign_owner_expected,
            &fixture.data,
        ),
        Err(Error::Consumed)
    ));
    eprintln!(
        "word_sql_public whole_test_ms={:.3} compiled_SQL=true actual_Source_DATA_Word_fused_Query_product=true full4096_oracle=true owner_private_premise_replaces_public_Query=false network=false SQL_accepted=false current_head=false finality=false locks_granted=false security_assessed=false",
        began.elapsed().as_secs_f64() * 1000.
    );
}
