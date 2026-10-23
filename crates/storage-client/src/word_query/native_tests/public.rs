//! Genuine public proofs from compiled SQL; plaintext fixtures are assertions only.
use super::*;
use registry200_joint::word::predicate::BorrowedPredicate;

fn pending_sql(fixture: &HashInstalledFixture, nonce: u8) -> (PendingQuery, word::Expected) {
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
    retained: &installed::hash::CheckedData,
    evidence: word::read::QueryEvidence<'_>,
) -> word::read::hash::Result<word::read::hash::ArithmeticCheckedRead<'a>> {
    word::read::hash::Verifier::new(expected)?.verify_retained(retained, evidence)
}

#[test]
fn compiled_sql_public_proofs_bind_original_data_before_completion_and_share_single_use() {
    let began = Instant::now();
    let fixture = hash_installed_fixture();
    let producer = word::hash::Prover::new().unwrap();
    let private_producer = word::Prover::new(word::Role::Predicate).unwrap();
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
        pending.prepare_public(&fixture.owner, &foreign_expected, &fixture.data),
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

    // The timer includes guarded public preparation, the genuine SDK product,
    // both fresh proofs, independent public setup/checking and bound decryption.
    let began_query = Instant::now();
    let prepared = pending
        .prepare_public(&fixture.owner, &expected, &fixture.data)
        .unwrap();
    let preparation_ms = began_query.elapsed().as_secs_f64() * 1000.;
    assert_eq!(
        prepared.query_expected().statement_root(),
        expected.claims().statement
    );
    let began_product = Instant::now();
    let response = evaluator.evaluate(prepared.public_request()).unwrap();
    let product_ms = began_product.elapsed().as_secs_f64() * 1000.;
    let read = word::read::Expected::checked(
        &expected,
        &fixture.data,
        &prepared.public_request().formation_request().unwrap(),
        prepared.query_expected().core_expected().roots()[0],
        response.output().to_vec(),
    )
    .unwrap();
    assert_eq!(
        read.query_expected().binding(),
        prepared.query_expected().binding()
    );

    // Only independent PUBLIC receiving preparation runs beside native proving.
    // No proof or verification verdict exists when this setup starts. The same
    // shared Rayon budget handles both; the protected producer stays local.
    let (proved, receiver, setup_ms, prove_ms, setup_proving_wall_ms) =
        std::thread::scope(|scope| {
            let began_overlap = Instant::now();
            let receiving = scope.spawn(|| {
                let began_setup = Instant::now();
                let verifier = word::read::hash::Verifier::new(&read).unwrap();
                (verifier, began_setup.elapsed().as_secs_f64() * 1000.)
            });
            let began_prove = Instant::now();
            let proved = prepared.prove(&producer).unwrap();
            let prove_ms = began_prove.elapsed().as_secs_f64() * 1000.;
            let (receiver, setup_ms) = receiving.join().unwrap();
            (
                proved,
                receiver,
                setup_ms,
                prove_ms,
                began_overlap.elapsed().as_secs_f64() * 1000.,
            )
        });
    let overlap_lower_bound_ms = (setup_ms + prove_ms - setup_proving_wall_ms).max(0.);
    let receiving_setup_overlapped = overlap_lower_bound_ms > 0.;
    let began_receive = Instant::now();
    let checked = receiver
        .verify_retained(
            &fixture.retained,
            word::read::QueryEvidence {
                word: proved.word(),
                query: proved.query(),
                product: response.certificate(),
            },
        )
        .unwrap();
    let receive_ms = began_receive.elapsed().as_secs_f64() * 1000.;
    drop(receiver);
    let began_complete = Instant::now();
    let completed = proved.complete(&fixture.owner, &checked).unwrap();
    eprintln!(
        "word_sql_public_query from_prepared_original=true public_preparation_ms={preparation_ms:.3} native_Word_Query_prove_ms={prove_ms:.3} SDK_product_certificate_ms={product_ms:.3} receiving_setup_ms={setup_ms:.3} public_setup_proving_wall_ms={setup_proving_wall_ms:.3} public_setup_overlap_lower_bound_ms={overlap_lower_bound_ms:.3} fresh_public_receive_ms={receive_ms:.3} receiving_setup_overlapped={receiving_setup_overlapped} client_decrypt_ms={:.3} total_ms={:.3} Word_bytes={} Query_bytes={} product_bytes={} network=false SQL_accepted=false current_head=false finality=false locks_granted=false security_assessed=false",
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

    // A remote verifier reconstructs all endpoints from bounded public bytes
    // and its OWN immutable Source; no local verified theorem is serialized.
    let began_packet = Instant::now();
    let packet = proved
        .packet(
            &read,
            ImmutableEvidence {
                state: &fixture.state_proof,
                child: &fixture.child_proof,
                data: &fixture.data_proof,
            },
            response.certificate(),
        )
        .unwrap();
    let parsed = BorrowedPredicate::parse(&fixture.source, packet.as_bytes()).unwrap();
    let reconstructed = parsed.expected(&expected).unwrap();
    assert_eq!(
        reconstructed.data_expected().core_expected().binding(),
        fixture.data.core_expected().binding()
    );
    assert_eq!(
        reconstructed.query_expected().binding(),
        proved.query_expected().binding()
    );
    let (packet_checked, _) = word::read::hash::Verifier::new(&reconstructed)
        .unwrap()
        .verify_and_retain(parsed.evidence())
        .unwrap();
    assert_eq!(
        proved
            .complete(&fixture.owner, &packet_checked)
            .unwrap()
            .coefficients(),
        oracle.as_slice()
    );
    eprintln!(
        "word_predicate_packet bytes={} encode_parse_all6_receive_decrypt_ms={:.3} complete_original_Source=true actual_native_all6=true network=false SQL=false freshness=false locks=false security_assessed=false",
        packet.as_bytes().len(),
        began_packet.elapsed().as_secs_f64() * 1000.,
    );
    assert!(parsed.expected(&foreign_expected).is_err());
    let claim = fixture.source.statement();
    let images: [Vec<u8>; 2] = core::array::from_fn(|i| {
        let mut image = claim.heads[i].to_vec();
        image.extend_from_slice(&claim.packets[i]);
        image
    });
    let heads = claim
        .heads
        .map(|head| compact_store::Commitment::decode(&head, source::statement::limits()).unwrap());
    let foreign_source = source::version::SourceVersionExpected::checked(
        [&images[0], &images[1]],
        [&heads[0], &heads[1]],
        encode_digest(claim.key_commitment),
        encode_digest([Val::ONE; 4]),
    )
    .unwrap();
    assert_eq!(foreign_source.version_id(), fixture.source.version_id());
    assert!(BorrowedPredicate::parse(&foreign_source, packet.as_bytes()).is_err());
    assert!(
        proved
            .packet(
                &read,
                ImmutableEvidence {
                    state: &[],
                    child: &fixture.child_proof,
                    data: &fixture.data_proof,
                },
                response.certificate(),
            )
            .is_err()
    );
    assert!(matches!(
        proved.packet(
            &public_read_expected(&proved, &foreign_expected, &fixture.data, &response),
            ImmutableEvidence {
                state: &fixture.state_proof,
                child: &fixture.child_proof,
                data: &fixture.data_proof,
            },
            response.certificate(),
        ),
        Err(Error::Binding)
    ));
    let mut legacy = packet.as_bytes().to_vec();
    legacy[..8].copy_from_slice(b"DCSWJP01");
    assert!(BorrowedPredicate::parse(&fixture.source, &legacy).is_err());
    for length in [0, 7, 415, packet.as_bytes().len() - 1] {
        assert!(BorrowedPredicate::parse(&fixture.source, &packet.as_bytes()[..length]).is_err());
    }
    for at in [0, 7, 8, 39, 40, 47, 408, 415] {
        let mut damaged = packet.as_bytes().to_vec();
        damaged[at] ^= 1;
        assert!(BorrowedPredicate::parse(&fixture.source, &damaged).is_err());
    }
    for component in 0..8 {
        let mut damaged = packet.as_bytes().to_vec();
        damaged[376 + 4 * component..380 + 4 * component].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(BorrowedPredicate::parse(&fixture.source, &damaged).is_err());
    }
    for at in [80, 112, 144, 152, 216, 280, 312, 344, 352, 360, 368] {
        let mut damaged = packet.as_bytes().to_vec();
        damaged[at..at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(BorrowedPredicate::parse(&fixture.source, &damaged).is_err());
    }
    for at in [344, 352, 360, 368] {
        let mut damaged = packet.as_bytes().to_vec();
        damaged[at..at + 8].copy_from_slice(&Val::ORDER_U64.to_le_bytes());
        assert!(BorrowedPredicate::parse(&fixture.source, &damaged).is_err());
    }
    // A canonical changed Cw cannot retain the original complete DATA binding.
    let mut changed_cw = packet.as_bytes().to_vec();
    let cw = u64::from_le_bytes(changed_cw[344..352].try_into().unwrap());
    changed_cw[344..352].copy_from_slice(&((cw + 1) % Val::ORDER_U64).to_le_bytes());
    assert!(BorrowedPredicate::parse(&fixture.source, &changed_cw).is_err());
    let mut trailing = packet.as_bytes().to_vec();
    trailing.push(0);
    assert!(BorrowedPredicate::parse(&fixture.source, &trailing).is_err());
    let lengths: Vec<_> = packet.as_bytes()[376..408]
        .as_chunks::<4>()
        .0
        .iter()
        .map(|n| u32::from_le_bytes(*n) as usize)
        .collect();
    let mut end = 416 + lengths[0] + lengths[1];
    for (component, length) in lengths[2..].iter().enumerate() {
        end += *length;
        let mut damaged = packet.as_bytes().to_vec();
        damaged[end - 1] ^= 1;
        let parsed = BorrowedPredicate::parse(&fixture.source, &damaged).unwrap();
        let e = parsed.expected(&expected).unwrap();
        assert!(
            word::read::hash::Verifier::new(&e)
                .unwrap()
                .verify_and_retain(parsed.evidence())
                .is_err(),
            "damaged complete proof {component}"
        );
    }

    let receiver = word::read::hash::Verifier::new(&read).unwrap();
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
        word::read::hash::Verifier::new(&foreign_read)
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
        other.prove(&fixture.owner, &private_producer, &other_expected),
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
    let private_proved = private
        .prove(&fixture.owner, &private_producer, &private_expected)
        .unwrap();
    // Genuine old-family mathematics is not SHA evidence. Packaging it grants
    // no compatibility route, even with otherwise original SHA endpoints.
    drop(word::verify(&private_expected, private_proved.word()).unwrap());
    let mixed_packet = registry200_joint::word::predicate::PredicatePacket::from_read(
        &read,
        parsed.public_request(),
        word::read::Evidence {
            word: private_proved.word(),
            ..parsed.evidence()
        },
    )
    .unwrap();
    let mixed = BorrowedPredicate::parse(&fixture.source, mixed_packet.as_bytes()).unwrap();
    assert!(matches!(
        receiver.verify_retained(&fixture.retained, mixed.evidence().query()),
        Err(word::read::hash::Error::Word(word::Error::Encoding))
    ));
    assert!(
        receiver
            .verify_retained(&fixture.retained, parsed.evidence().query())
            .is_ok()
    );
    drop(private_proved);
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
            invalid_entropy.prove(&fixture.owner, &private_producer, &intent),
            Err(Error::Consumed)
        ));
    }

    // Abandoning a prepared query cannot release its protected witnesses for
    // either public or private retry, even though no native proof was produced.
    let (mut abandoned, abandoned_expected) = pending_sql(&fixture, 0xb6);
    drop(
        abandoned
            .prepare_public(&fixture.owner, &abandoned_expected, &fixture.data)
            .unwrap(),
    );
    assert!(matches!(
        abandoned.prepare_public(&fixture.owner, &abandoned_expected, &fixture.data),
        Err(Error::Consumed)
    ));
    assert!(matches!(
        abandoned.prove(&fixture.owner, &private_producer, &abandoned_expected),
        Err(Error::Consumed)
    ));

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
