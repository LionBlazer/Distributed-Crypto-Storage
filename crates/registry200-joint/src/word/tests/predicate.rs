//! Genuine six-proof Predicate mathematics reaches the actual closed journal gate.
use super::*;
use crate::word::predicate::PredicatePacket;
use bfv_ciphertext_formation::gold::{data, query as fused};
use bfv_query_core::gold as protected;
use registry200_proof::two_lane_encoding::{
    self as encoding, data_formation as installed, statement::KeyBinding,
};

struct DataFixture {
    owner: protected::Owner,
    expected: installed::Expected,
    state: Vec<u8>,
    child: Vec<u8>,
    frame: Vec<u8>,
}

fn original_data(f: &Fixture) -> DataFixture {
    let key = |cs| {
        KeyBinding::new(
            f.descriptor.database(),
            [0x73; 16],
            1,
            [0x95; 32],
            source::statement::encode_digest(cs),
        )
        .unwrap()
    };
    let owner = protected::Owner::generate(
        [0x95; 32],
        installed::secret_context(&key([Val::ZERO; 4])).map(|v| v.as_canonical_u64()),
    )
    .unwrap();
    let encoding = encoding::statement::Expected::source_version(
        f.descriptor.source(),
        key(owner.key_expected().root_words().map(Val::from_u64)),
    )
    .unwrap();
    let witness = encoding::circuit::Witness::source_version(
        &encoding,
        Zeroizing::new(f.plain.to_vec()),
        [2; 4],
        [5; 4],
    )
    .unwrap();
    let mut raw = witness.coefficients();
    // Undo only the fixed representation scale of the original input witness.
    // This prepares encryption input; no selected query answer is calculated.
    assert_eq!(protected::SCALE * 41_392 % protected::T, 1);
    raw.iter_mut()
        .for_each(|word| *word = *word * 41_392 % protected::T);
    let original = owner.originate_data(raw).unwrap();
    let request = data::Request::checked([0x61; 32], original.ciphertext().to_vec()).unwrap();
    let expected = installed::Expected::checked(&request, &witness.statement()).unwrap();
    // Only this Predicate fixture creates the separate SHA immutable proofs.
    // Shared Bootstrap/Control fixtures retain their original proof family.
    let state = source::hash::prove(
        f.descriptor.source(),
        &source::circuit::Witness::new(
            [0x71; 32],
            [Val::ONE; 4],
            [Val::TWO; 4],
            [255, 0, 255, 128],
        ),
    )
    .unwrap();
    let child = encoding::hash::prove(&witness.statement(), &witness).unwrap();
    let frame = installed::hash::prove_prepared(
        &expected,
        &request,
        installed::hash::Prerequisites::checked(&state, &child).unwrap(),
        owner
            .prepare_data(&original, expected.core_expected(), Zeroizing::new([5; 4]))
            .unwrap(),
    )
    .unwrap();
    DataFixture {
        owner,
        expected,
        state,
        child,
        frame,
    }
}

fn public_bytes(words: &[u64]) -> [u8; 32] {
    assert_eq!(words.len(), 8);
    core::array::from_fn(|i| u32::try_from(words[i / 4]).unwrap().to_le_bytes()[i % 4])
}

fn evidence(frames: [&[u8]; 6]) -> math::read::Evidence<'_> {
    math::read::Evidence {
        state: frames[0],
        child: frames[1],
        data: frames[2],
        word: frames[3],
        query: frames[4],
        product: frames[5],
    }
}

#[test]
fn genuine_predicate_proofs_reach_closed_journal_admission_without_publishing_a_bank() {
    fn require_send_sync<T: Send + Sync>() {}
    require_send_sync::<Verifier>();
    let began = Instant::now();
    let f = fixture();
    let g = genesis(&f.descriptor);
    let a = Application::new(f.descriptor.clone(), &g).unwrap();
    let verifier = Verifier::new(f.descriptor.clone(), &g, &f.source).unwrap();
    let mut journal = Journal::new(g).unwrap();

    // Establish the actual owner-authorized bootstrap and BEGIN lineage first.
    let (bootstrap, bootstrap_evidence, empty) = boot(f, &a, journal.genesis_head().block);
    let bootstrap_id = OperationId::new(&a, &bootstrap, bootstrap_evidence.as_bytes()).unwrap();
    let (bootstrap_header, bootstrap_body) = candidate(
        &journal,
        &a,
        &bootstrap,
        &bootstrap_evidence,
        Control::Pending,
        &owner(),
    );
    verifier
        .prepare_import(
            &mut journal,
            bootstrap_header.clone(),
            &bootstrap_body,
            200,
            bootstrap_id,
        )
        .unwrap()
        .0
        .commit();
    let (begin, begin_evidence, bank) = begin(f, &a, bootstrap_header.id(), empty);
    let begin_id = OperationId::new(&a, &begin, begin_evidence.as_bytes()).unwrap();
    let (begin_header, begin_body) = candidate(
        &journal,
        &a,
        &begin,
        &begin_evidence,
        Control::Active {
            enrollment: begin.enrollment(),
            registry: begin.claims().old,
        },
        &owner(),
    );
    verifier
        .prepare_import(
            &mut journal,
            begin_header.clone(),
            &begin_body,
            200,
            begin_id,
        )
        .unwrap()
        .0
        .commit();
    let parent = begin_header.id();
    let enrollment = begin.enrollment();
    let old = math::registry_root(&bank.map(|v| v.as_canonical_u64())).unwrap();
    assert_eq!(old, begin.claims().next);

    // Supply only the real old bank. Normal owner recipes produce Next/Result.
    let blind_sql = words(&[0x4e; 32]).try_into().unwrap();
    let draft = math::Expected::checked(
        f.descriptor.source(),
        math::Role::Predicate,
        a.genesis(),
        parent,
        enrollment,
        math::Claims {
            old,
            command: [Val::ZERO; 4],
            statement: [Val::ZERO; 4],
            next: [Val::ZERO; 4],
            result: [Val::ZERO; 4],
            blind_sql,
        },
    )
    .unwrap();
    let mut mask = [0; 32];
    mask[16..].fill(255); // Hidden predicate age>=128.
    let prepared = math::prepare_transition(
        &draft,
        math::TransitionMaterial {
            source: opening(f),
            registry: math::CurrentRegistry::new(
                [
                    words(&[0x41; 32]).try_into().unwrap(),
                    words(&[0x42; 32]).try_into().unwrap(),
                ],
                Zeroizing::new(bank.map(|v| v.as_canonical_u64())),
                Zeroizing::new([7; 4]),
            )
            .unwrap(),
            command: math::CommandInput {
                op: 1,
                actor: Some(0),
                principal: 1,
                id: 1,
                mode: 4,
                wait: 2,
                limit: 1,
                projection: 3,
                ..Default::default()
            },
            walk: math::WalkInput {
                client: words(&[0x47; 32]).try_into().unwrap(),
                call: 1,
                invocation: words(&[0x48; 32]).try_into().unwrap(),
                sql: blind_sql,
                new_salt: [Val::from_u32(9); 4],
                statement_salt: [Val::from_u32(8); 4],
                ..Default::default()
            },
            mask: Zeroizing::new(mask),
            salts: [
                [Val::from_u32(3); 4],
                [Val::from_u32(4); 4],
                [Val::from_u32(5); 4],
            ],
        },
    )
    .unwrap();
    let (expected, inputs, opening) = prepared.into_parts();
    let statement = inputs
        .statement_opening(&expected.statement_domain())
        .unwrap()
        .into_words();
    let (next, result) = opening.into_words();
    assert_eq!(math::registry_root(&next).unwrap(), expected.claims().next);
    assert_eq!(
        math::result_root(&result).unwrap(),
        expected.claims().result
    );
    assert_ne!(expected.claims().next, old);

    let data = original_data(f);
    let original = data
        .owner
        .originate(
            protected::Mask256::new(mask),
            protected::InputBinding::checked(protected::InputScope {
                database: f.descriptor.database(),
                transaction: 1,
                call: 1,
                principal: 1,
                application: math::profile_digest(),
                genesis: a.genesis(),
                rules: math::wire_profile_digest(),
                context: Sha256::digest(expected.binding()).into(),
                parent,
                client: public_bytes(&statement[33..41]),
                controller: public_bytes(&statement[46..54]),
                source_version: f.descriptor.source().version_id(),
                data_admission: Sha256::digest(data.expected.core_expected().binding()).into(),
                snapshot: public_bytes(&statement[70..78]),
                statement: source::statement::encode_digest(expected.claims().statement),
                command: source::statement::encode_digest(expected.claims().command),
                attempt: public_bytes(&statement[54..62]),
                nonce: [0xa9; 32],
            })
            .unwrap(),
            data.expected.core_expected(),
        )
        .unwrap();
    let formation_request = original.public_request().formation_request().unwrap();
    let context = math::read::query::encoding_context(
        &formation_request,
        data.expected.core_expected(),
        expected.claims().statement,
    )
    .unwrap();
    let vector = data
        .owner
        .query_commitment(&original, context.map(|v| v.as_canonical_u64()), &[10; 4])
        .unwrap()
        .map(Val::from_u64);
    let query_expected = math::read::query::expected(
        &formation_request,
        data.expected.core_expected(),
        expected.claims().statement,
        vector,
    )
    .unwrap();
    let query_inputs = data
        .owner
        .prepare_query(
            &original,
            &query_expected,
            statement.clone(),
            Zeroizing::new([10; 4]),
        )
        .unwrap();
    let word = math::hash::Prover::new()
        .unwrap()
        .produce(&expected, inputs)
        .unwrap()
        .into_bytes();
    let query = fused::hash::prove(&query_expected, query_inputs).unwrap();
    let response = protected::Evaluator::new()
        .unwrap()
        .evaluate(original.public_request())
        .unwrap();
    let read = math::read::Expected::checked(
        &expected,
        &data.expected,
        &formation_request,
        vector,
        response.output().to_vec(),
    )
    .unwrap();
    let frames = [
        data.state.as_slice(),
        data.child.as_slice(),
        data.frame.as_slice(),
        word.as_slice(),
        query.as_slice(),
        response.certificate(),
    ];
    let packet =
        PredicatePacket::from_read(&read, original.public_request(), evidence(frames)).unwrap();

    // Actual native mathematical success is separate from the admission guard.
    let math_started = Instant::now();
    verifier
        .check_predicate_relation(&expected, packet.as_bytes())
        .unwrap();
    let checked_ms = math_started.elapsed().as_secs_f64() * 1000.;
    // The SAME original immutable proofs are retained; all three per-query
    // native checks still run for this re-verification of the same candidate.
    let repeated = Instant::now();
    verifier
        .check_predicate_relation(&expected, packet.as_bytes())
        .unwrap();
    let repeated_ms = repeated.elapsed().as_secs_f64() * 1000.;
    let request =
        Request::predicate(&a, parent, [0xb1; 32], enrollment, expected.claims()).unwrap();
    let proof = Evidence::predicate(&packet).unwrap();
    let id = OperationId::new(&a, &request, proof.as_bytes()).unwrap();
    let before = Control::Active {
        enrollment,
        registry: old,
    };
    let (header, body) = candidate(&journal, &a, &request, &proof, before, &owner());
    let count = journal.header_count();
    let floor = journal.ancestry_floor();
    assert!(matches!(
        verifier.check_block(&journal, &header, &body, 200, id),
        Err(Error::RejectedComputationProof)
    ));
    assert!(matches!(
        verifier.prepare_import(&mut journal, header.clone(), &body, 200, id),
        Err(Error::RejectedComputationProof)
    ));
    assert_eq!(journal.header_count(), count);
    assert_eq!(journal.ancestry_floor(), floor);

    let foreign_owner = SigningKey::from_bytes(&[0x82; 32]);
    let (unauthorized_header, unauthorized_body) =
        candidate(&journal, &a, &request, &proof, before, &foreign_owner);
    assert!(matches!(
        verifier.check_block(&journal, &unauthorized_header, &unauthorized_body, 200, id),
        Err(Error::Unauthorized)
    ));
    let foreign_intent =
        Request::predicate(&a, parent, [0xb2; 32], enrollment, expected.claims()).unwrap();
    let foreign_id = OperationId::new(&a, &foreign_intent, proof.as_bytes()).unwrap();
    assert!(matches!(
        verifier.check_block(&journal, &header, &body, 200, foreign_id),
        Err(Error::WrongDomain)
    ));
    for stale_parent in [false, true] {
        let mut claims = expected.claims();
        if !stale_parent {
            claims.old[0] += Val::ONE;
        }
        let altered = Request::predicate(
            &a,
            if stale_parent {
                bootstrap_header.id()
            } else {
                parent
            },
            [0xb3; 32],
            enrollment,
            claims,
        )
        .unwrap();
        let altered_id = OperationId::new(&a, &altered, proof.as_bytes()).unwrap();
        // Keep the real outer parent and old heads, so the common verifier
        // must reject the foreign request association after Journal checks.
        let mut altered_body = Body::decode(&body, journal.profile()).unwrap();
        let Body::Transition(transition) = &mut altered_body else {
            panic!("expected original signed transition")
        };
        transition.request = altered.encode();
        transition.sign(a.genesis(), &owner());
        let mut altered_header = journal
            .candidate(parent, &altered_body, header.timestamp)
            .unwrap();
        altered_header.mine(4).unwrap();
        let altered_body = altered_body.encode(journal.profile()).unwrap();
        assert!(
            verifier
                .check_block(&journal, &altered_header, &altered_body, 200, altered_id)
                .is_err()
        );
    }

    // Complete metadata stays valid; each real native proof is independently required.
    for changed in 0..frames.len() {
        let mut damaged = frames[changed].to_vec();
        *damaged.last_mut().unwrap() ^= 1;
        let mut changed_frames = frames;
        changed_frames[changed] = &damaged;
        let bad =
            PredicatePacket::from_read(&read, original.public_request(), evidence(changed_frames))
                .unwrap();
        assert!(
            verifier
                .check_predicate_relation(&expected, bad.as_bytes())
                .is_err(),
            "damaged proof {changed}"
        );
        if changed == 4 {
            let bad_proof = Evidence::predicate(&bad).unwrap();
            let bad_id = OperationId::new(&a, &request, bad_proof.as_bytes()).unwrap();
            let (bad_header, bad_body) =
                candidate(&journal, &a, &request, &bad_proof, before, &owner());
            assert!(matches!(
                verifier.check_block(&journal, &bad_header, &bad_body, 200, bad_id),
                Err(Error::RejectedComputationProof)
            ));
        }
    }
    // The old Source theorem retained for Bootstrap/Control cannot replace the
    // distinct SHA State argument required by this five-AIR Predicate family.
    let mut mixed_frames = frames;
    mixed_frames[0] = &f.source;
    let mixed =
        PredicatePacket::from_read(&read, original.public_request(), evidence(mixed_frames))
            .unwrap();
    assert!(
        verifier
            .check_predicate_relation(&expected, mixed.as_bytes())
            .is_err()
    );
    // Neither a bad immutable frame nor a bad per-query proof can poison or
    // replace the retained valid theorem. The genuine candidate remains usable.
    let after_damage = Instant::now();
    verifier
        .check_predicate_relation(&expected, packet.as_bytes())
        .unwrap();
    let after_damage_ms = after_damage.elapsed().as_secs_f64() * 1000.;
    // A fresh encryption of the SAME private statement has different QueryCt,
    // vector, request nonce and product. Only its immutable DATA is reusable.
    let fresh = data
        .owner
        .originate(
            protected::Mask256::new(mask),
            original.public_request().binding().clone(),
            data.expected.core_expected(),
        )
        .unwrap();
    let fresh_request = fresh.public_request().formation_request().unwrap();
    assert_ne!(fresh_request.nonce(), formation_request.nonce());
    assert_ne!(
        fresh.public_request().as_bytes(),
        original.public_request().as_bytes()
    );
    let fresh_context = math::read::query::encoding_context(
        &fresh_request,
        data.expected.core_expected(),
        expected.claims().statement,
    )
    .unwrap();
    let fresh_vector = data
        .owner
        .query_commitment(
            &fresh,
            fresh_context.map(|v| v.as_canonical_u64()),
            &[11; 4],
        )
        .unwrap()
        .map(Val::from_u64);
    let fresh_query_expected = math::read::query::expected(
        &fresh_request,
        data.expected.core_expected(),
        expected.claims().statement,
        fresh_vector,
    )
    .unwrap();
    let fresh_query = fused::hash::prove(
        &fresh_query_expected,
        data.owner
            .prepare_query(
                &fresh,
                &fresh_query_expected,
                statement,
                Zeroizing::new([11; 4]),
            )
            .unwrap(),
    )
    .unwrap();
    let fresh_product = protected::Evaluator::new()
        .unwrap()
        .evaluate(fresh.public_request())
        .unwrap();
    let fresh_read = math::read::Expected::checked(
        &expected,
        &data.expected,
        &fresh_request,
        fresh_vector,
        fresh_product.output().to_vec(),
    )
    .unwrap();
    let fresh_frames = [
        frames[0],
        frames[1],
        frames[2],
        frames[3],
        fresh_query.as_slice(),
        fresh_product.certificate(),
    ];
    let fresh_packet =
        PredicatePacket::from_read(&fresh_read, fresh.public_request(), evidence(fresh_frames))
            .unwrap();
    let fresh_started = Instant::now();
    verifier
        .check_predicate_relation(&expected, fresh_packet.as_bytes())
        .unwrap();
    let fresh_ms = fresh_started.elapsed().as_secs_f64() * 1000.;
    // An old Query proof cannot satisfy this genuinely different expectation.
    let mut old_query = fresh_frames;
    old_query[4] = frames[4];
    let foreign_query =
        PredicatePacket::from_read(&fresh_read, fresh.public_request(), evidence(old_query))
            .unwrap();
    assert!(
        verifier
            .check_predicate_relation(&expected, foreign_query.as_bytes())
            .is_err()
    );
    verifier
        .check_predicate_relation(&expected, fresh_packet.as_bytes())
        .unwrap();
    assert_eq!(journal.header_count(), count);
    assert_eq!(journal.ancestry_floor(), floor);
    assert_eq!(
        math::registry_root(&bank.map(|v| v.as_canonical_u64())).unwrap(),
        old
    );
    eprintln!(
        "word_journal_predicate full_native_six_proofs_ms={checked_ms:.3} same_candidate_reverification_ms={repeated_ms:.3} after_damage_reverification_ms={after_damage_ms:.3} fresh_encryption_receive_ms={fresh_ms:.3} whole_test_ms={:.3} original_bootstrap_BEGIN_parent=true original_registry=true owner_header=true actual_FHE=true all6_initial_native=true immutable_evidence_exact=true fresh_Word_Query_product=true joint_admission=false SQL_accepted=false current_head=false finality=false locks_granted=false security_assessed=false",
        began.elapsed().as_secs_f64() * 1000.
    );
}
