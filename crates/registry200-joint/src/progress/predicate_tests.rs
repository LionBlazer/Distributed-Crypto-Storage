//! Validated local BFV/proof/application integration; see the README execution record.
//! No network, weighted QC, freshness, durable owner or SQL execution credit.
use super::*;
use bfv_ciphertext_formation::{EncodedCommitment, EncodedOpening, Expected as FormationExpected};
use bfv_mul_relin_proof::{
    Expected as ProductExpected, INPUT_FRAMES, InputEvidence, PROOF_RECORDS, Provenance, Prover,
};
use bfv_product_evidence::RecordingVerifier;
use bfv_query_core::{CoefficientRow, OperandInput, PeerEvaluator, QueryContext};
use bfv_relinearization_key_source::PreparedKey;
use registry200_proof::coefficient_encoding::{
    self as encoding,
    statement::{BfvBinding, Expected as EncodingExpected},
};
use std::{io::Cursor, time::Instant};

#[test]
#[ignore = "Full genuine input16/output118 and new-G Predicate896 application gate; Root runs serial native explicitly"]
fn new_genesis_predicate_records_real_fhe_and_imports_the_exact_original_operation() {
    let started = Instant::now();
    let f = fixture();
    let fixture_ready = started.elapsed();
    let material = &f.material;
    let authority = test_authority();
    let owner =
        Owner::restore_private_state(&f.setup, &material.identity, &authority, &material.owner)
            .unwrap();
    let anchor = owner
        .restore_key_anchor(
            &f.setup,
            &material.anchor,
            &material.identity,
            &authority,
            &material.anchor_record,
        )
        .unwrap();
    let mut epoch = anchor
        .restore_ready_epoch(
            &f.setup,
            &material.key,
            &material.identity,
            &authority,
            &material.ready,
        )
        .unwrap();
    // Ready restore verifies the original Key proof and compares ALL33 against
    // material.key. Each actual Basis below checks that same pinned statement.
    let restored = started.elapsed();

    // Genuine new application/G and owner-signed Bootstrap803 -> Begin815.
    // Every import invokes the fixed closed verifier; native model output never
    // acts as the verifier or supplies a sealed parent/application result.
    let g = genesis(&f.descriptor);
    let a = Application::new(f.descriptor.clone(), &g).unwrap();
    let dir = Directory::new();
    let quota = ParticipantQuota::create_new(dir.root(), [0xb6; 32], 10_000_000_000).unwrap();
    let depot = ProgressDepot::open(quota.depot_budget(), &f.descriptor).unwrap();
    let ingress = depot.ingress();
    let setup_claim = depot.retain_setup(&f.setup).unwrap();
    let verifier = ProgressVerifier::new(f.descriptor.clone(), &g, &setup_claim, depot).unwrap();
    let mut journal = Journal::new(g).unwrap();
    let enroll = enrollment(f, &a);
    let (boot, expected, _) = operation(f, &a, &journal, &ingress, true, enroll, [0; 32]);
    let h = header(&journal, &boot);
    let bytes = boot.encode(journal.profile()).unwrap();
    let (pending, checked) = verifier
        .prepare_import(&mut journal, h, &bytes, 2000, expected)
        .unwrap();
    let bootstrap_root = checked.next_root();
    pending.commit();
    drop(checked);
    let begin_parent = journal.best_validated().block;
    let (begin, expected, begin_manifest) =
        operation(f, &a, &journal, &ingress, false, enroll, bootstrap_root);
    let h = header(&journal, &begin);
    let bytes = begin.encode(journal.profile()).unwrap();
    let (pending, checked) = verifier
        .prepare_import(&mut journal, h, &bytes, 2000, expected)
        .unwrap();
    assert_eq!(checked.next_root(), begin_manifest.next_root());
    pending.commit();
    drop(checked);
    let bank = Zeroizing::new(
        core::circuit::State::default()
            .control(
                &lifecycle::circuit::model::Command::control(
                    lifecycle::circuit::model::Operation::Begin,
                    1,
                    1,
                    0,
                ),
                begin_parent,
            )
            .unwrap(),
    );
    let boot_begin = started.elapsed();

    // Intent q is independently chosen before Source/Copen/Encoding/commands.
    let parent = journal.best_validated().block;
    let nonce = [0xe1; 32];
    let q = intent_query(
        a.source_spec(),
        a.genesis(),
        parent,
        nonce,
        enroll,
        Operation::Transition,
    );
    let mut source = f.source.clone();
    source.request = q;
    source.open_commitment = source::commitment::digest(&source::commitment::opening_fields(
        &source,
        [Val::from_u8(9); 4],
        &f.plain,
    ));
    let canonical = CanonicalSource::checked_claim(&source).unwrap();
    let source_proof = source::prove(
        &canonical,
        &source::circuit::Witness::new(
            [0x71; 32],
            [Val::ONE; 4],
            [Val::from_u8(9); 4],
            [255, 0, 255, 128],
        ),
    )
    .unwrap();
    let binding = BfvBinding::new(material.anchor.full_setup_id(), material.key.clone());
    let source_expected = EncodingExpected::source(&canonical, binding.clone()).unwrap();
    let mut mask = [0; 32];
    mask[16] = 1;
    mask[31] = 0x80; // PUBLIC test mask: ages 128/255.
    let draft = EncodingExpected::private_mask(
        &canonical,
        binding.clone(),
        [0xe2; 32],
        [0xe3; 32],
        [0; 32],
    )
    .unwrap();
    let cmask = encoding::commitment::command_digest(&encoding::commitment::command_fields(
        &draft,
        mask,
        [Val::from_u8(11); 4],
    ));
    let query_expected = EncodingExpected::private_mask(
        &canonical,
        binding,
        [0xe2; 32],
        [0xe3; 32],
        source::statement::encode_digest(cmask),
    )
    .unwrap();
    let witnesses = [
        encoding::circuit::Witness::source(
            &source_expected,
            Zeroizing::new(f.plain.to_vec()),
            [9; 4],
            [10; 4],
        )
        .unwrap(),
        encoding::circuit::Witness::private_mask(
            &query_expected,
            Zeroizing::new(mask),
            [11; 4],
            [12; 4],
        )
        .unwrap(),
    ];
    let mut frames: [Vec<u8>; INPUT_FRAMES] = std::array::from_fn(|_| Vec::new());
    frames[0] = epoch.key_evidence().unwrap().as_bytes().to_vec();
    let statements: [encoding::statement::Statement; 2] = std::array::from_fn(|i| {
        let expected = if i == 0 {
            &source_expected
        } else {
            &query_expected
        };
        let (claim, bytes) = encoding::prove(expected, &witnesses[i], source_proof.as_bytes())
            .unwrap()
            .into_parts();
        frames[1 + i] = bytes;
        claim
    });
    let query = statements[1].clone();
    let encodings = started.elapsed();

    // Prove Core before retaining all input frames/output graph, reducing the
    // simultaneous proof/trace lifetime without skipping any proof boundary.
    let old = begin_manifest.next_root();
    let draft =
        core::transition::Expected::predicate(&query, a.genesis(), parent, enroll, old, [0; 32])
            .unwrap();
    assert_eq!(
        source::statement::encode_digest(
            bank.root(draft.registry_context(), &f.plain, &CONTROLLERS, [7; 4])
                .unwrap()
        ),
        old
    );
    let tx = &bank.registry.transactions[0];
    let hidden = Zeroizing::new(core::circuit::StatementOpening {
        scope: draft.statement_scope(),
        enrollment: source::statement::decode_digest(enroll)
            .unwrap()
            .map(|v| v.as_canonical_u64()),
        client: [0xe4; 32],
        call: 1,
        transaction: tx.id,
        principal: tx.principal,
        controller: CONTROLLERS[0],
        invocation: [0xe5; 32],
        sql_identity: query.expected.sql_identity(),
        snapshot: tx.snapshot,
        mask,
        mode: 4,
        wait: 2,
        offset: 1,
        limit: 1,
        projection: 1,
        salt: [17; 4],
    });
    let mut command = lifecycle::circuit::model::Command::control(
        lifecycle::circuit::model::Operation::Acquire,
        tx.id,
        tx.principal,
        tx.sequence,
    );
    command.mask = mask;
    command.mode = hidden.mode;
    command.wait = hidden.wait;
    command.offset = hidden.offset;
    command.limit = hidden.limit;
    command.projection = hidden.projection;
    let command = Zeroizing::new(command);
    let ccmd = core::transition::command_commitment(
        &draft,
        &command,
        bank.registry.revision,
        &CONTROLLERS,
        [13; 4],
    )
    .unwrap();
    let expected =
        core::transition::Expected::predicate(&query, a.genesis(), parent, enroll, old, ccmd)
            .unwrap();
    let step = Zeroizing::new(
        bank.predicate(&hidden, [255, 0, 255, 128], [16; 4])
            .unwrap(),
    );
    let witness = core::transition::Witness::predicate(
        &expected,
        Zeroizing::new(f.plain),
        Zeroizing::new(CONTROLLERS),
        Zeroizing::new((*bank).clone()),
        Zeroizing::new((*hidden).clone()),
        Zeroizing::new([
            [9; 4], [3; 4], [7; 4], [13; 4], [14; 4], [15; 4], [16; 4], [11; 4],
        ]),
    )
    .unwrap();
    let prerequisites = core::transition::Prerequisites {
        source: source_proof.as_bytes(),
        query: Some(&frames[2]),
    };
    let core_proof = core::transition::prove(&expected, &witness, &prerequisites).unwrap();
    drop(witness);
    let mut damaged = core_proof.as_bytes().to_vec();
    *damaged.last_mut().unwrap() ^= 1;
    assert!(
        core::transition::verify(&expected, core_proof.statement(), &prerequisites, &damaged)
            .is_err()
    );
    drop(damaged);
    let child = ingress.retain_public_blob(core_proof.as_bytes()).unwrap();
    let next = core_proof.statement().next();
    let result = core_proof.statement().result();
    drop(core_proof);
    let core_ready = started.elapsed();

    // Encrypt ALL four original rows, plus the complete private256 mask. Source
    // and Formation prove these exact inputs; no owner filtering/window occurs.
    let rows: [CoefficientRow; 4] = std::array::from_fn(|i| CoefficientRow {
        age: f.plain[3 * i],
        amount: u16::from_le_bytes([f.plain[3 * i + 1], f.plain[3 * i + 2]]),
    });
    let original = owner
        .encrypt_original_coefficient_rows_for_experiment(&rows)
        .unwrap();
    let prepared = owner
        .prepare_private_coefficient_predicate_for_experiment(
            QueryContext::new([0xf0; 16], source.heads[0], source.heads[1]),
            q,
            &original,
            &mask,
        )
        .unwrap();
    drop(original);
    let ciphertexts = prepared.operand_ciphertexts().unwrap();
    for operand in 0..2 {
        let s = &statements[operand];
        let encoded = EncodedCommitment::new(
            s.producer_identity(),
            s.expected.encoding_context().map(|v| v.as_canonical_u64()),
            s.encoded.map(|v| v.as_canonical_u64()),
        )
        .unwrap();
        let mut job = epoch
            .begin_operand(
                q,
                OperandInput {
                    ciphertext: ciphertexts[operand],
                    encoding: encoded.clone(),
                },
            )
            .unwrap();
        let mut bases = Vec::with_capacity(5);
        for basis in 0..5 {
            let proof = job.prove_next_basis().unwrap();
            let checked = f
                .setup
                .verify_basis_convolution(
                    &material.anchor,
                    q,
                    ciphertexts[operand],
                    basis,
                    &frames[0],
                    proof.as_bytes(),
                )
                .unwrap();
            assert_eq!(
                checked.statement().expected.key().public_values(),
                material.key.public_values()
            );
            bases.push(checked.statement().clone());
            frames[3 + 5 * operand + basis] = proof.into_bytes();
        }
        let formation =
            FormationExpected::new(encoded.clone(), bases.try_into().ok().unwrap()).unwrap();
        job.begin_formation(
            EncodedOpening::new(
                witnesses[operand].coefficients(),
                [if operand == 0 { 10 } else { 12 }; 4],
                encoded,
            )
            .unwrap(),
        )
        .unwrap();
        frames[13 + operand] = job
            .prove_formation(
                &formation,
                std::array::from_fn(|i| frames[3 + 5 * operand + i].as_slice()),
            )
            .unwrap()
            .into_bytes();
    }
    drop(epoch);
    drop(anchor);
    drop(witnesses);
    let provenance = Provenance::new(
        f.setup.clone(),
        material.anchor.clone(),
        statements,
        ciphertexts.map(<[u8]>::to_vec),
    )
    .unwrap();
    let inputs = started.elapsed();

    // Actual public-key SDK ciphertext multiplication/relinearization and ALL
    // 118 real proof records. The local Cursor proves local EOF only, not TLS.
    let peer = PeerEvaluator::from_public_setup(&f.setup).unwrap();
    let evaluated = peer
        .evaluate_private_coefficient_predicate_for_experiment(&prepared.request)
        .unwrap();
    assert_eq!(evaluated.ct_ct_multiplications, 1);
    evaluated
        .require_request(&f.setup, &prepared.request)
        .unwrap();
    drop(peer);
    let evaluated_at = started.elapsed();
    let product_expected = ProductExpected::new(
        provenance,
        evaluated.ciphertext_for_experiment().unwrap().to_vec(),
    )
    .unwrap();
    let key = PreparedKey::from_original(&f.setup, material.anchor.full_setup_id()).unwrap();
    let mut prover = Prover::new(&product_expected, &key).unwrap();
    let graph = prover.graph().identity();
    let mut recorder = RecordingVerifier::new_shared(
        ingress.recording_store(),
        &product_expected,
        &key,
        f.descriptor.source_object(),
        &prepared.request,
        &evaluated.output,
    )
    .unwrap();
    let claims = prover
        .graph()
        .claims()
        .encode(bfv_mul_relin_proof::profile_digest());
    recorder.accept_claims(&claims).unwrap();
    drop(claims);
    recorder
        .verify_inputs(&InputEvidence::from_frames(frames.each_ref().map(Vec::as_slice)).unwrap())
        .unwrap();
    drop(frames);
    drop(source_proof); // No raw input proof collection retained during output118 production.
    for ordinal in 0..PROOF_RECORDS {
        let record = prover
            .prove_next()
            .unwrap()
            .expect("all118 actual proof records");
        recorder.accept(&record).unwrap();
        assert_eq!(recorder.progress(), ordinal + 1);
    }
    assert!(prover.prove_next().unwrap().is_none());
    drop(prover);
    let recorded = recorder
        .finish(&[], &mut Cursor::new([]))
        .unwrap()
        .publish()
        .unwrap();
    assert_eq!(recorded.product().identity(), graph);
    let catalog = recorded.catalog();
    drop(recorded);
    drop(key);
    drop(product_expected);
    let recorded_at = started.elapsed();

    let manifest = Manifest::predicate(next, result, catalog, child).unwrap();
    let request = Request::new(
        &a,
        Lane::Predicate,
        InnerRequest {
            operation: Operation::Transition,
            genesis: a.genesis(),
            parent,
            application: a.source_spec().id(),
            nonce,
            query: q,
            enrollment: enroll,
            opening: source::statement::encode_digest(source.open_commitment),
            command: ccmd,
            packets: source.packets.clone(),
        },
    )
    .unwrap();
    let operation = OperationId::new(&a, &request, &manifest).unwrap();
    let b = body(
        &a,
        &request,
        &manifest,
        Control::Active {
            enrollment: enroll,
            registry: old,
        },
    );
    let h = header(&journal, &b);
    let expected_block = h.id();
    let bytes = b.encode(journal.profile()).unwrap();
    // Genuine catalog/child but independent wrong own intent: reject BEFORE
    // another full product traversal, preserving exact owned Journal state.
    let wrong_manifest =
        Manifest::predicate(next, result, catalog, id(b"foreign operation child")).unwrap();
    let wrong = OperationId::new(&a, &request, &wrong_manifest).unwrap();
    let before = journal.best_validated();
    let accounted = journal.accounted_bytes();
    let usage = quota.usage().unwrap();
    assert!(
        verifier
            .prepare_import(&mut journal, h.clone(), &bytes, 2000, wrong)
            .is_err()
    );
    assert_eq!(journal.best_validated(), before);
    assert_eq!(journal.accounted_bytes(), accounted);
    assert_eq!(quota.usage().unwrap(), usage);
    let (pending, checked) = verifier
        .prepare_import(&mut journal, h, &bytes, 2000, operation)
        .unwrap();
    assert_eq!(checked.operation_id(), operation);
    assert_eq!(checked.request(), request.encode().unwrap().as_slice());
    assert_eq!(checked.product().unwrap().product().identity(), graph);
    assert_eq!(
        checked.product().unwrap().encrypted_response(),
        evaluated.output.as_slice()
    );
    assert_eq!(
        checked
            .transition_statement()
            .unwrap()
            .expected()
            .query()
            .unwrap()
            .values(),
        query.values()
    );
    let outcome = pending.commit();
    assert_eq!(outcome.block, expected_block);
    assert_eq!(journal.best_validated().height, 3);

    // Open the actual NEW Result160 only AFTER closed app verification. The
    // existing length160 Poseidon helper is identical primitive mathematics;
    // fields carry Core's NEW Result domain/profile, never Result144 casting.
    let public = checked.transition_statement().unwrap().values();
    assert_eq!(public.len(), core::PREDICATE_VALUES);
    let context: [Val; 100] = public[8 + 772..8 + 772 + 100].try_into().unwrap();
    let fields = step
        .result_fields(
            &context,
            [
                source::statement::decode_digest(old).unwrap(),
                source::statement::decode_digest(next).unwrap(),
                hidden.root().unwrap(),
            ],
            &hidden,
            [[Val::ZERO; 4]; 2],
            [15; 4],
        )
        .unwrap();
    assert_eq!(fields.len(), core::RESULT_FIELDS);
    assert_eq!(
        source::statement::encode_digest(lifecycle::statement::digest(&fields)),
        checked.result_root()
    );
    let opened = core::result_opening::ResultOpening::open(
        checked.transition_step().unwrap(),
        Zeroizing::new(std::array::from_fn(|i| fields[i].as_canonical_u64())),
        &hidden,
        None,
        None,
    )
    .unwrap();
    assert!(opened.status() == core::circuit::Status::Done);
    assert_eq!(opened.selected(), step.selected);
    assert!(
        checked
            .transition_step()
            .unwrap()
            .statement()
            .expected()
            .is_predicate()
    );
    assert!(step.status == core::circuit::Status::Done);
    assert_eq!(step.selected, [false, false, true, false]);
    assert_eq!(
        source::statement::encode_digest(
            step.next
                .root(expected.registry_context(), &f.plain, &CONTROLLERS, [14; 4])
                .unwrap()
        ),
        checked.next_root()
    );
    let rows = owner
        .decrypt_private_coefficient_predicate_unverified_for_experiment(
            prepared.pending,
            checked.product().unwrap().encrypted_response(),
        )
        .unwrap();
    assert_eq!(
        rows.rows
            .iter()
            .map(|r| (r.ordinal, r.present, r.age, r.amount))
            .collect::<Vec<_>>(),
        vec![
            (0, true, 255, 0),
            (1, false, 0, 0),
            (2, true, 255, 256),
            (3, true, 128, 255)
        ]
    );
    // Only proved Result160 flags filter the already decrypted full result.
    // No second WHERE/OFFSET/LIMIT evaluation or owner row computation occurs.
    assert_eq!(
        rows.rows
            .iter()
            .zip(step.selected)
            .filter_map(|(row, selected)| selected.then_some((row.ordinal, row.age, row.amount)))
            .collect::<Vec<_>>(),
        vec![(2, 255, 256)]
    );
    eprintln!(
        "progress_local_gate fixture_ms={} restore_ms={} boot_begin_ms={} source_encoding_ms={} core_ms={} basis_formation_ms={} sdk_product_ms={} product118_record_ms={} final_app_completion_ms={} retained_bytes={}",
        fixture_ready.as_millis(),
        (restored - fixture_ready).as_millis(),
        (boot_begin - restored).as_millis(),
        (encodings - boot_begin).as_millis(),
        (core_ready - encodings).as_millis(),
        (inputs - core_ready).as_millis(),
        (evaluated_at - inputs).as_millis(),
        (recorded_at - evaluated_at).as_millis(),
        (started.elapsed() - recorded_at).as_millis(),
        quota.usage().unwrap().total_bytes()
    );
}
