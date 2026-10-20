//! Actual owning lifecycle on four OS validators and a separate OS FHE peer.
//! Exercises the owned recovery API and typed Bootstrap producer.
//! The shared fixture defines public configuration and signs owner Bodies only;
//! every Registry opening below comes from an actual typed operation completion.
//! No filesystem restart, Vault CAS, SQL capability or current lease is asserted.
use super::super::full_acquire_fixture as fixture;
use super::*;
use crate::private_predicate::{
    CompletedJointControl, EncryptedJointRecovery, JointControlIntent, JointControlOutcome,
    JointControlParent, JointEndDisposition, JointOwnedRecovery, JointRecoveryIdentity,
    JointRecoveryInputs, JointRecoveryKey, PreparedJointControl,
    RecoverableJointLockingPreparation,
};

fn fresh<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    getrandom::getrandom(&mut bytes).expect("Actual owner-local OS randomness required");
    bytes
}

fn phase(started: Instant, name: &str) {
    println!(
        "Joint typed lifecycle phase finished: {name} ({:.1} ms)",
        started.elapsed().as_secs_f64() * 1000.
    );
}

// Concrete network control operation, not a local QC builder or supplied verifier.
fn control_operation(
    prepared: PreparedJointControl,
    binding: &JointBinding,
    history: &mut JointHistory,
    ingress: &JointEvidenceIngress,
    clients: &[JointFinalityClient],
    previous: &(registry200_finality::CandidateBlock, JointCheckpoint),
    started: Instant,
) -> (
    CompletedJointControl,
    registry200_finality::CandidateBlock,
    JointCheckpoint,
) {
    let before = history.checked_parent().unwrap().unwrap().clone();
    let context = history.context().unwrap().id();
    let (request, life, kind, candidate) = prepared.into_parts();
    let next = registry200_proof::source::statement::encode_digest(life.statement().next);
    let result = registry200_proof::source::statement::encode_digest(life.statement().result);
    let pair = ingress.retain_public_blob(life.as_bytes()).unwrap();
    let kind_id = ingress.retain_public_blob(kind.as_bytes()).unwrap();
    let expected = candidate
        .expectation(Manifest::control(next, result, pair, kind_id).unwrap())
        .unwrap();
    drop(life);
    drop(kind);
    let block = fixture::transition(
        binding,
        before.head(),
        request,
        Manifest::control(next, result, pair, kind_id).unwrap(),
        before.control(),
    );
    // A real earlier OS QC cannot fulfill this independently retained own intent.
    assert!(
        history
            .apply_control(&previous.1, &previous.0, &expected)
            .is_err(),
        "Earlier genuine QC must fail before importing this control operation"
    );
    assert_eq!(
        history.checked_parent().unwrap().unwrap().head(),
        before.head()
    );
    assert_eq!(history.context().unwrap().id(), context);
    for client in clients {
        upload_manifest(client, &block, ingress, binding);
    }
    submit_to_all_validators(clients, &block, started);
    let qcs: Vec<_> = clients
        .iter()
        .map(|client| checkpoint(client, before.slot(), &block))
        .collect();
    let fetched = clients[0].candidate_block(block.header().id()).unwrap();
    assert_eq!(fetched.encode(), block.encode());
    let operation = history.apply_control(&qcs[0], &fetched, &expected).unwrap();
    assert_eq!(operation.request_bytes(), expected.request_bytes());
    assert_eq!(operation.body_bytes(), fetched.body());
    assert_eq!(operation.checkpoint_bytes(), qcs[0].encode());
    let completed = candidate.complete(operation).unwrap();
    (completed, fetched, qcs.into_iter().next().unwrap())
}

#[test]
#[ignore = "Actual typed Bootstrap/Begin/recoverable Acquire/End, four OS validators and separate OS FHE peer; requires DCS_PEER_EXE"]
fn four_os_typed_lifecycle_restores_owned_acquire_and_closes_only_its_exact_registry_transaction() {
    let exe = PathBuf::from(
        std::env::var_os("DCS_PEER_EXE")
            .expect("DCS_PEER_EXE must name the actual built dcs-peer binary"),
    );
    assert!(
        exe.is_absolute() && exe.is_file(),
        "Actual OS binary is mandatory"
    );
    let started = Instant::now();
    let directory = fixture::Directory::new();
    let owner_identity = fixture::identity();
    let (storage, remote) = source_peer(&exe, &directory, &owner_identity);
    let storage_pid = storage.pid();

    // Arrange real canonical storage. These PUBLIC NONSECRET rows are only the
    // ingest data and final test oracle, never an owner-selected FHE answer.
    let source_owner =
        SourceOwner::new([0x21; 16], [0x42; 16], Zeroizing::new([0x63; 32])).unwrap();
    let table = source_owner
        .seal_partition(
            &TableId::from_bytes([0x19; 32]).unwrap(),
            &[
                PlainRow {
                    age: 0,
                    amount: 65535,
                },
                PlainRow { age: 1, amount: 0 },
                PlainRow {
                    age: 128,
                    amount: 255,
                },
                PlainRow {
                    age: 255,
                    amount: 65534,
                },
            ],
            RowIds::generate(4).unwrap(),
        )
        .unwrap();
    let heads = table.read_heads();
    let bundle = RawBundle::from_snapshots(table.snapshot(), table.encrypted_index()).unwrap();
    let object = *bundle.target_version().unwrap().object();
    assert!(
        matches!(remote.call(Request::Store(bundle)).unwrap(), Response::Stored(info) if info.id == object)
    );
    drop(table);
    let Response::RawBundle(bundle) = remote.call(Request::Fetch { object }).unwrap() else {
        panic!("Actual fetched canonical source required")
    };

    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let handle = owner
        .key_anchor(
            &setup,
            KeyScope {
                database: [0x21; 16],
                bfv_key_domain: [0x88; 16],
                epoch: 1,
            },
        )
        .unwrap();
    let anchor = handle.public_anchor().clone();
    let mut epoch = handle.proof_epoch(&setup).unwrap();
    epoch.prove_key().unwrap();
    let quota = ParticipantQuota::create_new(
        directory.path("owner-evidence"),
        NAMESPACE,
        fixture::CAPACITY,
    )
    .unwrap();
    let (binding, key_values) = {
        let checked_key = setup
            .verify_key_transform(&anchor, epoch.key_evidence().unwrap().as_bytes())
            .unwrap();
        let loaded = source_owner
            .load(crate::private_predicate::FetchedSource {
                object,
                bundle: &bundle,
                heads: &heads,
            })
            .unwrap();
        (
            fixture::binding(
                &loaded,
                &setup,
                &anchor,
                checked_key.statement(),
                object,
                &quota,
            ),
            checked_key.statement().public_values(),
        )
    };
    // ONE original byte vector is supplied to all five actual children. The
    // Descriptor independently binds its full digest, anchor and ALL33 Key PVs.
    let original_setup = setup.to_bytes().unwrap();
    let (validators, clients) =
        start_validators(&exe, &directory, &binding, &owner_identity, &original_setup);
    let validator_pids: Vec<_> = validators.iter().map(os_process::Process::pid).collect();
    assert!(matches!(
        remote.call(Request::InstallSetup(original_setup)).unwrap(),
        Response::Setup(_)
    ));

    // Act 1: only the live checked Pending factory may start Registry Bootstrap.
    let depot = JointDepot::open(quota.depot_budget()).unwrap();
    let ingress = depot.ingress();
    let mut history = JointHistory::new(binding.clone(), depot).unwrap();
    let bootstrap_parent = history.bootstrap_parent().unwrap();
    let bootstrap_nonce = fresh();
    let prepared = source_owner
        .prepare_joint_bootstrap(
            crate::private_predicate::FetchedSource {
                object,
                bundle: &bundle,
                heads: &heads,
            },
            &binding,
            &bootstrap_parent,
            Zeroizing::new(fixture::CONTROLLERS),
            bootstrap_nonce,
        )
        .unwrap();
    let (request, life, candidate) = prepared.into_parts();
    let next = registry200_proof::source::statement::encode_digest(life.statement().next);
    let pair = ingress.retain_public_blob(life.as_bytes()).unwrap();
    let expected = candidate
        .expectation(Manifest::bootstrap(next, pair).unwrap())
        .unwrap();
    drop(life);
    let bootstrap_block = fixture::transition(
        &binding,
        bootstrap_parent.head(),
        request,
        Manifest::bootstrap(next, pair).unwrap(),
        registry200_journal::Control::Pending,
    );
    for client in &clients {
        upload_manifest(client, &bootstrap_block, &ingress, &binding);
    }
    submit_to_all_validators(&clients, &bootstrap_block, started);
    let qcs: Vec<_> = clients
        .iter()
        .map(|client| checkpoint(client, bootstrap_parent.slot() - 1, &bootstrap_block))
        .collect();
    let fetched = clients[0]
        .candidate_block(bootstrap_block.header().id())
        .unwrap();
    assert_eq!(fetched.encode(), bootstrap_block.encode());
    let operation = history
        .apply_bootstrap(&qcs[0], &fetched, &expected)
        .unwrap();
    assert_eq!(operation.request_bytes(), expected.request_bytes());
    assert_eq!(operation.body_bytes(), fetched.body());
    assert_eq!(operation.checkpoint_bytes(), qcs[0].encode());
    let opening = candidate.complete(operation).unwrap().into_opening();
    let bootstrap = (fetched, qcs.into_iter().next().unwrap());
    assert!(
        history.bootstrap_parent().is_err(),
        "Actual Active parent is not Pending"
    );
    phase(
        started,
        "typed Bootstrap Source/Life, four-OS QC and owner opening",
    );

    // Act 2: consume ONLY the completed Bootstrap opening, not fixture state.
    let control_parent = JointControlParent::from_verified(
        history.checked_parent().unwrap().unwrap(),
        &binding,
        history.context().unwrap(),
    )
    .unwrap();
    let begin_nonce = fresh();
    let prepared = source_owner
        .prepare_joint_control(
            crate::private_predicate::FetchedSource {
                object,
                bundle: &bundle,
                heads: &heads,
            },
            &control_parent,
            opening,
            JointControlIntent::begin(1, 1, begin_nonce).unwrap(),
        )
        .unwrap();
    let (completed, begin_block, begin_qc) = control_operation(
        prepared,
        &binding,
        &mut history,
        &ingress,
        &clients,
        &bootstrap,
        started,
    );
    let begin_outcome = completed.outcome();
    let opening = completed.into_opening();
    phase(
        started,
        "typed Begin Source/Life/Kind, four-OS QC and owner opening",
    );
    let sealed_parent = history.checked_parent().unwrap().unwrap().clone();
    let current = history.context().unwrap().clone();
    let control_parent =
        JointControlParent::from_verified(&sealed_parent, &binding, &current).unwrap();
    let recovery_parent = JointLockingParent::from_verified(
        &sealed_parent,
        &binding,
        context(&owner, &setup, &anchor),
        &epoch,
    )
    .unwrap();
    let owned = opening.for_acquire(&control_parent, 1, 1).unwrap();
    drop(history);
    drop(ingress);

    // Act 3: ALL originals and the encrypted truth table are formed by the real
    // producer. Each local identity/nonce is fresh once, then preserved exactly.
    let compiled = CompiledLockingSelect::compile(
        "SELECT age, amount FROM records WHERE age IN (0,255) LIMIT 1 OFFSET 1 FOR UPDATE SKIP LOCKED",
        Zeroizing::new(fresh()), fresh(), fresh(),
    )
    .unwrap();
    let identity = JointRecoveryIdentity::new(fresh());
    let wrapping = JointRecoveryKey::new(Zeroizing::new(fresh()));
    let RecoverableJointLockingPreparation::Prepared(recoverable) = source_owner
        .prepare_joint_locking_owned_recoverable(
            context(&owner, &setup, &anchor),
            &mut epoch,
            crate::private_predicate::FetchedSource {
                object,
                bundle: &bundle,
                heads: &heads,
            },
            &compiled,
            owned,
            JointOwnedRecovery::new(&control_parent, &identity, &wrapping),
        )
        .unwrap()
    else {
        panic!("Uncontended actual Registry must prepare the owned Acquire")
    };
    let (prepared, record) = recoverable.into_parts();
    let (inputs, life, link, outer, original_candidates) = prepared.into_parts();
    let (provenance, mut original_pending, frames) = inputs.into_parts();
    assert_eq!(key_values.len(), 33);
    assert_eq!(
        provenance.original_setup_digest(),
        binding.application_descriptor().full_setup_digest()
    );
    assert_eq!(
        provenance.anchor().encode_claim().unwrap(),
        anchor.encode_claim().unwrap()
    );
    for encoding in provenance.encodings() {
        assert_eq!(encoding.expected.bfv().key().public_values(), key_values);
    }
    assert_eq!(provenance.query(), outer.inner().query);
    let exact_request = core::mem::take(&mut original_pending.request);
    let original_claim = provenance.encode_claim().unwrap();
    drop(original_pending);
    drop(original_candidates);
    drop(compiled);
    let capsule = EncryptedJointRecovery::from_bytes(record.as_bytes()).unwrap();
    drop(record);
    let public = || JointRecoveryInputs {
        request: &outer,
        provenance: &provenance,
        encrypted_request: &exact_request,
        proofs: frames.as_input_evidence(),
        lifecycle: life.as_bytes(),
        link: link.as_bytes(),
    };
    let wrong_key = JointRecoveryKey::new(Zeroizing::new(fresh()));
    assert!(
        capsule
            .restore_compute_prepared(
                &identity,
                &wrong_key,
                context(&owner, &setup, &anchor),
                &epoch,
                &recovery_parent,
                public(),
            )
            .is_err()
    );
    let wrong_identity = JointRecoveryIdentity::new(fresh());
    assert!(
        capsule
            .restore_compute_prepared(
                &wrong_identity,
                &wrapping,
                context(&owner, &setup, &anchor),
                &epoch,
                &recovery_parent,
                public(),
            )
            .is_err()
    );
    let recovered = capsule
        .restore_compute_prepared(
            &identity,
            &wrapping,
            context(&owner, &setup, &anchor),
            &epoch,
            &recovery_parent,
            public(),
        )
        .unwrap();
    let (pending, candidates) = recovered.into_parts();
    let exact_restored_request = pending.request == exact_request;
    pending.operand_ciphertexts().unwrap();
    drop(exact_request);
    drop(capsule);
    drop(wrapping);
    drop(wrong_key);
    drop(epoch);
    drop(handle);
    phase(
        started,
        "real input16/Life/Link and authenticated same-request recovery after original pending/candidates drop",
    );

    let life_frame =
        wire::frame::Frame::parse(wire::frame::Role::Transition, life.as_bytes()).unwrap();
    let query_frame = coefficient_encoding::wire::BorrowedFrame::parse(
        &provenance.encodings()[1].expected,
        frames.as_input_evidence().encodings[1],
    )
    .unwrap();
    assert_eq!(
        life_frame.source,
        query_frame.source(),
        "ONE literal Source is shared"
    );
    let next = registry200_proof::source::statement::encode_digest(life.statement().next);
    let result = registry200_proof::source::statement::encode_digest(life.statement().result);
    let mut store = ProductStore::open(quota.depot_budget()).unwrap();
    let life_child = store.retain_public_blob(life_frame.child).unwrap();
    let link_id = store.retain_public_blob(link.as_bytes()).unwrap();
    drop(life);
    drop(link);
    let recorded = remote
        .prove_private_product_recorded(
            object,
            provenance,
            &pending.request,
            &frames.as_input_evidence(),
            &mut store,
        )
        .unwrap();
    let (stream_checked, catalog) = recorded.into_parts();
    let graph_identity = stream_checked.product().identity();
    let response_hash: [u8; 32] = sha2::Sha256::digest(stream_checked.encrypted_response()).into();
    drop(stream_checked);
    drop(frames);
    drop(store);
    phase(
        started,
        "actual OS FHE input16/output118 through recorded clean END/EOF",
    );

    let app = registry200_joint::Application::new(
        binding.application_descriptor().clone(),
        binding.journal_genesis(),
    )
    .unwrap();
    let source_provenance =
        bfv_mul_relin_proof::Provenance::decode_claim(setup.clone(), &original_claim).unwrap();
    let expected = AcquireExpectation::new(
        &binding,
        &sealed_parent,
        &current,
        AcquireExpected::new(&app, &outer, &source_provenance, &pending.request, catalog).unwrap(),
    )
    .unwrap();
    drop(source_provenance);
    drop(original_claim);
    let block = fixture::transition(
        &binding,
        sealed_parent.head(),
        outer,
        Manifest::acquire(next, result, catalog, life_child, link_id).unwrap(),
        sealed_parent.control(),
    );
    let depot = JointDepot::open(quota.depot_budget()).unwrap();
    let ingress = depot.ingress();
    let mut history = JointHistory::new(binding.clone(), depot).unwrap();
    history.apply(&bootstrap.1, &bootstrap.0).unwrap();
    history.apply(&begin_qc, &begin_block).unwrap();
    assert_eq!(history.context().unwrap(), &current);
    assert!(
        history
            .apply_acquire(&begin_qc, &begin_block, &expected)
            .is_err()
    );
    assert_eq!(
        history.checked_parent().unwrap().unwrap().head(),
        sealed_parent.head()
    );
    assert_eq!(history.context().unwrap(), &current);
    for client in &clients {
        upload_manifest(client, &block, &ingress, &binding);
        let claim = ingress.catalog_claim(catalog).unwrap();
        for reference in claim.references() {
            let bytes = ingress
                .read_public_blob(reference.blob_id(), reference.byte_cap())
                .unwrap();
            upload_public_blob(
                client,
                &block,
                ProofBlobSelector::catalog(reference.role(), reference.ordinal()).unwrap(),
                reference.blob_id(),
                &bytes,
            );
        }
    }
    phase(
        started,
        "all exact Acquire evidence uploaded to four independent OS validators",
    );
    submit_to_all_validators(&clients, &block, started);
    let qcs: Vec<_> = clients
        .iter()
        .map(|client| checkpoint(client, sealed_parent.slot(), &block))
        .collect();
    let fetched = clients[0].candidate_block(block.header().id()).unwrap();
    assert_eq!(fetched.encode(), block.encode());
    let operation = history.apply_acquire(&qcs[0], &fetched, &expected).unwrap();
    assert_eq!(operation.acquired().product().identity(), graph_identity);
    assert_eq!(
        <[u8; 32]>::from(sha2::Sha256::digest(
            operation.acquired().encrypted_response()
        )),
        response_hash
    );
    assert_eq!(operation.body_bytes(), fetched.body());
    assert_eq!(operation.checkpoint_bytes(), qcs[0].encode());
    let completed = candidates
        .complete_acquire(&owner, pending, operation)
        .unwrap();
    let (rows, opening) = completed.into_opening();
    drop(owner);
    drop(setup);
    phase(
        started,
        "actual Acquire QC, fresh keyless all16/118/Life/Link replay and one owner completion",
    );

    // Act 4: End receives ONLY the completed Acquire bank and actual next parent.
    let parent = JointControlParent::from_verified(
        history.checked_parent().unwrap().unwrap(),
        &binding,
        history.context().unwrap(),
    )
    .unwrap();
    let prepared = source_owner
        .prepare_joint_control(
            crate::private_predicate::FetchedSource {
                object,
                bundle: &bundle,
                heads: &heads,
            },
            &parent,
            opening,
            JointControlIntent::end(1, 1, JointEndDisposition::Close, fresh()).unwrap(),
        )
        .unwrap();
    drop(source_owner);
    drop(bundle);
    let previous = (fetched, qcs.into_iter().next().unwrap());
    let (completed, end_block, _) = control_operation(
        prepared,
        &binding,
        &mut history,
        &ingress,
        &clients,
        &previous,
        started,
    );
    let end_outcome = completed.outcome();
    let end_parent = JointControlParent::from_verified(
        history.checked_parent().unwrap().unwrap(),
        &binding,
        history.context().unwrap(),
    )
    .unwrap();
    let ended_transaction_is_absent = matches!(
        completed.into_opening().for_acquire(&end_parent, 1, 1),
        Err(crate::Error::InvalidInput(ref message)) if message == "Acquire transaction is absent"
    );
    let final_head = history.checked_parent().unwrap().unwrap().head();
    let final_slot = history.checked_parent().unwrap().unwrap().slot();
    phase(
        started,
        "typed End Source/Life/Kind, actual four-OS QC and consuming Registry close",
    );
    drop(history);
    drop(ingress);
    drop(quota);
    drop(remote);

    // Join every actual child before final success assertions, including when an
    // earlier finish returned Err. No ACK or local signature substitutes for QC.
    let validator_results: Vec<_> = validators
        .into_iter()
        .map(|validator| validator.finish())
        .collect();
    let storage_result = storage.finish();
    for result in validator_results {
        result.unwrap();
    }
    storage_result.unwrap();
    let mut all_pids = validator_pids;
    all_pids.push(storage_pid);
    all_pids.sort_unstable();
    all_pids.dedup();
    assert_eq!(
        all_pids.len(),
        5,
        "All five independent OS children must be distinct"
    );
    assert!(!all_pids.contains(&std::process::id()));
    assert_eq!(begin_outcome, JointControlOutcome::Begun);
    assert!(
        exact_restored_request,
        "Capsule must restore the identical original request"
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].ordinal, 3);
    assert_eq!(rows[0].age, Some(255));
    assert_eq!(rows[0].amount, Some(65534));
    assert_eq!(end_outcome, JointControlOutcome::ClosedRegistry);
    assert!(
        ended_transaction_is_absent,
        "The exact completed End removes tx1"
    );
    assert_eq!(final_slot, 4);
    assert_eq!(final_head.block, end_block.header().id());
    println!(
        "{}",
        serde_json::json!({
            "case":"actual-four-OS-typed-Bootstrap-Begin-recoverable-Acquire-End",
            "validator_processes":4,"FHE_processes":1,"joint_operations":4,
            "input_proofs":16,"output_records":118,"logical_nodes":134,
            "completed_ordinal":3,"total_ms":started.elapsed().as_secs_f64()*1000.,
            "persistent_restart":false,"current_lease":false,
            "SQL_capability_opened":false,"Vault_installed":false
        })
    );
}
