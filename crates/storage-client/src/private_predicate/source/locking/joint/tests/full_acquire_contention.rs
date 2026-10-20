//! Real held-conflict branch: no fabricated held Registry, local QC builder,
//! plaintext peer predicate or fixture FHE answer. This is a separate heavy gate.
//! SourceOwner and the same Ready epoch survive the first completion solely to
//! prepare query two. Both are dropped before its fresh public replay; the BFV
//! Owner remains only for the allowed client decrypt. No Vault/install, general
//! SQL grant, permanent lease, latency or RAM guarantee is established here.
use super::*;
use bfv_query_core::PreparedPrivateCoefficientPredicate;
use registry200_finality::{CandidateBlock, joint::VerifiedJointParent};
use work_finality::consensus::Context;

struct RecordedAcquire {
    prepared: PreparedPrivateCoefficientPredicate,
    candidates: JointLockingCandidates,
    request: JointRequest,
    manifest: Manifest,
    catalog: bfv_product_evidence::CatalogId,
    original_claim: Vec<u8>,
    graph_identity: [u8; 64],
    response_hash: [u8; 32],
}
fn record(
    prepared: PreparedJointLockingInputs,
    remote: &RemotePeer,
    object: [u8; 32],
    quota: &ParticipantQuota,
) -> RecordedAcquire {
    let (inputs, life, link, request, candidates) = prepared.into_parts();
    let (provenance, prepared, frames) = inputs.into_parts();
    let original_claim = provenance.encode_claim().unwrap();
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
        "The literal Source is shared within each exact query"
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
            &prepared.request,
            &frames.as_input_evidence(),
            &mut store,
        )
        .unwrap();
    let (checked, catalog) = recorded.into_parts();
    let graph_identity = checked.product().identity();
    let response_hash = sha2::Sha256::digest(checked.encrypted_response()).into();
    drop(checked);
    drop(frames);
    drop(store);
    println!(
        "Joint contention phase finished: one actual OS FHE input16/output118 stream recorded through END/EOF"
    );
    RecordedAcquire {
        prepared,
        candidates,
        request,
        manifest: Manifest::acquire(next, result, catalog, life_child, link_id).unwrap(),
        catalog,
        original_claim,
        graph_identity,
        response_hash,
    }
}
struct ParentSnapshot<'a> {
    parent: &'a VerifiedJointParent,
    context: &'a Context,
    originals: &'a [(CandidateBlock, JointCheckpoint)],
}
struct FinishedAcquire {
    completed: CompletedJointAcquire,
    parent: VerifiedJointParent,
    context: Context,
    block: CandidateBlock,
    checkpoint: JointCheckpoint,
}
fn finish_recorded(
    owner: &Owner,
    setup: &PublicSetup,
    binding: &JointBinding,
    quota: &ParticipantQuota,
    clients: &[JointFinalityClient],
    before: ParentSnapshot<'_>,
    recorded: RecordedAcquire,
) -> FinishedAcquire {
    let RecordedAcquire {
        prepared,
        candidates,
        request,
        manifest,
        catalog,
        original_claim,
        graph_identity,
        response_hash,
    } = recorded;
    let app = registry200_joint::Application::new(
        binding.application_descriptor().clone(),
        binding.journal_genesis(),
    )
    .unwrap();
    let provenance =
        bfv_mul_relin_proof::Provenance::decode_claim(setup.clone(), &original_claim).unwrap();
    let expected = AcquireExpectation::new(
        binding,
        before.parent,
        before.context,
        AcquireExpected::new(&app, &request, &provenance, &prepared.request, catalog).unwrap(),
    )
    .unwrap();
    drop(provenance);
    drop(original_claim);
    let block = fixture::transition(
        binding,
        before.parent.head(),
        request,
        manifest,
        before.parent.control(),
    );
    let depot = JointDepot::open(quota.depot_budget()).unwrap();
    let ingress = depot.ingress();
    let mut history = JointHistory::new(binding.clone(), depot).unwrap();
    for (block, checkpoint) in before.originals {
        history.apply(checkpoint, block).unwrap();
    }
    assert_eq!(history.context().unwrap(), before.context);
    assert_eq!(
        history.checked_parent().unwrap().unwrap().head(),
        before.parent.head()
    );
    for client in clients {
        upload_manifest(client, &block, &ingress, binding);
        let claim = ingress.catalog_claim(expected.inputs().catalog()).unwrap();
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
    println!(
        "Joint contention phase finished: same-depot closed parent replay and evidence uploads to all four OS validators"
    );
    submit_to_all_validators(clients, &block, Instant::now());
    let checkpoints: Vec<_> = clients
        .iter()
        .map(|c| checkpoint(c, before.parent.slot(), &block))
        .collect();
    let fetched = clients[0].candidate_block(block.header().id()).unwrap();
    assert_eq!(fetched.encode(), block.encode());
    let operation = history
        .apply_acquire(&checkpoints[0], &fetched, &expected)
        .unwrap();
    assert_eq!(operation.acquired().product().identity(), graph_identity);
    assert_eq!(
        <[u8; 32]>::from(sha2::Sha256::digest(
            operation.acquired().encrypted_response()
        )),
        response_hash
    );
    assert_eq!(operation.parent(), before.parent.head());
    assert_eq!(operation.slot(), before.parent.slot() + 1);
    assert_eq!(operation.body_bytes(), fetched.body());
    assert_eq!(operation.checkpoint_bytes(), checkpoints[0].encode());
    // This same genuine operation binds all private flags before they can be
    // interpreted as accepted SQL locking semantics or passed to one decrypt.
    candidates.require_operation(&prepared, &operation).unwrap();
    let completed = candidates
        .complete_acquire(owner, prepared, operation)
        .unwrap();
    let parent = history.checked_parent().unwrap().unwrap().clone();
    let context = history.context().unwrap().clone();
    drop(history);
    drop(ingress);
    println!(
        "Joint contention phase finished: genuine Acquire QC, fresh all16/118/Life/Link replay and one owner completion"
    );
    FinishedAcquire {
        completed,
        parent,
        context,
        block,
        checkpoint: checkpoints.into_iter().next().unwrap(),
    }
}

#[test]
#[ignore = "Actual 4 OS validators + OS FHE peer, two sequential complete FHE Acquire operations; requires DCS_PEER_EXE"]
fn four_os_real_prior_acquire_makes_skip_locked_conflict_precede_offset_and_limit() {
    let exe = PathBuf::from(
        std::env::var_os("DCS_PEER_EXE")
            .expect("DCS_PEER_EXE must name the actual built dcs-peer binary"),
    );
    assert!(
        exe.is_absolute() && exe.is_file(),
        "A real explicit OS peer binary is mandatory"
    );
    let started = Instant::now();
    let directory = fixture::Directory::new();
    let identity = fixture::identity();
    let (storage, remote) = source_peer(&exe, &directory, &identity);
    let source_owner =
        SourceOwner::new([0x21; 16], [0x42; 16], Zeroizing::new([0x63; 32])).unwrap();
    let rows = [
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
    ];
    let table = source_owner
        .seal_partition(
            &TableId::from_bytes([0x19; 32]).unwrap(),
            &rows,
            RowIds::generate(4).unwrap(),
        )
        .unwrap();
    let heads = table.read_heads();
    let bundle = RawBundle::from_snapshots(table.snapshot(), table.encrypted_index()).unwrap();
    let object = *bundle.target_version().unwrap().object();
    drop(table);
    assert!(
        matches!(remote.call(Request::Store(bundle)).unwrap(),Response::Stored(info) if info.id==object)
    );
    let Response::RawBundle(bundle) = remote.call(Request::Fetch { object }).unwrap() else {
        panic!("Actual stored Source required")
    };
    let loaded = source_owner
        .load(FetchedSource {
            object,
            bundle: &bundle,
            heads: &heads,
        })
        .unwrap();
    let row_ids: [[u8; 32]; 4] = core::array::from_fn(|i| {
        loaded.plain[2220 + 32 * i..2252 + 32 * i]
            .try_into()
            .unwrap()
    });
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    assert!(matches!(
        remote
            .call(Request::InstallSetup(setup.to_bytes().unwrap()))
            .unwrap(),
        Response::Setup(_)
    ));
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
    let checked = setup
        .verify_key_transform(&anchor, epoch.key_evidence().unwrap().as_bytes())
        .unwrap();
    let quota = ParticipantQuota::create_new(
        directory.path("owner-evidence"),
        NAMESPACE,
        fixture::CAPACITY,
    )
    .unwrap();
    let binding = fixture::binding(
        &loaded,
        &setup,
        &anchor,
        checked.statement(),
        object,
        &quota,
    );
    let setup_wire = setup.to_bytes().unwrap();
    let (validators, clients) =
        start_validators(&exe, &directory, &binding, &identity, &setup_wire);
    drop(setup_wire);
    let depot = JointDepot::open(quota.depot_budget()).unwrap();
    let ingress = depot.ingress();
    let mut history = JointHistory::new(binding.clone(), depot).unwrap();
    let mut state = fixture::ControlState::empty();
    let mut parent = version_journal::Journal::new(binding.journal_genesis().clone())
        .unwrap()
        .genesis_head();
    let mut originals = Vec::new();
    for phase in 0..3 {
        let block = match phase {
            0 => fixture::control_block(
                &source_owner,
                &loaded,
                &binding,
                parent,
                &mut state,
                &ingress,
                true,
            ),
            1 => fixture::begin_block(
                &source_owner,
                &loaded,
                &binding,
                parent,
                &mut state,
                &ingress,
                (1, 1),
            ),
            _ => fixture::begin_block(
                &source_owner,
                &loaded,
                &binding,
                parent,
                &mut state,
                &ingress,
                (2, 2),
            ),
        };
        for client in &clients {
            upload_manifest(client, &block, &ingress, &binding);
        }
        submit_to_all_validators(&clients, &block, started);
        let checkpoints: Vec<_> = clients
            .iter()
            .map(|c| checkpoint(c, phase, &block))
            .collect();
        let fetched = clients[0].candidate_block(block.header().id()).unwrap();
        assert_eq!(fetched.encode(), block.encode());
        parent = history.apply(&checkpoints[0], &fetched).unwrap().head();
        originals.push((block, checkpoints.into_iter().next().unwrap()));
    }
    assert_eq!(state.registry.revision, 2);
    assert_eq!(state.registry.transactions.len(), 2);
    assert!(
        state
            .registry
            .transactions
            .iter()
            .all(|tx| tx.held == [0; 4])
    );
    let sealed = history.checked_parent().unwrap().unwrap().clone();
    let current = history.context().unwrap().clone();
    let parent = JointLockingParent::from_verified(
        &sealed,
        &binding,
        context(&owner, &setup, &anchor),
        &epoch,
    )
    .unwrap();
    drop(history);
    drop(ingress);
    drop(loaded);
    println!(
        "Joint contention phase finished: actual Bootstrap, Begin(tx1) and Begin(tx2) QCs; neither transaction holds a row yet"
    );
    let compiled = CompiledLockingSelect::compile(
        "SELECT age, amount FROM records WHERE age IN (0) LIMIT 1 FOR UPDATE",
        Zeroizing::new([0xc6; 32]),
        [0xe7; 32],
        [0xf8; 16],
    )
    .unwrap();
    let actor = LockingActor::new(
        1,
        1,
        state.registry.revision,
        state.registry.transactions[0].sequence,
    )
    .unwrap();
    let control = LockingControl::new(
        state.registry,
        fixture::CONTROLLERS,
        [fixture::ENROLL_SALT, state.salt],
        actor,
    )
    .unwrap();
    let JointLockingPreparation::Prepared(prepared) = source_owner
        .prepare_joint_locking(
            context(&owner, &setup, &anchor),
            &mut epoch,
            FetchedSource {
                object,
                bundle: &bundle,
                heads: &heads,
            },
            &compiled,
            &parent,
            control,
        )
        .unwrap()
    else {
        panic!("First uncontended actual Acquire must prepare")
    };
    assert_eq!(
        epoch.stage(),
        ProofEpochStage::Ready,
        "The same actual Key33 epoch must be reusable by the second input scope"
    );
    drop(compiled);
    drop(parent);
    drop(bundle);
    let recorded = record(*prepared, &remote, object, &quota);
    let first_query = recorded.request.inner().query;
    let first = finish_recorded(
        &owner,
        &setup,
        &binding,
        &quota,
        &clients,
        ParentSnapshot {
            parent: &sealed,
            context: &current,
            originals: &originals,
        },
        recorded,
    );
    assert_eq!(
        first.completed.rows(),
        [CompletedJointRow {
            ordinal: 0,
            row_id: row_ids[0],
            age: Some(0),
            amount: Some(65535)
        }]
    );
    let (first_rows, mut staged) = first.completed.into_parts();
    drop(first_rows);
    assert_eq!(staged.next.transactions[0].id, 1);
    assert_eq!(staged.next.transactions[0].held, [4, 0, 0, 0]);
    assert_eq!(staged.next.transactions[1].id, 2);
    assert_eq!(staged.next.transactions[1].held, [0; 4]);
    assert_eq!(staged.next.revision, 3);
    let actor2 = LockingActor::new(
        2,
        staged.next.transactions[1].principal,
        staged.next.revision,
        staged.next.transactions[1].sequence,
    )
    .unwrap();
    // Move the actual completed next Registry, retaining its actual salts. No
    // model step, fabricated held state, public successor constructor or clone.
    let registry = core::mem::take(&mut *staged.next);
    let mut controllers = *staged.controllers;
    let mut salts = *staged.salts;
    let control = LockingControl::new(registry, controllers, salts, actor2).unwrap();
    controllers.zeroize();
    salts.zeroize();
    staged.controllers.zeroize();
    staged.salts.zeroize();
    drop(staged);
    originals.push((first.block, first.checkpoint));
    let sealed = first.parent;
    let current = first.context;
    let parent = JointLockingParent::from_verified(
        &sealed,
        &binding,
        context(&owner, &setup, &anchor),
        &epoch,
    )
    .unwrap();
    let Response::RawBundle(bundle) = remote.call(Request::Fetch { object }).unwrap() else {
        panic!("Second query must re-fetch the actual stored Source")
    };
    let compiled=CompiledLockingSelect::compile("SELECT age, amount FROM records WHERE age IN (0,255) LIMIT 1 OFFSET 1 FOR UPDATE SKIP LOCKED",
        Zeroizing::new([0xc7;32]),[0xe8;32],[0xf9;16]).unwrap();
    let JointLockingPreparation::Prepared(prepared) = source_owner
        .prepare_joint_locking(
            context(&owner, &setup, &anchor),
            &mut epoch,
            FetchedSource {
                object,
                bundle: &bundle,
                heads: &heads,
            },
            &compiled,
            &parent,
            control,
        )
        .unwrap()
    else {
        panic!("SKIP must admit despite the genuinely held conflicting row")
    };
    drop(compiled);
    drop(parent);
    drop(bundle);
    drop(epoch);
    drop(handle);
    drop(source_owner);
    println!(
        "Joint contention phase finished: second input16/Life/Link prepared from ACTUAL completed Registry; SourceOwner/epoch/handle dropped, client BFV Owner retained for decrypt"
    );
    let recorded = record(*prepared, &remote, object, &quota);
    assert_ne!(
        recorded.request.inner().query,
        first_query,
        "A changed parent/query never relabels prior input or product proofs"
    );
    assert_eq!(recorded.request.inner().parent, sealed.head().block);
    // These are private candidate checks only UNTIL the exact genuine operation
    // rehashes Result144 and completes below; they alone authorize nothing.
    assert_eq!(recorded.candidates._completion.flags[0], [false; 4]);
    assert_eq!(
        recorded.candidates._completion.flags[1],
        [true, false, false, false]
    );
    assert_eq!(
        recorded.candidates._completion.flags[2],
        [false, false, false, true]
    );
    let second = finish_recorded(
        &owner,
        &setup,
        &binding,
        &quota,
        &clients,
        ParentSnapshot {
            parent: &sealed,
            context: &current,
            originals: &originals,
        },
        recorded,
    );
    assert!(
        second.completed.rows().is_empty(),
        "Conflict ordinal0 is skipped before OFFSET consumes ordinal3; no row remains for LIMIT1"
    );
    assert_eq!(second.completed.operation_head(), second.parent.head());
    assert_eq!(second.parent.slot(), 5);
    let (second_rows, staged) = second.completed.into_parts();
    assert!(second_rows.is_empty());
    drop(second_rows);
    assert_eq!(staged.next.transactions[0].id, 1);
    assert_eq!(staged.next.transactions[0].held, [4, 0, 0, 0]);
    assert_eq!(staged.next.transactions[1].id, 2);
    assert_eq!(staged.next.transactions[1].held, [0, 0, 0, 4]);
    assert_eq!(staged.next.revision, 4);
    assert_eq!(staged.next.transactions[1].sequence, 2);
    drop(staged);
    drop(owner);
    drop(setup);
    drop(quota);
    for validator in validators {
        validator.finish().unwrap();
    }
    storage.finish().unwrap();
    println!(
        "{}",
        serde_json::json!({"case":"actual-four-OS-quorum-two-FHE-Acquires-SKIP-before-OFFSET","validator_processes":4,"FHE_processes":1,
        "completed_Acquires":2,"input_proofs_per_query":16,"output_records_per_query":118,"first_returned_ordinal":0,"second_returned_rows":0,
        "prior_lock_obtained_by_actual_Acquire_QC":true,"total_ms":started.elapsed().as_secs_f64()*1000.,
        "SQL_capability_opened":false,"Vault_installed":false,"permanent_current_lease":false})
    );
}
