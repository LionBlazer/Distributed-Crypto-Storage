//! Actual four-OS-validator QC plus a separate OS FHE peer. Expected rows are
//! test assertions only. No local fixture signs a QC or supplies an FHE answer.
use super::*;
use bfv_product_evidence::ProductStore;
use peer_runtime::{
    Bootstrap, Connector, RemotePeer, Request, Response,
    finality::{JointFinalityClient, ProofBlobSelector},
    participant::ParticipantInstall,
};
use protocol_storage::{BlobId, ParticipantQuota};
use registry200_finality::joint::{AcquireExpectation, JointCheckpoint, JointHistory};
use registry200_joint::{AcquireExpected, JointDepot, JointEvidenceIngress, Manifest};
use registry200_proof::{coefficient_encoding, wire};
use sha2::Digest;
use std::{
    io,
    net::TcpListener,
    path::PathBuf,
    time::{Duration, Instant},
};

// Test-only supervision shared with the daemon owning suite. No production
// storage-client source imports an app, Source fixture or process launcher.
#[path = "full_acquire_contention.rs"]
mod contention;
#[path = "full_acquire_lifecycle.rs"]
mod lifecycle;
use super::full_acquire_fixture as fixture;
#[path = "../../../../../../../../apps/dcs-peer/tests/support/joint_process.rs"]
mod os_process;

const NAMESPACE: [u8; 32] = [0x91; 32];
const WAIT: Duration = Duration::from_secs(1800);

fn until<T>(mut action: impl FnMut() -> io::Result<Option<T>>) -> T {
    let end = Instant::now() + WAIT;
    loop {
        match action() {
            Ok(Some(value)) => return value,
            Ok(None) => (),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => (),
            Err(e) => panic!(
                "Actual bounded peer operation failed (kind={:?}, os={:?}): {e}",
                e.kind(),
                e.raw_os_error()
            ),
        }
        assert!(
            Instant::now() < end,
            "Actual peer operation failed to become observable"
        );
        std::thread::park_timeout(Duration::from_millis(25));
    }
}
fn submit_to_all_validators(
    clients: &[JointFinalityClient],
    block: &registry200_finality::CandidateBlock,
    started: Instant,
) {
    assert_eq!(
        clients.len(),
        4,
        "Four independent validator clients are required"
    );
    std::thread::scope(|scope| {
        // Only these four initial exact-candidate offers overlap. Each worker
        // retains the existing bounded per-endpoint retry/error contract.
        let workers: [_; 4] = core::array::from_fn(|index| {
            let client = &clients[index];
            scope.spawn(move || {
                until(|| client.submit(block).map(|()| Some(())));
                println!(
                    "Joint candidate import ACK: validator {index} ({:.1} ms)",
                    started.elapsed().as_secs_f64() * 1000.
                );
            })
        });
        // Join every admitted worker before propagating any failure. Returning
        // means four actual ACKs; the caller must still fetch and verify QCs.
        let results = workers.map(|worker| worker.join());
        for result in results {
            if let Err(payload) = result {
                std::panic::resume_unwind(payload);
            }
        }
    });
}
fn upload_public_blob(
    client: &JointFinalityClient,
    block: &registry200_finality::CandidateBlock,
    selector: ProofBlobSelector,
    id: BlobId,
    bytes: &[u8],
) {
    // An interrupted content-addressed upload may be repeated with the exact
    // same signed Body, fixed role, BlobId and bytes. This does not submit a
    // candidate, accept a proof, or retry a partial FHE result stream.
    until(|| match client.put_proof_blob(block, selector, id, bytes) {
        Ok(()) => Ok(Some(())),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::TimedOut
                    | io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::NotConnected
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::UnexpectedEof
            ) =>
        {
            eprintln!(
                "Exact public blob upload interrupted ({selector:?}, kind={:?}, os={:?}); retrying identical bytes: {e}",
                e.kind(),
                e.raw_os_error()
            );
            std::thread::park_timeout(Duration::from_millis(100));
            Ok(None)
        }
        Err(e) => Err(e),
    });
}
fn checkpoint(
    client: &JointFinalityClient,
    before: u64,
    block: &registry200_finality::CandidateBlock,
) -> JointCheckpoint {
    let qc = until(|| client.checkpoint_after(before));
    assert_eq!(qc.candidate().header(), block.header());
    assert_eq!(qc.candidate().slot(), before + 1);
    qc
}
fn upload_manifest(
    client: &JointFinalityClient,
    block: &registry200_finality::CandidateBlock,
    ingress: &JointEvidenceIngress,
    binding: &JointBinding,
) {
    let version_journal::Body::Transition(body) =
        version_journal::Body::decode(block.body(), &binding.journal_genesis().profile).unwrap()
    else {
        panic!("Transition required")
    };
    let manifest = Manifest::decode(&body.proof).unwrap();
    for reference in manifest.references() {
        let bytes = ingress
            .read_public_blob(reference.blob_id(), reference.byte_cap())
            .unwrap();
        upload_public_blob(
            client,
            block,
            ProofBlobSelector::manifest(reference.ordinal().try_into().unwrap()).unwrap(),
            reference.blob_id(),
            &bytes,
        );
    }
}
fn start_validators(
    exe: &std::path::Path,
    directory: &fixture::Directory,
    binding: &JointBinding,
    owner_identity: &peer_runtime::Identity,
    original_setup: &[u8],
) -> (Vec<os_process::Process>, Vec<JointFinalityClient>) {
    let identities: Vec<_> = (0..4).map(|_| fixture::identity()).collect();
    let reserved: Vec<_> = (0..4)
        .map(|_| Some(TcpListener::bind("127.0.0.1:0").unwrap()))
        .collect();
    let endpoints: Vec<_> = reserved
        .iter()
        .zip(&identities)
        .map(|(socket, identity)| peer_runtime::Endpoint {
            address: socket.as_ref().unwrap().local_addr().unwrap(),
            identity: identity.fingerprint(),
        })
        .collect();
    let mut reserved = reserved;
    let signers = fixture::signers();
    let work = binding.work_genesis().encode().unwrap();
    let journal = binding.journal_genesis().encode().unwrap();
    let descriptor = binding.application_descriptor().encode();
    let setup = binding.setup_claim().encode();
    let mut processes = Vec::with_capacity(4);
    let mut clients = Vec::with_capacity(4);
    let connector = Connector::permissionless(owner_identity).unwrap();
    for (i, (identity, signer)) in identities.iter().zip(&signers).enumerate() {
        let neighbors: Vec<_> = endpoints
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, e)| e.clone())
            .collect();
        let config=Zeroizing::new(serde_json::to_vec(&serde_json::json!({
            "version":1,"kind":"registry200-joint-participant-finality-v1","identity":identity,"authority":[],
            "owner":owner_identity.fingerprint(),"listen":endpoints[i].address,"neighbors":neighbors,"namespace":NAMESPACE,"capacity":fixture::CAPACITY,
            "work_genesis":binding.work_genesis().id(),"journal_genesis":binding.journal_genesis().id().unwrap(),"binding":binding.id(),
            "rules":{"max_round":32,"timeouts_ms":fixture::TIMEOUTS,"timeout_delta_ms":fixture::DELTA,"wal_bytes":work_finality::consensus::MAX_RECORD_BYTES as u64},
            "signer":signer.to_bytes().to_vec()
        })).unwrap());
        let mut frames = vec![
            config.as_slice(),
            work.as_slice(),
            journal.as_slice(),
            descriptor.as_slice(),
            setup.as_slice(),
        ];
        frames.extend(original_setup.chunks(protocol_storage::MAX_BLOB_BYTES as usize));
        drop(reserved[i].take());
        let process = os_process::Process::start_joint(
            exe,
            &directory.path(&format!("validator-{i}")),
            ParticipantInstall::New,
            &frames,
        )
        .unwrap();
        assert_eq!(process.ready().binding, binding.id());
        assert_eq!(process.ready().namespace, NAMESPACE);
        assert_eq!(
            process.ready().profile,
            peer_runtime::joint_participant::joint_participant_host_profile_digest()
        );
        assert_eq!(process.endpoint(), &endpoints[i]);
        assert_ne!(process.pid(), std::process::id());
        clients.push(JointFinalityClient::new(
            connector.clone(),
            process.endpoint().clone(),
            binding,
        ));
        processes.push(process);
    }
    let unique: std::collections::BTreeSet<_> = processes.iter().map(|p| p.pid()).collect();
    assert_eq!(unique.len(), 4);
    (processes, clients)
}
fn source_peer(
    exe: &std::path::Path,
    directory: &fixture::Directory,
    owner_identity: &peer_runtime::Identity,
) -> (os_process::StorageProcess, RemotePeer) {
    let bootstrap = Bootstrap {
        identity: fixture::identity(),
        authority: vec![],
        owner: owner_identity.fingerprint(),
        node_id: 201,
        quota_bytes: 16 * 1024 * 1024,
        listen: "127.0.0.1:0".parse().unwrap(),
    };
    let process =
        os_process::Process::start_storage(exe, &directory.path("FHE-peer"), &bootstrap).unwrap();
    let remote = RemotePeer::new(
        process.endpoint().clone(),
        Connector::permissionless(owner_identity).unwrap(),
    );
    (process, remote)
}
fn foreign_intent(
    binding: &JointBinding,
    block: &registry200_finality::CandidateBlock,
) -> registry200_finality::CandidateBlock {
    let version_journal::Body::Transition(mut body) =
        version_journal::Body::decode(block.body(), &binding.journal_genesis().profile).unwrap()
    else {
        unreachable!()
    };
    let outer = registry200_joint::Request::decode(&body.request).unwrap();
    let mut inner = outer.inner().clone();
    inner.nonce[31] ^= 1;
    let app = registry200_joint::Application::new(
        binding.application_descriptor().clone(),
        binding.journal_genesis(),
    )
    .unwrap();
    inner.query = registry200_journal::intent_query(
        app.source_spec(),
        app.genesis(),
        inner.parent,
        inner.nonce,
        inner.enrollment,
        inner.operation,
    );
    body.request = registry200_joint::Request::new(&app, registry200_joint::Lane::Acquire, inner)
        .unwrap()
        .encode()
        .unwrap();
    body.sign(
        app.genesis(),
        &ed25519_dalek::SigningKey::from_bytes(&[0x5b; 32]),
    );
    let bytes = version_journal::Body::Transition(body)
        .encode(&binding.journal_genesis().profile)
        .unwrap();
    let mut header = block.header().clone();
    header.body_hash = version_journal::hash(&bytes);
    header.nonce = 0;
    header.mine(1).unwrap();
    registry200_finality::CandidateBlock::new(header, bytes).unwrap()
}
fn blob_path(quota: &ParticipantQuota, id: BlobId) -> PathBuf {
    let name = id
        .sha256()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    quota
        .depot_directory()
        .join(format!("{name}-{:016x}.blob", id.bytes()))
}
fn replay_parent(
    quota: &ParticipantQuota,
    binding: &JointBinding,
    originals: &[(registry200_finality::CandidateBlock, JointCheckpoint)],
) -> JointHistory {
    let mut history = JointHistory::new(
        binding.clone(),
        JointDepot::open(quota.depot_budget()).unwrap(),
    )
    .unwrap();
    for (block, qc) in originals {
        history.apply(qc, block).unwrap();
    }
    history
}

#[test]
#[ignore = "Actual 4 OS validators + separate OS FHE peer, input16/output118, fresh Joint Acquire and owner completion; requires DCS_PEER_EXE"]
fn four_os_quorum_and_fhe_peer_complete_only_the_exact_own_joint_acquire_after_fresh_replay() {
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
    let owner_identity = fixture::identity();
    let (storage, remote) = source_peer(&exe, &directory, &owner_identity);
    assert_ne!(storage.pid(), std::process::id());
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
    assert!(
        matches!(remote.call(Request::Store(bundle)).unwrap(),Response::Stored(info) if info.id==object)
    );
    drop(table);
    let Response::RawBundle(bundle) = remote.call(Request::Fetch { object }).unwrap() else {
        panic!("Real fetched source required")
    };
    let loaded = source_owner
        .load(crate::private_predicate::FetchedSource {
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
    let key = setup
        .verify_key_transform(&anchor, epoch.key_evidence().unwrap().as_bytes())
        .unwrap();
    let quota = ParticipantQuota::create_new(
        directory.path("owner-evidence"),
        NAMESPACE,
        fixture::CAPACITY,
    )
    .unwrap();
    let binding = fixture::binding(&loaded, &setup, &anchor, key.statement(), object, &quota);
    let original_setup = setup.to_bytes().unwrap();
    let (validators, clients) =
        start_validators(&exe, &directory, &binding, &owner_identity, &original_setup);
    drop(original_setup);
    let depot = JointDepot::open(quota.depot_budget()).unwrap();
    let ingress = depot.ingress();
    let mut history = JointHistory::new(binding.clone(), depot).unwrap();
    let mut control_state = fixture::ControlState::empty();
    let mut parent = version_journal::Journal::new(binding.journal_genesis().clone())
        .unwrap()
        .genesis_head();
    let mut originals = Vec::new();
    for ordinal in 0..2 {
        let block = fixture::control_block(
            &source_owner,
            &loaded,
            &binding,
            parent,
            &mut control_state,
            &ingress,
            ordinal == 0,
        );
        for client in &clients {
            upload_manifest(client, &block, &ingress, &binding);
        }
        submit_to_all_validators(&clients, &block, started);
        let qcs: Vec<_> = clients
            .iter()
            .map(|c| checkpoint(c, ordinal, &block))
            .collect();
        let fetched = clients[0].candidate_block(block.header().id()).unwrap();
        assert_eq!(fetched.encode(), block.encode());
        let checked = history.apply(&qcs[0], &fetched).unwrap();
        parent = checked.head();
        originals.push((block, qcs.into_iter().next().unwrap()));
    }
    println!(
        "Joint full Acquire phase finished: actual four-OS Bootstrap/Begin QC and client proof replay ({:.1} ms)",
        started.elapsed().as_secs_f64() * 1000.
    );
    let sealed_parent = history.checked_parent().unwrap().unwrap().clone();
    let current = history.context().unwrap().clone();
    let parent = JointLockingParent::from_verified(
        &sealed_parent,
        &binding,
        context(&owner, &setup, &anchor),
        &epoch,
    )
    .unwrap();
    drop(history);
    drop(ingress);
    drop(loaded);
    // SAME depot is closed before any heavy owner input production or recorder.
    let compiled=CompiledLockingSelect::compile("SELECT age, amount FROM records WHERE age IN (0,255) LIMIT 1 OFFSET 1 FOR UPDATE SKIP LOCKED",Zeroizing::new([0xc6;32]),[0xe7;32],[0xf8;16]).unwrap();
    let JointLockingPreparation::Prepared(prepared) = source_owner
        .prepare_joint_locking(
            context(&owner, &setup, &anchor),
            &mut epoch,
            crate::private_predicate::FetchedSource {
                object,
                bundle: &bundle,
                heads: &heads,
            },
            &compiled,
            &parent,
            LockingControl::new(
                control_state.registry,
                fixture::CONTROLLERS,
                [fixture::ENROLL_SALT, control_state.salt],
                LockingActor::new(1, 1, 1, 1).unwrap(),
            )
            .unwrap(),
        )
        .unwrap()
    else {
        panic!("Free Registry must admit genuine successful mathematical Acquire")
    };
    drop(compiled);
    drop(parent);
    drop(epoch);
    drop(handle);
    drop(source_owner);
    drop(bundle);
    println!(
        "Joint full Acquire phase finished: real Source/input16/Lifecycle/Link preparation; private producer owners dropped ({:.1} ms)",
        started.elapsed().as_secs_f64() * 1000.
    );
    let (inputs, life, link, outer, mut candidates) = prepared.into_parts();
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
        "ONE literal Source must remain shared"
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
    let (stream_checked, catalog) = recorded.into_parts();
    let identity = stream_checked.product().identity();
    let response_hash: [u8; 32] = sha2::Sha256::digest(stream_checked.encrypted_response()).into();
    drop(stream_checked);
    drop(frames);
    drop(store);
    println!(
        "Joint full Acquire phase finished: OS FHE input16/output118 recorded through clean END/EOF ({:.1} ms)",
        started.elapsed().as_secs_f64() * 1000.
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
        AcquireExpected::new(&app, &outer, &source_provenance, &prepared.request, catalog).unwrap(),
    )
    .unwrap();
    drop(source_provenance);
    drop(original_claim);
    drop(setup);
    let old = sealed_parent.control();
    let block = fixture::transition(
        &binding,
        sealed_parent.head(),
        outer,
        Manifest::acquire(next, result, catalog, life_child, link_id).unwrap(),
        old,
    );
    let depot = JointDepot::open(quota.depot_budget()).unwrap();
    let ingress = depot.ingress();
    let mut history = JointHistory::new(binding.clone(), depot).unwrap();
    for (block, qc) in &originals {
        history.apply(qc, block).unwrap();
    }
    assert_eq!(history.context().unwrap(), &current);
    // All uploads finish before any voter is asked to import/propose the Body.
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
    println!(
        "Joint full Acquire phase finished: all fixed-role evidence uploaded to all four actual validators ({:.1} ms)",
        started.elapsed().as_secs_f64() * 1000.
    );
    // Every byte in this repaired, owner-signed Body still refers to genuine
    // original proofs. The changed independent intent must not obtain a vote.
    let foreign = foreign_intent(&binding, &block);
    until(|| match clients[0].submit(&foreign) {
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(e) if e.kind() == io::ErrorKind::InvalidData => Ok(Some(())),
        Err(e) => Err(e),
        Ok(()) => panic!("Genuine foreign-intent proofs obtained admission"),
    });
    assert!(clients[0].checkpoint_after(2).unwrap().is_none());
    assert_eq!(history.context().unwrap(), &current);
    submit_to_all_validators(&clients, &block, started);
    let qcs: Vec<_> = clients
        .iter()
        .enumerate()
        .map(|(index, client)| {
            let qc = checkpoint(client, 2, &block);
            println!(
                "Joint full Acquire actual QC fetched: validator {index} ({:.1} ms)",
                started.elapsed().as_secs_f64() * 1000.
            );
            qc
        })
        .collect();
    let fetched = clients[0].candidate_block(block.header().id()).unwrap();
    assert_eq!(fetched.encode(), block.encode());
    println!(
        "Joint full Acquire phase finished: exact candidate and QC bytes fetched from four OS validators ({:.1} ms)",
        started.elapsed().as_secs_f64() * 1000.
    );
    let operation = history.apply_acquire(&qcs[0], &fetched, &expected).unwrap();
    assert_eq!(operation.acquired().product().identity(), identity);
    assert_eq!(
        <[u8; 32]>::from(sha2::Sha256::digest(
            operation.acquired().encrypted_response()
        )),
        response_hash
    );
    assert_eq!(operation.slot(), 3);
    assert_eq!(operation.parent(), sealed_parent.head());
    assert_eq!(operation.checkpoint_bytes(), qcs[0].encode());
    assert_eq!(operation.body_bytes(), fetched.body());
    println!(
        "Joint full Acquire phase finished: fresh keyless input16/output118/Life/Link/QC replay matched own operation ({:.1} ms)",
        started.elapsed().as_secs_f64() * 1000.
    );
    // Mutate and restore the ACTUAL guarded banks, retaining the SAME genuine
    // operation throughout. No replacement receipt, bank clone or decrypt is
    // used to test Result144's three committed flag banks, actor and salt.
    candidates.require_operation(&prepared, &operation).unwrap();
    for bank in 0..3 {
        candidates._completion.flags[bank][3] ^= true;
        assert!(
            candidates.require_operation(&prepared, &operation).is_err(),
            "Changed Result144 flag bank {bank} must fail before decrypt"
        );
        candidates._completion.flags[bank][3] ^= true;
    }
    candidates._staged.actor.transaction = 2;
    assert!(
        candidates.require_operation(&prepared, &operation).is_err(),
        "A different canonical transaction must not open this Result144"
    );
    candidates._staged.actor.transaction = 1;
    let mut original_salt = candidates._completion.result_salt[0];
    candidates._completion.result_salt[0] = u64::from(original_salt == 0);
    assert!(
        candidates.require_operation(&prepared, &operation).is_err(),
        "A different canonical salt must not open this Result144"
    );
    candidates._completion.result_salt[0] = original_salt;
    original_salt.zeroize();
    candidates.require_operation(&prepared, &operation).unwrap();
    println!(
        "Joint full Acquire phase finished: genuine-receipt flag/actor/salt tamper rejections and original-bank restoration ({:.1} ms)",
        started.elapsed().as_secs_f64() * 1000.
    );
    let completed = candidates
        .complete_acquire(&owner, prepared, operation)
        .unwrap();
    assert_eq!(
        completed.rows(),
        [CompletedJointRow {
            ordinal: 3,
            row_id: row_ids[3],
            age: Some(255),
            amount: Some(65534)
        }]
    );
    assert_eq!(completed.operation_head().block, block.header().id());
    // Completion consumed OFFSET/LIMIT flags once. This fixture has no competing
    // held row and therefore does NOT claim genuine SKIP LOCKED contention.
    let (rows, staged) = completed.into_parts();
    assert_eq!(
        staged.next.transactions[0].held,
        [4, 0, 0, 4],
        "OFFSET-stepped ordinal0 is locked along with returned ordinal3"
    );
    assert_eq!(staged.next.revision, 2);
    assert_eq!(staged.next.transactions[0].sequence, 2);
    println!(
        "Joint full Acquire phase finished: one decrypt and one committed projection; OFFSET and returned rows actually held ({:.1} ms)",
        started.elapsed().as_secs_f64() * 1000.
    );
    drop(rows);
    drop(staged);
    drop(owner);
    assert!(
        history.apply(&originals[1].1, &originals[1].0).is_err(),
        "An older genuine Begin QC cannot replace latest Acquire"
    );
    // A fresh latest-semantic retry must actually replay, not reconstruct a
    // receipt from the previously verified parent or streamed product.
    let repeated = history.apply_acquire(&qcs[1], &fetched, &expected).unwrap();
    assert_eq!(repeated.acquired().product().identity(), identity);
    drop(repeated);
    let claim = ingress.catalog_claim(catalog).unwrap();
    let last = claim
        .references()
        .find(|r| r.role() == 11 && r.ordinal() == 117)
        .unwrap()
        .blob_id();
    let last_bytes = ingress
        .read_public_blob(
            last,
            bfv_mul_relin_proof::RECORD_HEADER + bfv_mul_relin_proof::MAX_PROOF_BYTES,
        )
        .unwrap();
    let link_bytes = ingress
        .read_public_blob(
            link_id,
            registry200_proof::predicate_acquire::wire::MAX_FRAME,
        )
        .unwrap();
    drop(history);
    drop(ingress);
    // Explicit hostile mutation of PUBLIC test artifacts, under the owned
    // namespace. Repaired originals are byte-identical; production has no repair.
    std::fs::remove_file(blob_path(&quota, last)).unwrap();
    let mut fresh = replay_parent(&quota, &binding, &originals);
    assert!(
        fresh.apply_acquire(&qcs[0], &fetched, &expected).is_err(),
        "A real QC cannot replace missing output record117"
    );
    assert_eq!(
        fresh.checked_parent().unwrap().unwrap().head(),
        sealed_parent.head()
    );
    drop(fresh);
    std::fs::write(blob_path(&quota, last), last_bytes).unwrap();
    // Missing retained evidence poisons the old participant ledger. Reconstruct
    // an independently healthy ledger before testing a DIFFERENT hostile fault;
    // otherwise the next refusal could be caused by that previous poison.
    drop(quota);
    let quota = ParticipantQuota::open_existing(
        directory.path("owner-evidence"),
        NAMESPACE,
        fixture::CAPACITY,
    )
    .unwrap();
    drop(
        JointDepot::open(quota.depot_budget())
            .expect("Repaired PUBLIC fixture must open cleanly before independent Link corruption"),
    );
    let mut damaged = link_bytes.clone();
    damaged[0] ^= 1;
    std::fs::write(blob_path(&quota, link_id), damaged).unwrap();
    assert!(
        JointDepot::open(quota.depot_budget()).is_err(),
        "Fresh CAS open must reject corrupt retained Link even after a genuine QC"
    );
    std::fs::write(blob_path(&quota, link_id), link_bytes).unwrap();
    drop(quota);
    for validator in validators {
        validator.finish().unwrap();
    }
    storage.finish().unwrap();
    println!(
        "{}",
        serde_json::json!({"case":"actual-four-OS-quorum-FHE-new-G-Acquire-completion","validator_processes":4,"FHE_processes":1,
        "input_proofs":16,"output_records":118,"logical_nodes":134,"completed_ordinal":3,"total_ms":started.elapsed().as_secs_f64()*1000.,
        "current_lease":false,"SQL_capability_opened":false,"Vault_installed":false})
    );
}
