//! Public-fixture, actual OS-process/TLS/FHE tests; no simulated transport or GUI.
use compact_query::{AgeRange, PlainRow, bfv as backend};
use compact_store::Limits;
use peer_runtime::{
    Bootstrap, Bundle, Connector, Endpoint, Identity, Operation, RemotePeer, Request, Response,
};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use std::{
    fs,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct Authority {
    der: Vec<u8>,
    issuer: Issuer<'static, KeyPair>,
}
impl Authority {
    fn new() -> Self {
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
        ];
        let key = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key).unwrap();
        Self {
            der: certificate.der().to_vec(),
            issuer: Issuer::new(params, key),
        }
    }
    fn identity(&self) -> Identity {
        let mut params = CertificateParams::new(vec!["dcs-peer".into()]).unwrap();
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let key = KeyPair::generate().unwrap();
        let certificate = params.signed_by(&key, &self.issuer).unwrap();
        Identity {
            certificate: certificate.der().to_vec(),
            private_key_pkcs8: key.serialize_der(),
        }
    }
}
struct Process {
    child: Child,
    endpoint: Endpoint,
    directory: PathBuf,
}
impl Process {
    fn start(authority: &Authority, owner: [u8; 32], id: u64, directory: Option<PathBuf>) -> Self {
        Self::start_with_supervision(authority, owner, id, directory, false)
    }
    fn start_with_supervision(
        authority: &Authority,
        owner: [u8; 32],
        id: u64,
        directory: Option<PathBuf>,
        supervised: bool,
    ) -> Self {
        let directory = directory.unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../.local/network-tests")
                .join(format!(
                    "{}-{id}-{}",
                    std::process::id(),
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ))
        });
        let mut command = Command::new(env!("CARGO_BIN_EXE_dcs-peer"));
        command
            .args(["--state-dir", directory.to_str().unwrap()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .env("RAYON_NUM_THREADS", "2");
        if supervised {
            command.arg("--exit-on-stdin-close");
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let mut child = command.spawn().unwrap();
        let config = Bootstrap {
            identity: authority.identity(),
            authority: authority.der.clone(),
            owner,
            node_id: id,
            quota_bytes: 1024 * 1024,
            listen: "127.0.0.1:0".parse().unwrap(),
        };
        let secret = zeroize::Zeroizing::new(serde_json::to_vec(&config).unwrap());
        peer_transport::write_frame(child.stdin.as_mut().unwrap(), &secret, 64 * 1024).unwrap();
        if !supervised {
            drop(child.stdin.take());
        }
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
            let _ = tx.send(result);
        });
        let endpoint = match rx
            .recv_timeout(Duration::from_secs(10))
            .and_then(|result| result.map_err(|_| mpsc::RecvTimeoutError::Disconnected))
        {
            Ok(line) => serde_json::from_str(&line).unwrap(),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("Peer startup failed: {error}");
            }
        };
        assert_ne!(child.id(), std::process::id());
        Self {
            child,
            endpoint,
            directory,
        }
    }
    fn remote(&self, connector: &Connector) -> RemotePeer {
        RemotePeer::new(self.endpoint.clone(), connector.clone())
    }
    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        self.kill();
    }
}
#[test]
fn authenticated_shutdown_wakes_the_listener_and_releases_the_process_directory() {
    let authority = Authority::new();
    let owner = authority.identity();
    let connector = Connector::new(&owner, &authority.der).unwrap();
    let mut process = Process::start(&authority, owner.fingerprint(), 1, None);
    let remote = process.remote(&connector);
    let outsider = Connector::new(&authority.identity(), &authority.der).unwrap();
    assert!(process.remote(&outsider).call(Request::Shutdown).is_err());
    assert_eq!(remote.status().unwrap().pid, process.child.id());

    assert!(matches!(
        remote.call(Request::Shutdown).unwrap(),
        Response::Done
    ));

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = process.child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Shutdown did not wake the listener"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(remote.status().is_err());
    let reopened = Process::start(
        &authority,
        owner.fingerprint(),
        1,
        Some(process.directory.clone()),
    );
    assert_eq!(
        reopened.remote(&connector).status().unwrap().pid,
        reopened.child.id()
    );
}

#[test]
fn supervised_peer_exits_on_owner_pipe_eof_and_releases_its_directory() {
    // Arrange: a real daemon remains reachable while its owner holds the pipe.
    let authority = Authority::new();
    let owner = authority.identity();
    let connector = Connector::new(&owner, &authority.der).unwrap();
    let mut process =
        Process::start_with_supervision(&authority, owner.fingerprint(), 1, None, true);
    assert_eq!(
        process.remote(&connector).status().unwrap().pid,
        process.child.id()
    );

    // Act: EOF is the same OS notification produced by a forcibly killed owner.
    drop(process.child.stdin.take());

    // Assert: the complete daemon exits, not just its listener/watchdog thread.
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = process.child.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "Supervised peer outlived its owner pipe"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(status.success());
    assert!(process.remote(&connector).status().is_err());
    let reopened = Process::start(
        &authority,
        owner.fingerprint(),
        1,
        Some(process.directory.clone()),
    );
    assert_eq!(
        reopened.remote(&connector).status().unwrap().pid,
        reopened.child.id()
    );
}

#[test]
fn independent_peer_remains_reachable_after_its_bootstrap_pipe_closes() {
    let authority = Authority::new();
    let owner = authority.identity();
    let connector = Connector::new(&owner, &authority.der).unwrap();

    let mut process = Process::start(&authority, owner.fingerprint(), 1, None);

    assert!(process.child.stdin.is_none());
    assert!(process.child.try_wait().unwrap().is_none());
    assert_eq!(
        process.remote(&connector).status().unwrap().pid,
        process.child.id()
    );
}

#[test]
fn frame_activity_reports_real_io_before_completion_and_nothing_for_an_unreachable_peer() {
    use peer_runtime::ActivityPhase;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };
    let authority = Authority::new();
    let owner = authority.identity();
    let connector = Connector::new(&owner, &authority.der).unwrap();
    let mut process = Process::start(&authority, owner.fingerprint(), 1, None);
    let observed = Arc::new(Mutex::new(Vec::new()));
    let completed = Arc::new(AtomicBool::new(false));
    let sink = observed.clone();
    let before_completion = completed.clone();
    let on_completion = completed.clone();
    let remote = process
        .remote(&connector)
        .with_activity(Arc::new(move |activity| {
            assert!(
                !before_completion.load(Ordering::Acquire),
                "I/O observation must precede completed-RPC telemetry"
            );
            sink.lock().unwrap().push(activity);
        }))
        .with_trace(Arc::new(move |_| {
            on_completion.store(true, Ordering::Release);
        }));

    let status = remote.status().unwrap();

    assert_eq!(status.node_id, 1);
    assert!(completed.load(Ordering::Acquire));
    let activity = observed.lock().unwrap();
    assert_eq!(activity.len(), 2);
    assert_eq!(activity[0].phase, ActivityPhase::RequestSent);
    assert_eq!(activity[1].phase, ActivityPhase::ReplyReceived);
    assert_eq!(activity[0].request_id, activity[1].request_id);
    assert!(activity.iter().all(|event| event.bytes > 0
        && event.operation == "status"
        && event.peer == process.endpoint.identity));
    drop(activity);

    process.kill();
    observed.lock().unwrap().clear();
    completed.store(false, Ordering::Release);
    assert!(remote.status().is_err());
    assert!(
        observed.lock().unwrap().is_empty(),
        "A failed connect must not invent sent frames"
    );
}

fn fixture(owner: &backend::Owner) -> (Bundle, compact_query::TableId) {
    let table = owner
        .seal(
            &[
                PlainRow {
                    age: 17,
                    amount: 10,
                },
                PlainRow {
                    age: 18,
                    amount: 20,
                },
                PlainRow {
                    age: 42,
                    amount: 30,
                },
            ],
            256,
            Limits::default(),
        )
        .unwrap();
    let bundle = Bundle {
        data_head: table.commitment().encode().to_vec(),
        index_head: table.index_commitment().encode().to_vec(),
        data: table.snapshot().encode(),
        index: table.encrypted_index().encode(),
    };
    (bundle, *table.table_id())
}
#[test]
fn separate_processes_execute_real_fhe_and_copy_ciphertext_without_owner_keys() {
    let authority = Authority::new();
    let owner_tls = authority.identity();
    let connector = Connector::new(&owner_tls, &authority.der).unwrap();
    let mut first = Process::start(&authority, owner_tls.fingerprint(), 1, None);
    let second = Process::start(&authority, owner_tls.fingerprint(), 2, None);
    assert_ne!(first.child.id(), second.child.id());
    let a = first.remote(&connector);
    let b = second.remote(&connector);
    let (owner, public) = backend::Owner::generate(*b"NETWORK-TEST-001").unwrap();
    let setup = public.encode_public_setup_for_experiment().unwrap();
    drop(public);
    let Response::Setup(setup_id) = a.call(Request::InstallSetup(setup)).unwrap() else {
        panic!("public setup expected")
    };
    let (bundle, table_id) = fixture(&owner);
    let object = bundle.id();
    let table = owner
        .restore_table_for_experiment(
            &bundle.data,
            &bundle.index,
            &table_id,
            &compact_store::Commitment::decode(&bundle.data_head, Limits::default()).unwrap(),
            &compact_store::Commitment::decode(&bundle.index_head, Limits::default()).unwrap(),
            Limits::default(),
        )
        .unwrap();
    assert!(matches!(
        a.call(Request::Store(bundle.clone())).unwrap(),
        Response::Stored(_)
    ));
    let prepared = owner
        .prepare_exact_aggregate_for_experiment(
            &table,
            AgeRange {
                lower: 18,
                upper: 255,
            },
            256,
            Limits::default(),
        )
        .unwrap();
    let Response::UnverifiedCiphertext(output) = a
        .call(Request::Evaluate {
            object,
            setup: setup_id,
            operation: Operation::Aggregate,
            ciphertext: prepared.request().to_vec(),
        })
        .unwrap()
    else {
        panic!("encrypted output expected")
    };
    let actual = owner
        .complete_exact_aggregate_unverified_for_experiment(&table, prepared, &output)
        .unwrap();
    assert_eq!((actual.count, actual.sum), (2, 50));
    let prepared = owner
        .prepare_exact_select_for_experiment(
            &table,
            AgeRange {
                lower: 0,
                upper: 255,
            },
            backend::RowProjection::AgeAmount,
            256,
            Limits::default(),
        )
        .unwrap();
    let Response::UnverifiedCiphertext(output) = a
        .call(Request::Evaluate {
            object,
            setup: setup_id,
            operation: Operation::Select,
            ciphertext: prepared.request().to_vec(),
        })
        .unwrap()
    else {
        panic!("encrypted output expected")
    };
    let actual = owner
        .complete_exact_select_unverified_for_experiment(&table, prepared, &output)
        .unwrap();
    assert_eq!(
        actual
            .rows
            .iter()
            .map(|r| (r.age.unwrap(), r.amount.unwrap()))
            .collect::<Vec<_>>(),
        vec![(17, 10), (18, 20), (42, 30)]
    );
    assert!(matches!(
        b.call(Request::Copy {
            source: first.endpoint.clone(),
            object
        })
        .unwrap(),
        Response::Stored(_)
    ));
    assert_eq!(b.status().unwrap().objects.len(), 1);
    assert!(
        a.status()
            .unwrap()
            .recent
            .iter()
            .any(|e| e.operation == "fetch" && e.remote == second.endpoint.identity)
    );
    first.kill();
    assert!(a.status().is_err());
    let Response::Bundle(surviving) = b.call(Request::Fetch { object }).unwrap() else {
        panic!("physical replica expected")
    };
    assert_eq!(surviving, bundle);
    let restarted = Process::start(
        &authority,
        owner_tls.fingerprint(),
        1,
        Some(first.directory.clone()),
    );
    assert!(
        matches!(restarted.remote(&connector).call(Request::Fetch{object}).unwrap(),Response::Bundle(value) if value==bundle)
    );
}
#[test]
fn unauthenticated_foreign_and_wrong_identity_connections_cannot_access_the_peer() {
    let authority = Authority::new();
    let owner = authority.identity();
    let connector = Connector::new(&owner, &authority.der).unwrap();
    let process = Process::start(&authority, owner.fingerprint(), 1, None);
    let foreign = Authority::new();
    let outsider = foreign.identity();
    let outsider = Connector::new(&outsider, &foreign.der).unwrap();
    assert!(process.remote(&outsider).status().is_err());
    let mut wrong = process.endpoint.clone();
    wrong.identity[0] ^= 1;
    assert!(RemotePeer::new(wrong, connector.clone()).status().is_err());
    let member = authority.identity();
    let member = Connector::new(&member, &authority.der).unwrap();
    assert!(
        process
            .remote(&member)
            .call(Request::Quota(2_000_000))
            .is_err()
    );
    assert_eq!(
        process.remote(&connector).status().unwrap().quota_bytes,
        1_048_576
    );
}
#[test]
fn missing_proof_rejects_real_network_results_and_never_commits_insert_or_update() {
    let authority = Authority::new();
    let owner = authority.identity();
    let connector = Connector::new(&owner, &authority.der).unwrap();
    let mut process = Process::start(&authority, owner.fingerprint(), 1, None);
    let peer = process.remote(&connector);
    let database = storage_client::Database::create(
        "network".into(),
        &[PlainRow {
            age: 18,
            amount: 20,
        }],
        vec![storage_client::Participant {
            id: 1,
            remote: peer.clone(),
        }],
    )
    .unwrap();
    let original = peer.status().unwrap().objects;
    for sql in [
        "SELECT * FROM records",
        "SELECT COUNT(*),SUM(amount) FROM records",
        "INSERT INTO records VALUES (42,30)",
        "UPDATE records SET amount=amount+5",
    ] {
        assert!(
            matches!(
                database.execute(sql),
                Err(storage_client::Error::MissingComputationProof)
            ),
            "{sql}"
        );
    }
    let status = peer.status().unwrap();
    assert_eq!(status.objects.len(), original.len());
    assert_eq!(status.objects[0].id, original[0].id);
    assert_eq!(
        status
            .recent
            .iter()
            .filter(|event| event.operation == "fhe" && event.succeeded)
            .count(),
        4
    );
    process.kill();
    assert!(matches!(
        database.execute("SELECT * FROM records"),
        Err(storage_client::Error::UnavailableShard(1))
    ));
}
#[test]
fn real_disk_tampering_and_quota_failures_never_return_cached_owner_data() {
    let authority = Authority::new();
    let owner = authority.identity();
    let connector = Connector::new(&owner, &authority.der).unwrap();
    let process = Process::start(&authority, owner.fingerprint(), 1, None);
    let peer = process.remote(&connector);
    let (data_owner, _) = backend::Owner::generate(*b"NETWORK-TEST-002").unwrap();
    let (bundle, _) = fixture(&data_owner);
    let object = bundle.id();
    assert!(matches!(
        peer.call(Request::Store(bundle.clone())).unwrap(),
        Response::Stored(_)
    ));
    assert!(peer.call(Request::Quota(1)).is_err());
    let file = fs::read_dir(&process.directory)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().and_then(|e| e.to_str()) == Some("bundle"))
        .unwrap();
    let mut bytes = fs::read(&file).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(file, bytes).unwrap();
    assert!(peer.call(Request::Fetch { object }).is_err());
    assert!(!peer.status().unwrap().objects[0].available);
    assert!(
        peer.call(Request::Store(bundle)).is_err(),
        "An existing corrupt immutable file must never receive a false store acknowledgement"
    );
}

// Public non-secret byte fixtures exercise custody independently of SQL/FHE.
fn page_fixture() -> (compact_store::Owner, Bundle) {
    let owner = compact_store::Owner::generate([63; 16]).unwrap();
    let layout = compact_store::Layout {
        schema: [64; 16],
        row_width: 1,
        rows_per_page: 8,
        row_count: 24,
    };
    let data = owner
        .seal(layout, &(0..24).collect::<Vec<_>>(), Limits::default())
        .unwrap();
    let index = owner
        .seal(
            compact_store::Layout {
                schema: [65; 16],
                ..layout
            },
            &[93; 24],
            Limits::default(),
        )
        .unwrap();
    let bundle = Bundle {
        data_head: data.commitment().encode().to_vec(),
        index_head: index.commitment().encode().to_vec(),
        data: data.encode(),
        index: index.encode(),
    };
    (owner, bundle)
}
fn page_request(bundle: &Bundle) -> peer_runtime::PageBatchRequest {
    use peer_runtime::{PageAddress, PageBatchRequest, PageImage};
    PageBatchRequest::new(
        bundle.id(),
        &compact_store::Commitment::decode(&bundle.data_head, Limits::default()).unwrap(),
        &compact_store::Commitment::decode(&bundle.index_head, Limits::default()).unwrap(),
        &[
            PageAddress {
                image: PageImage::Index,
                index: 0,
            },
            PageAddress {
                image: PageImage::Data,
                index: 2,
            },
        ],
    )
    .unwrap()
}
fn bundle_path(process: &Process, object: &[u8; 32]) -> PathBuf {
    process.directory.join(
        object
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
            + ".bundle",
    )
}
#[test]
fn exact_page_rpc_reads_actual_ciphertext_survives_restart_and_fails_over_to_a_real_replica() {
    use std::sync::{Arc, Mutex};
    let authority = Authority::new();
    let owner_tls = authority.identity();
    let connector = Connector::new(&owner_tls, &authority.der).unwrap();
    let mut first = Process::start(&authority, owner_tls.fingerprint(), 1, None);
    let second = Process::start(&authority, owner_tls.fingerprint(), 2, None);
    let (owner, bundle) = page_fixture();
    let request = page_request(&bundle);
    let traces = Arc::new(Mutex::new(Vec::new()));
    let sink = traces.clone();
    let a = first
        .remote(&connector)
        .with_trace(Arc::new(move |trace| sink.lock().unwrap().push(trace)));
    a.call(Request::Store(bundle.clone())).unwrap();
    second
        .remote(&connector)
        .call(Request::Copy {
            source: first.endpoint.clone(),
            object: bundle.id(),
        })
        .unwrap();
    traces.lock().unwrap().clear();

    let pages = a.fetch_pages(&request).unwrap();

    assert_eq!(
        pages
            .iter()
            .map(|(address, _)| *address)
            .collect::<Vec<_>>(),
        request.addresses()
    );
    assert_eq!(owner.decrypt(&pages[0].1).unwrap().as_bytes(), &[93; 8]);
    assert_eq!(
        owner.decrypt(&pages[1].1).unwrap().as_bytes(),
        &[16, 17, 18, 19, 20, 21, 22, 23]
    );
    let recorded = traces.lock().unwrap();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].operation, "fetch-pages");
    assert!(recorded[0].succeeded);
    assert!(
        recorded[0].response_bytes > 0
            && recorded[0].response_bytes <= peer_runtime::MAX_PAGE_BATCH_RESPONSE_BYTES as u64
    );
    drop(recorded);
    first.kill();
    assert!(a.fetch_pages(&request).is_err());
    let surviving = second.remote(&connector).fetch_pages(&request).unwrap();
    assert_eq!(
        owner.decrypt(&surviving[1].1).unwrap().as_bytes(),
        &[16, 17, 18, 19, 20, 21, 22, 23]
    );
    let restarted = Process::start(
        &authority,
        owner_tls.fingerprint(),
        1,
        Some(first.directory.clone()),
    );
    let restored = restarted.remote(&connector).fetch_pages(&request).unwrap();
    assert_eq!(owner.decrypt(&restored[0].1).unwrap().as_bytes(), &[93; 8]);
}
#[test]
fn page_rpc_preserves_authentication_write_authority_quota_and_exact_object_heads() {
    let authority = Authority::new();
    let owner = authority.identity();
    let connector = Connector::new(&owner, &authority.der).unwrap();
    let process = Process::start(&authority, owner.fingerprint(), 1, None);
    let peer = process.remote(&connector);
    let (_, bundle) = page_fixture();
    let request = page_request(&bundle);
    peer.call(Request::Store(bundle.clone())).unwrap();
    let before = peer.status().unwrap();
    assert!(peer.call(Request::Quota(1)).is_err());
    assert_eq!(peer.status().unwrap().quota_bytes, before.quota_bytes);
    assert_eq!(
        peer.status().unwrap().objects[0].stored_bytes,
        before.objects[0].stored_bytes
    );
    assert!(peer.fetch_pages(&request).is_ok());
    let oversized_owner = compact_store::Owner::generate([66; 16]).unwrap();
    let image = oversized_owner
        .seal(
            compact_store::Layout {
                schema: [67; 16],
                row_width: 1,
                rows_per_page: 65536,
                row_count: 600_000,
            },
            &vec![7; 600_000],
            Limits::default(),
        )
        .unwrap();
    let oversized = Bundle {
        data_head: image.commitment().encode().to_vec(),
        index_head: image.commitment().encode().to_vec(),
        data: image.encode(),
        index: image.encode(),
    };
    let absent = peer_runtime::PageBatchRequest::new(
        oversized.id(),
        image.commitment(),
        image.commitment(),
        &[peer_runtime::PageAddress {
            image: peer_runtime::PageImage::Data,
            index: 0,
        }],
    )
    .unwrap();
    assert!(peer.call(Request::Store(oversized)).is_err());
    assert!(peer.fetch_pages(&absent).is_err());
    assert_eq!(peer.status().unwrap().objects.len(), 1);
    let member = Connector::new(&authority.identity(), &authority.der).unwrap();
    // Authenticated nonowners retain the existing opaque ciphertext-read policy.
    assert!(process.remote(&member).fetch_pages(&request).is_ok());
    assert!(
        process
            .remote(&member)
            .call(Request::Store(bundle.clone()))
            .is_err()
    );
    let foreign = Authority::new();
    let foreign_connector = Connector::new(&foreign.identity(), &foreign.der).unwrap();
    assert!(
        process
            .remote(&foreign_connector)
            .fetch_pages(&request)
            .is_err()
    );
    let mut wrong_pin = process.endpoint.clone();
    wrong_pin.identity[0] ^= 1;
    assert!(
        RemotePeer::new(wrong_pin, connector)
            .fetch_pages(&request)
            .is_err()
    );
    let missing = peer_runtime::PageBatchRequest::new(
        [0; 32],
        request.data_head(),
        request.index_head(),
        request.addresses(),
    )
    .unwrap();
    assert!(peer.fetch_pages(&missing).is_err());
    let (_, other) = page_fixture();
    let wrong_head =
        compact_store::Commitment::decode(&other.index_head, Limits::default()).unwrap();
    let mismatched = peer_runtime::PageBatchRequest::new(
        bundle.id(),
        request.data_head(),
        &wrong_head,
        request.addresses(),
    )
    .unwrap();
    assert!(peer.fetch_pages(&mismatched).is_err());
    // Reading a retained old object is an explicit snapshot read, never 'latest'.
    peer.call(Request::Store(other)).unwrap();
    assert!(peer.fetch_pages(&request).is_ok());
}
#[test]
fn page_rpc_audits_unrequested_bytes_after_store_and_reopen_and_rejects_truncation() {
    let authority = Authority::new();
    let owner = authority.identity();
    let connector = Connector::new(&owner, &authority.der).unwrap();
    let mut process = Process::start(&authority, owner.fingerprint(), 1, None);
    let peer = process.remote(&connector);
    let (_, bundle) = page_fixture();
    let request = page_request(&bundle);
    peer.call(Request::Store(bundle.clone())).unwrap();
    assert!(peer.fetch_pages(&request).is_ok());
    process.kill();
    let restarted = Process::start(
        &authority,
        owner.fingerprint(),
        1,
        Some(process.directory.clone()),
    );
    let peer = restarted.remote(&connector);
    assert!(peer.fetch_pages(&request).is_ok());
    let path = bundle_path(&restarted, &bundle.id());
    let original = fs::read(&path).unwrap();
    let mut damaged = original.clone();
    // Last byte is index page 2, absent from the requested index page 0/data page 2.
    *damaged.last_mut().unwrap() ^= 1;
    fs::write(&path, &damaged).unwrap();

    assert!(peer.fetch_pages(&request).is_err());

    assert!(!peer.status().unwrap().objects[0].available);
    assert!(peer.call(Request::Store(bundle)).is_err());
    fs::write(&path, &original).unwrap();
    assert!(peer.fetch_pages(&request).is_ok());
    fs::write(&path, &original[..original.len() - 1]).unwrap();
    assert!(peer.fetch_pages(&request).is_err());
}

#[test]
fn static_read_image_uses_real_data_prefix_proofs_and_rejects_unrequested_disk_corruption_after_restart()
 {
    let authority = Authority::new();
    let owner_tls = authority.identity();
    let connector = Connector::new(&owner_tls, &authority.der).unwrap();
    let mut process = Process::start(&authority, owner_tls.fingerprint(), 1, None);
    let (owner, bundle) = page_fixture();
    let data_head =
        compact_store::Commitment::decode(&bundle.data_head, Limits::default()).unwrap();
    let index_head =
        compact_store::Commitment::decode(&bundle.index_head, Limits::default()).unwrap();
    let request =
        peer_runtime::ReadImageRequest::new(bundle.id(), &data_head, &index_head, 2).unwrap();
    let remote = process.remote(&connector);
    remote.call(Request::Store(bundle.clone())).unwrap();

    let image = remote.fetch_read_image(&request).unwrap();

    assert_eq!(image.data().encode(), bundle.data);
    assert_eq!(
        owner
            .decrypt(&image.index_page(1, Limits::default()).unwrap())
            .unwrap()
            .as_bytes(),
        &[93; 8]
    );
    assert!(image.index_page(2, Limits::default()).is_err());
    assert!(
        remote
            .status()
            .unwrap()
            .recent
            .iter()
            .any(|event| event.operation == "read-image"
                && event.succeeded
                && event.sent_bytes == request.encoded_response_bytes().unwrap() as u64)
    );
    assert!(remote.call(Request::Quota(1)).is_err());
    let member = Connector::new(&authority.identity(), &authority.der).unwrap();
    assert!(process.remote(&member).fetch_read_image(&request).is_ok());
    assert!(
        process
            .remote(&member)
            .call(Request::Store(bundle.clone()))
            .is_err()
    );
    let foreign = Authority::new();
    let foreign_connector = Connector::new(&foreign.identity(), &foreign.der).unwrap();
    assert!(
        process
            .remote(&foreign_connector)
            .fetch_read_image(&request)
            .is_err()
    );
    let mut wrong_pin = process.endpoint.clone();
    wrong_pin.identity[0] ^= 1;
    assert!(
        RemotePeer::new(wrong_pin, connector.clone())
            .fetch_read_image(&request)
            .is_err()
    );
    let wrong_object =
        peer_runtime::ReadImageRequest::new([0; 32], &data_head, &index_head, 2).unwrap();
    assert!(remote.fetch_read_image(&wrong_object).is_err());
    let wrong_heads =
        peer_runtime::ReadImageRequest::new(bundle.id(), &index_head, &data_head, 2).unwrap();
    assert!(remote.fetch_read_image(&wrong_heads).is_err());
    process.kill();
    let restarted = Process::start(
        &authority,
        owner_tls.fingerprint(),
        1,
        Some(process.directory.clone()),
    );
    let remote = restarted.remote(&connector);
    assert!(remote.fetch_read_image(&request).is_ok());
    let path = bundle_path(&restarted, &bundle.id());
    let mut damaged = fs::read(&path).unwrap();
    // Index page2 is outside this static prefix; complete custody must still reject it.
    *damaged.last_mut().unwrap() ^= 1;
    fs::write(&path, damaged).unwrap();
    assert!(remote.fetch_read_image(&request).is_err());
    assert!(!remote.status().unwrap().objects[0].available);
    assert!(remote.call(Request::Store(bundle)).is_err());
}

// Public, non-secret ciphertext custody fixtures; they do not stand in for SQL proofs.
fn delta_fixture() -> (Bundle, Bundle, peer_runtime::StoreDeltaRequest) {
    use compact_store::{Layout, Owner};
    use peer_runtime::{PageAddress, PageImage, StoreDeltaRequest};
    let limits = Limits::default();
    let owner = Owner::generate([81; 16]).unwrap();
    let layout = Layout {
        schema: [82; 16],
        row_width: 1,
        rows_per_page: 512,
        row_count: 300 * 512 - 3,
    };
    let mut data = owner
        .seal(layout, &vec![7; layout.row_count as usize], limits)
        .unwrap();
    let mut index = owner
        .seal(
            Layout {
                schema: [83; 16],
                ..layout
            },
            &vec![8; layout.row_count as usize],
            limits,
        )
        .unwrap();
    let old_data = data.commitment().clone();
    let old_index = index.commitment().clone();
    let base = Bundle {
        data_head: old_data.encode().to_vec(),
        index_head: old_index.encode().to_vec(),
        data: data.encode(),
        index: index.encode(),
    };
    owner
        .replace_page(&mut data, &old_data, 2, &[9; 512], limits)
        .unwrap();
    owner
        .replace_page(&mut index, &old_index, 299, &[10; 509], limits)
        .unwrap();
    let next = Bundle {
        data_head: data.commitment().encode().to_vec(),
        index_head: index.commitment().encode().to_vec(),
        data: data.encode(),
        index: index.encode(),
    };
    let delta = StoreDeltaRequest::new(
        base.id(),
        &old_data,
        &old_index,
        &next,
        &[
            (
                PageAddress {
                    image: PageImage::Data,
                    index: 2,
                },
                data.lookup(2, limits).unwrap(),
            ),
            (
                PageAddress {
                    image: PageImage::Index,
                    index: 299,
                },
                index.lookup(299, limits).unwrap(),
            ),
        ],
    )
    .unwrap();
    (base, next, delta)
}

#[test]
fn padded_delta_rpc_requires_owner_and_recovers_exact_durable_ciphertext_after_lost_ack_and_restart()
 {
    use std::sync::{Arc, Mutex};
    let authority = Authority::new();
    let owner = authority.identity();
    let connector = Connector::new(&owner, &authority.der).unwrap();
    let mut process = Process::start(&authority, owner.fingerprint(), 1, None);
    let peer = process.remote(&connector);
    peer.call(Request::Quota(16 * 1024 * 1024)).unwrap();
    let (base, next, delta) = delta_fixture();
    peer.call(Request::Store(base.clone())).unwrap();
    let original = fs::read(bundle_path(&process, &base.id())).unwrap();
    let member = Connector::new(&authority.identity(), &authority.der).unwrap();

    assert!(
        process
            .remote(&member)
            .call(Request::StoreDelta(delta.clone()))
            .is_err()
    );
    assert_eq!(peer.status().unwrap().objects.len(), 1);
    assert!(!bundle_path(&process, &next.id()).exists());

    let traces = Arc::new(Mutex::new(Vec::new()));
    let sink = traces.clone();
    let control = peer_transport::RequestControl::default();
    let scope = control.begin().unwrap();
    let cancel = scope.cancellation();
    let cancelled = peer
        .clone()
        .with_control(control)
        .with_activity(Arc::new(move |event| {
            if event.operation == "store-delta"
                && event.phase == peer_runtime::ActivityPhase::ReplyReceived
            {
                cancel.cancel();
            }
        }))
        .with_trace(Arc::new(move |trace| sink.lock().unwrap().push(trace)));

    let error = cancelled
        .call(Request::StoreDelta(delta.clone()))
        .err()
        .expect("Cancellation must report a lost acknowledgement");

    assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
    assert_eq!(peer.status().unwrap().objects.len(), 2);
    assert_eq!(
        fs::read(bundle_path(&process, &base.id())).unwrap(),
        original
    );
    let recorded = traces.lock().unwrap();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].operation, "store-delta");
    assert_eq!(recorded[0].request_bytes, delta.request_bytes() as u64);
    assert!(recorded[0].response_bytes > 0);
    drop(recorded);
    assert!(
        matches!(peer.call(Request::StoreDelta(delta.clone())).unwrap(), Response::Stored(info) if info.id == next.id())
    );
    assert!(
        matches!(peer.call(Request::Fetch { object: next.id() }).unwrap(), Response::Bundle(actual) if actual == next)
    );
    process.kill();
    let restarted = Process::start(
        &authority,
        owner.fingerprint(),
        1,
        Some(process.directory.clone()),
    );
    let peer = restarted.remote(&connector);

    assert!(
        matches!(peer.call(Request::StoreDelta(delta.clone())).unwrap(), Response::Stored(info) if info.id == next.id())
    );
    assert_eq!(peer.status().unwrap().objects.len(), 2);
    let target = bundle_path(&restarted, &next.id());
    let mut damaged = fs::read(&target).unwrap();
    // Last index page is replaced, but this byte is still fully audited on replay.
    *damaged.last_mut().unwrap() ^= 1;
    fs::write(&target, damaged).unwrap();
    assert!(peer.call(Request::StoreDelta(delta)).is_err());
    assert_eq!(
        fs::read(bundle_path(&restarted, &base.id())).unwrap(),
        original
    );
}
