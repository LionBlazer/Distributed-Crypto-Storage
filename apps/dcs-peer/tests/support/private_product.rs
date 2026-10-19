//! Test-only actual process/IPC and public negative-input fixtures. No proof generator.
use bfv_mul_relin_proof::{INPUT_FRAMES, InputEvidence, Provenance};
use bfv_query_core::{CoefficientRow, Geometry, KeyScope, Owner, PublicSetup, QueryContext};
use compact_store::{Layout, Limits};
use p3_field::PrimeCharacteristicRing;
use peer_runtime::{
    ActivityPhase, Bootstrap, Connector, Endpoint, Identity, RawBundle, RemoteError, RemotePeer,
    Request, RequestControl, Response, RpcActivity, Status, Trace,
};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use registry200_proof::{
    Val,
    admission::CanonicalSource,
    coefficient_encoding::statement::{BfvBinding, Expected, Statement},
    source,
};
use sha2::{Digest, Sha256};
use std::{
    io::{self, BufRead, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(super) fn identity() -> Identity {
    let mut params = CertificateParams::new(vec!["dcs-peer".into()]).unwrap();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let key = KeyPair::generate().unwrap();
    let certificate = params.self_signed(&key).unwrap();
    Identity {
        certificate: certificate.der().to_vec(),
        private_key_pkcs8: key.serialize_der(),
    }
}

pub(super) struct Process {
    child: Child,
    endpoint: Endpoint,
}
impl Process {
    pub fn start(owner: [u8; 32], id: u64) -> Self {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../.local/network-tests")
            .join(format!(
                "private-product-{}-{id}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        let mut command = Command::new(env!("CARGO_BIN_EXE_dcs-peer"));
        let threads = std::env::var("DCS_TEST_PEER_THREADS").unwrap_or_else(|_| "2".into());
        assert!(threads.parse::<usize>().is_ok_and(|n| (1..=8).contains(&n)));
        command
            .args(["--state-dir", directory.to_str().unwrap()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .env("RAYON_NUM_THREADS", threads);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let mut child = command.spawn().unwrap();
        let config = Bootstrap {
            identity: identity(),
            authority: vec![],
            owner,
            node_id: id,
            quota_bytes: 16 * 1024 * 1024,
            listen: "127.0.0.1:0".parse().unwrap(),
        };
        let secret = zeroize::Zeroizing::new(serde_json::to_vec(&config).unwrap());
        peer_transport::write_frame(&mut child.stdin.take().unwrap(), &secret, 64 * 1024).unwrap();
        drop(secret);
        drop(config);
        let stdout = child.stdout.take().unwrap();
        let (sent, received) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
            let _ = sent.send(result);
        });
        let endpoint = match received.recv_timeout(Duration::from_secs(20)) {
            Ok(Ok(line)) => match serde_json::from_str(&line) {
                Ok(endpoint) => endpoint,
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    panic!("Invalid daemon startup at {}: {error}", directory.display());
                }
            },
            other => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                panic!(
                    "Daemon startup failed at {}: {other:?}",
                    directory.display()
                );
            }
        };
        reader.join().unwrap();
        assert_ne!(child.id(), std::process::id());
        println!("private_product_peer_pid={}", child.id());
        Self { child, endpoint }
    }
    pub fn pid(&self) -> u32 {
        self.child.id()
    }
    pub fn remote(&self, connector: &Connector) -> RemotePeer {
        RemotePeer::new(self.endpoint.clone(), connector.clone())
    }
    pub fn finish(mut self, remote: &RemotePeer) {
        assert!(matches!(
            remote.call(Request::Shutdown).unwrap(),
            Response::Done
        ));
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(
                Instant::now() < deadline,
                "Peer did not shut down after stream cleanup"
            );
            std::thread::yield_now();
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

pub(super) struct Fixture {
    setup: PublicSetup,
    manifest: Vec<u8>,
    request: Vec<u8>,
    bundle: RawBundle,
}
impl Fixture {
    pub fn public() -> &'static Self {
        static PUBLIC: OnceLock<Fixture> = OnceLock::new();
        PUBLIC.get_or_init(Self::generate)
    }
    fn generate() -> Self {
        // PUBLIC NONSECRET Owner-generated setup, actual sealed N4 ciphertext
        // objects, and actual encrypted ALL-original rows/private truth table.
        // Copen/Key transformed/Cw roots are deliberately UNPROVED math claims.
        // The zero index below has no canonical logical-index proof. Nothing
        // produced here may be treated as Source, Key or Formation authority.
        let rows = [
            CoefficientRow { age: 0, amount: 0 },
            CoefficientRow {
                age: 255,
                amount: 65535,
            },
            CoefficientRow {
                age: 73,
                amount: 4095,
            },
            CoefficientRow {
                age: 128,
                amount: 256,
            },
        ];
        let mut bytes = Vec::new();
        for row in rows {
            bytes.push(row.age);
            bytes.extend_from_slice(&row.amount.to_le_bytes());
        }
        let compact_owner = compact_store::Owner::generate([0x42; 16]).unwrap();
        let limits = source::statement::limits();
        let data = compact_owner
            .seal(
                Layout {
                    schema: source::DATA_SCHEMA,
                    row_width: 3,
                    rows_per_page: 256,
                    row_count: 4,
                },
                &bytes,
                limits,
            )
            .unwrap();
        let index = compact_owner
            .seal(
                Layout {
                    schema: source::INDEX_SCHEMA,
                    row_width: 1,
                    rows_per_page: 4096,
                    row_count: 2336,
                },
                &[0; 2336],
                limits,
            )
            .unwrap();
        let bundle = RawBundle::from_snapshots(&data, &index).unwrap();
        let q = [0xD3; 32];
        let claim = source::Statement::checked_relation(
            source::Relation::CanonicalIndex,
            [&data.encode(), &index.encode()],
            [data.commitment(), index.commitment()],
            q,
            source::statement::encode_digest([Val::from_u8(5); 4]),
            source::statement::encode_digest([Val::from_u8(6); 4]),
        )
        .unwrap();
        let canonical = CanonicalSource::checked_claim(&claim).unwrap();
        let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
        let anchor = owner
            .key_anchor(
                &setup,
                KeyScope {
                    database: [0x42; 16],
                    bfv_key_domain: [0x71; 16],
                    epoch: 11,
                },
            )
            .unwrap()
            .public_anchor()
            .clone();
        let key = bfv_key_transform::Statement {
            expected: bfv_key_transform::Expected {
                descriptor: bfv_key_transform::SetupDescriptor {
                    database: anchor.scope().database,
                    key_domain: anchor.scope().bfv_key_domain,
                    key_epoch: anchor.scope().epoch,
                    public_setup_digest: Sha256::digest(
                        setup.relinearization_material().unwrap().parameters(),
                    )
                    .into(),
                },
                coefficients: anchor.coefficient_commitment().map(Val::from_u64),
            },
            transformed: [Val::from_u8(7); 4],
        };
        let binding = BfvBinding::new(anchor.full_setup_id(), key);
        let encodings = [
            Statement {
                expected: Expected::source(&canonical, binding.clone()).unwrap(),
                encoded: [Val::from_u8(8); 4],
            },
            Statement {
                expected: Expected::private_mask(
                    &canonical,
                    binding,
                    [0xB1; 32],
                    [0xB2; 32],
                    source::statement::encode_digest([Val::from_u8(9); 4]),
                )
                .unwrap(),
                encoded: [Val::from_u8(10); 4],
            },
        ];
        let original = owner
            .encrypt_original_coefficient_rows_for_experiment(&rows)
            .unwrap();
        let prepared = owner
            .prepare_private_coefficient_predicate_for_experiment(
                QueryContext::new([0x22; 16], claim.heads[0], claim.heads[1]),
                q,
                &original,
                &[0xA5; 32],
            )
            .unwrap();
        let ciphertexts = prepared.operand_ciphertexts().unwrap().map(<[u8]>::to_vec);
        let provenance = Provenance::new(setup.clone(), anchor, encodings, ciphertexts).unwrap();
        let manifest = provenance.encode_claim().unwrap();
        Self {
            setup,
            manifest,
            request: prepared.request,
            bundle,
        }
    }
    pub fn object(&self) -> [u8; 32] {
        *self.bundle.target_version().unwrap().object()
    }
    pub fn install(&self, remote: &RemotePeer) {
        assert!(matches!(
            remote
                .call(Request::InstallSetup(self.setup.to_bytes().unwrap()))
                .unwrap(),
            Response::Setup(_)
        ));
        assert!(
            matches!(remote.call(Request::Store(self.bundle.clone())).unwrap(), Response::Stored(info) if info.id == self.object())
        );
    }
    pub fn store_different_source(&self, remote: &RemotePeer) -> [u8; 32] {
        let owner = compact_store::Owner::generate([0x42; 16]).unwrap();
        let data = owner
            .seal(
                Layout {
                    schema: source::DATA_SCHEMA,
                    row_width: 3,
                    rows_per_page: 256,
                    row_count: 4,
                },
                &[0x11; 12],
                Limits::default(),
            )
            .unwrap();
        let index = owner
            .seal(
                Layout {
                    schema: source::INDEX_SCHEMA,
                    row_width: 1,
                    rows_per_page: 4096,
                    row_count: 2336,
                },
                &[0x33; 2336],
                Limits::default(),
            )
            .unwrap();
        let bundle = RawBundle::from_snapshots(&data, &index).unwrap();
        let object = *bundle.target_version().unwrap().object();
        assert!(
            matches!(remote.call(Request::Store(bundle)).unwrap(), Response::Stored(info) if info.id == object)
        );
        object
    }
    pub fn assert_unchanged(&self, remote: &RemotePeer, before: &Status) {
        let after = remote.status().unwrap();
        assert_eq!(after.pid, before.pid);
        assert_eq!(after.disk_bytes(), before.disk_bytes());
        assert_eq!(after.journal_bytes, 0);
        assert_eq!(after.journal_bytes, before.journal_bytes);
        assert_eq!(after.public_setup_bytes, before.public_setup_bytes);
        let objects = |s: &Status| {
            s.objects
                .iter()
                .map(|o| (o.id, o.available, o.stored_bytes))
                .collect::<Vec<_>>()
        };
        assert_eq!(objects(&after), objects(before));
        assert!(
            matches!(remote.call(Request::Fetch { object: self.object() }).unwrap(), Response::RawBundle(bundle) if bundle == self.bundle)
        );
    }
}

pub(super) struct Attempt {
    pub error: io::Error,
    pub activity: Vec<RpcActivity>,
    pub trace: Vec<Trace>,
}
impl Attempt {
    pub fn run(
        remote: &RemotePeer,
        fixture: &Fixture,
        object: [u8; 32],
        cancel_after_input: Option<RequestControl>,
    ) -> Self {
        let activity = Arc::new(Mutex::new(Vec::new()));
        let trace = Arc::new(Mutex::new(Vec::new()));
        let events = activity.clone();
        let traces = trace.clone();
        let writes = AtomicUsize::new(0);
        let observed = remote
            .clone()
            .with_activity(Arc::new(move |event| {
                let sent = event.phase == ActivityPhase::RequestSent;
                events.lock().unwrap().push(event);
                if sent
                    && writes.fetch_add(1, Ordering::Relaxed) == 1
                    && let Some(control) = &cancel_after_input
                {
                    assert!(control.cancel());
                }
            }))
            .with_trace(Arc::new(move |event| {
                traces.lock().unwrap().push(event);
            }));
        let provenance =
            Provenance::decode_claim(fixture.setup.clone(), &fixture.manifest).unwrap();
        let dummy = [1u8];
        let inputs = InputEvidence::from_frames([&dummy; INPUT_FRAMES]).unwrap();
        let error = observed
            .prove_private_product(object, provenance, &fixture.request, &inputs)
            .err()
            .expect("Invalid proof inputs/cancelled start must never yield CheckedPrivateProduct");
        let activity = activity.lock().unwrap().clone();
        let trace = trace.lock().unwrap().clone();
        Self {
            error,
            activity,
            trace,
        }
    }
    pub fn sent_frames(&self) -> usize {
        self.activity
            .iter()
            .filter(|e| e.phase == ActivityPhase::RequestSent)
            .count()
    }
    pub fn received_sizes(&self) -> Vec<u64> {
        self.activity
            .iter()
            .filter(|e| e.phase == ActivityPhase::ReplyReceived)
            .map(|e| e.bytes)
            .collect()
    }
    pub fn request_id(&self) -> u64 {
        assert_eq!(self.trace.len(), 1);
        self.trace[0].request_id
    }
    pub fn assert_failed_trace(&self) {
        assert_eq!(self.trace.len(), 1);
        let trace = &self.trace[0];
        assert_eq!(trace.operation, "private-product");
        assert!(!trace.succeeded);
        assert!(
            self.activity
                .iter()
                .all(|event| event.operation == "private-product"
                    && event.request_id == trace.request_id)
        );
        assert_eq!(
            trace.request_bytes,
            self.activity
                .iter()
                .filter(|e| e.phase == ActivityPhase::RequestSent)
                .map(|e| e.bytes)
                .sum::<u64>()
        );
        assert_eq!(
            trace.response_bytes,
            self.received_sizes().iter().sum::<u64>()
        );
    }
    fn assert_semantic_rejection(&self) {
        assert_eq!(self.error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(self.error.to_string(), "peer rejected private product");
        self.assert_failed_trace();
    }
    pub fn assert_start_rejected(&self) {
        self.assert_semantic_rejection();
        assert_eq!(self.sent_frames(), 1);
        assert_eq!(self.received_sizes(), vec![97]);
    }
    pub fn assert_all_inputs_rejected(&self) {
        self.assert_semantic_rejection();
        assert_eq!(self.sent_frames(), 1 + INPUT_FRAMES);
        assert_eq!(self.received_sizes(), vec![96, 97]); // Ready then FAILED, no Output/claims.
        assert!(
            self.activity
                .iter()
                .filter(|e| e.phase == ActivityPhase::RequestSent)
                .skip(1)
                .all(|event| event.bytes == 97)
        );
    }
}

fn busy(error: &io::Error) -> bool {
    matches!(
        error
            .get_ref()
            .and_then(|e| e.downcast_ref::<RemoteError>()),
        Some(RemoteError::Busy)
    )
}
pub(super) fn until_not_busy(remote: &RemotePeer, fixture: &Fixture, object: [u8; 32]) -> Attempt {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let attempt = Attempt::run(remote, fixture, object, None);
        if !busy(&attempt.error) {
            return attempt;
        }
        attempt.assert_failed_trace();
        assert!(
            Instant::now() < deadline,
            "Private product permit was not released"
        );
        assert!(
            remote.status().is_ok(),
            "Busy must not conceal an unreachable peer"
        );
        std::thread::yield_now();
    }
}
pub(super) fn wait_for_failed_observation(remote: &RemotePeer, attempt: &Attempt, before: &Status) {
    let deadline = Instant::now() + Duration::from_secs(10);
    let trace = &attempt.trace[0];
    let old = before.recent.iter().map(|o| o.sequence).max().unwrap_or(0);
    loop {
        let status = remote.status().unwrap();
        if status.recent.iter().any(|o| {
            o.sequence > old
                && o.operation == "private-product"
                && !o.succeeded
                && o.received_bytes == trace.request_bytes
                && o.sent_bytes == trace.response_bytes
        }) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "Server did not account for the rejected input stream"
        );
        std::thread::yield_now();
    }
}
