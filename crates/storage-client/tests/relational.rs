//! Public fixtures over actual TLS sockets and the public peer proof service.
//! Process deployment is independently covered by the playground process tests.
use peer_runtime::{Bootstrap, Connector, Identity, PeerServer, RemotePeer, RunningServer};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use relational_types::{ImportLimits, Value, import_database_dump};
use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use storage_client::{Participant, relational::RelationalSession};
use version_journal::{ProtocolProfile, Target};

fn identity() -> Identity {
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

fn test_profile() -> ProtocolProfile {
    // This deliberately easy local profile tests protocol behavior, not an
    // adversarial mining budget or production confirmation security.
    ProtocolProfile {
        initial_target: Target([0x0f; 32]),
        pow_limit: Target([0x0f; 32]),
        block_spacing_secs: 1,
        retarget_interval: 1024,
        max_future_secs: 30,
        confirmation_depth: 1,
        max_headers: 256,
        max_shards: 16,
        max_updates: 16,
        max_body_bytes: 32 * 1024 * 1024,
        max_request_bytes: 32 * 1024 * 1024,
        max_proof_bytes: 32 * 1024 * 1024,
        max_journal_bytes: 256 * 1024 * 1024,
    }
}

struct Network {
    directory: PathBuf,
    servers: Vec<RunningServer>,
    participants: Vec<Participant>,
    activity: Arc<Mutex<Vec<String>>>,
}
impl Network {
    fn new() -> Self {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../.local/relational-client-tests")
            .join(format!(
                "{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        fs::create_dir_all(&directory).unwrap();
        let owner = identity();
        let connector = Connector::permissionless(&owner).unwrap();
        let activity = Arc::new(Mutex::new(Vec::new()));
        let mut servers = Vec::new();
        let mut participants = Vec::new();
        for id in 1..=2 {
            let server = PeerServer::bind(
                Bootstrap {
                    identity: identity(),
                    authority: Vec::new(),
                    owner: owner.fingerprint(),
                    node_id: id,
                    quota_bytes: 32 * 1024 * 1024,
                    listen: "127.0.0.1:0".parse().unwrap(),
                },
                &directory.join(id.to_string()),
            )
            .unwrap()
            .spawn()
            .unwrap();
            let observed = activity.clone();
            participants.push(Participant {
                id,
                remote: RemotePeer::new(server.endpoint.clone(), connector.clone()).with_trace(
                    Arc::new(move |trace| {
                        observed.lock().unwrap().push(trace.operation);
                    }),
                ),
            });
            servers.push(server);
        }
        Self {
            directory,
            servers,
            participants,
            activity,
        }
    }

    fn damage_bundle(&self, peer: usize, object: [u8; 32]) {
        let name = object
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
            + ".bundle";
        let path = self.directory.join((peer + 1).to_string()).join(name);
        let mut ciphertext = fs::read(&path).unwrap();
        *ciphertext.last_mut().unwrap() ^= 1;
        fs::write(path, ciphertext).unwrap();
    }
}
impl Drop for Network {
    fn drop(&mut self) {
        for server in &mut self.servers {
            server.stop();
        }
        self.servers.clear();
        // Only this fixture's uniquely created child directory is owned here.
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn controlled_peers(
    network: &Network,
    control: &peer_runtime::RequestControl,
    operation: &'static str,
) -> Vec<Participant> {
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(true));
    network
        .participants
        .iter()
        .map(|peer| {
            let requests = control.clone();
            let armed = armed.clone();
            Participant {
                id: peer.id,
                remote: peer
                    .remote
                    .clone()
                    .with_control(control.clone())
                    .with_activity(Arc::new(move |event| {
                        if event.operation == operation
                            && event.phase == peer_runtime::ActivityPhase::RequestSent
                            && requests.current().is_some()
                            && armed.swap(false, std::sync::atomic::Ordering::AcqRel)
                        {
                            requests.cancel();
                        }
                    })),
            }
        })
        .collect()
}

#[test]
fn cancelling_a_proved_read_interrupts_its_rpc_without_poisoning_the_next_query() {
    let network = Network::new();
    let control = peer_runtime::RequestControl::default();
    let database=import_database_dump("CREATE TABLE notes (id INT NOT NULL, body NVARCHAR(30) NOT NULL); INSERT INTO notes VALUES (1,'public fixture');",ImportLimits::default()).unwrap();
    let mut session = RelationalSession::import(
        database,
        controlled_peers(&network, &control, "fhe-proof"),
        test_profile(),
    )
    .unwrap();
    let scope = control.begin().unwrap();

    let stopped = session.select("SELECT body FROM notes;");

    assert!(
        matches!(stopped,Err(storage_client::Error::Transport(ref error)) if error.kind()==std::io::ErrorKind::Interrupted)
    );
    assert!(scope.cancellation().is_cancelled());
    drop(scope);
    let answer = session.select("SELECT body FROM notes;").unwrap();
    assert_eq!(
        answer.rows,
        vec![vec![Value::Text("public fixture".into())]]
    );
    assert_eq!(answer.proof_blocks, 1);
}

#[test]
fn stopping_write_publication_retains_the_exact_mutation_for_single_application_recovery() {
    let network = Network::new();
    let control = peer_runtime::RequestControl::default();
    let mut session = storage_client::Session::create(
        "cancel-write".into(),
        &[compact_query::PlainRow {
            age: 18,
            amount: 20,
        }],
        controlled_peers(&network, &control, "journal-publish"),
        test_profile(),
    )
    .unwrap();
    let scope = control.begin().unwrap();

    let stopped = session.execute("UPDATE records SET amount = amount + 5;");

    assert!(
        matches!(stopped, Err(storage_client::Error::PendingMutation { .. })),
        "publication cancellation must preserve an ambiguous authorized write"
    );
    assert!(scope.cancellation().is_cancelled());
    drop(scope);
    assert!(matches!(
        session.resume_pending().unwrap(),
        Some(storage_client::VerifiedResult::Updated {
            changed_rows: 1,
            ..
        })
    ));
    let storage_client::VerifiedResult::Selected { rows, .. } =
        session.execute("SELECT amount FROM records;").unwrap()
    else {
        panic!("verified rows")
    };
    assert_eq!(
        rows,
        vec![vec![25]],
        "resuming must not repeat the addition"
    );
    assert!(session.resume_pending().unwrap().is_none());
}

fn large_public_dump() -> String {
    let mut sql = String::from(
        "CREATE TABLE accounts (id INT NOT NULL, label NVARCHAR(120) NOT NULL, region NVARCHAR(16) NULL, balance DECIMAL(10,2) NOT NULL, payload VARBINARY(4) NOT NULL);\n",
    );
    for id in 1..=300 {
        let region = if id % 3 == 0 {
            "NULL"
        } else if id % 2 == 0 {
            "'East'"
        } else {
            "'West'"
        };
        sql.push_str(&format!(
            "INSERT INTO accounts VALUES ({id},'public-fixture-{id:03}-{}',{region},{id}.25,0x00ff);\n",
            "abcdefghij".repeat(7)
        ));
    }
    sql.push_str(
        "CREATE TABLE catalog (code INT NOT NULL, item NVARCHAR(20) NOT NULL); INSERT INTO catalog VALUES (10,'one'),(20,'two');",
    );
    sql
}

#[test]
fn typed_tables_stream_more_than_128_rows_with_real_proofs_and_complete_private_indices() {
    let network = Network::new();
    let database = import_database_dump(&large_public_dump(), ImportLimits::default()).unwrap();
    let mut session =
        RelationalSession::import(database, network.participants.clone(), test_profile()).unwrap();
    assert_eq!(session.rows(), 302);
    assert_eq!(session.schemas().len(), 2);
    assert_eq!(session.shards()[0].rows, 300);

    // Unsupported typed mutations must fail before any peer I/O, preserving the
    // imported catalog instead of silently running them on the owner in plaintext.
    network.activity.lock().unwrap().clear();
    assert!(session.select("UPDATE accounts SET id = 0").is_err());
    assert!(network.activity.lock().unwrap().is_empty());

    let selected = session
        .select("SELECT id, label, balance, payload FROM accounts ORDER BY id")
        .unwrap();

    assert_eq!(selected.columns, ["id", "label", "balance", "payload"]);
    assert_eq!(selected.rows.len(), 300);
    assert!(
        selected.proof_blocks > 1,
        "Large rows must stream beyond a single FHE block"
    );
    for (ordinal, row) in selected.rows.iter().enumerate() {
        let id = ordinal as i64 + 1;
        assert_eq!(
            row,
            &vec![
                Value::Integer(id),
                Value::Text(format!("public-fixture-{id:03}-{}", "abcdefghij".repeat(7))),
                Value::Decimal {
                    unscaled: i128::from(id) * 100 + 25,
                    scale: 2
                },
                Value::Binary(vec![0, 255]),
            ]
        );
    }
    assert_eq!(
        network
            .activity
            .lock()
            .unwrap()
            .iter()
            .filter(|operation| *operation == "fhe-proof")
            .count(),
        selected.proof_blocks
    );
    let filtered = session.select("SELECT id FROM accounts WHERE region IS NULL OR (region = 'East' AND id >= 294) ORDER BY id DESC LIMIT 5").unwrap();
    assert_eq!(
        filtered.rows,
        [300, 298, 297, 296, 294].map(|id| vec![Value::Integer(id)])
    );
    assert_eq!(filtered.version.state_root, selected.version.state_root);
    let other = session
        .select("SELECT item FROM catalog WHERE code = 20")
        .unwrap();
    assert_eq!(other.rows, vec![vec![Value::Text("two".into())]]);
    let empty = session
        .select("SELECT id FROM accounts WHERE id < 0")
        .unwrap();
    assert!(empty.rows.is_empty());
    assert_eq!(
        empty.proof_blocks, 1,
        "An empty match still requires genuine evidence"
    );
    for (sql, expected) in [
        (
            "SELECT id FROM accounts WHERE id >= 294 AND NOT (region = 'East' OR id = 295) ORDER BY id",
            vec![299],
        ),
        (
            "SELECT id FROM accounts WHERE id >= 294 AND NOT (region = 'East' AND id < 296) ORDER BY id",
            vec![295, 296, 297, 298, 299, 300],
        ),
    ] {
        let selected = session.select(sql).unwrap();
        assert_eq!(
            selected.rows,
            expected
                .into_iter()
                .map(|id| vec![Value::Integer(id)])
                .collect::<Vec<_>>(),
            "SQL UNKNOWN must survive nested boolean negation: {sql}"
        );
    }
}

#[test]
fn proved_projection_uses_postgresql_null_order_before_applying_limit() {
    let network = Network::new();
    let database = import_database_dump(
        "CREATE TABLE ranks (id INT NOT NULL, score INT NULL); INSERT INTO ranks VALUES (1,NULL),(2,10),(3,-5),(4,NULL),(5,10);",
        ImportLimits::default(),
    )
    .unwrap();
    let mut session =
        RelationalSession::import(database, network.participants.clone(), test_profile()).unwrap();
    for (tail, expected) in [
        ("ORDER BY score LIMIT 1", vec![3]),
        ("ORDER BY score DESC LIMIT 2", vec![1, 4]),
        ("ORDER BY score ASC NULLS FIRST LIMIT 2", vec![1, 4]),
        ("ORDER BY score DESC NULLS LAST LIMIT 3", vec![2, 5, 3]),
        ("ORDER BY score NULLS FIRST, id DESC", vec![4, 1, 3, 5, 2]),
    ] {
        let sql = format!("SELECT id FROM ranks {tail}");
        network.activity.lock().unwrap().clear();
        let selected = session.select(&sql).unwrap();
        assert_eq!(
            selected.rows,
            expected
                .into_iter()
                .map(|id| vec![Value::Integer(id)])
                .collect::<Vec<_>>(),
            "{sql}"
        );
        assert_eq!(selected.proof_blocks, 1);
        assert_eq!(
            network
                .activity
                .lock()
                .unwrap()
                .iter()
                .filter(|operation| *operation == "fhe-proof")
                .count(),
            1,
            "{sql} must obtain real encrypted projection evidence"
        );
    }
}

#[test]
fn damaged_replicas_cannot_silently_omit_rows_or_return_an_unproved_empty_result() {
    let network = Network::new();
    let database = import_database_dump(
        "CREATE TABLE names (id INT NOT NULL, name NVARCHAR(20) NULL); INSERT INTO names VALUES (1,'first'),(2,NULL),(3,'last');",
        ImportLimits::default(),
    )
    .unwrap();
    let mut session =
        RelationalSession::import(database, network.participants.clone(), test_profile()).unwrap();
    let object = session.shards()[0].object;
    network.damage_bundle(0, object);

    let complete = session.select("SELECT * FROM names ORDER BY id").unwrap();

    assert_eq!(
        complete.rows,
        vec![
            vec![Value::Integer(1), Value::Text("first".into())],
            vec![Value::Integer(2), Value::Null],
            vec![Value::Integer(3), Value::Text("last".into())],
        ]
    );
    assert_eq!(complete.proof_blocks, 1);
    network.damage_bundle(1, object);
    assert!(matches!(
        session.select("SELECT * FROM names"),
        Err(storage_client::Error::UnavailableShard(1))
    ));
}

#[test]
fn malformed_owner_tables_are_rejected_before_creating_keys_or_writing_peer_state() {
    use relational_types::{DataType, ImportedDatabase};
    let network = Network::new();
    let original = import_database_dump(
        "CREATE TABLE inputs (id INT NOT NULL, label NVARCHAR(20) NOT NULL, payload VARBINARY(4) NOT NULL); INSERT INTO inputs VALUES (1,'public',0x00ff);",
        ImportLimits::default(),
    )
    .unwrap();
    type Malformation = (&'static str, fn(&mut ImportedDatabase));
    let malformed_cases: [Malformation; 7] = [
        ("missing cell", |database| {
            database.tables[0].rows[0].pop();
        }),
        ("wrong value type", |database| {
            database.tables[0].rows[0][0] = Value::Text("one".into());
        }),
        ("invalid integer width", |database| {
            database.tables[0].schema.columns[0].data_type = DataType::Integer {
                bits: 0,
                signed: true,
            };
        }),
        ("duplicate column", |database| {
            database.tables[0].schema.columns[1].name = "id".into();
        }),
        ("invalid primary-key ordinal", |database| {
            database.tables[0].schema.primary_key = vec![usize::MAX];
        }),
        ("oversized binary cell", |database| {
            database.tables[0].rows[0][2] = Value::Binary(vec![0; 5]);
        }),
        ("duplicate table", |database| {
            database.tables.push(database.tables[0].clone());
        }),
    ];
    network.activity.lock().unwrap().clear();

    for (case, modify) in malformed_cases {
        let mut database = original.clone();
        modify(&mut database);

        let result =
            RelationalSession::import(database, network.participants.clone(), test_profile());

        assert!(
            matches!(result, Err(storage_client::Error::InvalidInput(_))),
            "Malformed import accepted or failed after admission: {case}"
        );
        assert!(
            network.activity.lock().unwrap().is_empty(),
            "Malformed import reached a peer: {case}"
        );
    }
    for peer in &network.participants {
        let status = peer.remote.status().unwrap();
        assert!(status.objects.is_empty());
        assert_eq!(status.public_setup_bytes, 0);
        assert_eq!(status.journal_bytes, 0);
    }
}
