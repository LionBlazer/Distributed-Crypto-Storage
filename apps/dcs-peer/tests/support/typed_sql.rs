//! Genuine typed reads across independently running peers; public source fixtures only.
use super::*;
use peer_runtime::{ActivityPhase, RpcActivity, Trace};
use relational_types::{ImportLimits, Value, import_database_dump};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Condvar, Mutex},
};
use storage_client::relational::RelationalSession;

#[derive(Default)]
struct Observed {
    sent: BTreeMap<u64, usize>,
    active: BTreeSet<(u64, u64)>,
    maximum: usize,
    calls: Vec<(u64, String, bool)>,
    timed_out: bool,
}
impl Observed {
    fn total_proofs(&self) -> usize {
        self.sent.values().sum()
    }
}

struct TypedPeers {
    first: Process,
    _second: Process,
    session: RelationalSession,
    observed: Arc<(Mutex<Observed>, Condvar)>,
    control: peer_runtime::RequestControl,
}

fn public_dump() -> String {
    let mut sql = String::from(
        "CREATE TABLE typed_rows (id INT NOT NULL, label NVARCHAR(120) NOT NULL, region NVARCHAR(8) NULL, payload VARBINARY(2) NOT NULL);",
    );
    for id in 1..=300 {
        sql.push_str(&format!(
            "INSERT INTO typed_rows VALUES ({id},'public-{id:03}-{}é',NULL,0x00ff);",
            "abcdefghij".repeat(7)
        ));
    }
    sql
}
const SQL: &str = "SELECT label, id, payload FROM typed_rows ORDER BY id DESC";
fn assert_rows(answer: &storage_client::relational::Selected) {
    assert_eq!(answer.columns, ["label", "id", "payload"]);
    assert!(
        answer.proof_blocks > 2,
        "Public cells must cross several independently bound chunks"
    );
    assert_eq!(
        answer.rows,
        (1..=300)
            .rev()
            .map(|id| vec![
                Value::Text(format!("public-{id:03}-{}é", "abcdefghij".repeat(7))),
                Value::Integer(id),
                Value::Binary(vec![0, 255]),
            ])
            .collect::<Vec<_>>()
    );
}

fn start(gate_first_pair: bool, cancel_later_first_peer: bool) -> TypedPeers {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let first = Process::start(owner.fingerprint(), 1, None);
    let second = Process::start(owner.fingerprint(), 2, None);
    if std::env::var_os("DCS_TEST_TYPED_PIDS").is_some() {
        for (role, pid) in [
            ("owner", std::process::id()),
            ("peer-1", first.child.id()),
            ("peer-2", second.child.id()),
        ] {
            println!(
                "owned_typed_process={}",
                serde_json::json!({"role":role,"pid":pid})
            );
        }
    }
    let observed = Arc::new((Mutex::new(Observed::default()), Condvar::new()));
    let control = peer_runtime::RequestControl::default();
    let mut participants = Vec::new();
    for (id, process) in [(1, &first), (2, &second)] {
        let mut peer = process.participant(id, &connector);
        // Only the first peer's socket is cancellable. Falling back after its
        // Interrupted error would incorrectly turn cancellation into success.
        if id == 1 {
            peer.remote = peer.remote.with_control(control.clone());
        }
        let state = observed.clone();
        let cancellation = control.clone();
        peer.remote = peer
            .remote
            .with_activity(Arc::new(move |event: RpcActivity| {
                if event.operation != "fhe-proof" || event.phase != ActivityPhase::RequestSent {
                    return;
                }
                let (lock, changed) = &*state;
                let mut observation = lock.lock().unwrap();
                *observation.sent.entry(id).or_default() += 1;
                assert!(observation.active.insert((id, event.request_id)));
                observation.maximum = observation.maximum.max(observation.active.len());
                changed.notify_all();
                if gate_first_pair && observation.total_proofs() <= 2 {
                    let (mut ready, timeout) = changed
                        .wait_timeout_while(observation, Duration::from_secs(10), |observation| {
                            observation.total_proofs() < 2
                        })
                        .unwrap();
                    ready.timed_out |= timeout.timed_out();
                    observation = ready;
                }
                let cancel = cancel_later_first_peer && id == 1 && observation.sent[&id] == 2;
                drop(observation);
                if cancel && cancellation.current().is_some() {
                    cancellation.cancel();
                }
            }));
        let state = observed.clone();
        peer.remote = peer.remote.with_trace(Arc::new(move |trace: Trace| {
            let mut observation = state.0.lock().unwrap();
            assert!(observation.calls.len() < 1024, "Fixture metadata budget");
            observation.active.remove(&(id, trace.request_id));
            observation
                .calls
                .push((id, trace.operation, trace.succeeded));
        }));
        participants.push(peer);
    }
    let database = import_database_dump(&public_dump(), ImportLimits::default()).unwrap();
    let session = RelationalSession::import(database, participants, test_contract()).unwrap();
    *observed.0.lock().unwrap() = Observed::default();
    TypedPeers {
        first,
        _second: second,
        session,
        observed,
        control,
    }
}

#[test]
fn typed_300_row_select_accepts_complete_ordered_proved_bytes() {
    let mut peers = start(false, false);
    let started = Instant::now();

    let answer = peers.session.select(SQL).unwrap();

    eprintln!(
        "accepted_typed_sql_ms={:.3} proof_blocks={} rows={}",
        started.elapsed().as_secs_f64() * 1000.,
        answer.proof_blocks,
        answer.rows.len()
    );
    assert_rows(&answer);
    let observation = peers.observed.0.lock().unwrap();
    assert_eq!(observation.total_proofs(), answer.proof_blocks);
    assert!(observation.active.is_empty());
}

#[test]
fn typed_postgresql_windows_prove_offset_empty_and_null_peer_groups_after_holder_loss() {
    let mut peers = start(false, false);
    let initial = peers.session.version();
    for (tail, ids) in [
        ("ORDER BY id DESC LIMIT 1 OFFSET 298", vec![2]),
        ("ORDER BY id DESC OFFSET 299 ROWS LIMIT ALL", vec![1]),
        ("ORDER BY id DESC FETCH FIRST ROW ONLY OFFSET 298", vec![2]),
        (
            "WHERE id <= 5 ORDER BY region FETCH FIRST ROW WITH TIES",
            vec![1, 2, 3, 4, 5],
        ),
        ("ORDER BY id OFFSET 300 FETCH NEXT ROW ONLY", vec![]),
    ] {
        *peers.observed.0.lock().unwrap() = Observed::default();

        let answer = peers
            .session
            .select(&format!("SELECT id FROM typed_rows {tail}"))
            .unwrap();

        assert_eq!(
            answer.rows,
            ids.into_iter()
                .map(|id| vec![Value::Integer(id)])
                .collect::<Vec<_>>(),
            "{tail}"
        );
        assert_eq!(answer.version, initial);
        assert_eq!(answer.proof_blocks, 1);
        assert_eq!(peers.observed.0.lock().unwrap().total_proofs(), 1);
    }
    peers.first.kill();
    *peers.observed.0.lock().unwrap() = Observed::default();

    let answer = peers.session.select("SELECT id FROM typed_rows WHERE id <= 5 ORDER BY region, id DESC OFFSET 1 FETCH NEXT 2 ROWS WITH TIES").unwrap();

    assert_eq!(
        answer.rows,
        vec![vec![Value::Integer(4)], vec![Value::Integer(3)]]
    );
    assert_eq!(answer.version, initial);
    assert_eq!(answer.proof_blocks, 1);
    let observed = peers.observed.0.lock().unwrap();
    assert_eq!(observed.sent.get(&2), Some(&1));
    assert_eq!(
        observed
            .calls
            .iter()
            .filter(|(peer, _, _)| *peer == 1)
            .count(),
        1
    );
    assert!(observed.active.is_empty());
}

#[test]
fn typed_byte_workers_use_two_holders_and_preserve_cross_chunk_order() {
    let mut peers = start(true, false);

    let answer = peers.session.select(SQL).unwrap();

    assert_rows(&answer);
    let observation = peers.observed.0.lock().unwrap();
    assert!(
        !observation.timed_out,
        "Both actual proof requests must reach distinct peers before reply reads"
    );
    assert_eq!(observation.sent.len(), 2);
    assert_eq!(observation.total_proofs(), answer.proof_blocks);
    assert_eq!(observation.maximum, 2);
    assert!(observation.active.is_empty());
}

#[test]
fn stopped_typed_holder_is_attempted_once_per_query_and_survivor_proves_every_block() {
    let mut peers = start(false, false);
    peers.first.kill();
    for _ in 0..2 {
        *peers.observed.0.lock().unwrap() = Observed::default();

        let answer = peers.session.select(SQL).unwrap();

        assert_rows(&answer);
        let observation = peers.observed.0.lock().unwrap();
        let failed: Vec<_> = observation
            .calls
            .iter()
            .filter(|(peer, _, _)| *peer == 1)
            .collect();
        assert_eq!(
            failed.len(),
            1,
            "A new query retries once; no repeated dead-endpoint RPC in freshness/fetch/proofs"
        );
        assert!(!failed[0].2);
        assert_eq!(
            answer.version.state_root,
            peers.session.version().state_root
        );
        assert_eq!(
            observation
                .calls
                .iter()
                .filter(|(peer, operation, success)| *peer == 2
                    && operation == "journal-sync"
                    && *success)
                .count(),
            2,
            "Initial and final freshness need actual surviving-peer responses"
        );
        assert_eq!(observation.sent.get(&2), Some(&answer.proof_blocks));
        assert_eq!(
            observation.maximum, 1,
            "Same-endpoint proof RPCs must remain queued"
        );
        assert!(observation.active.is_empty());
    }
}

#[test]
fn cancelling_a_later_typed_block_joins_workers_and_never_falls_back_after_interrupted() {
    let mut peers = start(false, true);
    let initial = peers.session.version();
    let scope = peers.control.begin().unwrap();

    let stopped = peers.session.select(SQL);

    assert!(
        matches!(stopped, Err(storage_client::Error::Transport(ref error)) if error.kind() == std::io::ErrorKind::Interrupted)
    );
    assert!(scope.cancellation().is_cancelled());
    assert_eq!(peers.session.version(), initial);
    {
        let observation = peers.observed.0.lock().unwrap();
        assert_eq!(
            observation.total_proofs(),
            4,
            "No later batch or fallback onto the uncancelled second peer"
        );
        assert_eq!(observation.sent.get(&2), Some(&2));
        assert!(
            observation.active.is_empty(),
            "Every admitted client worker completed its Trace before returning"
        );
    }
    drop(scope);
    *peers.observed.0.lock().unwrap() = Observed::default();
    assert_rows(&peers.session.select(SQL).unwrap());
}
