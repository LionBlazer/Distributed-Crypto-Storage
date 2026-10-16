//! Actual reply cancellation before acceptance, with an uncancelled second peer.
use super::*;
use peer_runtime::{ActivityPhase, JournalBlock, RawBundle, RpcActivity, Trace};
use peer_transport::RequestControl;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use version_journal::{Body, HeadRef, Header};

const INSERT: &str = "INSERT INTO records(age,amount) VALUES(42,7)";
const MAX_OBSERVATIONS: usize = 256;

#[derive(Default)]
struct Observations {
    cancel_at: Option<(u64, &'static str)>,
    stores_before_arming: usize,
    store_acks: usize,
    cancelled: Option<(u64, String, u64)>,
    sent: Vec<(u64, String)>,
    sent_after_cancel: Vec<(u64, String)>,
    finished: Vec<(u64, String, u64, bool)>,
}
impl Observations {
    fn activity(&mut self, peer: u64, event: RpcActivity) -> bool {
        if event.phase == ActivityPhase::RequestSent {
            assert!(self.sent.len() < MAX_OBSERVATIONS);
            self.sent.push((peer, event.operation.clone()));
            if self.cancelled.is_some() {
                self.sent_after_cancel.push((peer, event.operation));
            }
        } else if self.cancelled.is_none()
            && self.store_acks >= self.stores_before_arming
            && self
                .cancel_at
                .is_some_and(|(target, operation)| target == peer && operation == event.operation)
        {
            self.cancelled = Some((peer, event.operation, event.request_id));
            return true;
        }
        false
    }
    fn trace(&mut self, peer: u64, event: Trace) {
        assert!(self.finished.len() < MAX_OBSERVATIONS);
        if event.operation == "store" && event.succeeded {
            self.store_acks += 1;
        }
        self.finished
            .push((peer, event.operation, event.request_id, event.succeeded));
    }
    fn count(&self, operation: &str) -> usize {
        self.sent
            .iter()
            .filter(|(_, name)| name == operation)
            .count()
    }
    fn assert_stopped(&self, peer: u64, operation: &str) {
        let (actual_peer, actual_operation, id) =
            self.cancelled.as_ref().expect("real reply received");
        assert_eq!((*actual_peer, actual_operation.as_str()), (peer, operation));
        assert!(
            self.finished.iter().any(|(p, op, request, success)| {
                *p == peer && op == operation && request == id && !success
            }),
            "The actual reply must become a transport cancellation"
        );
        assert!(
            self.sent_after_cancel.is_empty(),
            "No post-cancel request: {:?}",
            self.sent_after_cancel
        );
    }
}

struct Peers {
    session: Session,
    control: RequestControl,
    observations: Arc<Mutex<Observations>>,
    administrators: [RemotePeer; 2],
    _processes: [Process; 2],
}
impl Peers {
    fn new(cancel_peer: u64) -> Self {
        let owner = identity();
        let connector = Connector::permissionless(&owner).unwrap();
        let processes = [
            Process::start(owner.fingerprint(), 1, None),
            Process::start(owner.fingerprint(), 2, None),
        ];
        let control = RequestControl::default();
        let observations = Arc::new(Mutex::new(Observations::default()));
        let administrators = [
            processes[0].participant(1, &connector).remote,
            processes[1].participant(2, &connector).remote,
        ];
        let participants: Vec<_> = administrators
            .iter()
            .enumerate()
            .map(|(slot, admin)| {
                let id = slot as u64 + 1;
                let mut remote = admin.clone();
                // Only the chosen endpoint has this token. The other actual peer
                // remains usable, so ignoring Interrupted would expose failover.
                if id == cancel_peer {
                    remote = remote.with_control(control.clone());
                }
                let observed = observations.clone();
                let cancel = control.clone();
                remote = remote.with_activity(Arc::new(move |event| {
                    let cancelled = observed.lock().unwrap().activity(id, event);
                    if cancelled {
                        cancel.cancel();
                    }
                }));
                let observed = observations.clone();
                remote = remote.with_trace(Arc::new(move |event| {
                    observed.lock().unwrap().trace(id, event)
                }));
                Participant { id, remote }
            })
            .collect();
        let mut session = Session::create(
            "cancel-synchronization".into(),
            &[PlainRow {
                age: 18,
                amount: 10,
            }],
            vec![participants[0].clone()],
            test_contract(),
        )
        .unwrap();
        session
            .copy_shard(session.shards()[0].id, participants[1].clone())
            .unwrap();
        Self {
            session,
            control,
            observations,
            administrators,
            _processes: processes,
        }
    }
    fn arm(&self, peer: u64, operation: &'static str, stores_before_arming: usize) {
        *self.observations.lock().unwrap() = Observations {
            cancel_at: Some((peer, operation)),
            stores_before_arming,
            ..Observations::default()
        };
    }
    fn prepare_retry(&self) {
        let mut observations = self.observations.lock().unwrap();
        observations.cancel_at = None;
        observations.cancelled = None;
    }
    fn objects(&self) -> [BTreeMap<[u8; 32], RawBundle>; 2] {
        self.administrators.each_ref().map(|admin| {
            admin
                .status()
                .unwrap()
                .objects
                .into_iter()
                .map(|object| {
                    let Response::RawBundle(bundle) =
                        admin.call(Request::Fetch { object: object.id }).unwrap()
                    else {
                        panic!("actual complete ciphertext object");
                    };
                    (object.id, bundle)
                })
                .collect()
        })
    }
    fn blocks(&self, peer: usize) -> Vec<JournalBlock> {
        let network = self.session.version().genesis;
        let mut known = vec![network];
        let mut blocks = Vec::new();
        for _ in 0..16 {
            let Response::JournalBlocks(next) = self.administrators[peer]
                .call(Request::JournalBlocks {
                    network,
                    known: known.clone(),
                })
                .unwrap()
            else {
                panic!("actual journal response");
            };
            if next.is_empty() {
                return blocks;
            }
            assert_eq!(next.len(), 1);
            let block = next.into_iter().next().unwrap();
            let id = Header::decode(&block.header).unwrap().id();
            assert!(!known.contains(&id));
            known.push(id);
            blocks.push(block);
        }
        panic!("The small scenario exceeded its journal bound");
    }
    fn assert_recovered(&self, retained: &[BTreeMap<[u8; 32], RawBundle>; 2], binding: [u8; 32]) {
        let accepted = self.session.shards().remove(0);
        for (admin, original) in self.administrators.iter().zip(retained) {
            let Response::RawBundle(bundle) = admin
                .call(Request::Fetch {
                    object: accepted.object,
                })
                .unwrap()
            else {
                panic!("Retained mutation object");
            };
            assert_eq!(
                original.get(&accepted.object),
                Some(&bundle),
                "Exact nonce and ciphertext must survive retry"
            );
        }
        let blocks = self.blocks(0);
        let transitions: Vec<_> = blocks
            .iter()
            .filter_map(
                |block| match Body::decode(&block.body, &test_contract()).unwrap() {
                    Body::Transition(transition) => Some(transition),
                    Body::Empty => None,
                },
            )
            .collect();
        assert_eq!(
            transitions.len(),
            1,
            "One SQL statement must publish one authorized transition"
        );
        let manifest =
            peer_runtime::evidence::MutationManifest::decode(&transitions[0].request).unwrap();
        assert_eq!(manifest.query_binding, binding);
        assert_eq!(transitions[0].updates.len(), 1);
        assert_eq!(
            transitions[0].updates[0].new.data,
            accepted.data_head.encode()
        );
        assert_eq!(
            transitions[0].updates[0].new.index,
            accepted.index_head.encode()
        );
        let observed = self.observations.lock().unwrap();
        assert_eq!(
            observed.count("fhe-proof"),
            1,
            "Recovery must reuse the genuine checked proof"
        );
        assert_eq!(
            observed.count("store"),
            2,
            "Recovery must reuse both durable objects"
        );
        assert_eq!(observed.count("store-delta"), 0);
    }
}

fn pending_identity(error: &storage_client::Error) -> ([u8; 32], Option<HeadRef>) {
    let storage_client::Error::PendingMutation {
        query_binding,
        submitted,
        reason,
    } = error
    else {
        panic!("The authorized write must stay pending: {error}");
    };
    assert!(reason.contains("RPC operation cancelled"), "{reason}");
    (*query_binding, submitted.as_deref().copied())
}

#[test]
fn interrupted_journal_reply_stops_read_and_new_mutation_without_marking_a_holder_unavailable() {
    let mut peers = Peers::new(1);
    for sql in ["SELECT * FROM records", INSERT] {
        let before = peers.session.version();
        let objects = peers.objects();
        let scope = peers.control.begin().unwrap();
        peers.arm(1, "journal-sync", 0);

        let result = peers.session.execute(sql);

        assert!(
            matches!(result, Err(storage_client::Error::Transport(ref error)) if error.kind() == std::io::ErrorKind::Interrupted),
            "{result:?}"
        );
        assert!(scope.cancellation().is_cancelled());
        let observations = peers.observations.lock().unwrap();
        observations.assert_stopped(1, "journal-sync");
        assert_eq!(observations.sent, vec![(1, "journal-sync".into())]);
        drop(observations);
        assert_eq!(peers.session.version(), before);
        assert_eq!(peers.objects(), objects);
        assert!(peers.session.resume_pending().unwrap().is_none());
        drop(scope);
        peers.prepare_retry();
        let _next = peers.control.begin().unwrap();
        let outcome = peers.session.execute(sql).unwrap();
        assert_eq!(
            peers.observations.lock().unwrap().sent[1],
            (1, "journal-sync".into()),
            "A new scope retries the same real endpoint"
        );
        if sql == INSERT {
            assert!(matches!(outcome, VerifiedResult::Inserted { count: 1, .. }));
        } else {
            assert_eq!(rows(outcome), vec![vec![18, 10]]);
        }
    }
}

#[test]
fn interrupted_pending_journal_reply_retains_the_stored_write_before_any_mining() {
    let mut peers = Peers::new(1);
    let before = peers.session.version();
    let initial_blocks = peers.blocks(0);
    let scope = peers.control.begin().unwrap();
    peers.arm(1, "journal-sync", 2);

    let error = peers.session.execute(INSERT).unwrap_err();

    let (binding, submitted) = pending_identity(&error);
    assert_eq!(submitted, None);
    assert_eq!(peers.session.version(), before);
    assert!(scope.cancellation().is_cancelled());
    let observations = peers.observations.lock().unwrap();
    observations.assert_stopped(1, "journal-sync");
    assert_eq!(observations.store_acks, 2);
    assert_eq!(observations.count("journal-mine"), 0);
    assert_eq!(observations.count("journal-publish"), 0);
    drop(observations);
    assert_same_blocks(&peers.blocks(0), &initial_blocks);
    let retained = peers.objects();
    assert_eq!(retained[0], retained[1]);
    assert_eq!(retained[0].len(), 2);
    drop(scope);
    peers.prepare_retry();
    let _next = peers.control.begin().unwrap();

    let outcome = peers.session.resume_pending().unwrap().unwrap();

    assert!(matches!(outcome, VerifiedResult::Inserted { count: 1, .. }));
    peers.assert_recovered(&retained, binding);
    assert!(peers.session.resume_pending().unwrap().is_none());
    assert_eq!(
        rows(peers.session.execute("SELECT * FROM records").unwrap()),
        vec![vec![18, 10], vec![42, 7]]
    );
}

#[test]
fn interrupted_full_version_reply_never_imports_from_an_uncancelled_replica_and_retry_reuses_the_write()
 {
    let mut peers = Peers::new(1);
    let before = peers.session.shards().remove(0);
    let scope = peers.control.begin().unwrap();
    peers.arm(1, "fetch-version", 0);

    let error = peers.session.execute(INSERT).unwrap_err();

    let (binding, submitted) = pending_identity(&error);
    let submitted = submitted.expect("The owner already validated the original transition");
    assert!(scope.cancellation().is_cancelled());
    let observations = peers.observations.lock().unwrap();
    observations.assert_stopped(1, "fetch-version");
    assert_eq!(observations.count("fetch-version"), 1);
    let mines = observations.count("journal-mine");
    let publications = observations.count("journal-publish");
    drop(observations);
    assert_eq!(peers.session.shards()[0].object, before.object);
    assert_eq!(peers.session.shards()[0].data_head, before.data_head);
    assert_eq!(peers.session.shards()[0].index_head, before.index_head);
    let retained = peers.objects();
    drop(scope);
    peers.prepare_retry();
    let _next = peers.control.begin().unwrap();

    let outcome = peers.session.execute(INSERT).unwrap();

    let VerifiedResult::Inserted { count: 1, version } = outcome else {
        panic!("Original INSERT outcome");
    };
    assert_eq!(version, submitted);
    peers.assert_recovered(&retained, binding);
    let observations = peers.observations.lock().unwrap();
    assert_eq!(observations.count("journal-mine"), mines);
    assert_eq!(observations.count("journal-publish"), publications);
    drop(observations);
    assert!(peers.session.resume_pending().unwrap().is_none());
    assert_eq!(
        rows(peers.session.execute("SELECT * FROM records").unwrap()),
        vec![vec![18, 10], vec![42, 7]]
    );
}

#[test]
fn interrupted_mined_reply_never_tries_another_miner_and_retry_remines_only_the_retained_transition()
 {
    let mut peers = Peers::new(1);
    let before = peers.session.version();
    let initial_blocks = peers.blocks(0);
    let initial_sequence = peers.administrators[0]
        .status()
        .unwrap()
        .recent
        .last()
        .unwrap()
        .sequence;
    let scope = peers.control.begin().unwrap();
    peers.arm(1, "journal-mine", 0);

    let error = peers.session.execute(INSERT).unwrap_err();

    let (binding, submitted) = pending_identity(&error);
    assert_eq!(
        submitted, None,
        "The cancelled Mined frame was never owner-validated"
    );
    assert_eq!(peers.session.version(), before);
    assert!(scope.cancellation().is_cancelled());
    let observations = peers.observations.lock().unwrap();
    observations.assert_stopped(1, "journal-mine");
    assert_eq!(observations.count("journal-mine"), 1);
    assert_eq!(observations.count("journal-publish"), 0);
    drop(observations);
    // MineBlock returns a candidate, not a durable append. Observe that the real
    // peer successfully delivered it, without claiming any owner-validated head.
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let status = peers.administrators[0].status().unwrap();
        if status.recent.iter().any(|event| {
            event.sequence > initial_sequence
                && event.operation == "journal-mine"
                && event.succeeded
        }) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "No successful actual Mined response observed"
        );
        std::thread::yield_now();
    }
    assert_same_blocks(&peers.blocks(0), &initial_blocks);
    assert_same_blocks(&peers.blocks(1), &initial_blocks);
    let retained = peers.objects();
    drop(scope);
    peers.prepare_retry();
    let _next = peers.control.begin().unwrap();

    let outcome = peers.session.resume_pending().unwrap().unwrap();

    assert!(matches!(outcome, VerifiedResult::Inserted { count: 1, .. }));
    peers.assert_recovered(&retained, binding);
    assert_eq!(
        peers.observations.lock().unwrap().count("journal-mine"),
        3,
        "One lost candidate, then the original transition and one confirmation"
    );
    assert!(peers.session.resume_pending().unwrap().is_none());
    assert_eq!(
        rows(peers.session.execute("SELECT * FROM records").unwrap()),
        vec![vec![18, 10], vec![42, 7]]
    );
}

#[test]
fn interrupted_second_publication_reply_retains_the_exact_block_even_after_a_prior_durable_ack() {
    let mut peers = Peers::new(2);
    let before = peers.session.version();
    let initial_blocks = peers.blocks(0);
    let scope = peers.control.begin().unwrap();
    peers.arm(2, "journal-publish", 0);

    let error = peers.session.execute(INSERT).unwrap_err();

    let (binding, submitted) = pending_identity(&error);
    let submitted =
        submitted.expect("Validated original transition is retained before publication");
    assert_eq!(peers.session.version(), before);
    assert!(scope.cancellation().is_cancelled());
    let observations = peers.observations.lock().unwrap();
    observations.assert_stopped(2, "journal-publish");
    assert_eq!(observations.count("journal-mine"), 1);
    assert_eq!(observations.count("journal-publish"), 2);
    assert!(
        observations
            .finished
            .iter()
            .any(|(peer, op, _, succeeded)| *peer == 1 && op == "journal-publish" && *succeeded),
        "The first durable ACK precedes cancellation"
    );
    let sent_before_retry = observations.sent.len();
    drop(observations);
    let blocks = peers.blocks(0);
    assert_eq!(blocks.len(), initial_blocks.len() + 1);
    assert_same_blocks(&blocks[..initial_blocks.len()], &initial_blocks);
    let published_transition = blocks
        .iter()
        .find(|block| Header::decode(&block.header).unwrap().id() == submitted.block)
        .expect("The submitted transition was durably published");
    let second = peers.blocks(1);
    // Both journals already contain the initial empty confirmation. Exactly one
    // new block, the retained transition, was appended before the lost reply.
    assert_same_blocks(&blocks, &second);
    let retained = peers.objects();
    drop(scope);
    peers.prepare_retry();
    let _next = peers.control.begin().unwrap();

    let outcome = peers.session.execute(INSERT).unwrap();

    assert!(matches!(outcome, VerifiedResult::Inserted { count: 1, .. }));
    peers.assert_recovered(&retained, binding);
    let observations = peers.observations.lock().unwrap();
    assert_eq!(
        observations.sent[sent_before_retry],
        (1, "journal-publish".into()),
        "Even after the first ACK, retry first flushes the retained exact block"
    );
    assert_eq!(
        observations.count("journal-mine"),
        2,
        "Only the still-missing confirmation may be mined"
    );
    drop(observations);
    let published = peers.blocks(0);
    assert!(
        published
            .iter()
            .any(|block| block.header == published_transition.header
                && block.body == published_transition.body)
    );
    assert!(peers.session.resume_pending().unwrap().is_none());
    assert_eq!(
        rows(peers.session.execute("SELECT * FROM records").unwrap()),
        vec![vec![18, 10], vec![42, 7]]
    );
}

fn assert_same_blocks(actual: &[JournalBlock], expected: &[JournalBlock]) {
    assert_eq!(actual.len(), expected.len());
    for (actual, expected) in actual.iter().zip(expected) {
        assert_eq!(actual.header, expected.header);
        assert_eq!(actual.body, expected.body);
    }
}
