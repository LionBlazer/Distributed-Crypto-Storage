//! Four actual Word processes, genuine native proofs and real weighted QC/WAL.
//! Explicit PUBLIC NONSECRET keys/source; no SQL answer or lock grant is modeled.
#[path = "support/word_finality.rs"]
mod fixture;
#[path = "support/joint_process.rs"]
#[expect(
    dead_code,
    reason = "Shared supervisor also serves the separately tested older protocols"
)]
mod process;
use peer_runtime::{
    Connector, Endpoint, Identity, finality::WordFinalityClient, participant::ParticipantInstall,
};
use process::WordProcess;
use registry200_finality::{
    CandidateBlock,
    word::{Binding, Checkpoint, History},
};
use std::{
    io::{self, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use work_finality::consensus::MAX_RECORD_BYTES;
use zeroize::Zeroizing;

fn identity() -> Identity {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut p = rcgen::CertificateParams::new(vec!["dcs-peer".into()]).unwrap();
    p.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];
    Identity {
        certificate: p.self_signed(&key).unwrap().der().to_vec(),
        private_key_pkcs8: key.serialize_der(),
    }
}
fn directory() -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.local/network-tests");
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join(format!(
        "word-finality-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&path).unwrap();
    path
}
fn start(
    b: &Binding,
    root: &Path,
    tls: &[Identity],
    endpoints: &[Endpoint],
    owner: [u8; 32],
    new: bool,
    partition: bool,
) -> Vec<WordProcess> {
    (0..4).map(|i|{
        let neighbors:Vec<_>=endpoints.iter().enumerate().filter(|(j,_)|*j!=i && (!partition || *j/2==i/2)).map(|(_,e)|e.clone()).collect();
        let namespace=[0x91+i as u8;32];
        let config=Zeroizing::new(serde_json::to_vec(&serde_json::json!({"version":1,"kind":"registry208-word-participant-finality-v1","identity":tls[i],"authority":[],"owner":owner,"listen":endpoints[i].address,"neighbors":neighbors,"namespace":namespace,"capacity":10_000_000_000u64,"work_genesis":b.work_genesis().id(),"journal_genesis":b.journal_genesis().id().unwrap(),"binding":b.id(),"rules":{"max_round":32,"timeouts_ms":[1000,1500,2000],"timeout_delta_ms":10,"wal_bytes":MAX_RECORD_BYTES},"signer":fixture::keys()[i].to_bytes()})).unwrap());
        let work=b.work_genesis().encode().unwrap();let journal=b.journal_genesis().encode().unwrap();let descriptor=b.application_descriptor().encode();
        let frames=[config.as_slice(),work.as_slice(),journal.as_slice(),descriptor.as_slice(),fixture::fixture().source.as_slice()];
        let node=WordProcess::start(Path::new(env!("CARGO_BIN_EXE_dcs-peer")),&root.join(format!("validator{i}")),if new{ParticipantInstall::New}else{ParticipantInstall::Existing},&frames).unwrap();
        assert_eq!(node.ready().version,1);assert_eq!(node.ready().binding,b.id());assert_eq!(node.ready().namespace,namespace);
        assert_eq!(node.ready().profile,peer_runtime::word_participant::word_participant_host_profile_digest());
        assert_eq!(node.endpoint(),&endpoints[i]);println!("word_validator_pid={}",node.pid());node
    }).collect()
}
fn until(mut check: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(30);
    while !check() {
        assert!(
            Instant::now() < end,
            "Actual Word/TLS/QC condition timed out"
        );
        std::thread::park_timeout(Duration::from_millis(20));
    }
}
fn submit(client: &WordFinalityClient, block: &CandidateBlock) {
    until(|| match client.submit(block) {
        Ok(()) => true,
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => false,
        Err(e) => panic!("Genuine Word candidate rejected: {e}"),
    });
}
fn reject(mut call: impl FnMut() -> io::Result<()>) {
    until(|| match call() {
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => false,
        Err(_) => true,
        Ok(()) => panic!("Invalid Word operation was accepted"),
    });
}
fn checkpoint(clients: &[WordFinalityClient], slot: u64) -> Checkpoint {
    let mut result = None;
    until(|| {
        for c in clients {
            if let Ok(Some(q)) = c.checkpoint_after(slot) {
                result = Some(q);
                return true;
            }
        }
        false
    });
    result.unwrap()
}
fn check_checkpoint(
    history: &mut History,
    block: &CandidateBlock,
    q: &Checkpoint,
    expected: registry200_joint::word::OperationId,
) {
    let slot = history.context().unwrap().slot();
    // The real library owns original Source/native Word, owner, ancestry and
    // weighted QC verification. The intent pin predates the network response.
    let receiving = Instant::now();
    let checked = history.apply_operation(q, block, expected).unwrap();
    observation(format!(
        "word_process_receiver slot={slot} elapsed_ms={:.3} native_Word=true owner=true independent_intent=true weighted_QC=true currentness=false\n",
        receiving.elapsed().as_secs_f64() * 1000.0
    ));
    assert_eq!(checked.parent().slot(), slot);
    assert_eq!(checked.parent().head().block, block.header().id());
    assert_eq!(checked.operation().operation_id(), expected);
    assert_eq!(history.context().unwrap().slot(), slot + 1);
}
fn observation(line: String) {
    // A formatted record is one write; independently running peers share this
    // redirected stderr handle and may emit diagnostics concurrently.
    io::stderr().lock().write_all(line.as_bytes()).unwrap();
}
fn phase(label: &str, began: &mut Instant) {
    observation(format!(
        "word_process_phase name={label} elapsed_ms={:.3}\n",
        began.elapsed().as_secs_f64() * 1000.0
    ));
    *began = Instant::now();
}
#[test]
fn four_word_processes_require_native_proofs_and_quorum_then_replay_after_restart() {
    let began = Instant::now();
    let mut phase_began = Instant::now();
    let b = fixture::binding();
    let root = directory();
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let tls: Vec<_> = (0..4).map(|_| identity()).collect();
    let guards: Vec<_> = (0..4)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let endpoints: Vec<_> = guards
        .iter()
        .zip(&tls)
        .map(|(g, t)| Endpoint {
            address: g.local_addr().unwrap(),
            identity: t.fingerprint(),
        })
        .collect();
    drop(guards);
    let clients: Vec<_> = endpoints
        .iter()
        .map(|e| WordFinalityClient::new(connector.clone(), e.clone(), &b))
        .collect();
    let (boot, bank) = fixture::bootstrap(&b);
    let boot_intent = fixture::own_operation_id(&b, &boot);
    let installing = Instant::now();
    let mut history = History::new(b.clone()).unwrap();
    observation(format!(
        "word_process_receiver_install elapsed_ms={:.3} native_Source=true Word_setup=true currentness=false\n",
        installing.elapsed().as_secs_f64() * 1000.0
    ));
    phase("prepare_public_source_and_bootstrap", &mut phase_began);
    let nodes = start(&b, &root, &tls, &endpoints, owner.fingerprint(), true, true);
    phase("create_partitioned_participants", &mut phase_began);
    reject(|| clients[0].submit(&fixture::corrupt(&b, &boot)));
    let stranger = identity();
    let stranger = WordFinalityClient::new(
        Connector::permissionless(&stranger).unwrap(),
        endpoints[0].clone(),
        &b,
    );
    reject(|| stranger.submit(&boot));
    submit(&clients[0], &boot);
    let observed = Instant::now() + Duration::from_millis(800);
    while Instant::now() < observed {
        for c in &clients {
            assert!(c.checkpoint_after(0).unwrap().is_none());
            assert_eq!(c.observed_slot().unwrap(), 1);
        }
        std::thread::park_timeout(Duration::from_millis(20));
    }
    phase("rejections_and_no_quorum", &mut phase_began);
    for n in nodes {
        n.finish().unwrap();
    }
    phase("stop_partitioned_participants", &mut phase_began);
    let nodes = start(
        &b,
        &root,
        &tls,
        &endpoints,
        owner.fingerprint(),
        false,
        false,
    );
    phase("reopen_connected_participants", &mut phase_began);
    submit(&clients[0], &boot);
    let boot_qc = checkpoint(&clients, 0);
    phase("submit_bootstrap_to_first_qc", &mut phase_began);
    check_checkpoint(&mut history, &boot, &boot_qc, boot_intent);
    for c in &clients {
        until(|| c.observed_slot().is_ok_and(|v| v == 2));
    }
    phase(
        "independent_bootstrap_receive_and_all_catchup",
        &mut phase_began,
    );
    let control_began = Instant::now();
    let begin = fixture::begin(&b, bank, boot.header().id());
    let begin_intent = fixture::own_operation_id(&b, &begin);
    phase("prepare_begin_proof", &mut phase_began);
    submit(&clients[0], &begin);
    let begin_qc = checkpoint(&clients, 1);
    phase("submit_begin_to_first_qc", &mut phase_began);
    check_checkpoint(&mut history, &begin, &begin_qc, begin_intent);
    observation(format!(
        "word_control_operation elapsed_ms={:.3} owner_current_witness=true native_prove=true real_TLS_QC=true independent_proof_QC=true FHE=false SQL=false freshness_or_lock_grant=false\n",
        control_began.elapsed().as_secs_f64() * 1000.0
    ));
    for c in &clients {
        until(|| c.observed_slot().is_ok_and(|v| v == 3));
    }
    phase(
        "independent_begin_receive_and_all_catchup",
        &mut phase_began,
    );
    for n in nodes {
        n.finish().unwrap();
    }
    phase("stop_connected_participants", &mut phase_began);
    let nodes = start(
        &b,
        &root,
        &tls,
        &endpoints,
        owner.fingerprint(),
        false,
        false,
    );
    phase("reopen_and_replay_decided_history", &mut phase_began);
    for c in &clients {
        assert_eq!(c.observed_slot().unwrap(), 3);
        let stored = c.candidate_block(begin.header().id()).unwrap();
        assert_eq!(stored.header(), begin.header());
        assert_eq!(stored.body(), begin.body());
        let q = c.checkpoint_after(1).unwrap().unwrap();
        assert_eq!(q.candidate(), begin_qc.candidate());
        reject(|| c.submit_checkpoint(&boot_qc)); // Ancient QC cannot reset the floor.
    }
    phase("retained_block_qc_and_ancient_rejection", &mut phase_began);
    for n in nodes {
        n.finish().unwrap();
    }
    phase("stop_replayed_participants", &mut phase_began);
    observation(format!(
        "word_process whole_test_ms={:.3} actual_processes=true partition_no_quorum=true native_Source_Word=true independent_QC=true durable_replay=true SQL_accepted=false current_lock_grant=false\n",
        began.elapsed().as_secs_f64() * 1000.0
    ));
}
