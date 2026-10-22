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
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, Tag},
};
use peer_runtime::{
    Connector, Endpoint, Identity, finality::WordFinalityClient, participant::ParticipantInstall,
};
use process::WordProcess;
use protocol_storage::{BlobId, ByteBudget, EvidenceStore, StoreLimits};
use registry200_finality::{
    CandidateBlock,
    word::{Binding, Checkpoint, History},
};
use registry200_proof::registry_progress::word::CommandInput;
use std::{
    io::{self, Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use storage_client::word_control::{
    Error as OwnerError, Mining, Owner as ControlOwner, RecoveryIdentity, RecoveryKey,
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
fn owner_store(path: &Path) -> EvidenceStore {
    std::fs::create_dir_all(path).unwrap();
    EvidenceStore::open(
        path,
        ByteBudget::new(64 * 1024 * 1024).unwrap(),
        StoreLimits::new(protocol_storage::MAX_BLOB_BYTES, 16).unwrap(),
    )
    .unwrap()
}
fn replay_bootstrap(
    b: &Binding,
    boot: &CandidateBlock,
    qc: &Checkpoint,
    intent: registry200_joint::word::OperationId,
) -> History {
    let mut history = History::new(b.clone()).unwrap();
    history.apply_operation(qc, boot, intent).unwrap();
    history
}
fn store_record(store: &mut EvidenceStore, bytes: &[u8]) -> BlobId {
    let id = BlobId::new(version_journal::hash(bytes), bytes.len() as u64).unwrap();
    let mut staged = store.stage(id).unwrap();
    for chunk in bytes.chunks(64 * 1024) {
        staged.write_chunk(chunk).unwrap();
    }
    staged.finish().unwrap()
}
// Explicit PUBLIC NONSECRET key. Forge authenticated private contents so that
// rejection must come from the real native relation/openings, not an AEAD tag.
fn authenticated_record(bytes: &[u8], nonce_byte: u8, change: impl FnOnce(&mut [u8])) -> Vec<u8> {
    const HEADER: usize = 136;
    let mut header: [u8; HEADER] = bytes[..HEADER].try_into().unwrap();
    let mut private = Zeroizing::new(bytes[HEADER..bytes.len() - 16].to_vec());
    let cipher = XChaCha20Poly1305::new_from_slice(&[0xb7; 32]).unwrap();
    cipher
        .decrypt_in_place_detached(
            XNonce::from_slice(&header[104..128]),
            &header,
            private.as_mut(),
            Tag::<XChaCha20Poly1305>::from_slice(&bytes[bytes.len() - 16..]),
        )
        .unwrap();
    change(&mut private);
    header[104..128].fill(nonce_byte);
    let tag = cipher
        .encrypt_in_place_detached(
            XNonce::from_slice(&header[104..128]),
            &header,
            private.as_mut(),
        )
        .unwrap();
    let mut result = header.to_vec();
    result.extend(private.iter());
    result.extend(tag);
    result
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
    // An actual checked history does not authorize a wrong owner key or a
    // different private opening. These trial receivers perform real checks.
    for failure in 0..4 {
        let mut trial = History::new(b.clone()).unwrap();
        trial.apply_operation(&boot_qc, &boot, boot_intent).unwrap();
        let mut material = fixture::control_material(bank);
        let key = if failure == 0 {
            ed25519_dalek::SigningKey::from_bytes(&[0x88; 32])
        } else {
            match failure {
                1 => material.registry[84] ^= 1,
                2 => material.controllers[0][0] ^= 1,
                3 => material.enrollment_salt[0] ^= 1,
                _ => unreachable!(),
            }
            fixture::control_owner_key()
        };
        assert!(ControlOwner::new(trial, key, material).is_err());
    }
    phase("reject_foreign_owner_and_private_opening", &mut phase_began);
    let mut control = ControlOwner::new(
        history,
        fixture::control_owner_key(),
        fixture::control_material(bank),
    )
    .unwrap();
    phase("install_private_control_owner", &mut phase_began);
    let store_path = root.join("owner-records");
    let mut store = owner_store(&store_path);
    // PUBLIC NONSECRET wrapping key/identity, deliberately held outside Owner.
    let recovery_key = RecoveryKey::new(Zeroizing::new([0xb7; 32]));
    let recovery_identity = RecoveryIdentity::new([0x93; 32]).unwrap();
    let _initial_record = control
        .checkpoint(&mut store, &recovery_key, recovery_identity)
        .unwrap();
    let control_began = Instant::now();
    let (begin, begin_qc, confirmed_record) = {
        let (begin, pending_record) = {
            let mut pending = control
                .prepare_stored(
                    fixture::control_source(),
                    CommandInput {
                        op: 0,
                        principal: 1,
                        id: 1,
                        ..Default::default()
                    },
                    Mining {
                        timestamp: 102,
                        now: 1_000_000,
                        attempts: 16,
                    },
                    &mut store,
                    &recovery_key,
                    recovery_identity,
                )
                .unwrap();
            let begin = CandidateBlock::new(
                pending.candidate().unwrap().header().clone(),
                pending.candidate().unwrap().body().to_vec(),
            )
            .unwrap();
            let record = pending.record();
            assert!(pending.confirm(&boot_qc).is_err());
            assert_eq!(
                pending.confirmed_parent().unwrap().head().block,
                boot.header().id()
            );
            phase("prepare_and_store_begin_proof", &mut phase_began);
            submit(&clients[0], &begin);
            (begin, record)
        };
        assert!(matches!(
            control.prepare(
                fixture::control_source(),
                CommandInput {
                    op: 0,
                    principal: 1,
                    id: 2,
                    ..Default::default()
                },
                Mining {
                    timestamp: 102,
                    now: 1_000_000,
                    attempts: 16
                },
            ),
            Err(OwnerError::Pending)
        ));
        // The COMPLETE in-memory owner and actual file-store lifecycle end.
        // Only original public pins/record identity and external fixture keys remain.
        drop(control);
        drop(store);
        store = owner_store(&store_path);
        let wrong_key = RecoveryKey::new(Zeroizing::new([0xb8; 32]));
        assert!(
            ControlOwner::restore(
                replay_bootstrap(&b, &boot, &boot_qc, boot_intent),
                fixture::control_owner_key(),
                &mut store,
                &wrong_key,
                recovery_identity,
                pending_record
            )
            .is_err()
        );
        assert!(
            ControlOwner::restore(
                replay_bootstrap(&b, &boot, &boot_qc, boot_intent),
                fixture::control_owner_key(),
                &mut store,
                &recovery_key,
                RecoveryIdentity::new([0x94; 32]).unwrap(),
                pending_record
            )
            .is_err()
        );
        // A well-hashed blob is still not a valid AEAD snapshot or proof.
        let mut corrupt = vec![0; pending_record.bytes() as usize];
        let mut reader = store.reader(pending_record).unwrap();
        reader.read_exact(&mut corrupt).unwrap();
        reader.finish().unwrap();
        let original = corrupt.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        let corrupt_id = store_record(&mut store, &corrupt);
        assert!(
            ControlOwner::restore(
                replay_bootstrap(&b, &boot, &boot_qc, boot_intent),
                fixture::control_owner_key(),
                &mut store,
                &recovery_key,
                recovery_identity,
                corrupt_id
            )
            .is_err()
        );
        const PRIVATE_BASE: usize = 1880;
        let damaged = fixture::corrupt(&b, &begin);
        for mutation in 0..3 {
            let forged = authenticated_record(&original, 0xc1 + mutation, |private| {
                let block_len =
                    u32::from_le_bytes(private[PRIVATE_BASE..PRIVATE_BASE + 4].try_into().unwrap())
                        as usize;
                let block_at = PRIVATE_BASE + 4;
                let intent_at = block_at + block_len;
                let next_at = intent_at + 32 + 64;
                match mutation {
                    0 => private[next_at] ^= 1,
                    1 => private[next_at + 208 * 8] ^= 1,
                    _ => {
                        let encoded = damaged.encode();
                        assert_eq!(encoded.len(), block_len);
                        private[block_at..intent_at].copy_from_slice(&encoded);
                        private[intent_at..intent_at + 32]
                            .copy_from_slice(&fixture::own_operation_id(&b, &damaged).bytes());
                    }
                }
            });
            let id = store_record(&mut store, &forged);
            assert!(
                ControlOwner::restore(
                    replay_bootstrap(&b, &boot, &boot_qc, boot_intent),
                    fixture::control_owner_key(),
                    &mut store,
                    &recovery_key,
                    recovery_identity,
                    id,
                )
                .is_err(),
                "Authenticated recovery must reject false next/result/native proof: {mutation}"
            );
        }
        control = ControlOwner::restore(
            replay_bootstrap(&b, &boot, &boot_qc, boot_intent),
            fixture::control_owner_key(),
            &mut store,
            &recovery_key,
            recovery_identity,
            pending_record,
        )
        .unwrap();
        let mut pending = control
            .resume_stored(&mut store, &recovery_key, recovery_identity)
            .unwrap();
        assert_eq!(pending.candidate().unwrap().header(), begin.header());
        assert_eq!(pending.candidate().unwrap().body(), begin.body());
        phase("restore_same_private_pending_from_store", &mut phase_began);
        let begin_qc = checkpoint(&clients, 1);
        phase("observe_begin_qc_after_owner_recovery", &mut phase_began);
        let receiving = Instant::now();
        let completed = pending.confirm(&begin_qc).unwrap();
        assert_eq!(
            completed.confirmation().operation().parent().head().block,
            begin.header().id()
        );
        assert_eq!(completed.confirmation().result_words()[118], 1);
        let record = completed.confirmed_record();
        assert!(matches!(
            pending.confirm(&begin_qc),
            Err(OwnerError::Consumed)
        ));
        observation(format!(
            "word_process_receiver slot=2 elapsed_ms={:.3} native_Word=true owner=true independent_intent=true weighted_QC=true private_bank_confirmed=true stored=true currentness=false\n",
            receiving.elapsed().as_secs_f64() * 1000.0
        ));
        observation("word_owner_recovery same_original_candidate=true reopened_owner_and_store=true authenticated_false_next_rejected=true authenticated_false_result_rejected=true authenticated_bad_proof_rejected=true wrong_key_rejected=true wrong_identity_rejected=true bad_tag_rejected=true owner_OS_process_crash_tested=false\n".into());
        (begin, begin_qc, record)
    };
    observation(format!(
        "word_control_operation elapsed_ms={:.3} owner_current_witness=true native_prove=true real_TLS_QC=true independent_proof_QC=true FHE=false SQL=false freshness_or_lock_grant=false sealed_recovery=true\n",
        control_began.elapsed().as_secs_f64() * 1000.0
    ));
    for c in &clients {
        until(|| c.observed_slot().is_ok_and(|v| v == 3));
    }
    phase(
        "independent_begin_receive_and_all_catchup",
        &mut phase_began,
    );
    // Recreate a new receiver under the actual now-confirmed public lineage.
    let mut after_begin = replay_bootstrap(&b, &boot, &boot_qc, boot_intent);
    after_begin
        .apply_operation(&begin_qc, &begin, fixture::own_operation_id(&b, &begin))
        .unwrap();
    drop(control);
    control = ControlOwner::restore(
        after_begin,
        fixture::control_owner_key(),
        &mut store,
        &recovery_key,
        recovery_identity,
        confirmed_record,
    )
    .unwrap();
    assert!(matches!(
        control.resume_pending(),
        Err(OwnerError::Consumed)
    ));
    phase(
        "restore_confirmed_private_bank_from_store",
        &mut phase_began,
    );
    // END uses the restored CONFIRMED private bank, not the original fixture.
    let end_began = Instant::now();
    let (end, end_qc) = {
        let mut pending = control
            .prepare_stored(
                fixture::control_source(),
                CommandInput {
                    op: 6,
                    actor: Some(0),
                    principal: 1,
                    id: 1,
                    ..Default::default()
                },
                Mining {
                    timestamp: 103,
                    now: 1_000_000,
                    attempts: 16,
                },
                &mut store,
                &recovery_key,
                recovery_identity,
            )
            .unwrap();
        let end = CandidateBlock::new(
            pending.candidate().unwrap().header().clone(),
            pending.candidate().unwrap().body().to_vec(),
        )
        .unwrap();
        assert!(pending.confirm(&begin_qc).is_err());
        assert_eq!(
            pending.confirmed_parent().unwrap().head().block,
            begin.header().id()
        );
        submit(&clients[0], &end);
        let end_qc = checkpoint(&clients, 2);
        let completed = pending.confirm(&end_qc).unwrap();
        assert_eq!(completed.confirmation().result_words()[118], 1);
        assert_eq!(
            completed.confirmation().operation().parent().head().block,
            end.header().id()
        );
        (end, end_qc)
    };
    assert_eq!(control.confirmed_parent().unwrap().slot(), 3);
    observation(format!(
        "word_control_end_operation elapsed_ms={:.3} native_prove=true real_TLS_QC=true private_bank_confirmed=true stored=true FHE=false SQL=false\n",
        end_began.elapsed().as_secs_f64() * 1000.0
    ));
    for c in &clients {
        until(|| c.observed_slot().is_ok_and(|v| v == 4));
    }
    phase(
        "end_from_confirmed_private_bank_and_all_catchup",
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
        assert_eq!(c.observed_slot().unwrap(), 4);
        let stored = c.candidate_block(end.header().id()).unwrap();
        assert_eq!(stored.header(), end.header());
        assert_eq!(stored.body(), end.body());
        let q = c.checkpoint_after(2).unwrap().unwrap();
        assert_eq!(q.candidate(), end_qc.candidate());
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
