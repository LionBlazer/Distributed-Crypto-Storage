//! PUBLIC NONSECRET ordinary scheduling/metadata examples. No callback returns
//! accepted proof/QC/SQL authority and no test substitutes a genuine operation.
use super::*;
use super::{
    drive::{same_acquisition, same_call},
    upload::{
        BlobSlots, PeerAction, PeerFailure, PeerProgress, StepReply, SubmissionOrder,
        after_observation, observe_peer, run_peer_workers,
    },
};
fn connector() -> Connector {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["dcs-peer".into()]).unwrap();
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let cert = params.self_signed(&key).unwrap();
    let identity = peer_runtime::Identity {
        certificate: cert.der().to_vec(),
        private_key_pkcs8: key.serialize_der(),
    };
    Connector::permissionless(&identity).unwrap()
}
fn endpoint(port: u16) -> Endpoint {
    Endpoint {
        address: ([127, 0, 0, 1], port).into(),
        identity: [0x31; 32],
    }
}
#[test]
fn independently_configured_routes_reject_empty_duplicate_over_cap_and_zero_mining() {
    let transport = connector();
    let peer = endpoint(9);
    assert!(Config::new(transport.clone(), vec![], peer.clone(), 1).is_err());
    assert!(
        Config::new(
            transport.clone(),
            vec![peer.clone(), peer.clone()],
            peer.clone(),
            1
        )
        .is_err()
    );
    assert!(Config::new(transport.clone(), vec![peer.clone()], peer.clone(), 0).is_err());
    let peers = (1..=peer_runtime::finality::MAX_PEERS + 1)
        .map(|n| endpoint(n as u16))
        .collect();
    assert!(Config::new(transport.clone(), peers, peer.clone(), 1).is_err());
    assert!(Config::new(transport, vec![peer.clone()], peer, 1).is_ok());
    assert!(BlobSlots::new(0).is_err());
    assert!(BlobSlots::new(peer_runtime::finality::MAX_PEERS + 1).is_err());
}
#[test]
fn original_body_is_first_and_each_successful_turn_uploads_only_its_one_blob() {
    let peer = PeerProgress::new();
    let mut actual = Vec::new();
    for _ in 0..5 {
        assert!(
            peer.perform(
                &SubmissionOrder::SavedOriginal,
                2,
                || true,
                |action| {
                    actual.push(action);
                    Ok(StepReply::Completed(None))
                }
            )
            .unwrap()
            .is_none()
        );
    }
    assert_eq!(
        actual,
        vec![
            PeerAction::Original,
            PeerAction::Blob(0),
            PeerAction::Blob(1),
            PeerAction::Submit,
            PeerAction::Checkpoint
        ]
    );
    let fresh = PeerProgress::new();
    let mut actual = Vec::new();
    fresh
        .perform(
            &SubmissionOrder::Fresh,
            2,
            || true,
            |action| {
                actual.push(action);
                Ok(StepReply::Completed(None))
            },
        )
        .unwrap();
    assert_eq!(actual, vec![PeerAction::Blob(0)]);
}
#[test]
fn missing_ack_busy_and_cancellation_preserve_the_exact_unsent_ordinal() {
    let peer = PeerProgress::new();
    let mut actual = Vec::new();
    assert!(
        peer.perform(
            &SubmissionOrder::Fresh,
            2,
            || true,
            |action| {
                actual.push(action);
                Err(PeerFailure::Remote(io::Error::from(
                    io::ErrorKind::WouldBlock,
                )))
            }
        )
        .is_err()
    );
    assert_eq!(peer.position(), (0, 0, false));
    peer.perform(
        &SubmissionOrder::Fresh,
        2,
        || true,
        |action| {
            actual.push(action);
            Ok(StepReply::Stopped)
        },
    )
    .unwrap();
    assert_eq!(peer.position(), (0, 0, false));
    peer.perform(
        &SubmissionOrder::Fresh,
        2,
        || false,
        |_| panic!("cancelled scheduling must not call I/O"),
    )
    .unwrap();
    peer.perform(
        &SubmissionOrder::Fresh,
        2,
        || true,
        |action| {
            actual.push(action);
            Ok(StepReply::Completed(None))
        },
    )
    .unwrap();
    assert_eq!(
        actual,
        vec![
            PeerAction::Blob(0),
            PeerAction::Blob(0),
            PeerAction::Blob(0)
        ]
    );
    assert_eq!(peer.position(), (0, 1, false));
}
#[test]
fn waiting_blob_peer_gets_the_next_slot_before_a_fast_peer_can_requeue() {
    let slots = BlobSlots::new(5).unwrap();
    let first = slots.acquire(0, || true).unwrap().unwrap();
    let second = slots.acquire(1, || true).unwrap().unwrap();
    let third = slots.acquire(2, || true).unwrap().unwrap();
    let (sent, received) = std::sync::mpsc::sync_channel(2);
    let observed = std::thread::scope(|scope| {
        let slots_ref = &slots;
        let waiting_sent = sent.clone();
        let waiting = scope.spawn(move || {
            let _slot = slots_ref.acquire(3, || true).unwrap().unwrap();
            waiting_sent.send(3).unwrap();
        });
        let queued = slots.wait_queued(3, scheduling_deadline());
        drop(first);
        let slots_ref = &slots;
        let fast = scope.spawn(move || {
            let _slot = slots_ref.acquire(0, || true).unwrap().unwrap();
            sent.send(0).unwrap();
        });
        let result = (|| -> std::result::Result<Vec<usize>, String> {
            queued.map_err(|e| e.to_string())?;
            Ok(vec![
                received
                    .recv_timeout(SCHEDULING_FUSE)
                    .map_err(|e| e.to_string())?,
                received
                    .recv_timeout(SCHEDULING_FUSE)
                    .map_err(|e| e.to_string())?,
            ])
        })();
        slots.stop();
        drop((second, third));
        let waiting_joined = waiting.join().is_ok();
        let fast_joined = fast.join().is_ok();
        let joined = waiting_joined && fast_joined;
        (result, joined)
    });
    assert!(observed.1);
    assert_eq!(observed.0.unwrap(), vec![3, 0]);
    slots.finish().unwrap();
}

#[test]
fn local_original_loss_and_recovery_required_are_hard_errors_not_remote_sql_status() {
    let peer = PeerProgress::new();
    assert!(observe_peer(&peer, Err(PeerFailure::Local(Error::Encoding))).is_err());
    assert!(matches!(
        observe_peer(&peer, Err(PeerFailure::Local(Error::RecoveryRequired))),
        Err(Error::RecoveryRequired)
    ));
    assert!(
        observe_peer(
            &peer,
            Err(PeerFailure::Remote(io::Error::from(
                io::ErrorKind::WouldBlock
            )))
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(peer.position(), (0, 0, false));
}
#[test]
fn exact_completed_begin_end_retry_never_derives_a_new_transaction_from_the_bank() {
    let route = ClientBinding::new([0x61; 32], 1).unwrap();
    let pins = [0x81; 32];
    for sql in ["BEGIN", "COMMIT", "ROLLBACK"] {
        let call = Call::sql(route.id, 7, sql).unwrap();
        let mut saved = RawCall {
            slot: 0,
            kind: call.kind,
            sequence: 7,
            digest: hash(&[
                b"DCS/Progress-owner/bound-private-call/v1",
                &pins,
                &call.digest,
                &call.client,
                &call.sequence.to_le_bytes(),
            ]),
            transaction: 123,
        };
        assert!(same_call(&route, &pins, &call, saved));
        assert!(!same_acquisition(&route, route.id, saved));
        saved.transaction = 999;
        assert!(same_call(&route, &pins, &call, saved));
        let wrong = Call::sql(route.id, 8, sql).unwrap();
        assert!(!same_call(&route, &pins, &wrong, saved));
        let wrong = ClientBinding::new([0x62; 32], 1).unwrap();
        assert!(!same_call(&wrong, &pins, &call, saved));
        assert!(!same_call(&route, &[0x82; 32], &call, saved));
        let changed = Call::sql(route.id, 7, &format!(" {sql}")).unwrap();
        assert!(!same_call(&route, &pins, &changed, saved));
    }
    let saved = RawCall {
        slot: 0,
        kind: Kind::Acquire,
        sequence: 7,
        digest: [0x83; 32],
        transaction: 123,
    };
    assert!(same_acquisition(&route, route.id, saved));
    assert!(!same_acquisition(&route, [0x62; 32], saved));
}

#[test]
fn prepared_and_submitted_recording_keep_the_exact_before_and_after_attempt() {
    // Explicit PUBLIC UNVERIFIED byte metadata, not a fake Attempt or proof.
    let catalog = bfv_product_evidence::CatalogId::from_blob(
        protocol_storage::BlobId::new([0x37; 32], 256).unwrap(),
    )
    .unwrap();
    let mut before = b"public attempt association example".to_vec();
    before.extend([0; 40]);
    let split = before.len() - 40;
    let mut after = before.clone();
    after[split..split + 32].copy_from_slice(catalog.blob_id().sha256());
    after[split + 32..].copy_from_slice(&catalog.blob_id().bytes().to_le_bytes());
    let stamp = hash(&[b"DCS/Progress-owner/current-work/v1", &before]);
    assert!(require_recorded_attempt_bytes(&before, &after, catalog, stamp).is_ok());
    for i in 0..after.len() {
        let mut changed = after.clone();
        changed[i] ^= 1;
        assert!(require_recorded_attempt_bytes(&before, &changed, catalog, stamp).is_err());
    }
    assert!(require_recorded_attempt_bytes(&after, &after, catalog, stamp).is_err());
    assert!(require_recorded_attempt_bytes(&before, &after, catalog, [0; 32]).is_err());
    assert!(require_recorded_attempt_bytes(&before[..39], &after, catalog, stamp).is_err());
}

// Ordinary I/O scheduling only. Unit completion tokens below are (), never an
// accepted Checkpoint, proof, private owner state or simulated SQL answer.
const SCHEDULING_FUSE: Duration = Duration::from_secs(5);
fn scheduling_deadline() -> std::time::Instant {
    std::time::Instant::now() + SCHEDULING_FUSE
}
#[derive(Default)]
struct IoLatch {
    opened: std::sync::Mutex<bool>,
    wake: std::sync::Condvar,
}
impl IoLatch {
    fn open(&self) {
        let mut opened = self.opened.lock().unwrap();
        *opened = true;
        self.wake.notify_all();
    }
    fn wait(&self) -> Result<()> {
        let expires = scheduling_deadline();
        let mut opened = self.opened.lock().map_err(|_| Error::Encoding)?;
        while !*opened {
            let remaining = expires
                .checked_duration_since(std::time::Instant::now())
                .ok_or_else(|| Error::Io(io::Error::from(io::ErrorKind::TimedOut)))?;
            opened = self
                .wake
                .wait_timeout(opened, remaining)
                .map_err(|_| Error::Encoding)?
                .0;
        }
        Ok(())
    }
}
#[test]
fn fourth_put_runs_while_the_first_three_submit_calls_are_still_blocked() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let slots = BlobSlots::new(4).unwrap();
    let fourth = IoLatch::default();
    let submits = IoLatch::default();
    let live = AtomicUsize::new(0);
    let peak = AtomicUsize::new(0);
    let (sent, received) = std::sync::mpsc::sync_channel(8);
    let (observation, joined) = std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            run_peer_workers::<()>(
                4,
                0,
                |peer| {
                    if peer == 3 {
                        fourth.wait()?;
                    }
                    {
                        let _slot = slots.acquire(peer, || true)?.ok_or(Error::Phase)?;
                        let current = live.fetch_add(1, Ordering::AcqRel) + 1;
                        peak.fetch_max(current, Ordering::AcqRel);
                        let public_payload = [peer as u8; 8];
                        assert_eq!(public_payload.len(), 8);
                        sent.send(("put", peer)).map_err(|_| Error::Encoding)?;
                        live.fetch_sub(1, Ordering::AcqRel);
                    } // Both public payload owner and blob slot end BEFORE Submit.
                    if peer < 3 {
                        sent.send(("submit", peer)).map_err(|_| Error::Encoding)?;
                        submits.wait()?;
                    }
                    Ok(None)
                },
                || {
                    slots.stop();
                    fourth.open();
                    submits.open();
                },
                |_| panic!("No QC or accepted completion exists in this I/O test"),
            )
        });
        let observation = (|| -> std::result::Result<(), String> {
            let mut blocked = std::collections::BTreeSet::new();
            while blocked.len() < 3 {
                let (kind, peer) = received
                    .recv_timeout(SCHEDULING_FUSE)
                    .map_err(|e| e.to_string())?;
                if kind == "submit" {
                    blocked.insert(peer);
                }
            }
            fourth.open();
            loop {
                let event = received
                    .recv_timeout(SCHEDULING_FUSE)
                    .map_err(|e| e.to_string())?;
                if event == ("put", 3) {
                    break;
                }
            }
            Ok(())
        })();
        // Always unblock fake I/O before joins/assertions, including failure.
        fourth.open();
        submits.open();
        (observation, worker.join())
    });
    observation.unwrap();
    assert!(joined.unwrap().unwrap().is_none());
    assert!(peak.load(Ordering::Acquire) <= 3);
    assert_eq!(live.load(Ordering::Acquire), 0);
    slots.finish().unwrap();
}
#[test]
fn cancellation_wakes_a_queued_blob_request_and_releases_all_payload_slots() {
    let slots = BlobSlots::new(4).unwrap();
    let held = (0..3)
        .map(|peer| slots.acquire(peer, || true).unwrap().unwrap())
        .collect::<Vec<_>>();
    let result = std::thread::scope(|scope| {
        let waiting = scope.spawn(|| slots.acquire(3, || true).map(|slot| slot.is_none()));
        let queued = slots.wait_queued(3, scheduling_deadline());
        slots.stop();
        drop(held);
        (queued, waiting.join())
    });
    result.0.unwrap();
    assert!(result.1.unwrap().unwrap());
    slots.finish().unwrap();
}
#[test]
fn a_normal_remote_disqualification_does_not_cancel_healthy_peer_workers() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let stopped = AtomicBool::new(false);
    let remote_exited = IoLatch::default();
    let healthy = AtomicUsize::new(0);
    let result = run_peer_workers::<()>(
        3,
        0,
        |peer| {
            if peer == 0 {
                let progress = PeerProgress::new();
                observe_peer(
                    &progress,
                    Err(PeerFailure::Remote(io::Error::from(
                        io::ErrorKind::InvalidData,
                    ))),
                )?;
                remote_exited.open();
                return Ok(None);
            }
            remote_exited.wait()?;
            if stopped.load(Ordering::Acquire) {
                return Err(Error::Encoding);
            }
            healthy.fetch_add(1, Ordering::AcqRel);
            Ok(None)
        },
        || {
            stopped.store(true, Ordering::Release);
            remote_exited.open();
        },
        |_| panic!("No accepted QC exists"),
    );
    assert!(result.unwrap().is_none());
    assert_eq!(healthy.load(Ordering::Acquire), 2);
}
#[test]
fn late_local_failure_overrides_an_ordinary_completion_after_cancellation_and_join() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let stopped = IoLatch::default();
    let joined = AtomicUsize::new(0);
    let selected = AtomicUsize::new(0);
    let result = run_peer_workers::<()>(
        3,
        0,
        |peer| {
            if peer == 0 {
                joined.fetch_add(1, Ordering::AcqRel);
                return Ok(Some(())); // Ordinary I/O completion token, NOT a QC.
            }
            stopped.wait()?;
            joined.fetch_add(1, Ordering::AcqRel);
            if peer == 1 {
                Err(Error::RecoveryRequired)
            } else {
                Ok(None)
            }
        },
        || stopped.open(),
        |_| {
            selected.fetch_add(1, Ordering::AcqRel);
        },
    );
    assert!(matches!(result, Err(Error::RecoveryRequired)));
    assert_eq!(selected.load(Ordering::Acquire), 1);
    assert_eq!(joined.load(Ordering::Acquire), 3);
}
#[test]
fn worker_panic_cancels_and_joins_every_other_started_worker() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let stopped = IoLatch::default();
    let joined = AtomicUsize::new(0);
    let result = run_peer_workers::<()>(
        3,
        0,
        |peer| {
            if peer == 0 {
                panic!("Intentional ordinary worker failure");
            }
            stopped.wait()?;
            joined.fetch_add(1, Ordering::AcqRel);
            Ok(None)
        },
        || stopped.open(),
        |_| panic!("No accepted QC exists"),
    );
    assert!(result.is_err());
    assert_eq!(joined.load(Ordering::Acquire), 2);
}
#[test]
fn cancellation_tail_never_masks_a_classified_local_or_foreign_head_error() {
    assert!(matches!(
        after_observation::<()>(Err(PeerFailure::Local(Error::RecoveryRequired)), false),
        Err(PeerFailure::Local(Error::RecoveryRequired))
    ));
    assert!(matches!(
        after_observation::<()>(Err(PeerFailure::Local(Error::Encoding)), false),
        Err(PeerFailure::Local(Error::Encoding))
    ));
    assert!(matches!(
        after_observation::<()>(
            Err(PeerFailure::Remote(io::Error::from(
                io::ErrorKind::InvalidData
            ))),
            false
        ),
        Err(PeerFailure::Remote(_))
    ));
    assert!(after_observation(Ok(Some(())), false).unwrap().is_none());
}

// Reuses the actual move-only native result in the owning combined4; this helper
// mutates only temporary frame metadata and never the actual Owner/History/WAL.
pub(super) fn reject_substituted_live_frame(
    owner: &Owner,
    frame: &mut SubmittedRecording<'_>,
    material: &Material<'_>,
) {
    let cursor = owner.cursor().unwrap();
    let context = owner.history.context().unwrap().clone();
    let parent = owner.history.checked_parent().unwrap().unwrap().head();
    let wal = (owner.wal.sequence, owner.wal.digest, owner.wal.length);
    let bank = owner.bank.encode().unwrap();
    let book = owner.book.encode();
    assert!(owner.require_recorded_pair(cursor, frame, material).is_ok());

    frame.prepared.before_attempt[0] ^= 1;
    assert!(matches!(
        owner.require_recorded_pair(cursor, frame, material),
        Err(Error::Pins)
    ));
    frame.prepared.before_attempt[0] ^= 1;
    frame.after_attempt[0] ^= 1;
    assert!(matches!(
        owner.require_recorded_pair(cursor, frame, material),
        Err(Error::Pins)
    ));
    frame.after_attempt[0] ^= 1;
    frame.prepared.before_cursor.sequence ^= 1;
    assert!(matches!(
        owner.require_recorded_pair(cursor, frame, material),
        Err(Error::Pins)
    ));
    frame.prepared.before_cursor.sequence ^= 1;
    frame.after_cursor.digest[0] ^= 1;
    assert!(matches!(
        owner.require_recorded_pair(cursor, frame, material),
        Err(Error::Pins)
    ));
    frame.after_cursor.digest[0] ^= 1;
    let catalog = frame.catalog;
    let mut digest = *catalog.blob_id().sha256();
    digest[0] ^= 1;
    frame.catalog = CatalogId::from_blob(
        protocol_storage::BlobId::new(digest, catalog.blob_id().bytes()).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        owner.require_recorded_pair(cursor, frame, material),
        Err(Error::Pins)
    ));
    frame.catalog = catalog;
    frame.header.nonce ^= 1;
    assert!(matches!(
        owner.require_recorded_pair(cursor, frame, material),
        Err(Error::Pins)
    ));
    frame.header.nonce ^= 1;
    frame.body[0] ^= 1;
    assert!(matches!(
        owner.require_recorded_pair(cursor, frame, material),
        Err(Error::Pins)
    ));
    frame.body[0] ^= 1;

    assert!(owner.require_recorded_pair(cursor, frame, material).is_ok());
    assert!(owner.cursor().unwrap() == cursor);
    assert!(owner.history.context().unwrap() == &context);
    assert!(owner.history.checked_parent().unwrap().unwrap().head() == parent);
    assert!((owner.wal.sequence, owner.wal.digest, owner.wal.length) == wal);
    assert!(owner.bank.encode().unwrap().as_slice() == bank.as_slice());
    assert!(owner.book.encode().as_slice() == book.as_slice());
    eprintln!(
        "progress_driver phase=genuine_scoped_frame_substitutions_rejected owner_unchanged=true"
    );
}
