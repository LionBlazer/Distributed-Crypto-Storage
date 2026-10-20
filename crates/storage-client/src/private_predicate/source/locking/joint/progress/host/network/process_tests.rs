//! One actual four-validator gate with five genuine FHE jobs. All keys/data here are PUBLIC NONSECRET fixtures.
//! No local finality signatures, accepting verifier, model bank or SQL fallback.
use super::*;
use crate::private_predicate::source::locking::joint::tests::{
    full_acquire_fixture as fixture, os_process,
};
use protocol_storage::ParticipantQuota;
use registry200_proof::registry_progress::circuit::ProgressOpening;
use std::{path::PathBuf, time::Instant};
#[path = "process_capture.rs"]
mod process_capture;
#[path = "process_fixture.rs"]
mod process_fixture;
use process_fixture::{Boot, CAPACITY, Fixture, Network, authority, owner_signer};

const A: [u8; 32] = [0x61; 32];
const B: [u8; 32] = [0x62; 32];
const ACQUIRE_A: &str = "SELECT age, amount FROM records WHERE age = 255 FOR UPDATE";
const ACQUIRE_B: &str =
    "SELECT age, amount FROM records WHERE age >= 0 LIMIT 3 OFFSET 1 FOR UPDATE";
const SKIP_A: &str =
    "SELECT age, amount FROM records WHERE age >= 0 LIMIT 2 OFFSET 1 FOR UPDATE SKIP LOCKED";
const NOWAIT_A: &str = "SELECT age, amount FROM records WHERE age = 0 FOR UPDATE NOWAIT";
const BUDGET: Duration = peer_runtime::finality::PROGRESS_OPERATION_BUDGET;

#[test]
fn combined_public_fixture_sql_and_options_are_checked_before_any_crypto() {
    use sql_plan::{LockStrength, LockWait, Projection, QueryPlan, StatementPlan};
    for (client, seq, sql, kind) in [
        (A, 1, "BEGIN", Kind::Begin),
        (B, 1, "BEGIN", Kind::Begin),
        (A, 2, ACQUIRE_A, Kind::Acquire),
        (B, 2, ACQUIRE_B, Kind::Acquire),
        (A, 3, SKIP_A, Kind::Acquire),
        (A, 4, "COMMIT", Kind::EndClose),
        (A, 5, "BEGIN", Kind::Begin),
        (A, 6, NOWAIT_A, Kind::Acquire),
        (A, 7, "COMMIT", Kind::EndClose),
    ] {
        let call = Call::sql(client, seq, sql).unwrap();
        assert!(call.kind == kind);
        assert_eq!(call.client, client);
        assert_eq!(call.sequence, seq);
    }
    for (sql, wait, offset, limit) in [
        (ACQUIRE_A, LockWait::Wait, 0, None),
        (ACQUIRE_B, LockWait::Wait, 1, Some(3)),
        (NOWAIT_A, LockWait::NoWait, 0, None),
        (SKIP_A, LockWait::SkipLocked, 1, Some(2)),
    ] {
        let StatementPlan::Query(QueryPlan::LockingSelect {
            projection,
            window,
            locking,
            ..
        }) = sql_plan::parse_statement(sql).unwrap()
        else {
            panic!("literal requires genuine locking plan")
        };
        assert_eq!(projection, Projection::AgeAmount);
        assert_eq!(locking.strength, LockStrength::Update);
        assert_eq!(locking.wait, wait);
        assert_eq!(window.offset, offset);
        assert_eq!(window.limit, limit);
    }
}
fn mark(start: Instant, name: &str) {
    eprintln!(
        "progress_combined4 phase={name} elapsed_ms={}",
        start.elapsed().as_millis()
    );
}
fn quota_receipt(quota: &ParticipantQuota) {
    let u = quota.usage().unwrap();
    assert!(u.total_bytes() <= CAPACITY);
    eprintln!(
        "progress_combined4 owner_total_bytes={} owner_depot_bytes={} owner_control_bytes={} files={}",
        u.total_bytes(),
        u.depot_bytes(),
        u.control_bytes(),
        u.tracked_files()
    );
}
fn control(
    driver: &mut Driver,
    f: &Fixture,
    client: [u8; 32],
    seq: u64,
    sql: &str,
    expected: ControlOutcome,
) {
    let call = Call::sql(client, seq, sql).unwrap();
    let before = driver.owner.history.context().unwrap().slot();
    let cursor = driver.cursor().unwrap();
    match driver
        .execute(cursor, &call, &f.material(), f.fetched(), BUDGET)
        .unwrap()
    {
        Run::Terminal {
            outcome: Outcome::Control(actual),
            ..
        } => assert_eq!(*actual, expected),
        Run::Pending { reason, .. } => {
            panic!("connected control incomplete: {reason:?}; no budget renewal")
        }
        _ => panic!("actual QC/private Control/fsync terminal required"),
    }
    assert_eq!(driver.owner.history.context().unwrap().slot(), before + 1);
    let saved = driver.cursor().unwrap();
    let sequence = driver.owner.wal.sequence;
    // Lost-response exact retry must not derive a new Begin/End transaction.
    assert!(
        matches!(driver.execute(saved,&call,&f.material(),f.fetched(),BUDGET).unwrap(),Run::Terminal{outcome:Outcome::Control(actual),..} if *actual==expected)
    );
    assert!(matches!(
        driver.resume(saved, client, &f.material(), f.fetched(), BUDGET),
        Err(Error::Busy)
    ));
    let foreign = Call::sql(if client == A { B } else { A }, seq, sql).unwrap();
    assert!(matches!(
        driver.execute(saved, &foreign, &f.material(), f.fetched(), BUDGET),
        Err(Error::Busy)
    ));
    let wrong = Call::sql(client, seq + 1, sql).unwrap();
    assert!(matches!(
        driver.execute(saved, &wrong, &f.material(), f.fetched(), BUDGET),
        Err(Error::Busy)
    ));
    assert!(driver.cursor().unwrap() == saved);
    assert_eq!(driver.owner.wal.sequence, sequence);
    driver.acknowledge(saved).unwrap();
}
fn rows(reply: &Reply, expected: &[(u8, u8, u16)]) {
    assert_eq!(reply.rows().len(), expected.len());
    for (row, (ordinal, age, amount)) in reply.rows().iter().zip(expected) {
        assert_eq!(row.ordinal, *ordinal);
        assert_eq!(row.age, Some(*age));
        assert_eq!(row.amount, Some(*amount));
    }
}
fn catalog(driver: &Driver) -> CatalogId {
    driver.owner.attempt.as_ref().unwrap().catalog.unwrap()
}
fn parked(driver: &Driver) -> Zeroizing<ProgressOpening> {
    Zeroizing::new(
        driver
            .owner
            .bank
            .state
            .progress
            .iter()
            .flatten()
            .find(|p| p.statement.client == B)
            .expect("actual B parked opening")
            .clone(),
    )
}
fn assert_same_parked(driver: &Driver, original: &ProgressOpening) {
    let p = parked(driver);
    assert!(*p == *original);
    assert_eq!(driver.owner.book.clients[1].last, 1);
    assert!(driver.owner.book.flight.is_none());
    assert!(
        driver.owner.book.parked[1]
            .is_some_and(|p| p.call.transaction == original.statement.transaction
                && p.call.sequence == original.statement.call)
    );
    assert!(driver.owner.phase == Phase::Idle);
}

#[test]
#[ignore = "Four actual Progress validators + one independent FHE peer, eleven network QCs, five input16/output118 jobs, full parked Owner replay, WAIT then NOWAIT; requires DCS_PEER_EXE; whole-test observer7200s, operation1800s unchanged"]
fn actual_four_validators_wait_park_reopen_skip_locked_end_resume_then_nowait_abort() {
    // Arrange once. No native proof starts before this exact SQL preflight.
    combined_public_fixture_sql_and_options_are_checked_before_any_crypto();
    let started = Instant::now();
    let executable = PathBuf::from(
        std::env::var_os("DCS_PEER_EXE").expect("trusted actual dcs-peer executable required"),
    );
    assert!(executable.is_absolute() && executable.is_file());
    let dir = fixture::Directory::new();
    let (f, quota, boot) = Fixture::new(&dir);
    // A fresh v3 application/Genesis is constructed by the SAME fixture. No
    // old-contract QC/private-bank relabel or scoped token survives reopen.
    assert_eq!(
        f.binding.application_descriptor().encode()[8..40],
        registry200_joint::progress::contract_digest()
    );
    mark(started, "actual-v3-custody-and-Bootstrap803-ready");
    let network = Network::start(&f, &dir, &executable);
    mark(started, "five-actual-children-original-setup-installed");
    let boot_qc = network.bootstrap(&f.binding, &boot);
    let Boot {
        history,
        ingress,
        block,
        salts,
    } = boot;
    drop(ingress);
    drop(history);
    let gate = peer_runtime::ProofGate::new();
    let owner = Owner::create_new(
        f.pins(),
        authority(),
        &quota,
        gate.clone(),
        &f.material(),
        f.fetched(),
        Bootstrap {
            replay: &[Replay {
                checkpoint: &boot_qc,
                block: &block,
            }],
            salts: Zeroizing::new(salts),
        },
    )
    .unwrap();
    drop(boot_qc);
    drop(block);
    let mut driver = Driver::attach(owner, owner_signer(), network.config()).unwrap();
    assert_eq!(driver.owner.history.context().unwrap().slot(), 2);
    mark(started, "actual-network-Bootstrap-QC-private-owner-synced");

    // Fail fast at the real network/QC/Control160/WAL boundary, before any FHE.
    control(&mut driver, &f, A, 1, "BEGIN", ControlOutcome::Begun);
    mark(started, "Driver-BeginA-Control-QC-fsync-ACK-no-FHE");
    control(&mut driver, &f, B, 1, "BEGIN", ControlOutcome::Begun);
    assert_eq!(driver.owner.bank.state.registry.transactions[0].id, 1);
    assert_eq!(driver.owner.bank.state.registry.transactions[1].id, 2);
    quota_receipt(&quota);
    mark(started, "Driver-BeginB-Control-QC-fsync-ACK-no-FHE");

    // Act product1: A genuinely acquires row3 through the complete Driver.
    let call = Call::sql(A, 2, ACQUIRE_A).unwrap();
    let stale = driver.cursor().unwrap();
    match driver
        .execute(stale, &call, &f.material(), f.fetched(), BUDGET)
        .unwrap()
    {
        Run::Terminal {
            outcome: Outcome::Done(reply),
            ..
        } => rows(reply, &[(3, 255, 65534)]),
        Run::Pending { reason, .. } => panic!("product1 incomplete: {reason:?}; never repeat Work"),
        _ => panic!("product1 requires actual Done"),
    }
    let mut catalogs = vec![catalog(&driver)];
    assert_eq!(
        driver.owner.bank.state.registry.transactions[0].held,
        [0, 0, 0, 4]
    );
    assert!(matches!(
        driver.execute(stale, &call, &f.material(), f.fetched(), BUDGET),
        Err(Error::Cas)
    ));
    // Disabled capture performs no extra RPC, file IO or owner metadata lookup.
    // The only enabled positive is this already-required genuine product1.
    if let Some(target) = process_capture::requested_path() {
        let completed = driver.owner.history.checked_parent().unwrap().unwrap();
        process_capture::capture(
            PathBuf::from(target).as_path(),
            &f.binding,
            completed,
            &driver.owner.ingress,
            &network,
        )
        .unwrap();
    }
    driver.acknowledge(driver.cursor().unwrap()).unwrap();
    quota_receipt(&quota);
    mark(started, "product1-Driver-actual-Done-QC-fsync-ACK");

    // Act product2: offset row0 is locked, rows1/2 selected, row3 blocks B.
    let call = Call::sql(B, 2, ACQUIRE_B).unwrap();
    match driver
        .execute(
            driver.cursor().unwrap(),
            &call,
            &f.material(),
            f.fetched(),
            BUDGET,
        )
        .unwrap()
    {
        Run::Waiting { .. } => {}
        Run::Pending { reason, .. } => panic!("product2 incomplete: {reason:?}; not SQL WAIT"),
        _ => panic!("actual proven Parked must return owned Waiting"),
    }
    let original = parked(&driver);
    assert_eq!(original.statement.transaction, 2);
    assert_eq!(original.statement.call, 2);
    assert!(original.statement.mask == [255; 32]);
    assert_eq!(original.statement.offset, 1);
    assert_eq!(original.statement.limit, 3);
    assert_eq!(original.statement.wait, 0);
    assert_eq!(original.cursor, 3);
    assert_eq!(original.visited, [true, true, true, false]);
    assert_eq!(original.selected, [false, true, true, false]);
    assert_eq!(original.holder, 1);
    assert_eq!(
        driver.owner.bank.state.registry.transactions[1].held,
        [4, 4, 4, 0]
    );
    assert_same_parked(&driver, &original);
    assert!(matches!(
        driver.owner.outcome(driver.cursor().unwrap()).unwrap(),
        Some(Outcome::Waiting)
    ));
    let before = driver.cursor().unwrap();
    let ledger = driver.owner.book.encode();
    let wal = driver.owner.wal.sequence;
    assert!(matches!(driver.acknowledge(before), Err(Error::Phase)));
    assert!(driver.cursor().unwrap() == before);
    assert!(driver.owner.book.encode().as_ref() == ledger.as_ref());
    assert_eq!(driver.owner.wal.sequence, wal);
    let parent = driver
        .owner
        .history
        .checked_parent()
        .unwrap()
        .unwrap()
        .clone();
    let (original_request, original_manifest) = network.operation(&f.binding, &parent);
    let raw_catalog = original_manifest
        .references()
        .find(|r| r.role() == registry200_joint::progress::ManifestRole::ProductCatalog)
        .unwrap()
        .blob_id();
    let second = CatalogId::from_blob(raw_catalog).unwrap();
    assert!(!catalogs.contains(&second));
    catalogs.push(second);
    quota_receipt(&quota);
    mark(
        started,
        "product2-actual-Parked-prefix-fsynced-no-ACK-no-rows",
    );

    // One full real cold replay. Every original owner/depot/ingress handle drops.
    let original_bank = driver.owner.bank.encode().unwrap();
    let original_cursor = driver.cursor().unwrap();
    let original_context = driver.owner.history.context().unwrap().id();
    drop(driver.into_owner());
    drop(quota);
    mark(started, "parked-owner-all-handles-dropped");
    let quota =
        ParticipantQuota::open_existing(dir.path("participant"), [0x29; 32], CAPACITY).unwrap();
    let owner = Owner::open_existing(
        f.pins(),
        authority(),
        &quota,
        gate,
        &f.material(),
        f.fetched(),
    )
    .unwrap();
    let mut driver = Driver::attach(owner, owner_signer(), network.config()).unwrap();
    assert_same_parked(&driver, &original);
    assert!(driver.cursor().unwrap() == original_cursor);
    assert!(driver.owner.bank.encode().unwrap().as_ref() == original_bank.as_ref());
    assert!(driver.owner.book.encode().as_ref() == ledger.as_ref());
    assert_eq!(
        driver.owner.history.context().unwrap().id(),
        original_context
    );
    assert_eq!(driver.owner.history.context().unwrap().slot(), 6);
    quota_receipt(&quota);
    mark(started, "parked-full-proof-QC-WAL-replay-done");

    // Act product3: conflicts are skipped BEFORE OFFSET. B holds rows0/1/2;
    // A's own row3 is the only eligible offset row, so genuine Done is EMPTY.
    let parked_book = driver.owner.book.parked[1];
    let call = Call::sql(A, 3, SKIP_A).unwrap();
    match driver
        .execute(
            driver.cursor().unwrap(),
            &call,
            &f.material(),
            f.fetched(),
            BUDGET,
        )
        .unwrap()
    {
        Run::Terminal {
            outcome: Outcome::Done(reply),
            ..
        } => rows(reply, &[]),
        Run::Pending { reason, .. } => {
            panic!("product3 SKIP incomplete: {reason:?}; never repeat Work")
        }
        _ => panic!("actual SKIP requires Done EMPTY; no Waiting/Error fallback"),
    }
    assert_eq!(
        driver
            .owner
            .attempt
            .as_ref()
            .unwrap()
            .original
            .as_ref()
            .unwrap()
            .wait,
        2
    );
    let skipped = catalog(&driver);
    assert!(!catalogs.contains(&skipped));
    catalogs.push(skipped);
    assert_eq!(driver.owner.bank.state.registry.transactions[0].id, 1);
    assert_eq!(
        driver.owner.bank.state.registry.transactions[0].held,
        [0, 0, 0, 4]
    );
    assert!(!driver.owner.bank.state.registry.transactions[0].failed);
    assert_eq!(driver.owner.bank.state.registry.transactions[1].id, 2);
    assert_eq!(
        driver.owner.bank.state.registry.transactions[1].held,
        [4, 4, 4, 0]
    );
    assert!(!driver.owner.bank.state.registry.transactions[1].failed);
    assert_eq!(driver.owner.book.clients[0].last, 3);
    assert!(*parked(&driver) == *original);
    assert!(driver.owner.book.parked[1] == parked_book);
    assert_eq!(driver.owner.book.clients[1].last, 1);
    driver.acknowledge(driver.cursor().unwrap()).unwrap();
    assert_same_parked(&driver, &original);
    assert!(driver.owner.book.parked[1] == parked_book);
    assert!(matches!(
        driver.acknowledge(driver.cursor().unwrap()),
        Err(Error::Phase)
    ));
    quota_receipt(&quota);
    mark(
        started,
        "product3-SKIP-conflicts-before-OFFSET-Done-EMPTY-QC-fsync-ACK",
    );

    // Ordinary End, not NOWAIT failure, must release A's row3.
    control(&mut driver, &f, A, 4, "COMMIT", ControlOutcome::Closed);
    assert_eq!(driver.owner.bank.state.registry.transactions.len(), 1);
    assert_eq!(driver.owner.bank.state.registry.transactions[0].id, 2);
    assert_eq!(
        driver.owner.bank.state.registry.transactions[0].held,
        [4, 4, 4, 0]
    );
    assert_same_parked(&driver, &original);
    mark(
        started,
        "ordinary-EndA-Closed-released-row3-B-stableID-compacted",
    );

    // Act product4: SAME statement, fresh request, no replacement SQL argument.
    match driver
        .resume(
            driver.cursor().unwrap(),
            B,
            &f.material(),
            f.fetched(),
            BUDGET,
        )
        .unwrap()
    {
        Run::Terminal {
            outcome: Outcome::Done(reply),
            ..
        } => rows(reply, &[(1, 1, 0), (2, 128, 255), (3, 255, 65534)]),
        Run::Pending { reason, .. } => panic!("product4 incomplete: {reason:?}; never repeat Work"),
        _ => panic!("fresh resume requires actual cumulative Done"),
    }
    let attempt = driver.owner.attempt.as_ref().unwrap();
    assert!(
        attempt
            .original
            .as_ref()
            .is_some_and(|s| **s == original.statement)
    );
    assert_ne!(
        attempt.request.inner().nonce,
        original_request.inner().nonce
    );
    assert_ne!(
        attempt.request.inner().query,
        original_request.inner().query
    );
    assert_ne!(
        attempt.request.inner().opening,
        original_request.inner().opening
    );
    let resumed = catalog(&driver);
    assert!(!catalogs.contains(&resumed));
    catalogs.push(resumed);
    assert_eq!(driver.owner.bank.state.registry.transactions[0].id, 2);
    assert_eq!(
        driver.owner.bank.state.registry.transactions[0].held,
        [4; 4]
    );
    assert!(driver.owner.bank.state.progress.iter().all(Option::is_none));
    assert!(driver.owner.book.parked[1].is_none());
    assert_eq!(driver.owner.book.clients[1].last, 2);
    driver.acknowledge(driver.cursor().unwrap()).unwrap();
    quota_receipt(&quota);
    mark(
        started,
        "product4-fresh-resume-original-statement-Done-QC-fsync-ACK",
    );

    // NOWAIT comes AFTER true WAIT3. New A owns no prior locks.
    control(&mut driver, &f, A, 5, "BEGIN", ControlOutcome::Begun);
    assert_eq!(driver.owner.bank.state.registry.transactions[1].id, 3);
    let call = Call::sql(A, 6, NOWAIT_A).unwrap();
    match driver
        .execute(
            driver.cursor().unwrap(),
            &call,
            &f.material(),
            f.fetched(),
            BUDGET,
        )
        .unwrap()
    {
        Run::Terminal {
            outcome: Outcome::NoWaitError,
            ..
        } => {}
        Run::Pending { reason, .. } => panic!("product5 incomplete: {reason:?}; not NOWAIT"),
        _ => panic!("actual Result160 Error and failed-bank fsync required"),
    }
    let nowait = catalog(&driver);
    assert!(!catalogs.contains(&nowait));
    catalogs.push(nowait);
    assert_eq!(catalogs.len(), 5);
    assert_eq!(
        driver.owner.bank.state.registry.transactions[0].held,
        [4; 4]
    );
    assert!(driver.owner.bank.state.registry.transactions[1].failed);
    assert_eq!(
        driver.owner.bank.state.registry.transactions[1].held,
        [0; 4]
    );
    driver.acknowledge(driver.cursor().unwrap()).unwrap();
    quota_receipt(&quota);
    mark(
        started,
        "product5-actual-NOWAIT-Error-failed-bank-QC-fsync-ACK",
    );
    control(&mut driver, &f, A, 7, "COMMIT", ControlOutcome::Aborted);
    assert_eq!(driver.owner.bank.state.registry.transactions.len(), 1);
    assert_eq!(driver.owner.bank.state.registry.transactions[0].id, 2);
    assert_eq!(
        driver.owner.bank.state.registry.transactions[0].held,
        [4; 4]
    );
    assert_eq!(driver.owner.history.context().unwrap().slot(), 12);
    assert_eq!(
        driver
            .owner
            .history
            .checked_parent()
            .unwrap()
            .unwrap()
            .slot(),
        11
    );
    assert_eq!(driver.owner.wal.sequence, 40);
    assert!(driver.owner.book.flight.is_none());
    quota_receipt(&quota);
    mark(started, "actual-EndA-Aborted-eleven-network-QCs-complete");
    drop(driver.into_owner());
    drop(quota);
    network.finish();
    mark(started, "five-children-joined-before-owned-temp-cleanup");
    eprintln!(
        "progress_combined4 application_contract=v3 expected_original_native_scoped_completions=5 mandatory_full_cold_parked_reopen=1 accepted_catalogs=5 actual_qc_slots=11 planned_work_calls=5 verify_Work_compute_start_log_count=5 whole_test_budget_seconds=7200 production_operation_seconds=1800"
    );
}
