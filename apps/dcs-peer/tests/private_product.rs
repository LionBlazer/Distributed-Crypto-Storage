//! Actual OS-peer/TLS rejection and cancellation tests. No dummy is proof authority.
#[path = "support/private_product_success.rs"]
mod private_product_success;
#[path = "support/private_product.rs"]
mod support;

use peer_runtime::{Connector, RequestControl};
use std::io;
use support::{Attempt, Fixture, Process, identity};

#[test]
fn foreign_tls_identity_cannot_start_a_private_product_stream() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let process = Process::start(owner.fingerprint(), 101);
    let remote = process.remote(&connector);
    let fixture = Fixture::public();
    fixture.install(&remote);
    let before = remote.status().unwrap();

    // The outsider really authenticates over TLS and can reach the public
    // Status API. Only the owner is permitted to start this heavy operation.
    let outsider = Connector::permissionless(&identity()).unwrap();
    let foreign = process.remote(&outsider);
    assert_eq!(foreign.status().unwrap().pid, process.pid());
    let rejected = Attempt::run(&foreign, fixture, fixture.object(), None);

    assert!(
        matches!(
            rejected.error.kind(),
            io::ErrorKind::UnexpectedEof
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
        ),
        "Unauthorized stream must close before Ready, not time out: {}",
        rejected.error
    );
    assert_eq!(rejected.sent_frames(), 1);
    assert!(rejected.received_sizes().is_empty());
    rejected.assert_failed_trace();
    fixture.assert_unchanged(&remote, &before);
    // The same live daemon still admits the real owner to Ready, then rejects
    // its intentionally invalid evidence without returning an output.
    let owner_attempt = support::until_not_busy(&remote, fixture, fixture.object());
    owner_attempt.assert_all_inputs_rejected();
    process.finish(&remote);
}

#[test]
fn unknown_object_and_foreign_source_heads_reject_before_input_upload() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let process = Process::start(owner.fingerprint(), 102);
    let remote = process.remote(&connector);
    let fixture = Fixture::public();
    fixture.install(&remote);
    let other = fixture.store_different_source(&remote);
    assert_ne!(other, fixture.object());
    let before = remote.status().unwrap();
    let mut unknown = fixture.object();
    unknown[0] ^= 1;
    assert!(!before.objects.iter().any(|entry| entry.id == unknown));

    for object in [unknown, other] {
        let before_attempt = remote.status().unwrap();
        let rejected = support::until_not_busy(&remote, fixture, object);
        rejected.assert_start_rejected();
        support::wait_for_failed_observation(&remote, &rejected, &before_attempt);
        fixture.assert_unchanged(&remote, &before);
    }
    support::until_not_busy(&remote, fixture, fixture.object()).assert_all_inputs_rejected();
    process.finish(&remote);
}

#[test]
fn all_fifteen_dummy_proofs_reject_before_output_and_release_the_session_permit() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let process = Process::start(owner.fingerprint(), 103);
    let remote = process.remote(&connector);
    let fixture = Fixture::public();
    fixture.install(&remote);
    let before = remote.status().unwrap();

    let rejected = Attempt::run(&remote, fixture, fixture.object(), None);
    rejected.assert_all_inputs_rejected();
    // Observation accounts for every uploaded component read by the server,
    // rather than crediting only writes buffered at the client socket.
    support::wait_for_failed_observation(&remote, &rejected, &before);
    fixture.assert_unchanged(&remote, &before);

    let before_retry = remote.status().unwrap();
    let retry = support::until_not_busy(&remote, fixture, fixture.object());
    retry.assert_all_inputs_rejected();
    assert_ne!(retry.request_id(), rejected.request_id());
    support::wait_for_failed_observation(&remote, &retry, &before_retry);
    fixture.assert_unchanged(&remote, &before);
    process.finish(&remote);
}

#[test]
fn cancelled_private_product_upload_drops_its_scope_and_allows_a_fresh_session() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let process = Process::start(owner.fingerprint(), 104);
    let remote = process.remote(&connector);
    let fixture = Fixture::public();
    fixture.install(&remote);
    let before = remote.status().unwrap();
    let control = RequestControl::default();
    let controlled = remote.clone().with_control(control.clone());

    // A pre-cancelled token fails directly without inventing network activity.
    let scope = control.begin().unwrap();
    assert!(control.cancel());
    let cancelled = Attempt::run(&controlled, fixture, fixture.object(), None);
    assert_eq!(cancelled.error.kind(), io::ErrorKind::Interrupted);
    assert!(cancelled.activity.is_empty());
    assert!(cancelled.trace.is_empty());
    drop(scope);
    assert!(control.current().is_none());

    // Cancellation fires synchronously only AFTER a real first input write.
    // It closes the registered socket while the peer waits for the next input.
    let scope = control.begin().unwrap();
    let old_token = scope.cancellation();
    let cancelled = Attempt::run(
        &controlled,
        fixture,
        fixture.object(),
        Some(control.clone()),
    );
    assert_eq!(cancelled.error.kind(), io::ErrorKind::Interrupted);
    assert_eq!(cancelled.sent_frames(), 2); // Start and exactly one input.
    assert_eq!(cancelled.received_sizes(), vec![96]); // Real parsed Ready only.
    cancelled.assert_failed_trace();
    drop(scope);
    assert!(control.current().is_none());

    // No prefix is a CheckedPrivateProduct. A new scope/token and connection
    // are independent, and eventual permit release is observed by a new Ready.
    let fresh = control.begin().unwrap();
    old_token.cancel();
    assert!(!fresh.cancellation().is_cancelled());
    let before_retry = remote.status().unwrap();
    let retry = support::until_not_busy(&controlled, fixture, fixture.object());
    retry.assert_all_inputs_rejected();
    support::wait_for_failed_observation(&remote, &retry, &before_retry);
    fixture.assert_unchanged(&remote, &before);
    drop(fresh);
    assert!(control.current().is_none());
    process.finish(&remote);
}
