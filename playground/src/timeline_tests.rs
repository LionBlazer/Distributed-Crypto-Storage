//! Public synthetic UI events only; no fixture pretends to provide a valid proof.
use super::*;
use crate::traffic::{Observation, timeline::Timeline};
use fhe_playground::{NetworkNode, NetworkPacket, PacketKind, ReplicationInfo};
use std::{
    sync::mpsc,
    time::{Duration, Instant},
};

fn display_fixture() -> (Playground, mpsc::Receiver<Command>, mpsc::Sender<Event>) {
    let (worker, commands, events) = Worker::test_channel();
    let mut app = Playground::with_worker(worker);
    app.active_client = Some(1);
    app.snapshot = Some(LabSnapshot {
        name: "public display fixture".into(),
        revision: 1,
        owner_rows: vec![],
        peers: vec![],
        replication: Some(ReplicationInfo {
            desired_copies: 1,
            shards: vec![],
            failure_domains: vec![],
            read_peers: vec![],
            write_peers: vec![],
            unavailable_shards: vec![],
        }),
    });
    app.network = Some(NetworkSnapshot {
        time_ms: 0.0,
        speed: 1.0,
        paused: false,
        nodes: vec![NetworkNode {
            process_id: None,
            id: 1,
            name: "Public client".into(),
            role: NodeRole::Client,
            peer_id: None,
            online: true,
        }],
        links: vec![],
        packets: vec![],
        recent: vec![],
    });
    (app, commands, events)
}
fn sent(id: u64, kind: PacketKind) -> Event {
    Event::Traffic(Observation {
        packet: NetworkPacket {
            id,
            from: 1,
            to: 2,
            kind,
            progress: 1.0,
            request_id: Some(9),
        },
        operation: "public observed I/O fixture".into(),
        bytes: 20,
    })
}
fn failed_completion() -> Event {
    Event::Finished {
        snapshot: None,
        outcome: Err(fhe_playground::LabError::InvalidInput(
            "public rejected query fixture".into(),
        )),
        elapsed_ms: 300.0,
        client_id: Some(1),
    }
}
#[test]
fn paused_panel_holds_traffic_result_and_state_until_the_same_clock_reaches_them() {
    let (mut app, _commands, _events) = display_fixture();
    let start = Instant::now();
    app.timeline = Timeline::new(start);
    app.pending = Some(Pending {
        job: Job::Query,
        label: "public query".into(),
        client_id: Some(1),
    });
    app.playback.speed = 0.0;
    app.timeline.record(
        start + Duration::from_millis(100),
        sent(1, PacketKind::Request),
    );
    app.timeline.record(
        start + Duration::from_millis(200),
        sent(2, PacketKind::Response),
    );
    app.timeline
        .record(start + Duration::from_millis(300), failed_completion());
    app.timeline.record(
        start + Duration::from_millis(400),
        Event::Progress("after result".into()),
    );

    app.advance_display(start + Duration::from_secs(5));

    assert!(app.playback.packets().is_empty());
    assert!(app.history.is_empty());
    assert!(app.pending.is_some());
    app.playback.speed = 0.5;
    app.advance_display(start + Duration::from_millis(5400));
    assert_eq!(
        app.playback
            .packets()
            .iter()
            .map(|p| p.id)
            .collect::<Vec<_>>(),
        [1, 2]
    );
    assert!(app.pending.is_some());
    assert!(app.history.is_empty());
    app.advance_display(start + Duration::from_millis(5800));
    assert!(app.pending.is_none());
    assert_eq!(app.history.len(), 1);
    assert_eq!(app.status, "after result");
}

#[test]
fn run_catches_up_previous_state_before_submitting_and_preserves_selected_speed() {
    let (mut app, commands, _events) = display_fixture();
    app.playback.speed = 0.01;
    app.pending = Some(Pending {
        job: Job::Query,
        label: "previous public query".into(),
        client_id: Some(1),
    });
    let mut state = app.snapshot.clone().unwrap();
    state.revision = 2;
    app.timeline.record(
        Instant::now(),
        Event::Finished {
            snapshot: Some(state),
            outcome: Err(fhe_playground::LabError::InvalidInput(
                "public rejected query".into(),
            )),
            elapsed_ms: 1.0,
            client_id: Some(1),
        },
    );

    app.run_query();

    assert!(matches!(
        commands.try_recv().unwrap(),
        Command::Query { client_id: 1, .. }
    ));
    assert_eq!(app.snapshot.as_ref().unwrap().revision, 2);
    assert_eq!(app.history.len(), 1);
    assert_eq!(app.playback.speed, 0.01);
    assert_eq!(app.display_queued(), 0);
    assert!(app.pending.is_some());
}

#[test]
fn live_applies_a_waiting_result_instead_of_discarding_it() {
    let (mut app, _commands, events) = display_fixture();
    app.playback.speed = 0.0;
    app.pending = Some(Pending {
        job: Job::Query,
        label: "public query".into(),
        client_id: Some(1),
    });
    for event in [
        sent(1, PacketKind::Request),
        sent(2, PacketKind::Response),
        failed_completion(),
    ] {
        events
            .send(Event::Stamped {
                at: Instant::now(),
                event: Box::new(event),
            })
            .unwrap();
    }
    app.poll();
    assert!(app.pending.is_some());

    app.sync_live();

    assert!(app.pending.is_none());
    assert_eq!(app.history.len(), 1);
    assert_eq!(app.display_queued(), 0);
    assert_eq!(app.playback.speed, 1.0);
    assert!(app.playback.packets().is_empty());
}

#[test]
fn run_is_available_for_a_real_completed_but_undisplayed_query_and_never_for_an_active_one() {
    let (mut app, commands, events) = display_fixture();
    app.playback.speed = 0.0;
    app.pending = Some(Pending {
        job: Job::Query,
        label: "previous public query".into(),
        client_id: Some(1),
    });
    assert!(!app.can_query());
    assert!(commands.try_recv().is_err());
    let state = app.snapshot.clone();
    events
        .send(Event::Stamped {
            at: Instant::now(),
            event: Box::new(Event::Finished {
                snapshot: state,
                outcome: Err(fhe_playground::LabError::InvalidInput(
                    "public rejection".into(),
                )),
                elapsed_ms: 1.0,
                client_id: Some(1),
            }),
        })
        .unwrap();
    app.poll();
    assert!(app.pending.is_some());
    assert!(app.history.is_empty());
    assert!(app.can_query());
    assert!(app.run_disabled_reason().is_none());

    app.run_query();

    assert!(matches!(
        commands.try_recv().unwrap(),
        Command::Query { client_id: 1, .. }
    ));
    assert!(!app.can_query());
    assert_eq!(app.history.len(), 1);
    assert_eq!(app.playback.speed, 0.0);
    assert!(commands.try_recv().is_err());
}

#[test]
fn overflowing_a_paused_log_drops_only_optional_history_and_never_advances_displayed_state() {
    let (mut app, _commands, events) = display_fixture();
    app.playback.speed = 0.0;
    app.pending = Some(Pending {
        job: Job::Query,
        label: "public query".into(),
        client_id: Some(1),
    });
    for _ in 0..5000 {
        events
            .send(Event::Stamped {
                at: Instant::now(),
                event: Box::new(Event::Progress("future public status".into())),
            })
            .unwrap();
    }
    let mut next = app.snapshot.clone().unwrap();
    next.revision = 2;
    events
        .send(Event::Stamped {
            at: Instant::now(),
            event: Box::new(Event::Finished {
                snapshot: Some(next),
                outcome: Err(fhe_playground::LabError::InvalidInput(
                    "public rejected result".into(),
                )),
                elapsed_ms: 1.0,
                client_id: Some(1),
            }),
        })
        .unwrap();

    app.poll();

    assert_eq!(app.snapshot.as_ref().unwrap().revision, 1);
    assert_eq!(app.status, "Preparing...");
    assert!(app.pending.is_some());
    assert!(app.history.is_empty());
    assert!(app.display_queued() <= 4096);
    assert!(app.playback.omitted > 0);
    assert_eq!(app.playback.speed, 0.0);

    app.sync_live();

    assert_eq!(app.snapshot.as_ref().unwrap().revision, 2);
    assert!(app.pending.is_none());
    assert_eq!(app.history.len(), 1);
}

#[test]
fn run_catches_up_the_first_completed_creation_before_checking_new_database_and_client() {
    let (mut app, commands, events) = display_fixture();
    let created = app.snapshot.take();
    let network = app.network.take().unwrap();
    app.active_client = None;
    app.playback.speed = 0.0;
    app.pending = Some(Pending {
        job: Job::Database,
        label: "public create fixture".into(),
        client_id: None,
    });
    assert!(!app.can_query());
    for event in [
        Event::Finished {
            snapshot: created,
            outcome: Ok(Outcome::Created),
            elapsed_ms: 1.0,
            client_id: None,
        },
        Event::Network(network),
    ] {
        events
            .send(Event::Stamped {
                at: Instant::now(),
                event: Box::new(event),
            })
            .unwrap();
    }

    app.poll();

    assert!(app.snapshot.is_none());
    assert!(app.active_client.is_none());
    assert!(app.can_query());
    assert!(app.run_disabled_reason().is_none());

    app.run_query();

    assert!(matches!(
        commands.try_recv().unwrap(),
        Command::Query { client_id: 1, .. }
    ));
    assert!(app.snapshot.is_some());
    assert_eq!(app.active_client, Some(1));
    assert_eq!(app.playback.speed, 0.0);
    assert!(!app.can_query());
    assert!(commands.try_recv().is_err());
}

#[test]
fn catch_up_of_a_failed_first_creation_does_not_dispatch_without_a_real_database() {
    let (mut app, commands, events) = display_fixture();
    app.snapshot = None;
    app.network = None;
    app.active_client = None;
    app.playback.speed = 0.0;
    app.pending = Some(Pending {
        job: Job::Database,
        label: "public failed creation".into(),
        client_id: None,
    });
    events
        .send(Event::Stamped {
            at: Instant::now(),
            event: Box::new(Event::Finished {
                snapshot: None,
                outcome: Err(fhe_playground::LabError::InvalidInput(
                    "public creation rejection".into(),
                )),
                elapsed_ms: 1.0,
                client_id: None,
            }),
        })
        .unwrap();
    app.poll();
    assert!(app.can_query());

    app.run_query();

    assert!(commands.try_recv().is_err());
    assert!(app.snapshot.is_none());
    assert!(!app.can_query());
    assert_eq!(app.playback.speed, 0.0);
}
