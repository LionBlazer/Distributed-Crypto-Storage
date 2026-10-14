use std::sync::mpsc::{Receiver, Sender, TryRecvError};

use fhe_playground::PeerInfo;

use super::*;

#[path = "ui_preview.rs"]
mod preview;

// These tests feed egui in memory. No native window, OS input, screenshot, or FHE
// worker is started; the command channel is the client UI's observable boundary.
fn app() -> (Playground, Receiver<Command>, Sender<Event>) {
    let (worker, commands, events) = Worker::test_channel();
    let mut app = Playground::with_worker(worker);
    app.snapshot = Some(snapshot(3));
    (app, commands, events)
}

fn snapshot(peers: usize) -> LabSnapshot {
    let rows = sample_rows(4).unwrap();
    LabSnapshot {
        name: "demo".into(),
        revision: 0,
        peers: (0..peers)
            .map(|index| PeerInfo {
                id: index + 1,
                config: PeerConfig::numbered(index + 1),
                online: true,
                rows: (index..rows.len()).step_by(peers).count(),
                compressed_bytes: 100,
                owner_row_indices: (index..rows.len()).step_by(peers).collect(),
            })
            .collect(),
        owner_rows: rows,
    }
}

struct VisibleText {
    text: String,
    rect: egui::Rect,
}

fn render(ctx: &egui::Context, app: &mut Playground, events: Vec<egui::Event>) -> Vec<VisibleText> {
    let output = ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(980.0, 720.0),
            )),
            events,
            ..Default::default()
        },
        |ui| app.draw(ui),
    );
    fn collect(shape: &egui::Shape, clip: egui::Rect, texts: &mut Vec<VisibleText>) {
        match shape {
            egui::Shape::Text(shape) => {
                let rect = shape.galley.rect.translate(shape.pos.to_vec2());
                if rect.intersects(clip) {
                    texts.push(VisibleText {
                        text: shape.galley.job.text.clone(),
                        rect,
                    });
                }
            }
            egui::Shape::Vec(shapes) => {
                for shape in shapes {
                    collect(shape, clip, texts);
                }
            }
            _ => {}
        }
    }
    let mut texts = Vec::new();
    for shape in &output.shapes {
        collect(&shape.shape, shape.clip_rect, &mut texts);
    }
    output.drop_without_applying_deltas();
    texts
}

fn click(ctx: &egui::Context, app: &mut Playground, label: &str) {
    let texts = render(ctx, app, vec![]);
    let point = texts
        .iter()
        .find(|text| text.text == label)
        .unwrap_or_else(|| panic!("visible control not found: {label}"))
        .rect
        .center();
    click_point(ctx, app, point);
}

fn click_point(ctx: &egui::Context, app: &mut Playground, point: egui::Pos2) {
    render(
        ctx,
        app,
        vec![
            egui::Event::PointerMoved(point),
            egui::Event::PointerButton {
                pos: point,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: egui::Modifiers::NONE,
            },
        ],
    );
    render(
        ctx,
        app,
        vec![egui::Event::PointerButton {
            pos: point,
            button: egui::PointerButton::Primary,
            pressed: false,
            modifiers: egui::Modifiers::NONE,
        }],
    );
}

#[test]
fn selecting_a_map_node_inspects_its_owner_rows_and_targets_its_availability() {
    let (mut app, commands, _events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    app.tab = Tab::Infrastructure;
    let texts = render(&ctx, &mut app, vec![]);
    // The map node is above the directory entry with the same identifier.
    let node = texts
        .iter()
        .filter(|t| t.text == "P02")
        .min_by(|a, b| a.rect.top().total_cmp(&b.rect.top()))
        .unwrap()
        .rect
        .center();

    click_point(&ctx, &mut app, node);
    let texts = render(&ctx, &mut app, vec![]);

    assert_eq!(app.selected_peer, Some(2));
    for label in ["Shard rows", "Owner view", "18", "20", "Encrypted shard"] {
        assert!(
            texts.iter().any(|t| t.text == label),
            "missing inspector field: {label}"
        );
    }
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
    click(&ctx, &mut app, "Take offline");
    assert!(matches!(
        commands.try_recv(),
        Ok(Command::SetPeer {
            id: 2,
            online: false
        })
    ));
}

#[test]
fn adding_a_custom_peer_requires_explicit_apply_and_preserves_data_drafts() {
    let (mut app, commands, events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    app.tab = Tab::Infrastructure;
    app.draft_rows = "50,600".into();
    click(&ctx, &mut app, "Add peer");
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
    app.new_peer = Some(PeerConfig {
        name: "Fast SSD".into(),
        storage_limit_bytes: 8 * 1024 * 1024,
        delay_ms: 35,
    });

    click(&ctx, &mut app, "Add and repartition");

    let Command::ConfigurePeers(profiles) = commands.try_recv().unwrap() else {
        panic!("expected layout change")
    };
    assert_eq!(profiles.len(), 4);
    assert_eq!(profiles[3].name, "Fast SSD");
    assert_eq!(profiles[3].delay_ms, 35);
    assert_eq!(profiles[3].storage_limit_bytes, 8 * 1024 * 1024);
    let mut changed = snapshot(4);
    changed.peers[3].config = profiles[3].clone();
    events
        .send(Event::Finished {
            snapshot: Some(changed),
            outcome: Ok(Outcome::LayoutChanged),
            elapsed_ms: 1.0,
        })
        .unwrap();
    app.poll();
    assert_eq!(app.draft_rows, "50,600");
    assert_eq!(app.draft_peers, 4);
    assert!(app.new_peer.is_none());
}

#[test]
fn a_failed_peer_addition_keeps_the_form_and_original_map() {
    let (mut app, commands, events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    app.tab = Tab::Infrastructure;
    click(&ctx, &mut app, "Add peer");
    app.new_peer.as_mut().unwrap().storage_limit_bytes = 1024;
    click(&ctx, &mut app, "Add and repartition");
    let _ = commands.try_recv().unwrap();
    events
        .send(Event::Finished {
            snapshot: Some(snapshot(3)),
            outcome: Err(fhe_playground::LabError::InvalidInput(
                "Quota exceeded".into(),
            )),
            elapsed_ms: 1.0,
        })
        .unwrap();

    app.poll();

    assert_eq!(app.snapshot.as_ref().unwrap().peers.len(), 3);
    assert_eq!(app.new_peer.as_ref().unwrap().storage_limit_bytes, 1024);
    assert_eq!(app.input_error.as_deref(), Some("Quota exceeded"));
}

#[test]
fn saving_peer_settings_sends_only_the_selected_profile() {
    let (mut app, commands, _events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    app.tab = Tab::Infrastructure;
    app.select_peer(Some(2));
    app.peer_edit.as_mut().unwrap().name = "Storage node".into();
    app.peer_edit.as_mut().unwrap().delay_ms = 25;
    click(&ctx, &mut app, "Settings");

    click(&ctx, &mut app, "Save settings");

    assert!(
        matches!(commands.try_recv(), Ok(Command::ConfigurePeer { id: 2, config }) if config.name == "Storage node" && config.delay_ms == 25)
    );
}

#[test]
fn adding_a_data_row_changes_only_the_draft_until_creation() {
    let (mut app, commands, _events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    app.tab = Tab::Data;

    click(&ctx, &mut app, "Add row");

    let rows = parse_rows(&app.draft_rows).unwrap();
    assert_eq!(rows.len(), 5);
    assert_eq!((rows[4].age, rows[4].amount), (0, 0));
    assert_eq!(app.snapshot.as_ref().unwrap().owner_rows.len(), 4);
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn data_grid_places_records_on_separate_rows_under_their_column_headers() {
    let (mut app, _commands, _events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    app.tab = Tab::Data;
    let texts = render(&ctx, &mut app, vec![]);
    let cell = |value: &str| texts.iter().find(|t| t.text == value).unwrap().rect;
    assert!(cell("001").bottom() < cell("002").top());
    assert!(cell("002").bottom() < cell("003").top());
    assert!(cell("003").bottom() < cell("004").top());
    assert!((cell("001").center().y - cell("17").center().y).abs() < 5.0);
    assert!(cell("001").right() < cell("17").left());
    assert!(cell("17").right() < cell("10").left());
}

#[test]
fn route_highlighting_follows_worker_progress_and_clears_on_completion() {
    let (mut app, commands, events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    app.run_query();
    let _ = commands.try_recv().unwrap();
    app.tab = Tab::Infrastructure;
    events
        .send(Event::PeerProgress(fhe_playground::LabProgress {
            peer_id: 2,
            message: "Evaluating P02".into(),
        }))
        .unwrap();
    app.poll();
    let texts = render(&ctx, &mut app, vec![]);
    assert!(texts.iter().any(|t| t.text == "Executing..."));
    assert_eq!(app.active_peer, Some(2));

    events
        .send(Event::Finished {
            snapshot: Some(snapshot(3)),
            outcome: Ok(Outcome::Query(QueryOutcome::Aggregate {
                count: 2,
                sum: 50,
                peers: vec![],
            })),
            elapsed_ms: 2.0,
        })
        .unwrap();
    app.poll();

    assert_eq!(app.active_peer, None);
    assert!(
        !render(&ctx, &mut app, vec![])
            .iter()
            .any(|t| t.text == "Executing...")
    );
}

#[test]
fn all_sixteen_map_nodes_fit_the_minimum_window_and_fit_resets_navigation() {
    let (mut app, _commands, _events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    app.snapshot = Some(snapshot(16));
    app.tab = Tab::Infrastructure;
    let texts = render(&ctx, &mut app, vec![]);
    for id in 1..=16 {
        assert!(
            texts
                .iter()
                .any(|t| t.text == format!("P{id:02}") && t.rect.bottom() < 510.0),
            "map node {id} is not visible"
        );
    }
    app.graph_zoom = 2.0;
    app.graph_pan = egui::vec2(45.0, 30.0);
    click(&ctx, &mut app, "Fit");
    assert_eq!(app.graph_zoom, 1.0);
    assert_eq!(app.graph_pan, egui::Vec2::ZERO);
}

fn ctrl_enter() -> Vec<egui::Event> {
    vec![egui::Event::Key {
        key: egui::Key::Enter,
        physical_key: None,
        pressed: true,
        repeat: false,
        modifiers: egui::Modifiers::CTRL,
    }]
}

#[test]
fn selecting_a_preset_only_fills_sql_until_run_is_clicked() {
    let (mut app, commands, _events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    render(&ctx, &mut app, vec![]);

    // Act: select an UPDATE through the actual egui menu.
    click(&ctx, &mut app, "Presets");
    click(&ctx, &mut app, "Add 5");

    assert_eq!(app.sql, PRESETS[4].sql);
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));

    click(&ctx, &mut app, "Run");
    assert!(matches!(commands.try_recv(), Ok(Command::Query(sql)) if sql == PRESETS[4].sql));
}

#[test]
fn sql_layout_has_editor_above_results_and_no_infrastructure_controls() {
    let (mut app, _commands, _events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    let texts = render(&ctx, &mut app, vec![]);
    let editor = texts
        .iter()
        .find(|text| text.text == "Console.sql")
        .unwrap();
    let results = texts.iter().find(|text| text.text == "Result").unwrap();

    assert!(editor.rect.bottom() < results.rect.top());
    assert!(texts.iter().any(|text| text.text == "Database"));
    assert!(!texts.iter().any(|text| matches!(
        text.text.as_str(),
        "Peers" | "Online" | "COMPRESSED SHARDS" | "Query playground"
    )));
}

#[test]
fn switching_to_infrastructure_keeps_the_editor_and_does_not_execute_sql() {
    let (mut app, commands, _events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    let sql = app.sql.clone();
    render(&ctx, &mut app, vec![]);

    click(&ctx, &mut app, "Infrastructure");
    let texts = render(&ctx, &mut app, vec![]);

    assert!(texts.iter().any(|text| text.text == "Peers"));
    assert!(texts.iter().any(|text| text.text == "P01"));
    assert!(
        !texts
            .iter()
            .any(|text| text.text == "Run" || text.text == "Console.sql")
    );
    assert_eq!(app.sql, sql);
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn ctrl_enter_executes_only_from_the_sql_tab_and_never_queues_a_duplicate_job() {
    let (mut app, commands, _events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    app.tab = Tab::Infrastructure;

    render(&ctx, &mut app, ctrl_enter());
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
    app.tab = Tab::Sql;
    render(&ctx, &mut app, ctrl_enter());
    assert!(matches!(commands.try_recv(), Ok(Command::Query(sql)) if sql == PRESETS[1].sql));
    render(&ctx, &mut app, ctrl_enter());
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn applying_peer_layout_uses_live_rows_and_preserves_unapplied_data_edits() {
    let (mut app, commands, events) = app();
    app.tab = Tab::Infrastructure;
    app.draft_peers = 4;
    app.draft_name = "another database".into();
    app.draft_rows = "18,500".into();

    app.apply_layout();
    let Command::ConfigurePeers(profiles) = commands.try_recv().unwrap() else {
        panic!("expected layout rebuild");
    };
    assert_eq!(profiles.len(), 4);
    assert_eq!(profiles[0], PeerConfig::numbered(1));
    events
        .send(Event::Finished {
            snapshot: Some(snapshot(4)),
            outcome: Ok(Outcome::LayoutChanged),
            elapsed_ms: 1.0,
        })
        .unwrap();
    app.poll();

    assert_eq!(app.draft_rows, "18,500");
    assert_eq!(app.draft_name, "another database");
    assert!(app.tab == Tab::Infrastructure);
    assert_eq!(app.snapshot.unwrap().peers.len(), 4);
}

#[test]
fn a_completed_aggregate_is_rendered_as_a_result_row() {
    let (mut app, commands, events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    app.run_query();
    let _ = commands.try_recv().unwrap();
    events
        .send(Event::Finished {
            snapshot: Some(snapshot(3)),
            elapsed_ms: 25.0,
            outcome: Ok(Outcome::Query(QueryOutcome::Aggregate {
                count: 2,
                sum: 50,
                peers: vec![],
            })),
        })
        .unwrap();
    app.poll();

    let texts = render(&ctx, &mut app, vec![]);

    for expected in ["COUNT(*)", "SUM(amount)", "2", "50"] {
        assert!(
            texts.iter().any(|text| text.text == expected),
            "missing result cell: {expected}"
        );
    }
}

#[test]
fn a_rejected_update_opens_output_with_the_failure_reason() {
    let (mut app, commands, events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    app.insert_preset(PRESETS[5].sql);
    app.run_query();
    let _ = commands.try_recv().unwrap();
    events
        .send(Event::Finished {
            snapshot: Some(snapshot(3)),
            elapsed_ms: 25.0,
            outcome: Ok(Outcome::Query(QueryOutcome::Updated { committed: false })),
        })
        .unwrap();
    app.poll();

    let texts = render(&ctx, &mut app, vec![]);

    assert!(app.result_tab == ResultTab::Output);
    assert!(
        texts
            .iter()
            .any(|text| text.text == "Rejected: amount overflow; no changes")
    );
}
