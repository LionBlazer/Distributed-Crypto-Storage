use super::*;
use fhe_playground::DemoNetwork;
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
#[path = "ui_preview.rs"]
mod preview;

fn app() -> (Playground, Receiver<Command>, Sender<Event>) {
    let (worker, commands, events) = Worker::test_channel();
    let mut app = Playground::with_worker(worker);
    let state = snapshot(3);
    app.draft_name = state.name.clone();
    app.draft_rows = format_rows(&state.owner_rows);
    app.snapshot = Some(state);
    app.network = Some(network(3, 1));
    app.active_client = Some(1);
    (app, commands, events)
}

#[test]
fn data_import_and_long_paths_keep_the_splitter_stable_across_idle_frames() {
    let (worker, _commands, _events) = Worker::test_channel();
    let mut app = Playground::with_worker(worker);
    app.tab = Tab::Data;
    app.network = Some(network(0, 1));
    app.active_client = Some(1);
    let ctx = egui::Context::default();
    set_theme(&ctx);
    render(&ctx, &mut app, vec![]);
    let width = egui::containers::panel::PanelState::load(&ctx, egui::Id::new("client-workspace"))
        .unwrap()
        .size()
        .x;
    click(&ctx, &mut app, "Local .sql file path");
    render(
        &ctx,
        &mut app,
        vec![egui::Event::Text(format!(
            "E:/{}northwind.sql",
            "long-directory/".repeat(40)
        ))],
    );
    click(&ctx, &mut app, "Public sample databases");
    for _ in 0..60 {
        let text = render(&ctx, &mut app, vec![]);
        let current =
            egui::containers::panel::PanelState::load(&ctx, egui::Id::new("client-workspace"))
                .unwrap()
                .size()
                .x;
        assert!(
            (current - width).abs() < 1.0,
            "idle content must not move the splitter: {width} -> {current}"
        );
        assert!(
            text.iter()
                .find(|text| text.text == "Network")
                .unwrap()
                .rect
                .left()
                < 1000.0
        );
    }
}

#[test]
fn stop_cancels_only_the_active_sql_and_waits_for_its_real_completion() {
    let (mut app, commands, events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    assert!(!app.can_stop_query());
    click(&ctx, &mut app, "Run");
    assert!(matches!(commands.try_recv(), Ok(Command::Query { .. })));
    assert!(app.can_stop_query());
    click(&ctx, &mut app, "Stop");
    assert!(app.worker.query_cancelled());
    assert_eq!(app.status, "Stopping SQL…");
    assert!(app.pending.is_some());
    assert!(!app.can_query());
    assert!(!app.can_stop_query());
    assert!(
        matches!(commands.try_recv(), Err(TryRecvError::Empty)),
        "stop must not queue behind the SQL it interrupts"
    );
    events
        .send(Event::Finished {
            snapshot: None,
            outcome: Err(fhe_playground::LabError::InvalidInput("SQL stopped".into())),
            elapsed_ms: 1.0,
            client_id: Some(1),
        })
        .unwrap();
    app.poll();
    assert!(app.pending.is_none());
    assert!(app.can_query());
    click(&ctx, &mut app, "Run");
    assert!(matches!(commands.try_recv(), Ok(Command::Query { .. })));
    assert!(
        !app.worker.query_cancelled(),
        "new SQL has an independent cancellation scope"
    );
}

#[test]
fn a_new_workspace_has_no_canned_rows_or_automatic_database_command() {
    let (worker, commands, _events) = Worker::test_channel();
    let mut app = Playground::with_worker(worker);
    assert!(app.snapshot.is_none());
    assert!(app.draft_rows.is_empty());
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
    app.tab = Tab::Data;
    let ctx = egui::Context::default();
    set_theme(&ctx);
    let text = render(&ctx, &mut app, vec![]);
    for removed in ["Fixtures", "Generate", "Overflow", "Demo"] {
        assert!(!text.iter().any(|item| item.text == removed));
    }
}

#[test]
fn run_is_available_before_a_database_exists_and_dispatches_the_startup_script() {
    let (worker, commands, events) = Worker::test_channel();
    let mut app = Playground::with_worker(worker);
    events.send(Event::Network(network(0, 1))).unwrap();
    app.poll();
    assert!(app.snapshot.is_none());
    assert!(app.can_query());
    assert_eq!(app.run_disabled_reason(), None);
    assert!(
        storage_client::SqlScript::parse(&app.sql)
            .unwrap()
            .has_create()
    );
    let context = egui::Context::default();
    set_theme(&context);

    click(&context, &mut app, "Run");

    assert!(
        matches!(commands.try_recv(), Ok(Command::Query {client_id:1, sql}) if sql == STARTUP_SQL)
    );
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn a_missing_table_error_from_the_worker_is_shown_in_output() {
    let (worker, commands, events) = Worker::test_channel();
    let mut app = Playground::with_worker(worker);
    events.send(Event::Network(network(0, 1))).unwrap();
    app.poll();
    app.sql = "SELECT * FROM records;".into();
    app.run_query();
    assert!(matches!(commands.try_recv(), Ok(Command::Query { .. })));
    events
        .send(Event::Finished {
            snapshot: None,
            outcome: Err(fhe_playground::LabError::InvalidInput(
                "Statement 1: table records does not exist".into(),
            )),
            elapsed_ms: 1.0,
            client_id: Some(1),
        })
        .unwrap();

    app.poll();

    let context = egui::Context::default();
    set_theme(&context);
    assert_eq!(app.result_tab, ResultTab::Output);
    let text = render(&context, &mut app, vec![]);
    assert!(
        text.iter()
            .any(|item| item.text.contains("table records does not exist"))
    );
    assert!(app.snapshot.is_none());
}
fn snapshot(peers: usize) -> LabSnapshot {
    // Public synthetic rows, but real default custody/physical accounting. Cache
    // only the non-secret snapshot so headless UI examples share no live engine.
    static SNAPSHOTS: std::sync::OnceLock<std::sync::Mutex<HashMap<usize, LabSnapshot>>> =
        std::sync::OnceLock::new();
    SNAPSHOTS
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .entry(peers)
        .or_insert_with(|| {
            let mut engine = fhe_playground::LabEngine::default();
            engine
                .create(DatabaseDraft {
                    name: "demo".into(),
                    rows: sample_rows(4).unwrap(),
                    peers: (1..=peers).map(PeerConfig::numbered).collect(),
                })
                .unwrap()
        })
        .clone()
}
fn network(peers: usize, clients: usize) -> NetworkSnapshot {
    let mut net = DemoNetwork::default();
    for id in 1..=clients {
        net.add_client(format!("Client {id:02}")).unwrap();
    }
    for id in 1..=peers {
        net.add_peer(id, &PeerConfig::numbered(id), true).unwrap();
    }
    for _ in 0..40 {
        net.advance(0.1);
    }
    net.snapshot()
}
fn replicated_snapshot() -> LabSnapshot {
    use fhe_playground::{LogicalShardInfo, ReplicaLocation, ReplicationInfo};
    let mut state = snapshot(3);
    let owner = compact_store::Owner::generate([89; 16]).unwrap();
    let head = owner
        .seal(
            compact_store::Layout {
                schema: [1; 16],
                row_width: 1,
                rows_per_page: 16,
                row_count: 1,
            },
            &[18],
            compact_store::Limits::default(),
        )
        .unwrap()
        .commitment()
        .clone();
    state.replication = Some(ReplicationInfo {
        desired_copies: 2,
        shards: vec![LogicalShardInfo {
            id: 1,
            rows: 4,
            data_head: head.clone(),
            index_head: head,
            replicas: (1..=3)
                .map(|peer_id| ReplicaLocation {
                    peer_id,
                    failure_domain: 1,
                    online: true,
                    current: peer_id != 1,
                    data_bytes: 166,
                    index_bytes: 2336,
                })
                .collect(),
            executor: Some(2),
        }],
        failure_domains: vec![(1, 1), (2, 1), (3, 1)],
        read_peers: vec![2],
        write_peers: vec![2, 3],
        unavailable_shards: vec![],
    });
    state
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
                egui::vec2(1500.0, 900.0),
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
                    collect(shape, clip, texts)
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
fn click_point(
    ctx: &egui::Context,
    app: &mut Playground,
    point: egui::Pos2,
    button: egui::PointerButton,
) {
    render(
        ctx,
        app,
        vec![
            egui::Event::PointerMoved(point),
            egui::Event::PointerButton {
                pos: point,
                button,
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
            button,
            pressed: false,
            modifiers: egui::Modifiers::NONE,
        }],
    );
}
fn click(ctx: &egui::Context, app: &mut Playground, label: &str) {
    let texts = render(ctx, app, vec![]);
    let point = if matches!(label, "Run" | "Stop") {
        ctx.data(|data| {
            data.get_temp::<egui::Rect>(egui::Id::new(if label == "Run" {
                "sql-run-rect"
            } else {
                "sql-stop-rect"
            }))
        })
        .expect("SQL icon button is present")
        .center()
    } else {
        texts
            .iter()
            .find(|t| t.text == label)
            .unwrap_or_else(|| panic!("control missing:{label}"))
            .rect
            .center()
    };
    click_point(ctx, app, point, egui::PointerButton::Primary);
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
fn settings_copy_choice_sends_one_serialized_local_policy_command() {
    let (mut app, commands, _) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    let texts = render(&ctx, &mut app, vec![]);
    assert!(texts.iter().any(|text| text.text == "Settings"));
    assert!(!texts.iter().any(|text| text.text == "Min copies 1"));
    click(&ctx, &mut app, "Settings");
    assert_eq!(app.right_tab, RightTab::Settings);
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
    click(&ctx, &mut app, "Min copies 1");
    click(&ctx, &mut app, "2 copies");
    assert!(matches!(
        commands.try_recv().unwrap(),
        Command::SetReplication { copies: 2 }
    ));
    assert!(commands.try_recv().is_err());
    assert!(matches!(app.control_pending, Some(Control::Replication)));
    assert_eq!(
        app.snapshot
            .as_ref()
            .unwrap()
            .replication
            .as_ref()
            .unwrap()
            .desired_copies,
        1
    );
}

#[test]
fn confirming_existing_one_copy_keeps_default_fixed_custody_without_a_rebuild() {
    let (mut app, commands, _) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    app.right_tab = RightTab::Settings;
    let shard_count = app
        .snapshot
        .as_ref()
        .unwrap()
        .replication
        .as_ref()
        .unwrap()
        .shards
        .len();
    let texts = render(&ctx, &mut app, vec![]);
    assert!(texts.iter().any(|text| {
        text.text
            .contains(&format!("{shard_count}/{shard_count} at target"))
    }));
    assert!(commands.try_recv().is_err());
    click(&ctx, &mut app, "Min copies 1");
    click(&ctx, &mut app, "1 copy");
    assert!(commands.try_recv().is_err());
    assert_eq!(
        app.snapshot
            .as_ref()
            .unwrap()
            .replication
            .as_ref()
            .unwrap()
            .desired_copies,
        1
    );
}

#[test]
fn missing_custody_metadata_disables_policy_but_sql_reports_through_the_real_worker() {
    let (mut app, commands, _events) = app();
    app.snapshot.as_mut().unwrap().replication = None;
    app.right_tab = RightTab::Settings;
    let ctx = egui::Context::default();
    set_theme(&ctx);
    let texts = render(&ctx, &mut app, vec![]);
    assert!(
        texts
            .iter()
            .any(|text| text.text == "Storage state unavailable")
    );
    assert!(
        !texts
            .iter()
            .any(|text| text.text == "Min copies 1" || text.text.contains("Legacy"))
    );
    assert!(app.can_query());
    app.run_query();
    assert!(matches!(
        commands.try_recv(),
        Ok(Command::Query { client_id: 1, .. })
    ));
    assert!(app.history.is_empty());
}

#[test]
fn copy_health_counts_independent_domains_and_distinguishes_stale_copies() {
    let (mut app, _, _) = app();
    app.snapshot = Some(replicated_snapshot());
    app.right_tab = RightTab::Settings;
    let ctx = egui::Context::default();
    set_theme(&ctx);
    let texts = render(&ctx, &mut app, vec![]);
    assert!(texts.iter().any(|text| text.text.contains("0/1 at target")
        && text.text.contains("2 online current / 1 stale")));
    let texts = render(&ctx, &mut app, vec![]);
    assert!(texts.iter().any(|text| text.text == "Min copies 2"));
}

#[test]
fn inspector_preserves_owner_view_without_faking_independent_process_failure_domains() {
    let (mut app, commands, _) = app();
    app.snapshot = Some(replicated_snapshot());
    app.open_node(2);
    let ctx = egui::Context::default();
    set_theme(&ctx);
    let texts = render(&ctx, &mut app, vec![]);
    assert!(
        texts
            .iter()
            .any(|text| text.text.contains("stale / online"))
    );
    assert!(
        texts
            .iter()
            .any(|text| text.text.contains("Owner inspection")
                && text.text.contains("earlier values"))
    );
    assert!(commands.try_recv().is_err());
    assert!(!texts.iter().any(|text| text.text == "Save domain"));
    assert!(
        texts
            .iter()
            .any(|text| text.text == "Failure domain: local host")
    );
    assert!(commands.try_recv().is_err());
}

#[test]
fn context_menu_exposes_manual_local_replica_repair_without_a_new_panel() {
    let (mut app, commands, _) = app();
    app.snapshot = Some(replicated_snapshot());
    let ctx = egui::Context::default();
    set_theme(&ctx);
    render(&ctx, &mut app, vec![]);
    click_point(
        &ctx,
        &mut app,
        egui::pos2(1460.0, 810.0),
        egui::PointerButton::Secondary,
    );
    click(&ctx, &mut app, "Repair replicas");
    assert!(matches!(
        commands.try_recv().unwrap(),
        Command::RepairReplicas
    ));
    assert!(matches!(app.control_pending, Some(Control::Repair)));
}

#[test]
fn process_snapshots_do_not_finish_a_query_or_consume_an_unrelated_control() {
    let (mut app, commands, events) = app();
    app.run_query();
    let _ = commands.try_recv().unwrap();
    app.control_pending = Some(Control::Availability);
    events.send(Event::Snapshot(replicated_snapshot())).unwrap();
    app.poll();
    assert!(app.pending.is_some());
    assert!(matches!(app.control_pending, Some(Control::Availability)));
    assert!(app.history.is_empty());
}

#[test]
fn dense_network_shows_every_real_connection_without_changing_topology() {
    let (mut app, commands, _events) = app();
    app.network = Some(network(16, 1));
    app.snapshot = Some(snapshot(16));
    app.network_view = NetworkView::Matrix;
    let original = app.network.clone().unwrap();
    assert_eq!(original.links.len(), 136);
    let ctx = egui::Context::default();
    set_theme(&ctx);
    assert!(app.uses_matrix());
    let output = ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1500.0, 900.0),
            )),
            ..Default::default()
        },
        |ui| app.draw(ui),
    );
    fn connection_dots(shape: &egui::Shape) -> usize {
        match shape {
            egui::Shape::Circle(circle) if circle.radius == 2.0 => 1,
            egui::Shape::Vec(shapes) => shapes.iter().map(connection_dots).sum(),
            _ => 0,
        }
    }
    assert_eq!(
        output
            .shapes
            .iter()
            .map(|s| connection_dots(&s.shape))
            .sum::<usize>(),
        136 * 2,
        "Every undirected connection must appear in both matrix directions"
    );
    output.drop_without_applying_deltas();
    click(&ctx, &mut app, "Map");
    assert!(!app.uses_matrix());
    click(&ctx, &mut app, "Matrix");
    assert!(app.uses_matrix());
    assert_eq!(
        app.network.as_ref().unwrap().links.len(),
        original.links.len()
    );
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn dense_matrix_nodes_use_the_same_inspector_and_delete_commands() {
    let (mut app, commands, _events) = app();
    app.network = Some(network(16, 1));
    app.snapshot = Some(snapshot(16));
    app.network_view = NetworkView::Matrix;
    let ctx = egui::Context::default();
    set_theme(&ctx);
    let texts = render(&ctx, &mut app, vec![]);
    let peer = texts
        .iter()
        .rev()
        .find(|text| text.text == "Peer 02")
        .unwrap()
        .rect
        .center();
    click_point(&ctx, &mut app, peer, egui::PointerButton::Primary);
    click_point(&ctx, &mut app, peer, egui::PointerButton::Primary);
    assert!(app.right_tab == RightTab::Node(3));
    click(&ctx, &mut app, "Network");
    let texts = render(&ctx, &mut app, vec![]);
    let peer = texts
        .iter()
        .rev()
        .find(|text| text.text == "Peer 02")
        .unwrap()
        .rect
        .center();
    click_point(&ctx, &mut app, peer, egui::PointerButton::Secondary);
    click(&ctx, &mut app, "Delete node");
    assert!(matches!(
        commands.try_recv(),
        Ok(Command::RemoveNode { id: 3 })
    ));
}

#[test]
fn matrix_traces_discovery_before_a_connection_exists_in_the_correct_direction() {
    let (mut app, commands, _events) = app();
    app.network_view = NetworkView::Matrix;
    app.playback.health = true;
    let net = app.network.as_mut().unwrap();
    net.links.clear();
    net.packets = vec![fhe_playground::NetworkPacket {
        id: 99,
        from: 1,
        to: 3,
        kind: fhe_playground::PacketKind::Ping,
        progress: 0.5,
        request_id: None,
    }];
    let observed = net.clone();
    app.apply_display_event(Event::Network(observed));
    let ctx = egui::Context::default();
    set_theme(&ctx);
    let output = ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1500.0, 900.0),
            )),
            ..Default::default()
        },
        |ui| app.draw(ui),
    );
    let packet_markers: Vec<_> = output
        .shapes
        .iter()
        .filter_map(|shape| {
            if let egui::Shape::Circle(circle) = &shape.shape
                && circle.radius == 2.5
            {
                Some(circle)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(packet_markers.len(), 1);
    let color = packet_markers[0].fill;
    assert!(color.r() > color.b() && color.g() > color.b());
    assert!(app.network.as_ref().unwrap().links.is_empty());
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
    output.drop_without_applying_deltas();
}

#[test]
fn matrix_blank_space_can_add_nodes_even_with_an_empty_network() {
    for peers in [0, 3] {
        let (mut app, commands, _events) = app();
        app.network = Some(network(peers, usize::from(peers > 0)));
        app.network_view = NetworkView::Matrix;
        let ctx = egui::Context::default();
        set_theme(&ctx);
        render(&ctx, &mut app, vec![]);
        click_point(
            &ctx,
            &mut app,
            egui::pos2(1460.0, 810.0),
            egui::PointerButton::Secondary,
        );
        click(&ctx, &mut app, "Add client");
        assert!(matches!(commands.try_recv(), Ok(Command::AddClient { .. })));
    }
}

#[test]
fn automatic_map_fit_tracks_resize_and_preserves_a_manually_moved_camera() {
    let (mut app, _commands, _events) = app();
    app.network = Some(network(16, 1));
    app.snapshot = Some(snapshot(16));
    app.network_view = NetworkView::Map;
    let ctx = egui::Context::default();
    set_theme(&ctx);
    render(&ctx, &mut app, vec![]);
    let original = app.camera.zoom;
    let render_size = |app: &mut Playground, size: egui::Vec2| {
        let output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                ..Default::default()
            },
            |ui| app.draw(ui),
        );
        output.drop_without_applying_deltas();
    };
    render_size(&mut app, egui::vec2(1180.0, 720.0));
    assert!(app.camera.zoom < original);
    let canvas = app.last_graph_canvas.unwrap();
    for (_, point) in app.graph_layout.positions() {
        let screen = app
            .camera
            .world_to_screen(canvas, egui::pos2(point.x, point.y));
        assert!(canvas.contains(screen));
    }
    app.camera_manipulated = true;
    app.camera.center = egui::vec2(321.0, 123.0);
    let saved = (app.camera.center, app.camera.zoom);
    render_size(&mut app, egui::vec2(1500.0, 900.0));
    assert_eq!((app.camera.center, app.camera.zoom), saved);
}

#[test]
fn presets_fill_the_editor_without_execution_until_run_is_clicked() {
    let (mut app, commands, _events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    click(&ctx, &mut app, "Presets");
    click(&ctx, &mut app, "Increase adult amounts by 5");
    let preset = PRESETS
        .iter()
        .find(|preset| preset.name == "Increase adult amounts by 5")
        .unwrap();
    assert_eq!(app.sql, preset.sql);
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
    click(&ctx, &mut app, "Run");
    assert!(matches!(commands.try_recv(),Ok(Command::Query{client_id:1,sql})if sql==preset.sql));
}

#[test]
fn remaining_presets_only_fill_sql_until_the_user_runs_the_statement() {
    let (mut app, commands, _events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    for name in ["All rows", "Adults", "Insert one row"] {
        let preset = PRESETS.iter().find(|preset| preset.name == name).unwrap();

        click(&ctx, &mut app, "Presets");
        click(&ctx, &mut app, name);

        assert_eq!(app.sql, preset.sql);
        assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
    }
    let sql = app.sql.clone();
    click(&ctx, &mut app, "Run");
    assert!(
        matches!(commands.try_recv(), Ok(Command::Query { client_id: 1, sql: sent }) if sent == sql)
    );
}
#[test]
fn network_remains_beside_both_sql_and_data_without_old_sidebars() {
    let (mut app, commands, _events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    let texts = render(&ctx, &mut app, vec![]);
    let console = ctx
        .data(|data| data.get_temp::<egui::Rect>(egui::Id::new("sql-run-rect")))
        .unwrap();
    let network = texts.iter().find(|t| t.text == "Network").unwrap();
    assert!(console.right() < network.rect.left());
    for obsolete in [
        "Filter objects...",
        "Local database",
        "Tables",
        "Layout",
        "Add peer",
        "Back",
        "Forward",
    ] {
        assert!(!texts.iter().any(|t| t.text == obsolete));
    }
    click(&ctx, &mut app, "Data");
    let texts = render(&ctx, &mut app, vec![]);
    assert!(texts.iter().any(|t| t.text == "Network"));
    assert!(texts.iter().any(|t| t.text == "records"));
    assert!(!texts.iter().any(|t| t.text == "Add row"));
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn back_and_forward_restore_views_without_changing_edits_or_running_sql() {
    let (mut app, commands, _events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    app.open_node(2);
    app.sql = "SELECT age FROM records LIMIT 2;".into();
    app.draft_name = "unsaved".into();
    app.draft_rows = "22,99".into();
    app.peer_edits.get_mut(&2).unwrap().name = "Unsaved peer".into();
    app.camera.center = egui::vec2(91.0, -31.0);
    app.camera.zoom = 0.7;
    app.camera_manipulated = true;
    app.open_node(3);

    click_point(
        &ctx,
        &mut app,
        egui::pos2(1200.0, 600.0),
        egui::PointerButton::Extra1,
    );
    assert_eq!(app.right_tab, RightTab::Node(2));
    assert!(app.navigation.can_step(true));
    click_point(
        &ctx,
        &mut app,
        egui::pos2(1200.0, 600.0),
        egui::PointerButton::Extra2,
    );
    assert_eq!(app.right_tab, RightTab::Node(3));
    assert_eq!(app.sql, "SELECT age FROM records LIMIT 2;");
    assert_eq!(app.draft_name, "unsaved");
    assert_eq!(app.draft_rows, "22,99");
    assert_eq!(app.peer_edits[&2].name, "Unsaved peer");
    assert_eq!(app.camera.center, egui::vec2(91.0, -31.0));
    assert_eq!(app.camera.zoom, 0.7);
    assert_eq!(app.active_client, Some(1));
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn new_navigation_after_back_truncates_the_forward_branch_and_deduplicates_visits() {
    let (mut app, commands, _events) = app();
    app.open_node(2);
    app.open_node(3);
    app.navigate_history(false);
    app.navigate(Tab::Data, RightTab::Network);
    app.navigate(Tab::Data, RightTab::Network);

    assert!(!app.navigation.can_step(true));
    app.navigate_history(false);
    assert_eq!(app.tab, Tab::Sql);
    assert_eq!(app.right_tab, RightTab::Node(2));
    app.navigate_history(true);
    assert_eq!(app.tab, Tab::Data);
    assert_eq!(app.right_tab, RightTab::Network);
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn mouse_extra_buttons_and_alt_arrows_follow_the_same_navigation_history() {
    let (mut app, commands, _events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    app.open_node(2);
    app.open_node(3);
    let pointer = egui::pos2(1200.0, 600.0);
    click_point(&ctx, &mut app, pointer, egui::PointerButton::Extra1);
    assert_eq!(app.right_tab, RightTab::Node(2));
    click_point(&ctx, &mut app, pointer, egui::PointerButton::Extra2);
    assert_eq!(app.right_tab, RightTab::Node(3));
    for (key, expected) in [(egui::Key::ArrowLeft, 2), (egui::Key::ArrowRight, 3)] {
        render(
            &ctx,
            &mut app,
            vec![egui::Event::Key {
                key,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::ALT,
            }],
        );
        assert_eq!(app.right_tab, RightTab::Node(expected));
    }
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

fn pointer_event(position: egui::Pos2, button: egui::PointerButton, pressed: bool) -> egui::Event {
    egui::Event::PointerButton {
        pos: position,
        button,
        pressed,
        modifiers: egui::Modifiers::NONE,
    }
}

#[test]
fn side_navigation_activates_on_press_and_never_pans_while_held_or_on_release() {
    for button in [egui::PointerButton::Extra1, egui::PointerButton::Extra2] {
        let (mut app, commands, _events) = app();
        app.network_view = NetworkView::Map;
        let ctx = egui::Context::default();
        set_theme(&ctx);
        render(&ctx, &mut app, vec![]);
        app.camera_manipulated = true;
        app.camera.center = egui::vec2(91.0, -31.0);
        app.camera.zoom = 0.8;
        app.open_node(2);
        if button == egui::PointerButton::Extra2 {
            app.navigate(Tab::Sql, RightTab::Network);
            app.navigate_history(false);
        }
        let saved = (app.camera.center, app.camera.zoom);
        let start = egui::pos2(1450.0, 810.0);
        render(
            &ctx,
            &mut app,
            vec![
                egui::Event::PointerMoved(start),
                pointer_event(start, button, true),
            ],
        );
        assert_eq!(
            app.right_tab,
            RightTab::Network,
            "Navigation must happen before release"
        );
        let moved = start - egui::vec2(80.0, 60.0);
        render(&ctx, &mut app, vec![egui::Event::PointerMoved(moved)]);
        assert_eq!(
            (app.camera.center, app.camera.zoom),
            saved,
            "Holding a side button never drags the map"
        );
        render(&ctx, &mut app, vec![pointer_event(moved, button, false)]);
        assert_eq!(
            app.right_tab,
            RightTab::Network,
            "Release must not navigate twice"
        );
        assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
    }
}

#[test]
fn primary_secondary_and_middle_drags_pan_without_opening_a_context_menu() {
    for button in [
        egui::PointerButton::Primary,
        egui::PointerButton::Middle,
        egui::PointerButton::Secondary,
        egui::PointerButton::Extra1,
        egui::PointerButton::Extra2,
    ] {
        let (mut app, commands, _events) = app();
        app.network_view = NetworkView::Map;
        let ctx = egui::Context::default();
        set_theme(&ctx);
        render(&ctx, &mut app, vec![]);
        app.camera_manipulated = true;
        let saved = app.camera.center;
        let start = egui::pos2(1450.0, 810.0);
        render(
            &ctx,
            &mut app,
            vec![
                egui::Event::PointerMoved(start),
                pointer_event(start, button, true),
            ],
        );
        render(
            &ctx,
            &mut app,
            vec![egui::Event::PointerMoved(start - egui::vec2(80.0, 60.0))],
        );
        if matches!(
            button,
            egui::PointerButton::Primary
                | egui::PointerButton::Secondary
                | egui::PointerButton::Middle
        ) {
            assert_ne!(app.camera.center, saved, "{button:?} must pan the graph");
        } else {
            assert_eq!(
                app.camera.center, saved,
                "{button:?} must not pan the graph"
            );
        }
        let stopped = app.camera.center;
        let texts = render(
            &ctx,
            &mut app,
            vec![pointer_event(start - egui::vec2(80.0, 60.0), button, false)],
        );
        assert_eq!(
            app.camera.center, stopped,
            "Release must not move the camera"
        );
        assert!(
            !texts.iter().any(|text| text.text == "Add peer"),
            "Dragging with {button:?} must not open a context menu"
        );
        assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
    }
}

#[test]
fn document_tabs_share_one_baseline_across_pinned_and_scrolling_headers() {
    let (mut app, commands, _events) = app();
    for id in 2..=4 {
        app.open_node(id);
    }
    let ctx = egui::Context::default();
    set_theme(&ctx);
    render(&ctx, &mut app, vec![]);
    let texts = render(&ctx, &mut app, vec![]);
    let labels = [
        "SQL", "Data", "Network", "Settings", "Peer 01", "Peer 02", "Peer 03",
    ];
    let centers: Vec<_> = labels
        .into_iter()
        .map(|label| {
            texts
                .iter()
                .find(|text| text.text == label && text.rect.top() < 40.0)
                .unwrap_or_else(|| panic!("Tab {label} must remain in the header"))
                .rect
                .center()
                .y
        })
        .collect();
    for y in centers {
        assert!(
            (y - TAB_HEIGHT * 0.5).abs() < 1.0,
            "Pinned and scrolling tabs must share the same text baseline"
        );
    }
    for name in ["client-tabs", "network-header"] {
        let header = egui::containers::panel::PanelState::load(&ctx, egui::Id::new(name))
            .unwrap()
            .outer_rect;
        assert!(
            (header.height() - TAB_HEIGHT).abs() < 1.0,
            "Both workspaces must start their content at the same height: {name} = {header:?}"
        );
    }
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn inspector_tabs_middle_click_closes_active_or_inactive_without_deleting_nodes() {
    let (mut app, commands, _events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    app.open_node(2);
    app.open_node(3);
    app.open_node(4);
    let draft = app.sql.clone();
    for (label, remaining, active) in [
        ("Peer 02", vec![2, 4], RightTab::Node(4)),
        ("Peer 03", vec![2], RightTab::Node(2)),
    ] {
        let point = render(&ctx, &mut app, vec![])
            .into_iter()
            .find(|text| text.text == label && text.rect.top() < 55.0)
            .unwrap()
            .rect
            .center();
        click_point(&ctx, &mut app, point, egui::PointerButton::Middle);
        assert_eq!(app.node_tabs, remaining);
        assert_eq!(app.right_tab, active);
    }
    assert_eq!(app.sql, draft);
    assert_eq!(app.network.as_ref().unwrap().nodes.len(), 4);
    assert_eq!(app.active_client, Some(1));
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn inline_tab_cross_closes_without_selecting_and_last_tab_returns_to_network() {
    let (mut app, commands, _events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    app.open_node(2);
    app.open_node(3);
    app.open_node(4);
    for (ordinal, expected) in [
        (0, RightTab::Node(4)),
        (1, RightTab::Node(3)),
        (0, RightTab::Network),
    ] {
        let point = render(&ctx, &mut app, vec![])
            .into_iter()
            .filter(|text| text.text == "×" && text.rect.top() < 55.0)
            .nth(ordinal)
            .unwrap()
            .rect
            .center();
        click_point(&ctx, &mut app, point, egui::PointerButton::Primary);
        assert_eq!(app.right_tab, expected);
        render(&ctx, &mut app, vec![]);
        assert_eq!(
            app.right_tab, expected,
            "Closing must not select the closed tab"
        );
    }
    assert!(app.node_tabs.is_empty());
    assert_eq!(app.network.as_ref().unwrap().nodes.len(), 4);
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn result_panel_starts_at_half_window_and_can_grow_beyond_the_old_limit() {
    let (mut app, commands, _events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    render(&ctx, &mut app, vec![]);
    let panel = |name| {
        egui::containers::panel::PanelState::load(&ctx, egui::Id::new(name))
            .unwrap()
            .outer_rect
    };
    let original = panel("query-results");
    assert!((original.height() - ctx.content_rect().height() * 0.5).abs() < 3.0);
    let start = original.center_top();
    render(
        &ctx,
        &mut app,
        vec![
            egui::Event::PointerMoved(start),
            pointer_event(start, egui::PointerButton::Primary, true),
        ],
    );
    let raised = start - egui::vec2(0.0, 150.0);
    render(&ctx, &mut app, vec![egui::Event::PointerMoved(raised)]);
    render(
        &ctx,
        &mut app,
        vec![pointer_event(raised, egui::PointerButton::Primary, false)],
    );
    let expanded = panel("query-results");
    assert!(expanded.height() > original.height() + 140.0);
    assert!(expanded.height() > 420.0);
    let start = expanded.center_top();
    render(
        &ctx,
        &mut app,
        vec![
            egui::Event::PointerMoved(start),
            pointer_event(start, egui::PointerButton::Primary, true),
        ],
    );
    let lowered = start + egui::vec2(0.0, 90.0);
    render(&ctx, &mut app, vec![egui::Event::PointerMoved(lowered)]);
    render(
        &ctx,
        &mut app,
        vec![pointer_event(lowered, egui::PointerButton::Primary, false)],
    );
    assert!(panel("query-results").height() < expanded.height() - 80.0);
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn narrow_result_table_keeps_its_scroll_viewport_at_the_panel_right_edge() {
    // Public renderer fixture: no query or encrypted backend execution is claimed.
    let (mut app, commands, _events) = app();
    app.history.push_front(Record {
        job: Job::Query,
        label: "Public renderer fixture".into(),
        database: "demo".into(),
        revision: 0,
        elapsed_ms: 0.0,
        outcome: Ok(Outcome::Query(QueryOutcome::Selected {
            columns: vec![Column::Age, Column::Amount],
            rows: (0..128).map(|age| vec![age, age]).collect(),
        })),
    });
    let ctx = egui::Context::default();
    set_theme(&ctx);
    let mut viewport = None;
    let output = ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(600.0, 400.0),
            )),
            ..Default::default()
        },
        |ui| {
            let scroll = app.results(ui);
            viewport = Some((scroll.inner_rect, scroll.content_size));
        },
    );
    output.drop_without_applying_deltas();
    let (viewport, content) = viewport.unwrap();
    assert!(
        content.y > viewport.height(),
        "Rows must actually require scrolling"
    );
    assert!(
        viewport.right() > 560.0,
        "The viewport must fill the panel, not stop after the table"
    );
    assert!(viewport.height() > 300.0);
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn network_settings_follow_history_and_stay_beside_data_without_executing_sql() {
    let (mut app, commands, _events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    click(&ctx, &mut app, "Settings");
    click(&ctx, &mut app, "Data");
    assert_eq!(app.right_tab, RightTab::Settings);
    let texts = render(&ctx, &mut app, vec![]);
    assert!(texts.iter().any(|text| text.text == "Owner configuration"));
    click_point(
        &ctx,
        &mut app,
        egui::pos2(1200.0, 600.0),
        egui::PointerButton::Extra1,
    );
    assert_eq!(app.tab, Tab::Sql);
    assert_eq!(app.right_tab, RightTab::Settings);
    click_point(
        &ctx,
        &mut app,
        egui::pos2(1200.0, 600.0),
        egui::PointerButton::Extra1,
    );
    assert_eq!(app.right_tab, RightTab::Network);
    click_point(
        &ctx,
        &mut app,
        egui::pos2(1200.0, 600.0),
        egui::PointerButton::Extra2,
    );
    assert_eq!(app.right_tab, RightTab::Settings);
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn overflowing_tabs_reveal_the_active_inspector_and_keep_network_pinned() {
    let (mut app, commands, _events) = app();
    app.network = Some(network(16, 1));
    app.snapshot = Some(snapshot(16));
    for id in 2..=17 {
        app.open_node(id);
    }
    let ctx = egui::Context::default();
    set_theme(&ctx);
    for label in ["Peer 16", "Peer 15"] {
        if label == "Peer 15" {
            app.navigate_history(false);
        }
        let visible = (0..60).any(|_| {
            let texts = render(&ctx, &mut app, vec![]);
            ["Network", label].into_iter().all(|label| {
                texts.iter().any(|text| {
                    text.text == label
                        && text.rect.top() < 55.0
                        && text.rect.left() >= 615.0
                        && text.rect.right() <= 1500.0
                })
            })
        });
        assert!(
            visible,
            "The active {label} and pinned Network tab must be visible"
        );
    }
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn peer_cards_render_live_physical_payload_bytes_and_exact_quota_fraction() {
    // Public synthetic rows; the renderer takes a real engine snapshot and never
    // calculates query results or storage sizes from the owner's inspector rows.
    let mut engine = fhe_playground::LabEngine::default();
    let state = engine
        .create(DatabaseDraft {
            name: "metrics".into(),
            rows: sample_rows(4).unwrap(),
            peers: (1..=3).map(PeerConfig::numbered).collect(),
        })
        .unwrap();
    let expected = state
        .peers
        .iter()
        .find(|peer| peer.logical_bytes > 0)
        .unwrap()
        .clone();
    let (mut app, commands, _events) = app();
    app.snapshot = Some(state);
    app.network_view = NetworkView::Map;
    let ctx = egui::Context::default();
    set_theme(&ctx);
    let output = ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1500.0, 900.0),
            )),
            ..Default::default()
        },
        |ui| app.draw(ui),
    );
    let mut texts = Vec::new();
    let mut rectangles = Vec::new();
    for shape in &output.shapes {
        match &shape.shape {
            egui::Shape::Text(text) => texts.push((
                text.galley.job.text.clone(),
                text.galley.rect.translate(text.pos.to_vec2()),
            )),
            egui::Shape::Rect(rect) => rectangles.push(rect),
            _ => {}
        }
    }
    assert!(texts.iter().any(|(text, _)| text
        == &format!(
            "Payload {} B · {} {}",
            expected.logical_bytes,
            expected.rows,
            if expected.rows == 1 { "row" } else { "rows" }
        )));
    assert!(texts.iter().any(|(text, _)| text
        == &format!(
            "Stored {} / {} B",
            expected.stored_bytes, expected.config.storage_limit_bytes
        )));
    let title = texts
        .iter()
        .find(|(text, _)| text == &format!("P{:02}", expected.id))
        .unwrap()
        .1;
    let bar_min = egui::pos2(title.left(), title.center().y + 75.0 * app.camera.zoom);
    let track = rectangles
        .iter()
        .find(|rect| rect.fill == EDITOR && rect.rect.min.distance(bar_min) < 0.1)
        .unwrap();
    let fill = rectangles
        .iter()
        .find(|rect| rect.fill == GREEN && rect.rect.min.distance(bar_min) < 0.1)
        .unwrap();
    let actual_fraction = fill.rect.width() / track.rect.width();
    let expected_fraction =
        expected.stored_bytes as f32 / expected.config.storage_limit_bytes as f32;
    assert!((actual_fraction - expected_fraction).abs() < 0.00001);
    output.drop_without_applying_deltas();
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn stale_storage_uses_physical_payload_instead_of_the_current_shard_row_count() {
    let (mut app, commands, _events) = app();
    let mut state = replicated_snapshot();
    let peer = &mut state.peers[0];
    peer.rows = 1;
    peer.logical_bytes = 3;
    peer.data_bytes = 153;
    peer.index_bytes = 2332;
    peer.stored_bytes = 2501;
    let quota = peer.config.storage_limit_bytes;
    let node = app
        .network
        .as_ref()
        .unwrap()
        .nodes
        .iter()
        .find(|node| node.peer_id == Some(1))
        .unwrap();
    let hint = infrastructure::storage_tooltip(node, Some(&state));
    assert!(hint.contains(&format!("Physical storage: 2501 B / {quota} B quota")));
    assert!(hint.contains("Encrypted data: 153 B"));
    assert!(hint.contains("Encrypted index: 2332 B"));
    assert!(hint.contains("Replica record metadata: 16 B"));
    assert!(hint.contains("Logical payload: 3 B / 1 stored row"));
    assert!(hint.contains("Copies: 0 current / 1 stale"));
    app.snapshot = Some(state);
    app.network_view = NetworkView::Map;
    let ctx = egui::Context::default();
    set_theme(&ctx);
    let texts = render(&ctx, &mut app, vec![]);
    assert!(texts.iter().any(|text| text.text == "Payload 3 B · 1 row"));
    assert!(
        texts
            .iter()
            .any(|text| text.text.starts_with("0 current / 1 stale"))
    );
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn journal_bytes_count_toward_physical_quota_while_public_setup_remains_memory_metadata() {
    let (app, commands, _events) = app();
    let mut state = replicated_snapshot();
    let peer = &mut state.peers[0];
    peer.data_bytes = 153;
    peer.index_bytes = 2332;
    peer.journal_bytes = 1024;
    peer.public_setup_bytes = 2048;
    peer.stored_bytes = 153 + 2332 + 16 + 1024;
    let quota = peer.config.storage_limit_bytes;
    let node = app
        .network
        .as_ref()
        .unwrap()
        .nodes
        .iter()
        .find(|node| node.peer_id == Some(1))
        .unwrap();

    let hint = infrastructure::storage_tooltip(node, Some(&state));

    assert!(hint.contains(&format!("Physical storage: 3525 B / {quota} B quota")));
    assert!(hint.contains("Version/proof journal: 1024 B"));
    assert!(hint.contains("Replica record metadata: 16 B"));
    assert!(
        hint.contains(
            "Public setup in memory: 2048 B (serialized size; not disk usage or peak RAM)"
        )
    );
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn grouped_presets_start_with_simple_rows_then_filters_and_writes_without_execution() {
    let (mut app, commands, _events) = app();
    assert_eq!(PRESETS.first().unwrap().name, "All rows");
    assert_eq!(app.sql, STARTUP_SQL);
    let ctx = egui::Context::default();
    set_theme(&ctx);
    click(&ctx, &mut app, "Presets");
    let texts = render(&ctx, &mut app, vec![]);
    let y = |name: &str| {
        texts
            .iter()
            .find(|text| text.text == name)
            .unwrap()
            .rect
            .center()
            .y
    };
    assert!(y("All rows") < y("Adults"));
    assert!(y("Adults") < y("Insert one row"));
    assert!(y("Insert one row") < y("Increase adult amounts by 5"));
    click(&ctx, &mut app, "Insert one row");
    let insert = PRESETS
        .iter()
        .find(|preset| preset.name == "Insert one row")
        .unwrap();
    assert_eq!(app.sql, insert.sql);
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn insert_completion_reports_rows_and_keeps_unapplied_data_edits() {
    for dirty in [false, true] {
        let (mut app, commands, events) = app();
        app.sql = "INSERT INTO records (age, amount) VALUES (18, 10);".into();
        if dirty {
            app.draft_rows = "33,99".into();
        }
        app.run_query();
        let _ = commands.try_recv().unwrap();
        let mut state = snapshot(3);
        state.owner_rows.push(fhe_playground::PlainRow {
            age: 18,
            amount: 10,
        });
        state.revision = 1;
        let next_rows = format_rows(&state.owner_rows);
        events
            .send(Event::Finished {
                snapshot: Some(state),
                outcome: Ok(Outcome::Query(QueryOutcome::Inserted { count: 1 })),
                elapsed_ms: 1.0,
                client_id: Some(1),
            })
            .unwrap();
        app.poll();
        assert_eq!(
            app.draft_rows,
            if dirty {
                "33,99".to_string()
            } else {
                next_rows
            }
        );
        assert_eq!(app.result_tab, ResultTab::Output);
        let ctx = egui::Context::default();
        set_theme(&ctx);
        assert!(
            render(&ctx, &mut app, vec![])
                .iter()
                .any(|text| text.text == "Inserted 1 row")
        );
        assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
    }
}

#[test]
fn deleted_nodes_and_closed_inspectors_are_never_resurrected_by_history() {
    let (mut app, commands, events) = app();
    app.open_node(2);
    app.open_node(3);
    app.navigate_history(false);
    let mut net = network(3, 1);
    net.nodes.retain(|node| node.id != 2);
    net.links.retain(|link| link.from != 2 && link.to != 2);
    events.send(Event::Network(net)).unwrap();
    app.poll();

    assert_eq!(app.right_tab, RightTab::Network);
    app.navigate_history(true);
    assert_eq!(app.right_tab, RightTab::Node(3));
    app.close_node_tab(3);
    assert_eq!(app.right_tab, RightTab::Network);
    assert!(!app.navigation.can_step(true));
    assert!(!app.node_tabs.contains(&2));
    assert!(!app.node_tabs.contains(&3));
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn pruning_an_inspector_does_not_leave_repeated_identical_network_views() {
    let (mut app, commands, _events) = app();
    app.open_node(2);
    app.navigate(Tab::Sql, RightTab::Network);
    app.open_node(3);
    app.close_node_tab(2);

    app.navigate_history(false);
    assert_eq!(app.right_tab, RightTab::Network);
    assert!(!app.navigation.can_step(false));
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn closing_an_inspector_preserves_forward_navigation_across_a_left_pane_fallback() {
    let (mut app, commands, _events) = app();
    app.open_node(2);
    app.navigate(Tab::Data, RightTab::Node(2));
    app.navigate(Tab::Sql, RightTab::Node(2));
    app.navigate(Tab::Sql, RightTab::Network);
    app.navigate_history(false);
    app.navigate_history(false);
    app.close_node_tab(2);

    assert_eq!(app.tab, Tab::Data);
    assert_eq!(app.right_tab, RightTab::Network);
    assert!(app.navigation.can_step(true));
    app.navigate_history(true);
    assert_eq!(app.tab, Tab::Sql);
    assert_eq!(app.right_tab, RightTab::Network);
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn history_changes_only_presentation_while_explicit_client_open_selects_a_session() {
    let (mut app, commands, _events) = app();
    app.network = Some(network(3, 2));
    app.open_node(3);
    app.open_node(2);
    assert_eq!(app.active_client, Some(2));
    app.navigate_history(false);
    assert_eq!(app.right_tab, RightTab::Node(3));
    assert_eq!(app.active_client, Some(2));
    app.navigate_history(true);
    assert_eq!(app.active_client, Some(2));
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn navigation_history_capacity_keeps_the_current_route_and_nearest_views() {
    let mut navigation = Navigation::default();
    for id in 1..=300 {
        navigation.visit(navigation::Route {
            left: Tab::Sql,
            right: RightTab::Node(id),
        });
    }
    let mut steps = 0;
    while navigation.step(false).is_some() {
        steps += 1;
    }
    assert_eq!(steps, 255);
    assert_eq!(navigation.step(true).unwrap().right, RightTab::Node(46));
}

#[test]
fn sql_toolbar_has_one_run_action_and_explains_missing_clients_and_busy_state() {
    let (mut app, commands, events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    let texts = render(&ctx, &mut app, vec![]);
    assert!(!texts.iter().any(|text| text.text == "Run"));
    for id in ["sql-run-rect", "sql-stop-rect"] {
        let rect = ctx
            .data(|data| data.get_temp::<egui::Rect>(egui::Id::new(id)))
            .unwrap();
        assert_eq!(rect.size(), egui::vec2(32.0, 32.0));
    }
    assert!(!texts.iter().any(|text| text.text == "Console.sql"));
    events.send(Event::Network(network(3, 0))).unwrap();
    app.poll();
    let texts = render(&ctx, &mut app, vec![]);
    assert!(
        texts
            .iter()
            .any(|text| text.text == "Add a client from the Network context menu")
    );
    click(&ctx, &mut app, "Run");
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
    events.send(Event::Network(network(3, 1))).unwrap();
    app.poll();
    app.run_query();
    let _ = commands.try_recv().unwrap();
    let texts = render(&ctx, &mut app, vec![]);
    assert!(texts.iter().any(|text| text.text == "Operation running…"));
    click(&ctx, &mut app, "Run");
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn narrow_window_wraps_whole_toolbar_buttons_without_vertical_labels_or_overflow() {
    let (mut app, commands, _events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1180.0, 720.0));
    let output = ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(screen),
            ..Default::default()
        },
        |ui| app.draw(ui),
    );
    let labels = ["Presets", "Network", "Auto", "Map", "Matrix"];
    let mut observed = Vec::new();
    fn check(shape: &egui::Shape, labels: &[&str], screen: egui::Rect, observed: &mut Vec<String>) {
        match shape {
            egui::Shape::Text(text) if labels.contains(&text.galley.job.text.as_str()) => {
                let label = &text.galley.job.text;
                let bounds = text.galley.rect.translate(text.pos.to_vec2());
                assert_eq!(text.galley.rows.len(), 1, "{label} stays on a single line");
                assert!(
                    bounds.height() <= 32.0,
                    "{label} has a normal button-label height: {bounds:?}"
                );
                assert!(
                    screen.contains_rect(bounds),
                    "{label} remains within the window"
                );
                if ["Network", "Auto", "Map", "Matrix"].contains(&label.as_str()) {
                    assert!(
                        bounds.left() >= screen.width() * 0.41,
                        "{label} remains in the right pane"
                    );
                }
                observed.push(label.clone());
            }
            egui::Shape::Vec(shapes) => {
                for shape in shapes {
                    check(shape, labels, screen, observed);
                }
            }
            _ => {}
        }
    }
    for clipped in &output.shapes {
        check(&clipped.shape, &labels, screen, &mut observed);
    }
    for label in labels {
        assert!(
            observed.iter().any(|text| text == label),
            "{label} is visible"
        );
    }
    output.drop_without_applying_deltas();
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn selected_results_render_requested_column_order_and_worker_values() {
    let (mut app, commands, events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    app.sql = "SELECT amount, age FROM records LIMIT 2;".into();
    app.run_query();
    let _ = commands.try_recv().unwrap();
    events
        .send(Event::Finished {
            snapshot: Some(snapshot(3)),
            outcome: Ok(Outcome::Query(QueryOutcome::Selected {
                columns: vec![Column::Amount, Column::Age],
                rows: vec![vec![99, 22], vec![71, 38]],
            })),
            elapsed_ms: 12.0,
            client_id: Some(1),
        })
        .unwrap();
    app.poll();
    let texts = render(&ctx, &mut app, vec![]);
    let amount = texts.iter().find(|text| text.text == "amount").unwrap();
    let age = texts.iter().find(|text| text.text == "age").unwrap();
    assert!(amount.rect.left() < age.rect.left());
    for value in [
        "99",
        "22",
        "71",
        "38",
        "2 rows",
        "Encrypted SELECT · unverified",
    ] {
        assert!(
            texts.iter().any(|text| text.text == value),
            "Missing {value}"
        );
    }
    assert_eq!(app.result_tab, ResultTab::Result);
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn verified_network_selection_displays_its_confirmed_version_without_promoting_historical_fixtures()
{
    // Public renderer fixture only; real proof acceptance is exercised by process_backend tests.
    for batch in [false, true] {
        let (mut app, commands, events) = app();
        let ctx = egui::Context::default();
        set_theme(&ctx);
        app.run_query();
        let _ = commands.try_recv().unwrap();
        let outcome = Outcome::VerifiedQuery {
            outcome: QueryOutcome::Selected {
                columns: vec![Column::Age],
                rows: vec![vec![42]],
            },
            version: version_journal::HeadRef {
                genesis: [1; 32],
                database: [2; 16],
                block: [3; 32],
                height: 7,
                state_root: [4; 32],
            },
            affected_rows: None,
        };
        let outcome = if batch {
            Outcome::Script {
                completed: 2,
                created: false,
                changed: false,
                last: Box::new(outcome),
            }
        } else {
            outcome
        };
        events
            .send(Event::Finished {
                snapshot: Some(snapshot(3)),
                outcome: Ok(outcome),
                elapsed_ms: 12.0,
                client_id: Some(1),
            })
            .unwrap();
        app.poll();
        let texts = render(&ctx, &mut app, vec![]);
        assert!(
            texts
                .iter()
                .any(|text| text.text == "Encrypted SELECT · verified · v7")
        );
        assert_eq!(app.history.front().unwrap().revision, 7);
        assert!(
            !texts
                .iter()
                .any(|text| text.text == "Encrypted SELECT · unverified")
        );
        assert_eq!(app.result_tab, ResultTab::Result);
        assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
    }
}

#[test]
fn empty_selection_keeps_its_headers_and_standalone_aggregates_only_show_requested_columns() {
    for (outcome, expected, absent) in [
        (
            QueryOutcome::Selected {
                columns: vec![Column::Age],
                rows: vec![],
            },
            "age",
            "SUM(amount)",
        ),
        (
            QueryOutcome::Count {
                count: 3,
                peers: vec![],
            },
            "COUNT(*)",
            "SUM(amount)",
        ),
        (
            QueryOutcome::Sum {
                sum: 91,
                peers: vec![],
            },
            "SUM(amount)",
            "COUNT(*)",
        ),
    ] {
        let (mut app, commands, events) = app();
        let ctx = egui::Context::default();
        set_theme(&ctx);
        app.sql = "SELECT age FROM records LIMIT 0;".into();
        app.run_query();
        let _ = commands.try_recv().unwrap();
        events
            .send(Event::Finished {
                snapshot: Some(snapshot(3)),
                outcome: Ok(Outcome::Query(outcome)),
                elapsed_ms: 1.0,
                client_id: Some(1),
            })
            .unwrap();
        app.poll();
        let texts = render(&ctx, &mut app, vec![]);
        assert!(texts.iter().any(|text| text.text == expected));
        assert!(!texts.iter().any(|text| text.text == absent));
        assert_eq!(app.result_tab, ResultTab::Result);
    }
}
#[test]
fn ctrl_enter_only_executes_sql_and_never_queues_duplicate_requests() {
    let (mut app, commands, _events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    app.tab = Tab::Data;
    render(&ctx, &mut app, ctrl_enter());
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
    app.tab = Tab::Sql;
    render(&ctx, &mut app, ctrl_enter());
    assert!(matches!(
        commands.try_recv(),
        Ok(Command::Query { client_id: 1, .. })
    ));
    render(&ctx, &mut app, ctrl_enter());
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}
#[test]
fn double_clicking_a_peer_opens_a_right_hand_tab_and_its_owner_rows() {
    let (mut app, commands, _events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    let texts = render(&ctx, &mut app, vec![]);
    let point = texts
        .iter()
        .find(|t| t.text == "P02")
        .unwrap()
        .rect
        .center();
    click_point(&ctx, &mut app, point, egui::PointerButton::Primary);
    assert!(app.right_tab == RightTab::Network);
    click_point(&ctx, &mut app, point, egui::PointerButton::Primary);
    let texts = render(&ctx, &mut app, vec![]);
    assert!(app.right_tab == RightTab::Node(3));
    assert!(texts.iter().any(|t| t.text == "Rows / owner view"));
    for value in ["18", "20"] {
        assert!(texts.iter().any(|t| t.text == value));
    }
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}
#[test]
fn right_clicking_empty_space_adds_peers_and_clients_through_real_commands() {
    for label in ["Add peer", "Add client"] {
        let (mut app, commands, _events) = app();
        let ctx = egui::Context::default();
        set_theme(&ctx);
        render(&ctx, &mut app, vec![]);
        click_point(
            &ctx,
            &mut app,
            egui::pos2(1460.0, 810.0),
            egui::PointerButton::Secondary,
        );
        click(&ctx, &mut app, label);
        match (label, commands.try_recv().unwrap()) {
            ("Add peer", Command::AddPeer(_)) | ("Add client", Command::AddClient { .. }) => {}
            _ => panic!("wrong creation command"),
        }
        assert!(app.control_pending.is_some());
    }
}
#[test]
fn right_clicking_a_node_deletes_its_stable_network_id() {
    let (mut app, commands, _events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    let point = render(&ctx, &mut app, vec![])
        .iter()
        .find(|t| t.text == "P02")
        .unwrap()
        .rect
        .center();
    click_point(&ctx, &mut app, point, egui::PointerButton::Secondary);
    click(&ctx, &mut app, "Delete node");
    assert!(matches!(
        commands.try_recv(),
        Ok(Command::RemoveNode { id: 3 })
    ));
}
#[test]
fn no_clients_disables_sql_and_switching_clients_changes_request_identity() {
    let (mut app, commands, events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    events.send(Event::Network(network(3, 0))).unwrap();
    app.poll();
    render(&ctx, &mut app, ctrl_enter());
    click(&ctx, &mut app, "Run");
    assert_eq!(app.active_client, None);
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
    events.send(Event::Network(network(3, 2))).unwrap();
    app.poll();
    app.open_node(2);
    click(&ctx, &mut app, "Use this client");
    app.run_query();
    assert!(matches!(
        commands.try_recv(),
        Ok(Command::Query { client_id: 2, .. })
    ));
}
#[test]
fn live_network_controls_do_not_offer_simulation_or_finish_an_inflight_sql_job() {
    let (mut app, commands, events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    app.run_query();
    let _ = commands.try_recv().unwrap();
    let texts = render(&ctx, &mut app, vec![]);
    assert!(texts.iter().any(|text| text.text == "Live TCP/TLS"));
    assert!(
        texts.iter().any(|text| text.text == "Speed"),
        "visible: {:?}",
        texts.iter().map(|text| &text.text).collect::<Vec<_>>()
    );
    assert!(
        !texts
            .iter()
            .any(|text| text.text == "Pause" || text.text == "Trace speed")
    );
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
    events
        .send(Event::ControlFinished {
            snapshot: Some(snapshot(3)),
            outcome: Ok(Outcome::NodeAdded { id: 5 }),
        })
        .unwrap();
    app.poll();
    assert!(app.pending.is_some());
    assert!(app.history.is_empty());
}

#[test]
fn display_speed_fits_beside_network_view_controls() {
    let (mut app, commands, _events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    let text = render(&ctx, &mut app, vec![]);
    let center = |label: &str| {
        text.iter()
            .find(|item| item.text == label)
            .unwrap_or_else(|| panic!("Missing {label}"))
            .rect
            .center()
    };

    assert!((center("Map").y - center("Speed").y).abs() < 12.0);
    assert!((center("Speed").y - center("Live").y).abs() < 12.0);
    assert!(center("Speed").x > center("Map").x);
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn live_frame_observations_animate_while_sql_is_pending_without_completing_the_job() {
    let (mut app, commands, events) = app();
    app.run_query();
    let _ = commands.try_recv().unwrap();
    events
        .send(Event::Traffic(crate::traffic::Observation {
            packet: fhe_playground::NetworkPacket {
                id: 90001,
                from: 1,
                to: 2,
                kind: fhe_playground::PacketKind::Request,
                progress: 1.0,
                request_id: Some(9),
            },
            operation: "fhe-proof".into(),
            bytes: 1234,
        }))
        .unwrap();
    app.poll();
    app.playback.advance(0.0);
    app.playback.advance(0.1);
    let packet = app
        .playback
        .packets()
        .into_iter()
        .find(|packet| packet.id == 90001)
        .unwrap();
    assert!(packet.progress > 0.0 && packet.progress < 1.0);
    app.playback.speed = 0.0;
    app.playback.advance(20.0);
    assert_eq!(app.playback.packets()[0].progress, packet.progress);
    let ctx = egui::Context::default();
    set_theme(&ctx);
    render(&ctx, &mut app, vec![]);
    click(&ctx, &mut app, "Live");
    assert_eq!(app.playback.speed, 1.0);
    assert!(app.playback.packets().is_empty());
    assert!(app.pending.is_some());
    assert!(app.history.is_empty());
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

fn large_observed_topology() -> NetworkSnapshot {
    // Public renderer fixture only: no processes or cryptographic results claimed.
    NetworkSnapshot {
        time_ms: 0.0,
        speed: 1.0,
        paused: false,
        nodes: (1..=10_000)
            .map(|id| fhe_playground::NetworkNode {
                id,
                name: format!("Peer {id:05}"),
                role: NodeRole::Peer,
                peer_id: Some(id as usize),
                online: true,
                process_id: None,
            })
            .collect(),
        links: (1..=10_000)
            .map(|id| fhe_playground::NetworkLink {
                from: id,
                to: id % 10_000 + 1,
            })
            .collect(),
        packets: vec![],
        recent: vec![],
    }
}

#[test]
fn ten_thousand_nodes_render_as_groups_and_a_virtualized_matrix_without_changing_topology() {
    let (mut app, commands, _events) = app();
    app.network = Some(large_observed_topology());
    app.snapshot = None;
    app.active_client = None;
    let ctx = egui::Context::default();
    set_theme(&ctx);
    assert!(app.uses_overview());
    for mode in [NetworkView::Auto, NetworkView::Map, NetworkView::Matrix] {
        app.network_view = mode;
        let output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1500.0, 900.0),
                )),
                ..Default::default()
            },
            |ui| app.draw(ui),
        );
        assert!(
            output.shapes.len() < 8000,
            "{mode:?} must paint a bounded visible subset, got {} shapes",
            output.shapes.len()
        );
        output.drop_without_applying_deltas();
        assert_eq!(app.network.as_ref().unwrap().nodes.len(), 10_000);
        assert_eq!(app.network.as_ref().unwrap().links.len(), 10_000);
    }
    app.network_view = NetworkView::Overview;
    app.overview_search = "Peer 09999".into();
    let text = render(&ctx, &mut app, vec![]);
    assert!(text.iter().any(|text| text.text.contains("Peer 09999")));
    assert!(!text.iter().any(|text| text.text.contains("Peer 09998")));
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn relevant_links_reduce_dense_map_clutter_without_removing_observed_connections() {
    let (mut app, commands, _events) = app();
    app.network = Some(network(16, 1));
    app.snapshot = Some(snapshot(16));
    app.network_view = NetworkView::Map;
    let ctx = egui::Context::default();
    set_theme(&ctx);
    fn lines(shape: &egui::Shape) -> usize {
        match shape {
            egui::Shape::Path(path) if path.stroke.width == 1.1 => 1,
            egui::Shape::Vec(shapes) => shapes.iter().map(lines).sum(),
            _ => 0,
        }
    }
    for (scope, expected) in [(LinkView::Relevant, 16), (LinkView::All, 136)] {
        app.link_view = scope;
        let output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1500.0, 900.0),
                )),
                ..Default::default()
            },
            |ui| app.draw(ui),
        );
        assert_eq!(
            output
                .shapes
                .iter()
                .map(|shape| lines(&shape.shape))
                .sum::<usize>(),
            expected
        );
        output.drop_without_applying_deltas();
        assert_eq!(app.network.as_ref().unwrap().links.len(), 136);
    }
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}
#[test]
fn a_result_stays_bound_to_the_requesting_client_after_switching_sessions() {
    let (mut app, commands, events) = app();
    app.network = Some(network(3, 2));
    app.active_client = Some(1);
    app.run_query();
    let _ = commands.try_recv().unwrap();
    app.active_client = Some(2);
    events
        .send(Event::Finished {
            snapshot: Some(snapshot(3)),
            outcome: Ok(Outcome::Query(QueryOutcome::Aggregate {
                count: 2,
                sum: 50,
                peers: vec![],
            })),
            elapsed_ms: 20.0,
            client_id: Some(1),
        })
        .unwrap();
    app.poll();
    assert!(app.pending.is_none());
    assert!(app.history[0].label.starts_with("Client 01:"));
}
#[test]
fn peer_settings_and_data_drafts_require_explicit_apply() {
    let (mut app, commands, _events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    app.open_node(3);
    app.peer_edits.get_mut(&3).unwrap().name = "Fast SSD".into();
    click(&ctx, &mut app, "Save settings");
    assert!(
        matches!(commands.try_recv(),Ok(Command::ConfigurePeer{id:2,config})if config.name=="Fast SSD")
    );
    app.tab = Tab::Data;
    ctx.global_style_mut(|style| style.animation_time = 0.0);
    click(&ctx, &mut app, "Manual data draft");
    click(&ctx, &mut app, "Add row");
    assert_eq!(parse_rows(&app.draft_rows).unwrap().len(), 5);
    assert_eq!(app.snapshot.as_ref().unwrap().owner_rows.len(), 4);
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}
#[test]
fn world_grid_and_nodes_share_pan_zoom_transform() {
    let canvas = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(500.0, 400.0));
    let mut camera = Camera::default();
    let world = egui::pos2(28.0, 56.0);
    let original = camera.world_to_screen(canvas, world);
    assert!(camera.grid_points(canvas).contains(&original));
    camera.pan(egui::vec2(45.0, -20.0));
    let panned = camera.world_to_screen(canvas, world);
    assert_eq!(panned - original, egui::vec2(45.0, -20.0));
    assert!(camera.grid_points(canvas).contains(&panned));
    camera.zoom_at(canvas, panned, 1.5);
    assert!((camera.world_to_screen(canvas, world) - panned).length() < 0.001);
    assert!(
        camera
            .grid_points(canvas)
            .iter()
            .any(|p| (*p - panned).length() < 0.001)
    );
}

#[test]
fn editing_peer_fields_never_triggers_the_sql_shortcut() {
    let (mut app, commands, _events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    app.open_node(3);
    render(&ctx, &mut app, vec![]);
    ctx.memory_mut(|memory| memory.request_focus(egui::Id::new(("peer-name", 3_u64))));
    render(&ctx, &mut app, ctrl_enter());
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
    ctx.memory_mut(|memory| memory.request_focus(egui::Id::new("sql-editor-field")));
    render(&ctx, &mut app, ctrl_enter());
    assert!(matches!(
        commands.try_recv(),
        Ok(Command::Query { client_id: 1, .. })
    ));
}

#[test]
fn malformed_csv_and_empty_database_name_explain_disabled_creation() {
    let (mut app, commands, _events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    app.tab = Tab::Data;
    app.data_view = DataView::Csv;
    app.draft_rows = "18,x".into();
    ctx.global_style_mut(|style| style.animation_time = 0.0);
    click(&ctx, &mut app, "Manual data draft");
    let texts = render(&ctx, &mut app, vec![]);
    assert!(texts.iter().any(|t| t.text.contains("Line 1:")));
    click(&ctx, &mut app, "Create / replace");
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
    app.draft_rows = "18,7".into();
    app.draft_name.clear();
    let texts = render(&ctx, &mut app, vec![]);
    assert!(
        texts
            .iter()
            .any(|t| t.text.contains("Database name: 1..64"))
    );
    click(&ctx, &mut app, "Create / replace");
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn new_node_positions_survive_a_coalesced_old_snapshot_and_are_removed_with_nodes() {
    let (mut app, _commands, events) = app();
    app.control_pending = Some(Control::Add {
        position: egui::pos2(900.0, 120.0),
    });
    events
        .send(Event::ControlFinished {
            snapshot: Some(snapshot(4)),
            outcome: Ok(Outcome::NodeAdded { id: 5 }),
        })
        .unwrap();
    events.send(Event::Network(network(3, 1))).unwrap();
    app.poll();
    assert!(app.graph_seeds.contains_key(&5));
    events.send(Event::Network(network(4, 1))).unwrap();
    app.poll();
    events.send(Event::Network(network(3, 1))).unwrap();
    app.poll();
    assert!(!app.graph_seeds.contains_key(&5));
}

#[test]
fn fit_view_contains_widely_separated_nodes_and_keeps_grid_density_bounded() {
    let canvas = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(700.0, 500.0));
    let mut camera = Camera::default();
    let bounds = egui::Rect::from_min_max(egui::pos2(-3000.0, -800.0), egui::pos2(3000.0, 800.0));
    camera.fit(canvas, bounds);
    assert!(canvas.contains(camera.world_to_screen(canvas, bounds.min)));
    assert!(canvas.contains(camera.world_to_screen(canvas, bounds.max)));
    assert!(camera.grid_points(canvas).len() < 10_000);
}
