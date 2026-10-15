use super::*;
use fhe_playground::{DemoNetwork, PeerInfo};
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
#[path = "ui_preview.rs"]
mod preview;

fn app() -> (Playground, Receiver<Command>, Sender<Event>) {
    let (worker, commands, events) = Worker::test_channel();
    let mut app = Playground::with_worker(worker);
    app.snapshot = Some(snapshot(3));
    app.network = Some(network(3, 1));
    app.active_client = Some(1);
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
                data_bytes: 166,
                index_bytes: 2336,
                stored_bytes: 2502,
                owner_row_indices: (index..rows.len()).step_by(peers).collect(),
            })
            .collect(),
        owner_rows: rows,
        replication: None,
    }
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
    let point = texts
        .iter()
        .find(|t| t.text == label)
        .unwrap_or_else(|| panic!("control missing:{label}"))
        .rect
        .center();
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
fn inline_copy_choice_sends_one_serialized_policy_command() {
    let (mut app, commands, _) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    click(&ctx, &mut app, "Min copies 1");
    click(&ctx, &mut app, "2 copies");
    assert!(matches!(
        commands.try_recv().unwrap(),
        Command::SetReplication { copies: 2 }
    ));
    assert!(commands.try_recv().is_err());
    assert!(matches!(app.control_pending, Some(Control::Replication)));
    assert!(app.snapshot.as_ref().unwrap().replication.is_none());
}

#[test]
fn explicitly_confirming_one_copy_enables_fixed_custody_but_default_render_does_not() {
    let (mut app, commands, _) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    let texts = render(&ctx, &mut app, vec![]);
    assert!(
        texts
            .iter()
            .any(|text| text.text.contains("Legacy single-copy"))
    );
    assert!(commands.try_recv().is_err());
    click(&ctx, &mut app, "Min copies 1");
    click(&ctx, &mut app, "1 copy");
    assert!(matches!(
        commands.try_recv().unwrap(),
        Command::SetReplication { copies: 1 }
    ));
}

#[test]
fn copy_health_counts_independent_domains_and_distinguishes_stale_copies() {
    let (mut app, _, _) = app();
    app.snapshot = Some(replicated_snapshot());
    let ctx = egui::Context::default();
    set_theme(&ctx);
    let texts = render(&ctx, &mut app, vec![]);
    assert!(texts.iter().any(|text| text.text.contains("0/1 at target")
        && text.text.contains("2 online current / 1 stale")));
    assert!(texts.iter().any(|text| text.text == "Min copies 2"));
}

#[test]
fn stale_copy_inspector_labels_current_owner_fixture_and_saves_domain_explicitly() {
    let (mut app, commands, _) = app();
    app.snapshot = Some(replicated_snapshot());
    app.open_node(2);
    app.domain_edits.insert(2, 77);
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
            .any(|text| text.text.contains("Current owner fixture")
                && text.text.contains("earlier values"))
    );
    assert!(commands.try_recv().is_err());
    click(&ctx, &mut app, "Save domain");
    assert!(matches!(
        commands.try_recv().unwrap(),
        Command::SetFailureDomain { id: 1, domain: 77 }
    ));
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
fn maintenance_failure_does_not_finish_a_query_or_consume_an_unrelated_control() {
    let (mut app, commands, events) = app();
    app.run_query();
    let _ = commands.try_recv().unwrap();
    app.control_pending = Some(Control::Availability);
    events
        .send(Event::MaintenanceFinished {
            snapshot: Some(replicated_snapshot()),
            outcome: Err(fhe_playground::LabError::InvalidInput(
                "public repair quota failure".into(),
            )),
        })
        .unwrap();
    app.poll();
    assert!(app.pending.is_some());
    assert!(matches!(app.control_pending, Some(Control::Availability)));
    assert_eq!(app.history.len(), 1);
    assert!(app.history[0].job == Job::Maintenance);
    assert!(app.maintenance_status.contains("quota failure"));
}

#[test]
fn dense_network_shows_every_real_connection_without_changing_topology() {
    let (mut app, commands, _events) = app();
    app.network = Some(network(16, 1));
    app.snapshot = Some(snapshot(16));
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
                && circle.radius == 2.2
            {
                Some(circle)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(packet_markers.len(), 1);
    assert_eq!(packet_markers[0].fill, AMBER);
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
    click(&ctx, &mut app, "Add 5");
    assert_eq!(app.sql, PRESETS[4].sql);
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
    click(&ctx, &mut app, "Run");
    assert!(
        matches!(commands.try_recv(),Ok(Command::Query{client_id:1,sql})if sql==PRESETS[4].sql)
    );
}

#[test]
fn range_presets_only_fill_sql_until_the_user_runs_the_statement() {
    let (mut app, commands, _events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    for name in ["Under 18", "At most 18", "Over 18", "Ages 18..42"] {
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
    let console = texts.iter().find(|t| t.text == "Console.sql").unwrap();
    let network = texts.iter().find(|t| t.text == "Network").unwrap();
    assert!(console.rect.right() < network.rect.left());
    for obsolete in [
        "Filter objects...",
        "Local database",
        "Tables",
        "Layout",
        "Add peer",
    ] {
        assert!(!texts.iter().any(|t| t.text == obsolete));
    }
    click(&ctx, &mut app, "Data");
    let texts = render(&ctx, &mut app, vec![]);
    assert!(texts.iter().any(|t| t.text == "Network"));
    assert!(texts.iter().any(|t| t.text == "Add row"));
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
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
fn speed_and_topology_completions_never_finish_an_inflight_sql_job() {
    let (mut app, commands, events) = app();
    let ctx = egui::Context::default();
    set_theme(&ctx);
    app.run_query();
    let _ = commands.try_recv().unwrap();
    click(&ctx, &mut app, "Pause");
    assert!(matches!(
        commands.try_recv(),
        Ok(Command::SetSimulation { paused: true, .. })
    ));
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
