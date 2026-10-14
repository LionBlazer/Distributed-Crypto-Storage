use std::sync::mpsc::{Receiver, Sender, TryRecvError};

use fhe_playground::PeerInfo;

use super::*;

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
                online: true,
                rows: (index..rows.len()).step_by(peers).count(),
                compressed_bytes: 100,
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
    let Command::Create(draft) = commands.try_recv().unwrap() else {
        panic!("expected layout rebuild");
    };
    assert_eq!(draft.name, "demo");
    assert_eq!(draft.rows, sample_rows(4).unwrap());
    assert_eq!(draft.peer_count, 4);
    events
        .send(Event::Finished {
            snapshot: Some(snapshot(4)),
            outcome: Ok(Outcome::Created),
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
