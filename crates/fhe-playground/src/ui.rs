use std::collections::VecDeque;

use eframe::egui::{self, Color32, FontId, RichText, Stroke};
use fhe_playground::{
    DatabaseDraft, LabSnapshot, MAX_LAB_ROWS, MAX_PEERS, PRESETS, QueryOutcome, format_rows,
    parse_rows, sample_rows,
};

use crate::worker::{Command, Event, Outcome, Worker};

const BACKGROUND: Color32 = Color32::from_rgb(14, 18, 28);
const PANEL: Color32 = Color32::from_rgb(22, 28, 41);
const BORDER: Color32 = Color32::from_rgb(44, 54, 73);
const ACCENT: Color32 = Color32::from_rgb(133, 154, 255);
const MUTED: Color32 = Color32::from_rgb(144, 158, 184);
const GREEN: Color32 = Color32::from_rgb(99, 215, 174);
const AMBER: Color32 = Color32::from_rgb(245, 193, 109);
const RED: Color32 = Color32::from_rgb(244, 139, 154);

struct Record {
    is_query: bool,
    label: String,
    database: String,
    revision: u64,
    elapsed_ms: f64,
    outcome: Result<Outcome, String>,
}

pub struct Playground {
    worker: Worker,
    snapshot: Option<LabSnapshot>,
    sql: String,
    draft_name: String,
    draft_rows: String,
    draft_peers: usize,
    generate_rows: usize,
    busy: bool,
    worker_stopped: bool,
    pending_label: String,
    pending_is_query: bool,
    status: String,
    input_error: Option<String>,
    history: VecDeque<Record>,
    data_open: bool,
}

impl Playground {
    pub fn new(ctx: &egui::Context) -> Result<Self, std::io::Error> {
        set_theme(ctx);
        let mut app = Self {
            worker: Worker::start(ctx.clone())?,
            snapshot: None,
            sql: PRESETS[1].sql.into(),
            draft_name: "demo".into(),
            draft_rows: format_rows(&sample_rows(4).expect("bounded sample")),
            draft_peers: 3,
            generate_rows: 4,
            busy: false,
            worker_stopped: false,
            pending_label: String::new(),
            pending_is_query: false,
            status: "Starting the local experiment...".into(),
            input_error: None,
            history: VecDeque::new(),
            data_open: false,
        };
        app.create_database();
        Ok(app)
    }

    fn submit(&mut self, command: Command, label: String) {
        if self.busy || self.worker_stopped {
            return;
        }
        let is_query = matches!(&command, Command::Query(_));
        match self.worker.send(command) {
            Ok(()) => {
                self.busy = true;
                self.pending_label = label;
                self.pending_is_query = is_query;
                self.status = "Submitting operation...".into();
                self.input_error = None;
            }
            Err(message) => self.input_error = Some(message),
        }
    }

    fn create_database(&mut self) {
        match parse_rows(&self.draft_rows) {
            Ok(rows) => self.submit(
                Command::Create(DatabaseDraft {
                    name: self.draft_name.clone(),
                    rows,
                    peer_count: self.draft_peers,
                }),
                "Create / rebuild database".into(),
            ),
            Err(error) => self.input_error = Some(error.to_string()),
        }
    }

    fn run_query(&mut self) {
        if self.snapshot.is_some() {
            self.submit(Command::Query(self.sql.clone()), self.sql.clone());
        }
    }

    fn poll(&mut self) {
        if self.worker_stopped {
            return;
        }
        loop {
            match self.worker.poll() {
                Ok(Some(Event::Progress(message))) => self.status = message,
                Ok(Some(Event::Finished {
                    snapshot,
                    outcome,
                    elapsed_ms,
                })) => {
                    let created = matches!(outcome, Ok(Outcome::Created));
                    let draft_is_current = self.snapshot.as_ref().is_some_and(|state| {
                        self.draft_name.trim() == state.name
                            && self.draft_rows == format_rows(&state.owner_rows)
                    });
                    self.busy = false;
                    self.status = match &outcome {
                        Ok(Outcome::Created) => {
                            "Database ready. Choose a preset or write a supported query.".into()
                        }
                        Ok(Outcome::PeerChanged) => {
                            "Peer availability changed in the local simulation.".into()
                        }
                        Ok(Outcome::Query(QueryOutcome::Updated { committed: false })) => {
                            "Overflow: the update was rejected across all shards.".into()
                        }
                        Ok(Outcome::Query(_)) => {
                            "FHE operation completed. Result has no cryptographic query proof."
                                .into()
                        }
                        Err(error) => error.to_string(),
                    };
                    if let Some(state) = &snapshot
                        && (created
                            || (draft_is_current
                                && matches!(
                                    outcome,
                                    Ok(Outcome::Query(QueryOutcome::Updated { committed: true }))
                                )))
                    {
                        self.draft_rows = format_rows(&state.owner_rows);
                    }
                    if created {
                        self.history.clear();
                        self.data_open = false;
                    }
                    let (database, revision) = snapshot
                        .as_ref()
                        .map(|state| (state.name.clone(), state.revision))
                        .unwrap_or_default();
                    self.history.push_front(Record {
                        is_query: self.pending_is_query,
                        label: self.pending_label.clone(),
                        database,
                        revision,
                        elapsed_ms,
                        outcome: outcome.map_err(|error| error.to_string()),
                    });
                    self.history.truncate(8);
                    self.snapshot = snapshot;
                }
                Ok(None) => break,
                Err(message) => {
                    self.busy = false;
                    self.worker_stopped = true;
                    self.input_error = Some(message);
                    break;
                }
            }
        }
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(12.0);
        ui.label(RichText::new("DCS").size(32.0).strong().color(ACCENT));
        ui.label(RichText::new("FHE PLAYGROUND").size(12.0).color(MUTED));
        ui.add_space(18.0);
        badge(ui, "LOCAL PEER SIMULATION", AMBER);
        ui.add_space(18.0);
        if let Some(snapshot) = &self.snapshot {
            ui.label(RichText::new(&snapshot.name).size(20.0).strong());
            ui.label(
                RichText::new(format!(
                    "records  /  {} rows  /  v{}",
                    snapshot.owner_rows.len(),
                    snapshot.revision
                ))
                .color(MUTED),
            );
        } else {
            ui.label("Preparing demo database...");
        }
        ui.add_space(16.0);
        ui.separator();
        ui.add_space(12.0);
        ui.label(RichText::new("SHARD LAYOUT").small().color(MUTED));
        ui.add_enabled_ui(!self.busy && !self.worker_stopped, |ui| {
            ui.add(egui::Slider::new(&mut self.draft_peers, 1..=MAX_PEERS).text("peers"));
            ui.label(
                RichText::new("Applies when you rebuild the database.")
                    .small()
                    .color(MUTED),
            );
            if ui.button("Edit data / rebuild").clicked() {
                self.data_open = !self.data_open;
            }
        });
        ui.add_space(14.0);
        if let Some(snapshot) = &self.snapshot {
            draw_peers(ui, snapshot);
        }
        ui.add_space(14.0);
        ui.label(
            RichText::new("Toggle a peer to test unavailable shards.")
                .small()
                .color(MUTED),
        );
        let mut toggle = None;
        egui::ScrollArea::vertical()
            .id_salt("peer-list")
            .max_height(330.0)
            .show(ui, |ui| {
                if let Some(snapshot) = &self.snapshot {
                    for peer in &snapshot.peers {
                        card().inner_margin(10).show(ui, |ui| {
                            ui.set_min_width(190.0);
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(format!("P{:02}", peer.id))
                                        .strong()
                                        .color(if peer.online { GREEN } else { RED }),
                                );
                                ui.label(
                                    RichText::new(format!("{} rows", peer.rows))
                                        .small()
                                        .color(MUTED),
                                );
                                let mut online = peer.online;
                                if ui
                                    .add_enabled(
                                        !self.busy && !self.worker_stopped,
                                        egui::Checkbox::without_text(&mut online),
                                    )
                                    .changed()
                                {
                                    toggle = Some((peer.id, online));
                                }
                            });
                            ui.label(
                                RichText::new(format!(
                                    "{}  |  {} B encrypted",
                                    if peer.online { "Online" } else { "Offline" },
                                    peer.compressed_bytes
                                ))
                                .small()
                                .color(MUTED),
                            );
                        });
                        ui.add_space(5.0);
                    }
                }
            });
        if let Some((id, online)) = toggle {
            self.submit(
                Command::SetPeer { id, online },
                format!("Peer {id}: {}", if online { "online" } else { "offline" }),
            );
        }
        ui.add_space(16.0);
        ui.label(
            RichText::new(
                "One process · 2 CPU threads\nShared evaluation key\nEphemeral test database",
            )
            .small()
            .color(MUTED),
        );
    }

    fn content(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(RichText::new("Query playground").size(30.0).strong());
                ui.label(
                    RichText::new("Explore encrypted operations across local shards.").color(MUTED),
                );
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                badge(ui, "TEST HARNESS", ACCENT);
            });
        });
        ui.add_space(18.0);
        self.metrics(ui);
        ui.add_space(14.0);
        if self.data_open {
            self.data_editor(ui);
            ui.add_space(14.0);
        }
        card().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("SQL editor").size(18.0).strong());
                ui.label(
                    RichText::new("COUNT / SUM / UPDATE subset")
                        .small()
                        .color(MUTED),
                );
            });
            ui.add_space(10.0);
            ui.add_enabled_ui(!self.busy, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut self.sql)
                        .code_editor()
                        .font(FontId::monospace(16.0))
                        .desired_rows(5)
                        .desired_width(f32::INFINITY),
                );
            });
            ui.add_space(10.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Insert & run:").small().color(MUTED));
                for preset in PRESETS {
                    if ui
                        .add_enabled(
                            !self.busy && !self.worker_stopped && self.snapshot.is_some(),
                            egui::Button::new(preset.name),
                        )
                        .on_hover_text(preset.sql)
                        .clicked()
                    {
                        self.sql = preset.sql.into();
                        self.run_query();
                    }
                }
            });
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        !self.busy && !self.worker_stopped && self.snapshot.is_some(),
                        egui::Button::new(RichText::new("Run query").strong().color(BACKGROUND))
                            .fill(ACCENT)
                            .min_size(egui::vec2(128.0, 36.0)),
                    )
                    .clicked()
                {
                    self.run_query();
                }
                ui.label(RichText::new("Ctrl+Enter").small().color(MUTED));
                if self.busy {
                    ui.spinner();
                }
            });
        });
        ui.add_space(12.0);
        if let Some(message) = &self.input_error {
            ui.colored_label(RED, message);
        }
        ui.label(RichText::new(&self.status).color(if self.busy { ACCENT } else { MUTED }));
        ui.add_space(12.0);
        self.result(ui);
        ui.add_space(14.0);
        egui::CollapsingHeader::new("Recent operations").show(ui, |ui| {
            for record in &self.history {
                ui.horizontal(|ui| {
                    let (label, color) = record_status(&record.outcome);
                    ui.label(RichText::new(label).color(color));
                    ui.label(format!(
                        "{}  |  {}  |  {:.0} ms",
                        record.database,
                        record.label.lines().next().unwrap_or_default(),
                        record.elapsed_ms
                    ));
                });
            }
        });
        ui.add_space(14.0);
        ui.label(RichText::new("Local simulation. FHE results are unverified. Owner keys and test data stay in memory.").small().color(MUTED));
    }

    fn metrics(&self, ui: &mut egui::Ui) {
        let rows = self
            .snapshot
            .as_ref()
            .map_or(0, |state| state.owner_rows.len());
        let (online, total, bytes) = self
            .snapshot
            .as_ref()
            .map(|state| {
                (
                    state.peers.iter().filter(|peer| peer.online).count(),
                    state.peers.len(),
                    state
                        .peers
                        .iter()
                        .map(|peer| peer.compressed_bytes)
                        .sum::<usize>(),
                )
            })
            .unwrap_or_default();
        ui.columns(3, |columns| {
            metric(
                &mut columns[0],
                "OWNER ROWS",
                &rows.to_string(),
                "age u8 · amount u16",
            );
            metric(
                &mut columns[1],
                "ONLINE PEERS",
                &format!("{online} / {total}"),
                "logical shards in this process",
            );
            metric(
                &mut columns[2],
                "COMPRESSED SHARDS",
                &format!("{bytes} B"),
                "excludes evaluation key",
            );
        });
    }

    fn data_editor(&mut self, ui: &mut egui::Ui) {
        card().show(ui, |ui| {
            ui.label(RichText::new("Create / rebuild test database").size(18.0).strong());
            ui.label(RichText::new("Replacing a database generates new keys. SQL table name is always records.").small().color(MUTED));
            ui.add_space(8.0);
            ui.add_enabled_ui(!self.busy && !self.worker_stopped, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Name");
                    ui.add(egui::TextEdit::singleline(&mut self.draft_name).desired_width(140.0));
                    ui.label("Sample rows");
                    ui.add(egui::DragValue::new(&mut self.generate_rows).range(0..=MAX_LAB_ROWS));
                    if ui.button("Generate").clicked() { self.draft_rows = format_rows(&sample_rows(self.generate_rows).expect("bounded generator")); }
                    if ui.button("Overflow fixture").clicked() { self.draft_rows = "18,65535\n19,10".into(); }
                    if ui.button("Empty").clicked() { self.draft_rows.clear(); }
                });
                ui.add_space(8.0);
                ui.label(RichText::new("Owner fixture: one age,amount pair per line (up to 128 rows). Edit or paste values.").small().color(MUTED));
                egui::ScrollArea::vertical().id_salt("fixture-editor").max_height(140.0).show(ui, |ui| {
                    ui.add(egui::TextEdit::multiline(&mut self.draft_rows).code_editor().desired_width(f32::INFINITY).desired_rows(4));
                });
                ui.add_space(8.0);
                if ui.button(format!("Create / rebuild with {} peers", self.draft_peers)).clicked() { self.create_database(); }
            });
        });
    }

    fn result(&self, ui: &mut egui::Ui) {
        let record = self.history.iter().find(|record| record.is_query);
        card().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Last query result").size(18.0).strong());
                if let Some(record) = record {
                    ui.label(
                        RichText::new(format!(
                            "{} / v{} / {:.0} ms",
                            record.database, record.revision, record.elapsed_ms
                        ))
                        .small()
                        .color(MUTED),
                    );
                }
            });
            ui.add_space(12.0);
            match record.map(|record| &record.outcome) {
                Some(Ok(Outcome::Query(QueryOutcome::Aggregate { count, sum, peers }))) => {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(RichText::new("COUNT(*)").color(MUTED));
                            ui.label(
                                RichText::new(count.to_string())
                                    .size(30.0)
                                    .strong()
                                    .color(GREEN),
                            );
                        });
                        ui.add_space(60.0);
                        ui.vertical(|ui| {
                            ui.label(RichText::new("SUM(amount)").color(MUTED));
                            ui.label(
                                RichText::new(sum.to_string())
                                    .size(30.0)
                                    .strong()
                                    .color(GREEN),
                            );
                        });
                    });
                    ui.add_space(12.0);
                    egui::Grid::new("peer-results")
                        .striped(true)
                        .min_col_width(100.0)
                        .show(ui, |ui| {
                            for label in ["Peer", "COUNT", "SUM", "FHE + decrypt"] {
                                ui.label(RichText::new(label).color(MUTED));
                            }
                            ui.end_row();
                            for peer in peers {
                                ui.label(format!("P{:02}", peer.id));
                                ui.label(peer.count.to_string());
                                ui.label(peer.sum.to_string());
                                ui.label(format!("{:.0} ms", peer.elapsed_ms));
                                ui.end_row();
                            }
                        });
                    ui.add_space(10.0);
                    badge(ui, "UNVERIFIED FHE RESULT", AMBER);
                }
                Some(Ok(Outcome::Query(QueryOutcome::Updated { committed }))) => {
                    ui.colored_label(
                        if *committed { GREEN } else { AMBER },
                        if *committed {
                            "Update applied to all shards. Run a SELECT to see the result."
                        } else {
                            "Amount overflow. All shards retained their previous values."
                        },
                    );
                    ui.add_space(10.0);
                    badge(ui, "LOCAL UPDATE · NO QUERY PROOF", AMBER);
                }
                Some(Err(error)) => {
                    ui.colored_label(RED, error);
                }
                _ => {
                    ui.label(
                        RichText::new("Choose a preset to run your first encrypted query.")
                            .color(MUTED),
                    );
                }
            }
            if let Some(record) = record {
                ui.add_space(10.0);
                ui.label(
                    RichText::new(record.label.replace('\n', " "))
                        .small()
                        .monospace()
                        .color(MUTED),
                );
            }
        });
    }

    fn draw(&mut self, ui: &mut egui::Ui) {
        if !self.busy
            && ui.input_mut(|input| input.consume_key(egui::Modifiers::CTRL, egui::Key::Enter))
        {
            self.run_query();
        }
        egui::Panel::left("navigation")
            .exact_size(250.0)
            .resizable(false)
            .frame(
                egui::Frame::new()
                    .fill(Color32::from_rgb(17, 22, 33))
                    .inner_margin(18),
            )
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("navigation-scroll")
                    .show(ui, |ui| self.sidebar(ui));
            });
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(BACKGROUND).inner_margin(24))
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("main-content")
                    .show(ui, |ui| self.content(ui));
            });
    }
}

impl eframe::App for Playground {
    fn logic(&mut self, _ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
    }
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.draw(ui);
    }
}

fn record_status(outcome: &Result<Outcome, String>) -> (&'static str, Color32) {
    match outcome {
        Err(_) => ("ERR", RED),
        Ok(Outcome::Query(QueryOutcome::Updated { committed: false })) => ("REJECT", AMBER),
        Ok(_) => ("OK", GREEN),
    }
}

fn card() -> egui::Frame {
    egui::Frame::new()
        .fill(PANEL)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(12)
        .inner_margin(16)
}

fn badge(ui: &mut egui::Ui, text: &str, color: Color32) {
    egui::Frame::new()
        .fill(color.gamma_multiply(0.12))
        .corner_radius(6)
        .inner_margin(6)
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(10.0).strong().color(color));
        });
}

fn metric(ui: &mut egui::Ui, title: &str, value: &str, subtitle: &str) {
    card().show(ui, |ui| {
        ui.set_min_width((ui.available_width() - 2.0).max(10.0));
        ui.label(RichText::new(title).size(10.0).strong().color(MUTED));
        ui.label(RichText::new(value).size(26.0).strong());
        ui.label(RichText::new(subtitle).size(11.0).color(MUTED));
    });
}

fn draw_peers(ui: &mut egui::Ui, snapshot: &LabSnapshot) {
    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), 145.0),
        egui::Sense::hover(),
    );
    let painter = ui.painter_at(rect);
    let center = rect.center();
    let nodes: Vec<_> = snapshot
        .peers
        .iter()
        .enumerate()
        .map(|(index, peer)| {
            let angle = std::f32::consts::TAU * index as f32 / snapshot.peers.len() as f32
                - std::f32::consts::FRAC_PI_2;
            (center + egui::vec2(angle.cos(), angle.sin()) * 52.0, peer)
        })
        .collect();
    for (point, peer) in &nodes {
        painter.line_segment([center, *point], Stroke::new(1.0, BORDER));
        painter.circle_filled(
            *point,
            11.0,
            if peer.online {
                GREEN.gamma_multiply(0.2)
            } else {
                RED.gamma_multiply(0.2)
            },
        );
        painter.circle_stroke(
            *point,
            11.0,
            Stroke::new(1.0, if peer.online { GREEN } else { RED }),
        );
        painter.text(
            *point,
            egui::Align2::CENTER_CENTER,
            peer.id.to_string(),
            FontId::monospace(10.0),
            Color32::WHITE,
        );
    }
    painter.circle_filled(center, 18.0, PANEL);
    painter.text(
        center,
        egui::Align2::CENTER_CENTER,
        "FHE",
        FontId::monospace(11.0),
        ACCENT,
    );
}

fn set_theme(ctx: &egui::Context) {
    let mut style = (*ctx.global_style()).clone();
    style.visuals = egui::Visuals::dark();
    style.visuals.override_text_color = Some(Color32::from_rgb(228, 234, 246));
    style.visuals.panel_fill = BACKGROUND;
    style.visuals.window_fill = PANEL;
    style.visuals.extreme_bg_color = Color32::from_rgb(10, 14, 22);
    style.visuals.selection.bg_fill = ACCENT.gamma_multiply(0.3);
    style.visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
    style.visuals.widgets.inactive.weak_bg_fill = Color32::from_rgb(35, 44, 62);
    style.visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(48, 61, 87);
    style.spacing.item_spacing = egui::vec2(10.0, 8.0);
    style.spacing.button_padding = egui::vec2(12.0, 8.0);
    style
        .text_styles
        .insert(egui::TextStyle::Body, FontId::proportional(14.0));
    style
        .text_styles
        .insert(egui::TextStyle::Button, FontId::proportional(13.0));
    ctx.set_global_style(style);
}
