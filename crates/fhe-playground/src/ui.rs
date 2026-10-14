use std::collections::VecDeque;

use eframe::egui::{self, Color32, FontId, RichText, Stroke};
use fhe_playground::{
    DatabaseDraft, LabSnapshot, MAX_LAB_ROWS, MAX_PEERS, PRESETS, PeerConfig, QueryOutcome,
    format_rows, parse_rows, sample_rows,
};

use crate::worker::{Command, Event, Outcome, Worker};

mod data;
mod explorer;
mod infrastructure;
mod theme;
use theme::*;

#[derive(Clone, Copy, PartialEq, Eq)]
enum DataView {
    Grid,
    Csv,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PeerView {
    Shard,
    Settings,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Sql,
    Data,
    Infrastructure,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ResultTab {
    Result,
    Output,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Job {
    Query,
    Database,
    Layout,
    Availability,
    PeerSettings,
}

struct Pending {
    job: Job,
    label: String,
}

struct Record {
    job: Job,
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
    pending: Option<Pending>,
    worker_stopped: bool,
    status: String,
    input_error: Option<String>,
    history: VecDeque<Record>,
    tab: Tab,
    result_tab: ResultTab,
    data_view: DataView,
    explorer_filter: String,
    selected_peer: Option<usize>,
    peer_view: PeerView,
    peer_edit: Option<PeerConfig>,
    new_peer: Option<PeerConfig>,
    active_peer: Option<usize>,
    graph_zoom: f32,
    graph_pan: egui::Vec2,
}

impl Playground {
    pub fn new(ctx: &egui::Context) -> Result<Self, std::io::Error> {
        set_theme(ctx);
        let mut app = Self::with_worker(Worker::start(ctx.clone())?);
        app.create_database();
        Ok(app)
    }

    fn with_worker(worker: Worker) -> Self {
        Self {
            worker,
            snapshot: None,
            sql: PRESETS[1].sql.into(),
            draft_name: "demo".into(),
            draft_rows: format_rows(&sample_rows(4).expect("bounded sample")),
            draft_peers: 3,
            generate_rows: 4,
            pending: None,
            worker_stopped: false,
            status: "Ready".into(),
            input_error: None,
            history: VecDeque::new(),
            tab: Tab::Sql,
            result_tab: ResultTab::Result,
            data_view: DataView::Grid,
            explorer_filter: String::new(),
            selected_peer: None,
            peer_view: PeerView::Shard,
            peer_edit: None,
            new_peer: None,
            active_peer: None,
            graph_zoom: 1.0,
            graph_pan: egui::Vec2::ZERO,
        }
    }

    fn available(&self) -> bool {
        self.pending.is_none() && !self.worker_stopped
    }

    fn submit(&mut self, command: Command, job: Job, label: String) {
        if !self.available() {
            return;
        }
        match self.worker.send(command) {
            Ok(()) => {
                self.pending = Some(Pending { job, label });
                self.status = "Working...".into();
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
                    peers: self.profiles_for_count(self.draft_peers),
                }),
                Job::Database,
                "Create / replace database".into(),
            ),
            Err(error) => self.input_error = Some(error.to_string()),
        }
    }

    fn apply_layout(&mut self) {
        if self.snapshot.is_some() {
            self.submit(
                Command::ConfigurePeers(self.profiles_for_count(self.draft_peers)),
                Job::Layout,
                "Apply peer layout".into(),
            );
        }
    }

    fn profiles_for_count(&self, count: usize) -> Vec<PeerConfig> {
        (0..count)
            .map(|index| {
                self.snapshot
                    .as_ref()
                    .and_then(|state| state.peers.get(index))
                    .map(|peer| peer.config.clone())
                    .unwrap_or_else(|| PeerConfig::numbered(index + 1))
            })
            .collect()
    }

    fn select_peer(&mut self, id: Option<usize>) {
        if self.selected_peer != id {
            self.peer_view = PeerView::Shard;
        }
        self.selected_peer = id;
        self.new_peer = None;
        self.peer_edit = id.and_then(|id| {
            self.snapshot
                .as_ref()
                .and_then(|state| state.peers.iter().find(|peer| peer.id == id))
                .map(|peer| peer.config.clone())
        });
    }

    fn insert_preset(&mut self, sql: &str) {
        self.sql = sql.into();
    }

    fn run_query(&mut self) {
        if self.snapshot.is_some() {
            self.submit(
                Command::Query(self.sql.clone()),
                Job::Query,
                self.sql.clone(),
            );
        }
    }

    fn poll(&mut self) {
        if self.worker_stopped {
            return;
        }
        loop {
            match self.worker.poll() {
                Ok(Some(Event::Progress(message))) => self.status = message,
                Ok(Some(Event::PeerProgress(progress))) => {
                    self.active_peer = Some(progress.peer_id);
                    self.status = progress.message;
                }
                Ok(Some(Event::Finished {
                    snapshot,
                    outcome,
                    elapsed_ms,
                })) => {
                    let Some(pending) = self.pending.take() else {
                        continue;
                    };
                    let created = matches!(outcome, Ok(Outcome::Created));
                    let layout_changed = matches!(outcome, Ok(Outcome::LayoutChanged));
                    self.active_peer = None;
                    let updated = matches!(
                        outcome,
                        Ok(Outcome::Query(QueryOutcome::Updated { committed: true }))
                    );
                    let draft_is_current = self.snapshot.as_ref().is_some_and(|state| {
                        self.draft_name.trim() == state.name
                            && self.draft_rows == format_rows(&state.owner_rows)
                    });
                    if let Some(state) = &snapshot
                        && ((created && pending.job == Job::Database)
                            || (updated && draft_is_current))
                    {
                        self.draft_name = state.name.clone();
                        self.draft_rows = format_rows(&state.owner_rows);
                    }
                    if created || layout_changed {
                        self.history.clear();
                        if pending.job == Job::Database && self.tab == Tab::Data {
                            self.tab = Tab::Sql;
                        }
                    }
                    if pending.job == Job::Query {
                        self.result_tab = if matches!(
                            outcome,
                            Ok(Outcome::Query(QueryOutcome::Aggregate { .. }))
                        ) {
                            ResultTab::Result
                        } else {
                            ResultTab::Output
                        };
                    }
                    self.status = if outcome.is_ok() {
                        "Ready".into()
                    } else {
                        "Operation failed".into()
                    };
                    if pending.job != Job::Query
                        && let Err(error) = &outcome
                    {
                        self.input_error = Some(error.to_string());
                    }
                    let (database, revision) = snapshot
                        .as_ref()
                        .map(|state| (state.name.clone(), state.revision))
                        .unwrap_or_default();
                    self.history.push_front(Record {
                        job: pending.job,
                        label: pending.label,
                        database,
                        revision,
                        elapsed_ms,
                        outcome: outcome.map_err(|error| error.to_string()),
                    });
                    self.history.truncate(8);
                    self.snapshot = snapshot;
                    if (created || layout_changed)
                        && let Some(state) = &self.snapshot
                    {
                        self.draft_peers = state.peers.len();
                        if self.selected_peer.is_some_and(|id| id > state.peers.len()) {
                            self.select_peer(None);
                        }
                    }
                    if (created || layout_changed || pending.job == Job::PeerSettings)
                        && self.input_error.is_none()
                    {
                        self.new_peer = None;
                        self.select_peer(self.selected_peer);
                    }
                }
                Ok(None) => break,
                Err(message) => {
                    self.pending = None;
                    self.active_peer = None;
                    self.worker_stopped = true;
                    self.input_error = Some(message);
                    break;
                }
            }
        }
    }

    fn draw(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("tabs").frame(panel(12)).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("DCS").strong().color(ACCENT));
                ui.add_space(18.0);
                for (tab, label) in [
                    (Tab::Sql, "SQL"),
                    (Tab::Data, "Data"),
                    (Tab::Infrastructure, "Infrastructure"),
                ] {
                    if tab_button(ui, label, self.tab == tab).clicked() {
                        self.tab = tab;
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if let Some(state) = &self.snapshot {
                        ui.label(RichText::new(&state.name).color(MUTED));
                        icon(ui, Icon::Database, MUTED);
                    }
                });
            });
        });
        egui::Panel::bottom("status").frame(panel(6)).show(ui, |ui| {
            ui.horizontal(|ui| {
                if self.pending.is_some() { ui.spinner(); }
                ui.add(egui::Label::new(self.input_error.as_deref().unwrap_or(&self.status)).truncate());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new("Local / unverified").small().color(MUTED))
                        .on_hover_text("Peers share this process. FHE results have no cryptographic query proof. Keys and data are ephemeral.");
                });
            });
        });
        match self.tab {
            Tab::Sql => self.console(ui),
            Tab::Data => self.data_editor(ui),
            Tab::Infrastructure => self.infrastructure(ui),
        }
    }

    fn console(&mut self, ui: &mut egui::Ui) {
        if self.available()
            && ui.input_mut(|input| input.consume_key(egui::Modifiers::CTRL, egui::Key::Enter))
        {
            self.run_query();
        }
        self.explorer(ui);
        egui::Panel::bottom("query-results")
            .default_size(220.0)
            .size_range(120.0..=480.0)
            .resizable(true)
            .frame(panel(8))
            .show(ui, |ui| self.results(ui));
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(EDITOR).inner_margin(8))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Console.sql").monospace());
                    ui.separator();
                    if ui
                        .add_enabled(
                            self.available() && self.snapshot.is_some(),
                            egui::Button::new(RichText::new("Run").color(GREEN)),
                        )
                        .on_hover_text("Execute SQL (Ctrl+Enter)")
                        .clicked()
                    {
                        self.run_query();
                    }
                    ui.menu_button("Presets", |ui| {
                        for preset in PRESETS {
                            if ui.button(preset.name).on_hover_text(preset.sql).clicked() {
                                self.insert_preset(preset.sql);
                                ui.close();
                            }
                        }
                    });
                });
                ui.separator();
                let height = ui.available_height();
                egui::ScrollArea::both()
                    .id_salt("sql-editor")
                    .show(ui, |ui| {
                        ui.horizontal_top(|ui| {
                            let lines = (1..=self.sql.split('\n').count())
                                .map(|line| line.to_string())
                                .collect::<Vec<_>>()
                                .join("\n");
                            ui.add(egui::Label::new(
                                RichText::new(lines)
                                    .font(FontId::monospace(14.0))
                                    .color(MUTED),
                            ));
                            let mut layouter =
                                |ui: &egui::Ui, text: &dyn egui::TextBuffer, _width: f32| {
                                    ui.fonts_mut(|fonts| {
                                        fonts.layout_job(highlight_sql(text.as_str()))
                                    })
                                };
                            ui.add(
                                egui::TextEdit::multiline(&mut self.sql)
                                    .code_editor()
                                    .frame(egui::Frame::NONE)
                                    .margin(egui::Margin::ZERO)
                                    .font(FontId::monospace(14.0))
                                    .desired_width(ui.available_width())
                                    .min_size(egui::vec2(ui.available_width(), height))
                                    .layouter(&mut layouter),
                            );
                        });
                    });
            });
    }

    fn results(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.result_tab, ResultTab::Result, "Result");
            ui.selectable_value(&mut self.result_tab, ResultTab::Output, "Output");
            if let Some(record) = self.history.iter().find(|record| record.job == Job::Query) {
                ui.label(
                    RichText::new(format!(
                        "{} / v{} / {:.0} ms",
                        record.database, record.revision, record.elapsed_ms
                    ))
                    .small()
                    .color(MUTED),
                )
                .on_hover_text(&record.label);
            }
        });
        ui.separator();
        egui::ScrollArea::both()
            .id_salt("result-body")
            .show(ui, |ui| {
                if self.result_tab == ResultTab::Output {
                    for record in &self.history {
                        let (message, color) = outcome_message(&record.outcome);
                        ui.horizontal_wrapped(|ui| {
                            ui.colored_label(color, message);
                            ui.label(
                                RichText::new(format!("{:.0} ms", record.elapsed_ms)).color(MUTED),
                            );
                            ui.label(record.label.lines().next().unwrap_or_default())
                                .on_hover_text(&record.label);
                        });
                    }
                } else if let Some(record) =
                    self.history.iter().find(|record| record.job == Job::Query)
                {
                    match &record.outcome {
                        Ok(Outcome::Query(QueryOutcome::Aggregate { count, sum, .. })) => {
                            egui::Grid::new("aggregate-result")
                                .striped(true)
                                .min_col_width(120.0)
                                .show(ui, |ui| {
                                    for name in ["#", "COUNT(*)", "SUM(amount)"] {
                                        ui.label(RichText::new(name).strong());
                                    }
                                    ui.end_row();
                                    ui.label("1");
                                    ui.monospace(count.to_string());
                                    ui.monospace(sum.to_string());
                                    ui.end_row();
                                });
                        }
                        _ => {
                            let (message, color) = outcome_message(&record.outcome);
                            ui.colored_label(color, message);
                        }
                    }
                }
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

fn panel(margin: i8) -> egui::Frame {
    egui::Frame::new().fill(PANEL).inner_margin(margin)
}

fn outcome_message(outcome: &Result<Outcome, String>) -> (String, Color32) {
    match outcome {
        Err(message) => (message.clone(), RED),
        Ok(Outcome::Query(QueryOutcome::Updated { committed: false })) => {
            ("Rejected: amount overflow; no changes".into(), AMBER)
        }
        Ok(Outcome::Query(QueryOutcome::Updated { committed: true })) => ("Updated".into(), GREEN),
        Ok(_) => ("OK".into(), TEXT),
    }
}

fn highlight_sql(sql: &str) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    for token in
        sql.split_inclusive(|character: char| !character.is_alphanumeric() && character != '_')
    {
        let word = token
            .trim_end_matches(|character: char| !character.is_alphanumeric() && character != '_');
        let color = match word.to_ascii_uppercase().as_str() {
            "SELECT" | "FROM" | "WHERE" | "UPDATE" | "SET" => Color32::from_rgb(207, 142, 109),
            "COUNT" | "SUM" => Color32::from_rgb(86, 168, 245),
            _ if !word.is_empty() && word.chars().all(|character| character.is_ascii_digit()) => {
                Color32::from_rgb(106, 171, 115)
            }
            _ => TEXT,
        };
        job.append(
            word,
            0.0,
            egui::TextFormat {
                font_id: FontId::monospace(14.0),
                color,
                ..Default::default()
            },
        );
        job.append(
            &token[word.len()..],
            0.0,
            egui::TextFormat {
                font_id: FontId::monospace(14.0),
                color: TEXT,
                ..Default::default()
            },
        );
    }
    job
}

#[cfg(test)]
#[path = "ui_tests.rs"]
mod tests;
