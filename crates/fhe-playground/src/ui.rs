use crate::{
    graph_layout::GraphLayout,
    worker::{Command, Event, Outcome, Worker},
};
use eframe::egui::{self, Color32, FontId, RichText, Stroke};
use fhe_playground::{
    Column, DatabaseDraft, LabSnapshot, MAX_LAB_ROWS, MAX_PEERS, NetworkSnapshot, NodeId, NodeRole,
    PRESETS, PeerConfig, QueryOutcome, format_rows, parse_rows, sample_rows,
};
use std::collections::{HashMap, VecDeque};
mod camera;
mod data;
mod explorer;
mod infrastructure;
mod matrix;
mod navigation;
mod theme;
use camera::Camera;
use navigation::Navigation;
use theme::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tab {
    Sql,
    Data,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum DataView {
    Grid,
    Csv,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResultTab {
    Result,
    Output,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RightTab {
    Network,
    Node(NodeId),
}
#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum NetworkView {
    #[default]
    Auto,
    Map,
    Matrix,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Job {
    Query,
    Database,
    Maintenance,
}
struct Pending {
    job: Job,
    label: String,
    client_id: Option<NodeId>,
}
struct Record {
    job: Job,
    label: String,
    database: String,
    revision: u64,
    elapsed_ms: f64,
    outcome: Result<Outcome, String>,
}
enum Control {
    Add { position: egui::Pos2 },
    Delete(NodeId),
    Profile(NodeId),
    Availability,
    Replication,
    Domain(NodeId),
    Repair,
}

pub struct Playground {
    worker: Worker,
    snapshot: Option<LabSnapshot>,
    network: Option<NetworkSnapshot>,
    sql: String,
    draft_name: String,
    draft_rows: String,
    generate_rows: usize,
    pending: Option<Pending>,
    control_pending: Option<Control>,
    worker_stopped: bool,
    status: String,
    input_error: Option<String>,
    history: VecDeque<Record>,
    tab: Tab,
    data_view: DataView,
    result_tab: ResultTab,
    active_client: Option<NodeId>,
    selected_node: Option<NodeId>,
    node_tabs: Vec<NodeId>,
    right_tab: RightTab,
    navigation: Navigation,
    network_view: NetworkView,
    peer_edits: HashMap<NodeId, PeerConfig>,
    domain_edits: HashMap<NodeId, u64>,
    maintenance_status: String,
    graph_layout: GraphLayout,
    graph_router: crate::graph_routing::GraphRouter,
    graph_bundler: crate::graph_bundling::GraphBundler,
    graph_seeds: HashMap<NodeId, egui::Pos2>,
    camera: Camera,
    graph_initialized: bool,
    camera_manipulated: bool,
    last_graph_canvas: Option<egui::Rect>,
    simulation_speed: f64,
    simulation_paused: bool,
    context_position: egui::Pos2,
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
            network: None,
            sql: PRESETS
                .first()
                .expect("public presets are nonempty")
                .sql
                .into(),
            draft_name: "demo".into(),
            draft_rows: format_rows(&sample_rows(4).expect("bounded sample")),
            generate_rows: 4,
            pending: None,
            control_pending: None,
            worker_stopped: false,
            status: "Preparing...".into(),
            input_error: None,
            history: VecDeque::new(),
            tab: Tab::Sql,
            data_view: DataView::Grid,
            result_tab: ResultTab::Result,
            active_client: None,
            selected_node: None,
            node_tabs: Vec::new(),
            right_tab: RightTab::Network,
            navigation: Navigation::default(),
            network_view: NetworkView::Auto,
            peer_edits: HashMap::new(),
            domain_edits: HashMap::new(),
            maintenance_status: String::new(),
            graph_layout: GraphLayout::default(),
            graph_router: crate::graph_routing::GraphRouter::default(),
            graph_bundler: crate::graph_bundling::GraphBundler::default(),
            graph_seeds: HashMap::new(),
            camera: Camera::default(),
            graph_initialized: false,
            camera_manipulated: false,
            last_graph_canvas: None,
            simulation_speed: 1.0,
            simulation_paused: false,
            context_position: egui::Pos2::ZERO,
        }
    }
    fn available(&self) -> bool {
        self.pending.is_none() && !self.worker_stopped
    }
    fn controls_available(&self) -> bool {
        self.control_pending.is_none() && !self.worker_stopped
    }
    fn can_query(&self) -> bool {
        self.available()
            && self.controls_available()
            && self
                .snapshot
                .as_ref()
                .is_some_and(|state| state.replication.is_some())
            && self.active_client.is_some_and(|id| {
                self.network.as_ref().is_some_and(|net| {
                    net.nodes
                        .iter()
                        .any(|node| node.id == id && node.online && node.role == NodeRole::Client)
                })
            })
    }
    fn submit(&mut self, command: Command, job: Job, label: String) {
        if !self.available() {
            return;
        }
        let client_id = if let Command::Query { client_id, .. } = &command {
            Some(*client_id)
        } else {
            None
        };
        match self.worker.send(command) {
            Ok(()) => {
                self.pending = Some(Pending {
                    job,
                    label,
                    client_id,
                });
                self.status = "Working...".into();
                self.input_error = None;
            }
            Err(error) => self.input_error = Some(error),
        }
    }
    fn control(&mut self, command: Command, intent: Control) {
        if !self.controls_available() {
            return;
        }
        match self.worker.send(command) {
            Ok(()) => {
                self.control_pending = Some(intent);
                self.input_error = None;
            }
            Err(error) => self.input_error = Some(error),
        }
    }
    fn profiles(&self) -> Vec<PeerConfig> {
        self.snapshot
            .as_ref()
            .map(|s| s.peers.iter().map(|peer| peer.config.clone()).collect())
            .unwrap_or_else(|| (1..=3).map(PeerConfig::numbered).collect())
    }
    fn create_database(&mut self) {
        match parse_rows(&self.draft_rows) {
            Ok(rows) => self.submit(
                Command::Create(DatabaseDraft {
                    name: self.draft_name.clone(),
                    rows,
                    peers: self.profiles(),
                }),
                Job::Database,
                "Create / replace database".into(),
            ),
            Err(error) => self.input_error = Some(error.to_string()),
        }
    }
    fn insert_preset(&mut self, sql: &str) {
        self.sql = sql.into();
    }
    fn run_query(&mut self) {
        if self.can_query()
            && let Some(client_id) = self.active_client
        {
            self.submit(
                Command::Query {
                    client_id,
                    sql: self.sql.clone(),
                },
                Job::Query,
                format!("{}: {}", self.node_name(client_id), self.sql),
            );
        }
    }
    fn node_name(&self, id: NodeId) -> String {
        self.network
            .as_ref()
            .and_then(|n| n.nodes.iter().find(|n| n.id == id))
            .map(|n| n.name.clone())
            .unwrap_or_else(|| format!("Node {id}"))
    }
    fn open_node(&mut self, id: NodeId) {
        if !self.node_tabs.contains(&id) {
            self.node_tabs.push(id);
        }
        self.selected_node = Some(id);
        self.navigate(self.tab, RightTab::Node(id));
        if let Some(node) = self
            .network
            .as_ref()
            .and_then(|n| n.nodes.iter().find(|n| n.id == id))
        {
            if node.role == NodeRole::Client {
                self.active_client = Some(id);
            }
            if let Some(peer_id) = node.peer_id
                && let Some(peer) = self
                    .snapshot
                    .as_ref()
                    .and_then(|s| s.peers.iter().find(|p| p.id == peer_id))
            {
                self.peer_edits
                    .entry(id)
                    .or_insert_with(|| peer.config.clone());
            }
        }
    }
    fn poll(&mut self) {
        if self.worker_stopped {
            return;
        }
        loop {
            match self.worker.poll() {
                Ok(Some(Event::Network(net))) => {
                    if !self.active_client.is_some_and(|id| {
                        net.nodes
                            .iter()
                            .any(|n| n.id == id && n.role == NodeRole::Client)
                    }) {
                        self.active_client = net
                            .nodes
                            .iter()
                            .find(|n| n.role == NodeRole::Client)
                            .map(|n| n.id);
                    }
                    self.node_tabs
                        .retain(|id| net.nodes.iter().any(|n| n.id == *id));
                    self.peer_edits
                        .retain(|id, _| net.nodes.iter().any(|n| n.id == *id));
                    self.domain_edits
                        .retain(|id, _| net.nodes.iter().any(|n| n.id == *id));
                    self.graph_seeds.retain(|id, _| {
                        net.nodes.iter().any(|n| n.id == *id)
                            || !self
                                .network
                                .as_ref()
                                .is_some_and(|old| old.nodes.iter().any(|n| n.id == *id))
                    });
                    if let RightTab::Node(id) = self.right_tab
                        && !net.nodes.iter().any(|n| n.id == id)
                    {
                        self.right_tab = RightTab::Network;
                    }
                    if self.selected_node.is_some_and(|id| {
                        !net.nodes
                            .iter()
                            .any(|n| Some(n.id) == self.selected_node && n.id == id)
                    }) {
                        self.selected_node = None;
                    }
                    self.network = Some(net);
                    self.prune_navigation();
                }
                Ok(Some(Event::Progress(message))) => self.status = message,
                Ok(Some(Event::PeerProgress(progress))) => self.status = progress.message,
                Ok(Some(Event::ControlFinished { snapshot, outcome })) => {
                    let intent = self.control_pending.take();
                    if matches!(intent, Some(Control::Repair)) {
                        self.snapshot = snapshot;
                        self.record_maintenance(outcome);
                        continue;
                    }
                    if outcome.is_ok() {
                        self.snapshot = snapshot;
                        match (intent, &outcome) {
                            (Some(Control::Add { position }), Ok(Outcome::NodeAdded { id })) => {
                                self.graph_seeds.insert(*id, position);
                            }
                            (Some(Control::Profile(id)), _) => {
                                if let Some(peer_id) = self
                                    .network
                                    .as_ref()
                                    .and_then(|n| n.nodes.iter().find(|n| n.id == id))
                                    .and_then(|n| n.peer_id)
                                    && let Some(peer) = self
                                        .snapshot
                                        .as_ref()
                                        .and_then(|s| s.peers.iter().find(|p| p.id == peer_id))
                                {
                                    self.peer_edits.insert(id, peer.config.clone());
                                }
                            }
                            (Some(Control::Delete(expected)), Ok(Outcome::NodeRemoved { id }))
                                if expected == *id =>
                            {
                                self.graph_seeds.remove(id);
                                self.close_node_tab(*id);
                            }
                            (Some(Control::Domain(id)), _) => {
                                self.domain_edits.remove(&id);
                            }
                            _ => {}
                        }
                    } else if let Err(error) = outcome {
                        self.input_error = Some(error.to_string());
                    }
                }
                Ok(Some(Event::MaintenanceFinished { snapshot, outcome })) => {
                    self.snapshot = snapshot;
                    self.record_maintenance(outcome);
                }
                Ok(Some(Event::Finished {
                    snapshot,
                    outcome,
                    elapsed_ms,
                    client_id,
                })) => {
                    if !self
                        .pending
                        .as_ref()
                        .is_some_and(|pending| pending.client_id == client_id)
                    {
                        continue;
                    }
                    let Some(pending) = self.pending.take() else {
                        continue;
                    };
                    let created = matches!(outcome, Ok(Outcome::Created));
                    let updated = matches!(
                        outcome,
                        Ok(Outcome::Query(
                            QueryOutcome::Updated { committed: true }
                                | QueryOutcome::Inserted { .. }
                        ))
                    );
                    let current_draft = self.snapshot.as_ref().is_some_and(|s| {
                        self.draft_name.trim() == s.name
                            && self.draft_rows == format_rows(&s.owner_rows)
                    });
                    if let Some(state) = &snapshot
                        && (created || (updated && current_draft))
                    {
                        self.draft_name = state.name.clone();
                        self.draft_rows = format_rows(&state.owner_rows);
                    }
                    if created {
                        self.history.clear();
                        self.maintenance_status.clear();
                        self.domain_edits.clear();
                    }
                    if pending.job == Job::Query {
                        self.result_tab = if matches!(
                            outcome,
                            Ok(Outcome::Query(
                                QueryOutcome::Aggregate { .. }
                                    | QueryOutcome::Count { .. }
                                    | QueryOutcome::Sum { .. }
                                    | QueryOutcome::Selected { .. }
                            ))
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
                        .map(|s| (s.name.clone(), s.revision))
                        .unwrap_or_default();
                    self.history.push_front(Record {
                        job: pending.job,
                        label: pending.label,
                        database,
                        revision,
                        elapsed_ms,
                        outcome: outcome.map_err(|e| e.to_string()),
                    });
                    self.history.truncate(8);
                    self.snapshot = snapshot;
                }
                Ok(None) => break,
                Err(error) => {
                    self.pending = None;
                    self.control_pending = None;
                    self.worker_stopped = true;
                    self.input_error = Some(error);
                    break;
                }
            }
        }
    }
    fn record_maintenance(&mut self, outcome: Result<Outcome, fhe_playground::LabError>) {
        self.maintenance_status = match &outcome {
            Ok(Outcome::ReplicasRepaired { current, stale }) => {
                format!("Local repair complete: {current} current / {stale} stale")
            }
            Err(error) => format!("Local repair deferred/failed: {error}"),
            _ => "Local repair complete".into(),
        };
        let (database, revision) = self
            .snapshot
            .as_ref()
            .map(|state| (state.name.clone(), state.revision))
            .unwrap_or_default();
        self.history.push_front(Record {
            job: Job::Maintenance,
            label: self.maintenance_status.clone(),
            database,
            revision,
            elapsed_ms: 0.0,
            outcome: outcome.map_err(|error| error.to_string()),
        });
        self.history.truncate(8);
    }
    fn draw(&mut self, ui: &mut egui::Ui) {
        self.navigation_shortcuts(ui.ctx());
        egui::Panel::bottom("status").frame(panel(6)).show(ui, |ui| {
            ui.horizontal(|ui| {
                if self.pending.is_some() { ui.spinner(); }
                ui.add(egui::Label::new(self.input_error.as_deref().unwrap_or(&self.status)).truncate());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new("Local / unverified").small().color(MUTED)).on_hover_text("Local transport and real FHE. No query proofs, consensus or replication guarantees.");
                });
            });
        });
        let width = ui.available_width();
        egui::Panel::left("client-workspace")
            .default_size(width * 0.41)
            .size_range(330.0..=width * 0.65)
            .resizable(true)
            .frame(panel(0))
            .show(ui, |ui| {
                egui::Panel::top("client-tabs")
                    .frame(panel(10))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            for (tab, name) in [(Tab::Sql, "SQL"), (Tab::Data, "Data")] {
                                if tab_button(ui, name, self.tab == tab).clicked() {
                                    self.navigate(tab, self.right_tab);
                                }
                            }
                        });
                    });
                match self.tab {
                    Tab::Sql => self.console(ui),
                    Tab::Data => self.data_editor(ui),
                }
            });
        egui::CentralPanel::default()
            .frame(panel(0))
            .show(ui, |ui| self.infrastructure(ui));
    }
    fn client_selector(&mut self, ui: &mut egui::Ui) {
        let clients: Vec<_> = self
            .network
            .as_ref()
            .map(|n| {
                n.nodes
                    .iter()
                    .filter(|n| n.role == NodeRole::Client)
                    .map(|n| (n.id, n.name.clone()))
                    .collect()
            })
            .unwrap_or_default();
        let selected = self
            .active_client
            .map(|id| self.node_name(id))
            .unwrap_or_else(|| "No client".into());
        egui::ComboBox::from_id_salt("active-client")
            .selected_text(selected)
            .width(135.0)
            .show_ui(ui, |ui| {
                for (id, name) in clients {
                    if tab_button(ui, &name, self.active_client == Some(id)).clicked() {
                        self.active_client = Some(id);
                        ui.close();
                    }
                }
            });
    }
    fn console(&mut self, ui: &mut egui::Ui) {
        let focused = ui.ctx().memory(|memory| memory.focused());
        if (focused.is_none() || focused == Some(egui::Id::new("sql-editor-field")))
            && self.can_query()
            && ui.input_mut(|i| i.consume_key(egui::Modifiers::CTRL, egui::Key::Enter))
        {
            self.run_query();
        }
        egui::Panel::top("sql-toolbar")
            .frame(panel(10))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    let reason = self.run_disabled_reason();
                    if run_button(ui, self.can_query())
                        .on_hover_text("Execute SQL from this client (Ctrl+Enter)")
                        .on_disabled_hover_text(reason.unwrap_or("SQL is unavailable"))
                        .clicked()
                    {
                        self.run_query();
                    }
                    self.client_selector(ui);
                    ui.menu_button("Presets", |ui| {
                        ui.spacing_mut().item_spacing.y = 3.0;
                        ui.spacing_mut().interact_size.y = 24.0;
                        let mut group = None;
                        for preset in PRESETS {
                            if group != Some(preset.group) {
                                if group.is_some() {
                                    ui.separator();
                                }
                                ui.label(RichText::new(preset.group.label()).small().color(MUTED));
                                group = Some(preset.group);
                            }
                            if ui.button(preset.name).on_hover_text(preset.sql).clicked() {
                                self.insert_preset(preset.sql);
                                ui.close();
                            }
                        }
                    });
                });
                self.database_bar(ui);
                if let Some(reason) = self.run_disabled_reason() {
                    ui.label(RichText::new(reason).small().color(MUTED));
                }
            });
        egui::Panel::bottom("query-results")
            .default_size(230.0)
            .size_range(120.0..=420.0)
            .resizable(true)
            .frame(panel(10))
            .show(ui, |ui| self.results(ui));
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(EDITOR).inner_margin(10))
            .show(ui, |ui| {
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
                                    .id(egui::Id::new("sql-editor-field"))
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
    fn run_disabled_reason(&self) -> Option<&'static str> {
        if self.worker_stopped {
            Some("Worker stopped")
        } else if self.pending.is_some() {
            Some("Operation running…")
        } else if self.control_pending.is_some() {
            Some("Applying network changes…")
        } else if self.snapshot.is_none() {
            Some("Create a database in Data")
        } else if self
            .snapshot
            .as_ref()
            .is_some_and(|state| state.replication.is_none())
        {
            Some("Storage state unavailable")
        } else if self.active_client.is_none() {
            Some("Add a client from the Network context menu")
        } else if !self.can_query() {
            Some("The selected client is offline")
        } else {
            None
        }
    }
    fn results(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if tab_button(ui, "Result", self.result_tab == ResultTab::Result).clicked() {
                self.result_tab = ResultTab::Result;
            }
            if tab_button(ui, "Output", self.result_tab == ResultTab::Output).clicked() {
                self.result_tab = ResultTab::Output;
            }
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
                            if record.job != Job::Maintenance {
                                ui.label(
                                    RichText::new(format!("{:.0} ms", record.elapsed_ms))
                                        .color(MUTED),
                                );
                            }
                            ui.label(record.label.lines().next().unwrap_or_default())
                                .on_hover_text(&record.label);
                        });
                    }
                } else if let Some(record) =
                    self.history.iter().find(|record| record.job == Job::Query)
                {
                    match &record.outcome {
                        Ok(Outcome::Query(QueryOutcome::Aggregate { count, sum, .. })) => {
                            result_table(ui, &["COUNT(*)", "SUM(amount)"], &[vec![*count, *sum]]);
                        }
                        Ok(Outcome::Query(QueryOutcome::Count { count, .. })) => {
                            result_table(ui, &["COUNT(*)"], &[vec![*count]]);
                        }
                        Ok(Outcome::Query(QueryOutcome::Sum { sum, .. })) => {
                            result_table(ui, &["SUM(amount)"], &[vec![*sum]]);
                        }
                        Ok(Outcome::Query(QueryOutcome::Selected { columns, rows })) => {
                            ui.label(RichText::new("Encrypted SELECT · unverified").small().color(MUTED))
                                .on_hover_text("The owner prepares authenticated encrypted index inputs; peers project the rows with BFV. Only the authorized client decrypts the result. No computation proof is available.");
                            let headings: Vec<_> = columns.iter().map(|column| match column {
                                Column::Age => "age",
                                Column::Amount => "amount",
                            }).collect();
                            result_table(ui, &headings, rows);
                            ui.label(RichText::new(format!("{} rows", rows.len())).small().color(MUTED));
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

fn result_table(ui: &mut egui::Ui, columns: &[&str], rows: &[Vec<u32>]) {
    egui::Grid::new("query-result-table")
        .striped(true)
        .min_col_width(80.0)
        .show(ui, |ui| {
            ui.label(RichText::new("#").strong().color(MUTED));
            for column in columns {
                ui.label(RichText::new(*column).strong());
            }
            ui.end_row();
            for (index, row) in rows.iter().enumerate() {
                ui.label(RichText::new((index + 1).to_string()).color(MUTED));
                for value in row {
                    ui.monospace(value.to_string());
                }
                ui.end_row();
            }
        });
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
        Ok(Outcome::Query(QueryOutcome::Inserted { count })) => (
            format!("Inserted {count} row{}", if *count == 1 { "" } else { "s" }),
            GREEN,
        ),
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
            "SELECT" | "FROM" | "WHERE" | "INSERT" | "INTO" | "VALUES" | "UPDATE" | "SET"
            | "BETWEEN" | "AND" | "LIMIT" => Color32::from_rgb(207, 142, 109),
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
