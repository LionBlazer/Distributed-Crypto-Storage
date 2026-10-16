use crate::{
    graph_layout::GraphLayout,
    worker::{Command, Event, Outcome, Worker},
};
use eframe::egui::{self, Color32, FontId, RichText, Stroke};
#[cfg(test)]
use fhe_playground::sample_rows;
use fhe_playground::{
    DatabaseDraft, LabSnapshot, MAX_LAB_ROWS, MAX_PEERS, NetworkSnapshot, NodeId, NodeRole,
    PRESETS, PeerConfig, QueryOutcome, format_rows, parse_rows,
};
use relational_types::{ImportedDatabase, TableSchema, Value};
use sql_plan::Column;
use std::collections::{HashMap, VecDeque};
mod camera;
mod data;
mod explorer;
mod infrastructure;
mod matrix;
mod navigation;
mod overview;
mod theme;
use camera::Camera;
use navigation::Navigation;
use theme::*;

const STARTUP_SQL: &str = "CREATE TABLE IF NOT EXISTS records (\n    age TINYINT UNSIGNED NOT NULL,\n    amount SMALLINT UNSIGNED NOT NULL\n);\nSELECT * FROM records;";

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
    Settings,
    Node(NodeId),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
enum NetworkView {
    #[default]
    Auto,
    Map,
    Matrix,
    Overview,
}
#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum LinkView {
    #[default]
    Relevant,
    All,
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
    Repair,
}

pub struct Playground {
    worker: Worker,
    snapshot: Option<LabSnapshot>,
    catalog: Vec<(TableSchema, usize)>,
    selected_table: usize,
    network: Option<NetworkSnapshot>,
    peer_inventory: Vec<crate::process_backend::PeerProfile>,
    sql: String,
    draft_name: String,
    draft_rows: String,
    data_import: data::DataImport,
    pending: Option<Pending>,
    completion_waiting: bool,
    control_pending: Option<Control>,
    worker_stopped: bool,
    source_stopped: bool,
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
    link_view: LinkView,
    playback: crate::traffic::Playback,
    timeline: crate::traffic::timeline::Timeline<Event>,
    overview_search: String,
    overview_members: Option<Vec<NodeId>>,
    peer_edits: HashMap<NodeId, PeerConfig>,
    maintenance_status: String,
    graph_layout: GraphLayout,
    graph_router: crate::graph_routing::GraphRouter,
    graph_bundler: crate::graph_bundling::GraphBundler,
    graph_seeds: HashMap<NodeId, egui::Pos2>,
    camera: Camera,
    graph_initialized: bool,
    camera_manipulated: bool,
    last_graph_canvas: Option<egui::Rect>,
    context_position: egui::Pos2,
}

impl Playground {
    pub fn new(ctx: &egui::Context) -> Result<Self, std::io::Error> {
        set_theme(ctx);
        let mut app = Self::with_worker(Worker::start(ctx.clone())?);
        app.status = "Run the SQL script to create an empty table".into();
        Ok(app)
    }
    fn with_worker(worker: Worker) -> Self {
        Self {
            worker,
            snapshot: None,
            catalog: Vec::new(),
            selected_table: 0,
            network: None,
            peer_inventory: Vec::new(),
            sql: STARTUP_SQL.into(),
            draft_name: "database".into(),
            draft_rows: String::new(),
            data_import: data::DataImport::default(),
            pending: None,
            completion_waiting: false,
            control_pending: None,
            worker_stopped: false,
            source_stopped: false,
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
            link_view: LinkView::Relevant,
            playback: crate::traffic::Playback::default(),
            timeline: crate::traffic::timeline::Timeline::default(),
            overview_search: String::new(),
            overview_members: None,
            peer_edits: HashMap::new(),
            maintenance_status: String::new(),
            graph_layout: GraphLayout::default(),
            graph_router: crate::graph_routing::GraphRouter::default(),
            graph_bundler: crate::graph_bundling::GraphBundler::default(),
            graph_seeds: HashMap::new(),
            camera: Camera::default(),
            graph_initialized: false,
            camera_manipulated: false,
            last_graph_canvas: None,
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
        // Run may catch up a completed creation whose first database/client
        // snapshot is still queued. Dispatch rechecks all ordinary guards after
        // catch_up_display applies that state; this grants no invented database.
        if self.completion_waiting && !self.source_stopped && self.controls_available() {
            return true;
        }
        self.available()
            && !self.source_stopped
            && self.controls_available()
            && self.active_client.is_some_and(|id| {
                self.network.as_ref().is_some_and(|net| {
                    net.nodes
                        .iter()
                        .any(|node| node.id == id && node.online && node.role == NodeRole::Client)
                })
            })
    }
    fn can_stop_query(&self) -> bool {
        self.pending
            .as_ref()
            .is_some_and(|pending| pending.job == Job::Query)
            && !self.completion_waiting
            && !self.source_stopped
            && !self.worker.query_cancelled()
    }
    fn stop_query(&mut self) {
        if self.can_stop_query() && self.worker.cancel_query() {
            self.status = "Stopping SQL…".into();
        }
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
                self.completion_waiting = false;
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
        if !self.peer_inventory.is_empty() {
            return self
                .peer_inventory
                .iter()
                .map(|peer| peer.config.clone())
                .collect();
        }
        self.snapshot
            .as_ref()
            .map(|s| s.peers.iter().map(|peer| peer.config.clone()).collect())
            .unwrap_or_else(|| {
                (1..=3)
                    .map(crate::process_backend::default_peer_config)
                    .collect()
            })
    }
    fn peer_config(&self, id: NodeId) -> Option<PeerConfig> {
        self.peer_inventory
            .iter()
            .find(|peer| peer.node == id)
            .map(|peer| peer.config.clone())
            .or_else(|| {
                let peer_id = self
                    .network
                    .as_ref()?
                    .nodes
                    .iter()
                    .find(|node| node.id == id)?
                    .peer_id?;
                self.snapshot
                    .as_ref()?
                    .peers
                    .iter()
                    .find(|peer| peer.id == peer_id)
                    .map(|peer| peer.config.clone())
            })
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
    fn import_relational(&mut self, database: ImportedDatabase, label: String) {
        self.catch_up_display();
        if self.snapshot.is_some() || !self.catalog.is_empty() {
            self.input_error = Some(
                "Import requires a new empty workspace; existing encrypted data was not replaced."
                    .into(),
            );
            return;
        }
        self.submit(
            Command::ImportRelational(database),
            Job::Database,
            format!("Import {label}"),
        );
    }
    fn run_query(&mut self) {
        // A user action starts at the latest observed state, retaining their speed.
        self.catch_up_display();
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
            if let Some(config) = self.peer_config(id) {
                self.peer_edits.entry(id).or_insert(config);
            }
        }
    }
    fn collect_display_events(&mut self) {
        if self.source_stopped {
            return;
        }
        loop {
            match self.worker.poll() {
                Ok(Some(Event::Stamped { at, event })) => {
                    if let Event::DisplayGap(count) = event.as_ref() {
                        // This is a replay-integrity warning, not future network
                        // state. Surface lost observation counts even while paused.
                        self.playback.omitted += count;
                        continue;
                    }
                    if let Event::Finished { client_id, .. } = event.as_ref()
                        && self
                            .pending
                            .as_ref()
                            .is_some_and(|pending| pending.client_id == *client_id)
                    {
                        // Scheduling uses actual completion; presentation stays
                        // on the shared delayed clock until Run or Live catches up.
                        self.completion_waiting = true;
                    }
                    self.timeline.record(at, *event);
                }
                // Only explicit renderer/unit-test channels emit unstamped events.
                Ok(Some(event)) => self.apply_display_event(event),
                Ok(None) => break,
                Err(error) => {
                    self.source_stopped = true;
                    self.timeline
                        .record(std::time::Instant::now(), Event::Stopped(error));
                    break;
                }
            }
            // Bound optional history without changing the chosen time position.
            // Every accepted result/control completion stays in timestamp order.
            self.playback.omitted += self.timeline.trim_optional(|event| {
                matches!(
                    event,
                    Event::Snapshot(_)
                        | Event::Catalog(_)
                        | Event::Network(_)
                        | Event::Peers(_)
                        | Event::Progress(_)
                )
            });
            self.playback.omitted += self
                .timeline
                .trim_optional(|event| matches!(event, Event::Traffic(_)));
        }
    }
    fn poll(&mut self) {
        self.collect_display_events();
        self.advance_display(std::time::Instant::now());
    }
    fn advance_display(&mut self, now: std::time::Instant) {
        self.timeline.advance(now, self.playback.speed);
        while let Some((at, event)) = self.timeline.pop_ready() {
            self.playback.set_position(at);
            self.apply_display_event(event);
        }
        self.playback.set_position(self.timeline.position());
    }
    fn display_is_behind(&self) -> bool {
        self.timeline.queued() > 0 || self.timeline.lag() > 0.05
    }
    fn display_queued(&self) -> usize {
        self.timeline.queued()
    }
    fn display_lag_seconds(&self) -> f64 {
        self.timeline.lag()
    }
    fn catch_up_display(&mut self) {
        self.collect_display_events();
        while let Some((at, event)) = self.timeline.pop_any() {
            self.playback.set_position(at);
            self.apply_display_event(event);
        }
        self.timeline.catch_up(std::time::Instant::now());
        self.playback.sync_live();
        self.playback.set_position(self.timeline.position());
    }
    fn sync_live(&mut self) {
        self.catch_up_display();
        self.playback.speed = 1.0;
    }
    fn apply_display_event(&mut self, event: Event) {
        match event {
            Event::Stamped { at, event } => self.timeline.record(at, *event),
            Event::DisplayGap(count) => self.playback.omitted += count,
            Event::Stopped(error) => {
                self.completion_waiting = false;
                self.pending = None;
                self.control_pending = None;
                self.worker_stopped = true;
                self.input_error = Some(error);
            }
            Event::Traffic(observation) => self.playback.observe_io(&observation),
            Event::Snapshot(snapshot) => {
                self.snapshot = Some(snapshot);
            }
            Event::Catalog(catalog) => {
                self.catalog = catalog;
                self.selected_table = self
                    .selected_table
                    .min(self.catalog.len().saturating_sub(1));
                if !self.catalog.is_empty() && self.sql == STARTUP_SQL {
                    self.select_catalog_table(self.selected_table);
                }
            }
            Event::Peers(peers) => {
                self.peer_inventory = peers;
            }
            Event::Network(net) => {
                for packet in &net.packets {
                    self.playback.observe(packet);
                }
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
            Event::Progress(message) => self.status = message,
            Event::ControlFinished { snapshot, outcome } => {
                let intent = self.control_pending.take();
                if matches!(intent, Some(Control::Repair)) {
                    self.snapshot = snapshot;
                    self.record_maintenance(outcome);
                    return;
                }
                if outcome.is_ok() {
                    self.snapshot = snapshot;
                    match (intent, &outcome) {
                        (Some(Control::Add { position }), Ok(Outcome::NodeAdded { id })) => {
                            self.graph_seeds.insert(*id, position);
                        }
                        (Some(Control::Profile(id)), _) => {
                            if let Some(config) = self.peer_config(id) {
                                self.peer_edits.insert(id, config);
                            }
                        }
                        (Some(Control::Delete(expected)), Ok(Outcome::NodeRemoved { id }))
                            if expected == *id =>
                        {
                            self.graph_seeds.remove(id);
                            self.close_node_tab(*id);
                        }
                        _ => {}
                    }
                } else if let Err(error) = outcome {
                    self.input_error = Some(error.to_string());
                }
            }
            Event::Finished {
                snapshot,
                outcome,
                elapsed_ms,
                client_id,
            } => {
                if !self
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.client_id == client_id)
                {
                    return;
                }
                let Some(pending) = self.pending.take() else {
                    return;
                };
                self.completion_waiting = false;
                let created = outcome.as_ref().is_ok_and(Outcome::created);
                let updated = outcome.as_ref().is_ok_and(Outcome::changed);
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
                }
                if pending.job == Job::Query {
                    self.result_tab = if matches!(
                        outcome.as_ref().ok().map(Outcome::terminal),
                        Some(Outcome::TypedSelected(_))
                    ) || matches!(
                        outcome.as_ref().ok().and_then(Outcome::query),
                        Some(
                            QueryOutcome::Aggregate { .. }
                                | QueryOutcome::Aggregated { .. }
                                | QueryOutcome::Count { .. }
                                | QueryOutcome::Sum { .. }
                                | QueryOutcome::Selected { .. }
                        )
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
                let (database, mut revision) = snapshot
                    .as_ref()
                    .map(|s| (s.name.clone(), s.revision))
                    .unwrap_or_default();
                if let Some(
                    Outcome::VerifiedQuery { version, .. } | Outcome::TableReady { version, .. },
                ) = outcome.as_ref().ok().map(Outcome::terminal)
                {
                    revision = version.height;
                }
                if let Some(Outcome::TypedSelected(selected)) =
                    outcome.as_ref().ok().map(Outcome::terminal)
                {
                    revision = selected.version.height;
                }
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
        }
    }
    fn record_maintenance(&mut self, outcome: Result<Outcome, fhe_playground::LabError>) {
        self.maintenance_status = match &outcome {
            Ok(Outcome::ReplicasRepaired { current, stale }) => {
                format!("Peer copy complete: {current} current / {stale} stale")
            }
            Err(error) => format!("Peer copy deferred/failed: {error}"),
            _ => "Peer copy complete".into(),
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
        self.advance_display(std::time::Instant::now());
        if self.playback.playing() || (self.playback.speed > 0.0 && self.display_queued() > 0) {
            ui.ctx().request_repaint();
        }
        self.navigation_shortcuts(ui.ctx());
        egui::Panel::bottom("status").frame(panel(6)).show(ui, |ui| {
            ui.horizontal(|ui| {
                if self.pending.is_some() { ui.spinner(); }
                ui.add(egui::Label::new(self.input_error.as_deref().unwrap_or(&self.status)).truncate());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new("TCP/TLS · local test network").small().color(MUTED)).on_hover_text("Independent peer processes verify encrypted computation proofs and the agreed version. This playground uses an easy work target and one confirmation; production resistance to attackers is not established.");
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
                    .exact_size(TAB_HEIGHT)
                    .resizable(false)
                    .show_separator_line(false)
                    .frame(egui::Frame::NONE.fill(EDITOR))
                    .show(ui, |ui| {
                        tab_strip(ui, |ui| {
                            for (tab, name) in [(Tab::Sql, "SQL"), (Tab::Data, "Data")] {
                                if view_tab(ui, name, self.tab == tab, false)
                                    .response
                                    .clicked()
                                {
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
                    if stop_button(ui, self.can_stop_query())
                        .on_hover_text("Stop SQL. Already confirmed changes stay committed.")
                        .on_disabled_hover_text("No running SQL to stop")
                        .clicked()
                    {
                        self.stop_query();
                    }
                    self.client_selector(ui);
                    ui.menu_button("Presets", |ui| {
                        ui.spacing_mut().item_spacing.y = 3.0;
                        ui.spacing_mut().interact_size.y = 24.0;
                        if !self.catalog.is_empty() {
                            self.catalog_presets(ui);
                        } else {
                            let mut group = None;
                            for preset in PRESETS {
                                if group != Some(preset.group) {
                                    if group.is_some() {
                                        ui.separator();
                                    }
                                    ui.label(
                                        RichText::new(preset.group.label()).small().color(MUTED),
                                    );
                                    group = Some(preset.group);
                                }
                                if ui.button(preset.name).on_hover_text(preset.sql).clicked() {
                                    self.insert_preset(preset.sql);
                                    ui.close();
                                }
                            }
                        }
                    });
                });
                self.database_bar(ui);
                if let Some(reason) = self.run_disabled_reason() {
                    ui.label(RichText::new(reason).small().color(MUTED));
                }
            });
        let workspace_height = ui.available_height();
        let min_results = 120.0_f32.min(workspace_height * 0.5);
        egui::Panel::bottom("query-results")
            .default_size(ui.ctx().content_rect().height() * 0.5)
            .size_range(min_results..=(workspace_height - 80.0).max(min_results))
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
        if self.worker_stopped || self.source_stopped {
            Some("Worker stopped")
        } else if self.pending.is_some() && !self.completion_waiting {
            Some("Operation running…")
        } else if self.control_pending.is_some() {
            Some("Applying network changes…")
        } else if self.completion_waiting && !self.source_stopped {
            None
        } else if self.active_client.is_none() {
            Some("Add a client from the Network context menu")
        } else if !self.can_query() {
            Some("The selected client is offline")
        } else {
            None
        }
    }
    fn results(&mut self, ui: &mut egui::Ui) -> egui::scroll_area::ScrollAreaOutput<()> {
        tab_strip(ui, |ui| {
            if view_tab(ui, "Result", self.result_tab == ResultTab::Result, false)
                .response
                .clicked()
            {
                self.result_tab = ResultTab::Result;
            }
            if view_tab(ui, "Output", self.result_tab == ResultTab::Output, false)
                .response
                .clicked()
            {
                self.result_tab = ResultTab::Output;
            }
            if let Some(record) = self.history.iter().find(|record| record.job == Job::Query) {
                ui.allocate_ui_with_layout(
                    egui::vec2(ui.available_width(), TAB_HEIGHT),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        ui.add_space(12.0);
                        ui.add(
                            egui::Label::new(
                                RichText::new(format!(
                                    "{} / v{} / {:.0} ms",
                                    record.database, record.revision, record.elapsed_ms
                                ))
                                .small()
                                .color(MUTED),
                            )
                            .truncate(),
                        )
                        .on_hover_text(&record.label);
                    },
                );
            }
        });
        egui::ScrollArea::both()
            .id_salt("result-body")
            .auto_shrink([false, false])
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
                    if let Some(Outcome::TypedSelected(selected)) = record.outcome.as_ref().ok().map(Outcome::terminal) {
                        ui.label(RichText::new(format!("Encrypted SELECT · verified · v{} · {} proof blocks", selected.version.height, selected.proof_blocks)).small().color(GREEN))
                            .on_hover_text("The client checked every FHE projection proof, complete authenticated indexed selection and a confirmed agreed head before accepting this result. This local playground uses the explicit test work profile.");
                        typed_result_table(ui, &selected.columns, &selected.rows);
                        ui.label(RichText::new(format!("{} rows", selected.rows.len())).small().color(MUTED));
                        return;
                    }
                    match record.outcome.as_ref().ok().and_then(Outcome::query) {
                        Some(QueryOutcome::Aggregated { columns, values }) => {
                            if let Some(Outcome::VerifiedQuery { version, .. }) = record.outcome.as_ref().ok().map(Outcome::terminal) {
                                ui.label(RichText::new(format!("Encrypted aggregate · verified · v{}", version.height)).small().color(GREEN));
                            }
                            let headings: Vec<_> = columns.iter().map(String::as_str).collect();
                            let cells: Vec<_> = values.iter().map(|value| value.map_or_else(|| "NULL".into(), |value| value.to_string())).collect();
                            result_table(ui, &headings, &[cells]);
                        }
                        Some(QueryOutcome::Aggregate { count, sum, .. }) => {
                            result_table(ui, &["COUNT(*)", "SUM(amount)"], &[vec![*count, *sum]]);
                        }
                        Some(QueryOutcome::Count { count, .. }) => {
                            result_table(ui, &["COUNT(*)"], &[vec![*count]]);
                        }
                        Some(QueryOutcome::Sum { sum, .. }) => {
                            result_table(ui, &["SUM(amount)"], &[vec![*sum]]);
                        }
                        Some(QueryOutcome::Selected { columns, rows }) => {
                            if let Some(Outcome::VerifiedQuery { version, .. }) = record.outcome.as_ref().ok().map(Outcome::terminal) {
                                ui.label(RichText::new(format!("Encrypted SELECT · verified · v{}", version.height)).small().color(GREEN))
                                    .on_hover_text("The client checked the FHE computation/completeness proof and a confirmed agreed version before decrypting. Confirmation uses the explicit local test work profile; production attack resistance is unvalidated.");
                            } else {
                                ui.label(RichText::new("Encrypted SELECT · unverified").small().color(MUTED))
                                    .on_hover_text("Historical local or public renderer-fixture output; no network computation proof or agreed-version acceptance is claimed.");
                            }
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
            })
    }
}

fn result_table(ui: &mut egui::Ui, columns: &[&str], rows: &[Vec<impl std::fmt::Display>]) {
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

fn typed_result_table(ui: &mut egui::Ui, columns: &[String], rows: &[relational_types::Row]) {
    egui::Grid::new("typed-query-result-table")
        .striped(true)
        .min_col_width(90.0)
        .max_col_width(260.0)
        .show(ui, |ui| {
            ui.label(RichText::new("#").strong().color(MUTED));
            for column in columns {
                ui.label(RichText::new(column).strong());
            }
            ui.end_row();
            for (index, row) in rows.iter().enumerate() {
                ui.label(RichText::new((index + 1).to_string()).color(MUTED));
                for value in row {
                    let text = match value {
                        Value::Binary(bytes) => format!("BINARY · {} bytes", bytes.len()),
                        _ => value.to_string(),
                    };
                    ui.add(
                        egui::Label::new(RichText::new(text).monospace().color(
                            if matches!(value, Value::Null) {
                                MUTED
                            } else {
                                TEXT
                            },
                        ))
                        .truncate(),
                    );
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
        Ok(outcome) => outcome_summary(outcome),
    }
}
fn outcome_summary(outcome: &Outcome) -> (String, Color32) {
    if let Outcome::TypedSelected(selected) = outcome.terminal() {
        return (
            format!(
                "Selected {} rows · confirmed v{} · {} proof blocks",
                selected.rows.len(),
                selected.version.height,
                selected.proof_blocks
            ),
            GREEN,
        );
    }
    if let Outcome::Script {
        completed, last, ..
    } = outcome
    {
        let (message, color) = outcome_summary(last);
        return (
            format!("{completed} operations completed · {message}"),
            color,
        );
    }
    match outcome.query() {
        Some(QueryOutcome::Aggregated { .. }) => {
            if let Outcome::VerifiedQuery { version, .. } = outcome.terminal() {
                (
                    format!("Aggregate verified · confirmed v{}", version.height),
                    GREEN,
                )
            } else {
                ("Aggregate result · unverified".into(), MUTED)
            }
        }
        Some(QueryOutcome::Updated { committed: false }) => {
            ("Rejected: amount overflow; no changes".into(), AMBER)
        }
        Some(QueryOutcome::Updated { committed: true }) => {
            let message = if let Outcome::VerifiedQuery {
                changed_rows: Some(count),
                version,
                ..
            } = outcome.terminal()
            {
                format!("Updated {count} rows · confirmed v{}", version.height)
            } else {
                "Updated".into()
            };
            (message, GREEN)
        }
        Some(QueryOutcome::Inserted { count }) => {
            let mut message = format!("Inserted {count} row{}", if *count == 1 { "" } else { "s" });
            if let Outcome::VerifiedQuery { version, .. } = outcome.terminal() {
                message.push_str(&format!(" · confirmed v{}", version.height));
            }
            (message, GREEN)
        }
        Some(QueryOutcome::Selected { rows, .. }) => {
            let mut message = format!(
                "Selected {} row{}",
                rows.len(),
                if rows.len() == 1 { "" } else { "s" }
            );
            if let Outcome::VerifiedQuery { version, .. } = outcome.terminal() {
                message.push_str(&format!(" · confirmed v{}", version.height));
            }
            (message, GREEN)
        }
        _ => match outcome.terminal() {
            Outcome::TableReady { created, version } => (
                format!(
                    "Table records {} · v{}",
                    if *created {
                        "created"
                    } else {
                        "already exists"
                    },
                    version.height
                ),
                GREEN,
            ),
            Outcome::Created => ("Encrypted database created".into(), GREEN),
            _ => ("OK".into(), TEXT),
        },
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
            | "BETWEEN" | "AND" | "LIMIT" | "CREATE" | "TABLE" | "IF" | "NOT" | "EXISTS"
            | "NULL" | "UNSIGNED" | "TINYINT" | "SMALLINT" => Color32::from_rgb(207, 142, 109),
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

#[cfg(test)]
#[path = "timeline_tests.rs"]
mod timeline_tests;

#[cfg(test)]
mod peer_inventory_tests;

#[cfg(test)]
#[path = "ui/typed_catalog_tests.rs"]
mod typed_catalog_tests;
