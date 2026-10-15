use super::*;
use crate::graph_layout::{self, LayoutEdge, LayoutNode, Point, Size};
use fhe_playground::{NetworkNode, PacketKind};

pub(super) enum GraphAction {
    Open(NodeId),
    Client(NodeId),
    Delete(NodeId),
    Toggle { peer: usize, online: bool },
    AddPeer(egui::Pos2),
    AddClient(egui::Pos2),
    Repair,
    Fit,
}
const NODE_SIZE: egui::Vec2 = egui::vec2(224.0, 132.0);

impl Playground {
    pub(super) fn infrastructure(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("network-header")
            .frame(panel(10))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    if view_tab(ui, "Network", self.right_tab == RightTab::Network, false)
                        .response
                        .clicked()
                    {
                        self.navigate(self.tab, RightTab::Network);
                    }
                    if view_tab(ui, "Settings", self.right_tab == RightTab::Settings, false)
                        .response
                        .clicked()
                    {
                        self.navigate(self.tab, RightTab::Settings);
                    }
                    egui::ScrollArea::horizontal()
                        .id_salt("inspector-tabs")
                        .auto_shrink([false, true])
                        .stick_to_right(true)
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                let mut close = None;
                                for id in self.node_tabs.clone() {
                                    let label = self.node_name(id);
                                    ui.push_id(id, |ui| {
                                        let tab = view_tab(
                                            ui,
                                            &label,
                                            self.right_tab == RightTab::Node(id),
                                            true,
                                        );
                                        if tab.close {
                                            close = Some(id);
                                        } else if tab.response.clicked() {
                                            self.navigate(self.tab, RightTab::Node(id));
                                        }
                                    });
                                }
                                if let Some(id) = close {
                                    self.close_node_tab(id);
                                }
                            })
                        });
                });
            });
        match self.right_tab {
            RightTab::Network => {
                egui::Panel::top("simulation-controls").frame(panel(10)).show(ui,|ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label("Speed").on_hover_text("Virtual message time. FHE CPU computation retains its real duration.");
                        let speed_changed=ui.add(egui::DragValue::new(&mut self.simulation_speed).range(0.1..=8.0).speed(0.1).suffix("x")).changed();
                        let paused_changed=action_button(ui,if self.simulation_paused {"Resume"}else{"Pause"},!self.worker_stopped).clicked();
                        if paused_changed {self.simulation_paused = !self.simulation_paused;}
                        if (speed_changed||paused_changed) && let Err(error)=self.worker.send(Command::SetSimulation {speed:self.simulation_speed,paused:self.simulation_paused}) {self.input_error=Some(error);}
                        if let Some(net)=&self.network {
                            ui.label(RichText::new(format!("{} nodes / {} links",net.nodes.len(),net.links.len())).small().color(MUTED));
                        }
                        self.replication_summary(ui);
                        ui.separator();
                        for (view,label) in [(NetworkView::Auto,"Auto"),(NetworkView::Map,"Map"),(NetworkView::Matrix,"Matrix")] {
                            if tab_button(ui,label,self.network_view==view).on_hover_text(match view {
                                NetworkView::Auto=>"Uses the matrix for dense networks. Every connection stays visible.",
                                NetworkView::Map=>"Spatial map of all connections and actual traffic.",
                                NetworkView::Matrix=>"Every connection in a cell. Rows send; columns receive.",
                            }).clicked() {self.network_view=view;}
                        }
                        if self.network_view==NetworkView::Auto {ui.add(egui::Label::new(RichText::new(if self.uses_matrix(){"Matrix"}else{"Map"}).small().color(MUTED)).wrap_mode(egui::TextWrapMode::Extend));}
                    });
                });
                egui::CentralPanel::default()
                    .frame(egui::Frame::new().fill(EDITOR).inner_margin(10))
                    .show(ui, |ui| {
                        if self.uses_matrix() {
                            self.network_matrix(ui);
                        } else {
                            self.network_graph(ui);
                        }
                    });
            }
            RightTab::Settings => {
                egui::CentralPanel::default().frame(panel(16)).show(ui, |ui| {
                    egui::ScrollArea::vertical().auto_shrink([false,false]).show(ui, |ui| {
                        ui.heading("Network settings");
                        ui.label(RichText::new("Local prototype policy").small().color(AMBER));
                        ui.add_space(14.0);
                        ui.label("Copies per logical shard");
                        self.replication_controls(ui);
                        ui.add_space(12.0);
                        ui.label(RichText::new("Changes apply to this local experiment. A signed, agreed network-policy contract is still being designed.").color(MUTED));
                    });
                });
            }
            RightTab::Node(id) => {
                egui::CentralPanel::default()
                    .frame(panel(16))
                    .show(ui, |ui| {
                        egui::ScrollArea::vertical()
                            .id_salt(("node-inspector", id))
                            .show(ui, |ui| self.node_inspector(ui, id));
                    });
            }
        }
    }
    fn replication_controls(&mut self, ui: &mut egui::Ui) {
        let Some(mut copies) = self
            .snapshot
            .as_ref()
            .and_then(|state| state.replication.as_ref())
            .map(|replication| replication.desired_copies)
        else {
            ui.add_enabled(false, egui::Button::new("Storage state unavailable"));
            return;
        };
        let previous = copies;
        ui.add_enabled_ui(self.available() && self.controls_available() && self.snapshot.is_some(), |ui| {
            egui::ComboBox::from_id_salt("minimum-copies")
                .selected_text(format!("Min copies {copies}"))
                .width(110.0)
                .show_ui(ui, |ui| {
                    for count in 1..=3 { ui.selectable_value(&mut copies, count, if count == 1 { "1 copy".into() } else { format!("{count} copies") }); }
                }).response.on_hover_text("Minimum current copies in distinct configured failure domains; extra/stale copies remain charged. Logical shards retain their custody through topology changes. New placement is local repair after peer discovery; pause defers copies.");
        });
        if copies != previous {
            self.control(Command::SetReplication { copies }, Control::Replication);
        }
        self.replication_summary(ui);
    }
    fn replication_summary(&self, ui: &mut egui::Ui) {
        if let Some(state) = &self.snapshot {
            let stored: usize = state.peers.iter().map(|peer| peer.stored_bytes).sum();
            let label = if let Some(replication) = &state.replication {
                let at_target = replication
                    .shards
                    .iter()
                    .filter(|shard| {
                        let domains: std::collections::BTreeSet<_> = shard
                            .replicas
                            .iter()
                            .filter(|copy| copy.current && copy.online)
                            .map(|copy| copy.failure_domain)
                            .collect();
                        domains.len() >= replication.desired_copies
                    })
                    .count();
                let online_current = replication
                    .shards
                    .iter()
                    .flat_map(|shard| &shard.replicas)
                    .filter(|copy| copy.current && copy.online)
                    .count();
                let stale = replication
                    .shards
                    .iter()
                    .flat_map(|shard| &shard.replicas)
                    .filter(|copy| !copy.current)
                    .count();
                format!(
                    "{at_target}/{} at target · {online_current} online current / {stale} stale · {} stored",
                    replication.shards.len(),
                    bytes(stored)
                )
            } else {
                "Storage state unavailable".to_string()
            };
            ui.label(RichText::new(label).small().color(MUTED)).on_hover_text("Actual retained data+index ciphertext and replica-record metadata. Shared evaluation keys, owner state and transient memory are additional. Target counts configured independent domains, not a production availability guarantee.");
            if let Some(replication) = &state.replication
                && !replication.unavailable_shards.is_empty()
            {
                ui.colored_label(
                    RED,
                    format!(
                        "{} logical shards unavailable",
                        replication.unavailable_shards.len()
                    ),
                );
            }
        }
        if !self.maintenance_status.is_empty() {
            ui.label(RichText::new(&self.maintenance_status).small().color(MUTED)).on_hover_text("Completed local owner/manager copy work, not simulated ciphertext-transfer bytes. Repair waits for idle, unpaused simulation and real established peer routes. Right-click to retry.");
        }
    }
    fn node_inspector(&mut self, ui: &mut egui::Ui, id: NodeId) {
        let node = self
            .network
            .as_ref()
            .and_then(|n| n.nodes.iter().find(|n| n.id == id))
            .cloned();
        let Some(node) = node else {
            ui.label("Node removed");
            return;
        };
        ui.horizontal_wrapped(|ui| {
            ui.heading(&node.name);
            badge(
                ui,
                if node.role == NodeRole::Client {
                    "Client"
                } else {
                    "Peer"
                },
                if node.role == NodeRole::Client {
                    ACCENT
                } else {
                    GREEN
                },
            );
            badge(
                ui,
                if node.online { "Online" } else { "Offline" },
                if node.online { GREEN } else { RED },
            );
        });
        ui.label(RichText::new(format!("Node ID {id}")).small().color(MUTED));
        if node.role == NodeRole::Client {
            section(ui, "Session");
            ui.label("Authorized local client of the same database owner.");
            if primary_button(ui, "Use this client", node.online).clicked() {
                self.active_client = Some(id);
                self.navigate(Tab::Sql, self.right_tab);
            }
            if let Some(state) = &self.snapshot {
                ui.label(format!(
                    "{} / {} rows / v{}",
                    state.name,
                    state.owner_rows.len(),
                    state.revision
                ));
            }
        } else if let Some(peer_id) = node.peer_id {
            let peer = self
                .snapshot
                .as_ref()
                .and_then(|s| s.peers.iter().find(|p| p.id == peer_id))
                .cloned();
            if let Some(peer) = peer {
                section(ui, "Settings");
                let enabled = self.controls_available();
                let config = self
                    .peer_edits
                    .entry(id)
                    .or_insert_with(|| peer.config.clone());
                ui.add_enabled_ui(enabled, |ui| {
                    ui.label("Name");
                    ui.add(
                        egui::TextEdit::singleline(&mut config.name)
                            .id(egui::Id::new(("peer-name", id)))
                            .char_limit(48)
                            .desired_width(250.0),
                    );
                    ui.horizontal_wrapped(|ui| {
                        ui.label("Storage quota");
                        let mut kib = config.storage_limit_bytes / 1024;
                        if ui
                            .add(
                                egui::DragValue::new(&mut kib)
                                    .range(1..=65_536)
                                    .speed(64)
                                    .suffix(" KiB"),
                            )
                            .changed()
                        {
                            config.storage_limit_bytes = kib * 1024;
                        }
                        ui.label("Link delay");
                        ui.add(
                            egui::DragValue::new(&mut config.delay_ms)
                                .range(0..=1000)
                                .suffix(" ms"),
                        );
                    });
                });
                let modified = *config != peer.config;
                if primary_button(ui, "Save settings", enabled && modified).clicked() {
                    let config = self.peer_edits[&id].clone();
                    self.control(
                        Command::ConfigurePeer {
                            id: peer_id,
                            config,
                        },
                        Control::Profile(id),
                    );
                }
                let domain = self
                    .snapshot
                    .as_ref()
                    .and_then(|state| state.replication.as_ref())
                    .and_then(|replication| {
                        replication
                            .failure_domains
                            .iter()
                            .find(|(id, _)| *id == peer_id)
                    })
                    .map_or(peer_id as u64, |(_, domain)| *domain);
                let edited = self.domain_edits.entry(id).or_insert(domain);
                let domain_enabled = enabled
                    && self
                        .snapshot
                        .as_ref()
                        .is_some_and(|state| state.replication.is_some());
                ui.horizontal_wrapped(|ui| {
                    ui.label("Failure domain").on_hover_text("Owner-configured correlated-failure label; not an authenticated machine identity.");
                    ui.add_enabled(domain_enabled, egui::DragValue::new(edited).range(0..=u64::MAX));
                });
                let edited = *edited;
                if action_button(ui, "Save domain", domain_enabled && edited != domain).clicked() {
                    self.control(
                        Command::SetFailureDomain {
                            id: peer_id,
                            domain: edited,
                        },
                        Control::Domain(id),
                    );
                }
                section(ui, "Encrypted shard");
                ui.label(format!(
                    "{} rows / {} stored of {} quota",
                    peer.rows,
                    bytes(peer.stored_bytes),
                    bytes(peer.config.storage_limit_bytes)
                ));
                ui.add(
                    egui::ProgressBar::new(
                        peer.stored_bytes as f32 / peer.config.storage_limit_bytes as f32,
                    )
                    .fill(ACCENT)
                    .desired_height(5.0),
                );
                ui.label(
                    RichText::new(format!("Data {}  ·  Index {}", bytes(peer.data_bytes), bytes(peer.index_bytes)))
                        .small().color(MUTED),
                ).on_hover_text("Canonical encrypted data includes page authentication metadata. The index is counted separately. Shared evaluation keys and transient FHE memory are additional.");
                ui.label(RichText::new(format!("Logical payload {} B / {} stored {}",peer.logical_bytes,peer.rows,row_word(peer.rows))).small().color(MUTED))
                    .on_hover_text("Actual plaintext-size payload represented by all physical stored copies, including older stale copies; it is not unique current database coverage.");
                if let Some(replication) = self
                    .snapshot
                    .as_ref()
                    .and_then(|state| state.replication.as_ref())
                {
                    for shard in &replication.shards {
                        for copy in shard.replicas.iter().filter(|copy| copy.peer_id == peer_id) {
                            ui.label(format!(
                                "Shard {} · {} / {} · {} data + {} index · expected heads v{}/v{}",
                                shard.id,
                                if copy.current { "current" } else { "stale" },
                                if copy.online { "online" } else { "offline" },
                                bytes(copy.data_bytes),
                                bytes(copy.index_bytes),
                                shard.data_head.revision(),
                                shard.index_head.revision()
                            ));
                        }
                    }
                    ui.label(RichText::new("Repair copies authenticated ciphertext locally after discovery; it does not reseal the owner's rows.").small().color(MUTED));
                }
                section(ui, "Rows / owner view");
                ui.label(
                    RichText::new(
                        "Current owner fixture. Peers hold ciphertexts; stale copies may contain earlier values.",
                    )
                    .small()
                    .color(MUTED),
                );
                if let Some(state) = &self.snapshot {
                    egui::Grid::new(("shard-rows", id))
                        .striped(true)
                        .min_col_width(90.0)
                        .show(ui, |ui| {
                            for name in ["Row", "age", "amount"] {
                                ui.label(RichText::new(name).color(MUTED));
                            }
                            ui.end_row();
                            for index in &peer.owner_row_indices {
                                if let Some(row) = state.owner_rows.get(*index) {
                                    ui.monospace((index + 1).to_string());
                                    ui.monospace(row.age.to_string());
                                    ui.monospace(row.amount.to_string());
                                    ui.end_row();
                                }
                            }
                        });
                }
            }
        }
        section(ui, "Connections");
        if let Some(net) = &self.network {
            let adjacent: Vec<_> = net
                .links
                .iter()
                .filter_map(|l| {
                    if l.from == id {
                        Some(l.to)
                    } else if l.to == id {
                        Some(l.from)
                    } else {
                        None
                    }
                })
                .collect();
            if adjacent.is_empty() {
                ui.label(RichText::new("No established connections.").color(MUTED));
            }
            for neighbor in adjacent {
                ui.label(self.node_name(neighbor));
            }
        }
    }
    fn network_graph(&mut self, ui: &mut egui::Ui) {
        let (canvas, response) = ui.allocate_exact_size(
            ui.available_size().max(egui::vec2(100.0, 100.0)),
            egui::Sense::click_and_drag(),
        );
        let resized = self
            .last_graph_canvas
            .is_none_or(|previous| previous.size() != canvas.size());
        self.last_graph_canvas = Some(canvas);
        let side_button_down = ui.input(|input| {
            input.pointer.button_down(egui::PointerButton::Extra1)
                || input.pointer.button_down(egui::PointerButton::Extra2)
        });
        if !side_button_down
            && (response.dragged_by(egui::PointerButton::Primary)
                || response.dragged_by(egui::PointerButton::Secondary)
                || response.dragged_by(egui::PointerButton::Middle))
        {
            self.camera.pan(response.drag_delta());
            self.camera_manipulated = true;
        }
        let pointer = ui.input(|i| i.pointer.hover_pos());
        if pointer.is_some_and(|p| canvas.contains(p)) {
            let scroll = ui.input_mut(|i| {
                let delta = i.smooth_scroll_delta.y;
                i.smooth_scroll_delta.y = 0.0;
                delta
            });
            if scroll != 0.0 {
                self.camera_manipulated = true;
                self.camera
                    .zoom_at(canvas, pointer.unwrap(), (scroll * 0.002).exp());
            }
        }
        let Some(net) = self.network.clone() else {
            ui.painter().text(
                canvas.center(),
                egui::Align2::CENTER_CENTER,
                "Starting network...",
                FontId::proportional(14.0),
                MUTED,
            );
            return;
        };
        let nodes: Vec<_> = net
            .nodes
            .iter()
            .map(|node| LayoutNode {
                id: node.id,
                role: if node.role == NodeRole::Client {
                    graph_layout::NodeRole::Client
                } else {
                    graph_layout::NodeRole::Peer
                },
                size: Size {
                    width: NODE_SIZE.x,
                    height: NODE_SIZE.y,
                },
                position: self
                    .graph_seeds
                    .get(&node.id)
                    .map(|p| Point { x: p.x, y: p.y }),
            })
            .collect();
        let edges: Vec<_> = net
            .links
            .iter()
            .map(|l| LayoutEdge {
                from: l.from,
                to: l.to,
            })
            .collect();
        let changed = self.graph_layout.sync(&nodes, &edges);
        let initialize = !self.graph_initialized && !nodes.is_empty();
        if initialize {
            self.graph_layout.settle();
        }
        let moving = self.graph_layout.step(3);
        if moving {
            ui.ctx().request_repaint();
        }
        let route_nodes: Vec<_> = net
            .nodes
            .iter()
            .filter_map(|node| {
                self.graph_layout
                    .position(node.id)
                    .map(|center| crate::graph_routing::RouteNode {
                        id: node.id,
                        center,
                        size: Size {
                            width: NODE_SIZE.x,
                            height: NODE_SIZE.y,
                        },
                    })
            })
            .collect();
        self.graph_router.sync(&route_nodes);
        self.graph_bundler.sync(&route_nodes, &edges);
        if initialize || (!self.camera_manipulated && (changed || moving || resized)) {
            self.fit_graph(canvas);
            self.graph_initialized = true;
        }
        let p = ui.painter().with_clip_rect(canvas);
        p.rect_filled(canvas, 8, EDITOR);
        for point in self.camera.grid_points(canvas) {
            p.circle_filled(point, 0.9, BORDER.gamma_multiply(0.65));
        }
        let boxes: HashMap<_, _> = net
            .nodes
            .iter()
            .filter_map(|n| {
                self.graph_layout.position(n.id).map(|pos| {
                    let center = self
                        .camera
                        .world_to_screen(canvas, egui::pos2(pos.x, pos.y));
                    (
                        n.id,
                        egui::Rect::from_center_size(center, NODE_SIZE * self.camera.zoom),
                    )
                })
            })
            .collect();
        // Hover/selection adds individual paths; the full underlying edge set
        // remains present in the shared lanes or, for sparse graphs, normal paths.
        let focused = pointer
            .and_then(|pos| {
                boxes
                    .iter()
                    .find_map(|(id, rect)| rect.contains(pos).then_some(*id))
            })
            .or(self.selected_node);
        for link in &net.links {
            let route = if self.graph_layout.is_dense() {
                self.graph_bundler.route(link.from, link.to)
            } else {
                self.graph_router.route(link.from, link.to)
            };
            let route = if route.len() < 2 {
                self.visible_route(link.from, link.to, &route_nodes)
            } else {
                route
            };
            let screen: Vec<_> = route
                .iter()
                .map(|p| self.camera.world_to_screen(canvas, egui::pos2(p.x, p.y)))
                .collect();
            if screen.len() >= 2 {
                p.add(egui::Shape::line(
                    screen,
                    Stroke::new(1.1, Color32::from_rgb(65, 85, 108)),
                ));
            }
        }
        if self.graph_layout.is_dense()
            && let Some(id) = focused
        {
            for link in net
                .links
                .iter()
                .filter(|link| link.from == id || link.to == id)
            {
                let route = self.visible_route(link.from, link.to, &route_nodes);
                let screen: Vec<_> = route
                    .iter()
                    .map(|p| self.camera.world_to_screen(canvas, egui::pos2(p.x, p.y)))
                    .collect();
                if screen.len() >= 2 {
                    p.add(egui::Shape::line(
                        screen,
                        Stroke::new(1.2, ACCENT.gamma_multiply(0.6)),
                    ));
                }
            }
        }
        for packet in &net.packets {
            let route = self.visible_route(packet.from, packet.to, &route_nodes);
            let screen: Vec<_> = route
                .iter()
                .map(|p| self.camera.world_to_screen(canvas, egui::pos2(p.x, p.y)))
                .collect();
            if let Some(point) = point_on_route(&screen, packet.progress) {
                let color = packet_color(packet.kind);
                p.add(egui::Shape::line(
                    screen,
                    Stroke::new(1.0, color.gamma_multiply(0.25)),
                ));
                p.circle_filled(point, 8.0, color.gamma_multiply(0.12));
                p.circle_filled(point, 3.5, color);
                ui.interact(
                    egui::Rect::from_center_size(point, egui::Vec2::splat(14.0)),
                    ui.id().with(("packet", packet.id)),
                    egui::Sense::hover(),
                )
                .on_hover_text(format!(
                    "{:?} #{} · {} -> {} · {:.0}%",
                    packet.kind,
                    packet.id,
                    self.node_name(packet.from),
                    self.node_name(packet.to),
                    packet.progress * 100.0
                ));
            }
        }
        let mut action = None;
        let mut over_node = false;
        for node in &net.nodes {
            let Some(rect) = boxes.get(&node.id).copied() else {
                continue;
            };
            if !rect.intersects(canvas) {
                continue;
            }
            let hit = ui
                .interact(
                    rect.intersect(canvas),
                    ui.id().with(("node", node.id)),
                    egui::Sense::click(),
                )
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .on_hover_text(storage_tooltip(node, self.snapshot.as_ref()));
            if pointer.is_some_and(|pos| rect.contains(pos)) {
                over_node = true;
            }
            let selected =
                self.selected_node == Some(node.id) || self.active_client == Some(node.id);
            let visuals = control_visuals(ui, &hit, selected);
            draw_node(
                &p,
                rect,
                node,
                self.snapshot.as_ref(),
                net.links
                    .iter()
                    .any(|l| l.from == node.id || l.to == node.id),
                visuals,
                self.camera.zoom,
            );
            if hit.clicked() {
                self.selected_node = Some(node.id);
                if node.role == NodeRole::Client {
                    self.active_client = Some(node.id);
                }
            }
            if hit.double_clicked() {
                action = Some(GraphAction::Open(node.id));
            }
            hit.context_menu(|ui| self.node_context_menu(ui, node, &mut action));
        }
        if !over_node || response.context_menu_opened() {
            if response.secondary_clicked()
                && let Some(pos) = pointer
            {
                self.context_position = self.camera.screen_to_world(canvas, pos);
            }
            let at = self.context_position;
            response.context_menu(|ui| self.canvas_context_menu(ui, &net, at, &mut action, true));
            if response.double_clicked() {
                action = Some(GraphAction::Fit);
            }
        }
        p.text(
            canvas.left_top() + egui::vec2(12.0, 12.0),
            egui::Align2::LEFT_TOP,
            if self.graph_layout.is_dense() {
                "Shared lanes · select a node for individual links · Matrix shows every pair"
            } else {
                "Right-click to add / double-click a node to inspect"
            },
            FontId::proportional(11.0),
            MUTED,
        );
        if net.nodes.is_empty() {
            p.text(
                canvas.center(),
                egui::Align2::CENTER_CENTER,
                "Right-click to add a client or peer",
                FontId::proportional(16.0),
                MUTED,
            );
        }
        if !net.packets.is_empty() {
            ui.ctx().request_repaint();
        }
        if let Some(action) = action {
            self.graph_action(action, canvas);
        }
    }
    fn fit_graph(&mut self, canvas: egui::Rect) {
        let route_nodes: Vec<_> = self
            .graph_layout
            .positions()
            .into_iter()
            .map(|(id, center)| crate::graph_routing::RouteNode {
                id,
                center,
                size: Size {
                    width: NODE_SIZE.x,
                    height: NODE_SIZE.y,
                },
            })
            .collect();
        let edges: Vec<_> = self.network.as_ref().map_or(Vec::new(), |net| {
            net.links
                .iter()
                .map(|link| LayoutEdge {
                    from: link.from,
                    to: link.to,
                })
                .collect()
        });
        self.graph_bundler.sync(&route_nodes, &edges);
        let mut bounds = egui::Rect::NOTHING;
        for (_, pos) in self.graph_layout.positions() {
            bounds = bounds.union(egui::Rect::from_center_size(
                egui::pos2(pos.x, pos.y),
                NODE_SIZE,
            ));
        }
        if self.graph_layout.is_dense()
            && let Some((min, max)) = self.graph_bundler.bounds()
        {
            bounds = bounds.union(egui::Rect::from_min_max(
                egui::pos2(min.x, min.y),
                egui::pos2(max.x, max.y),
            ));
        }
        if bounds.is_positive() {
            self.camera.fit(canvas, bounds);
        }
    }
    fn visible_route(
        &mut self,
        from: NodeId,
        to: NodeId,
        nodes: &[crate::graph_routing::RouteNode],
    ) -> Vec<Point> {
        let route = self.graph_router.route(from, to);
        if route.len() >= 2 {
            return route;
        }
        // A geometric failure must never erase a real connection or packet.
        let Some(a) = nodes.iter().find(|node| node.id == from) else {
            return Vec::new();
        };
        let Some(b) = nodes.iter().find(|node| node.id == to) else {
            return Vec::new();
        };
        let port = |node: &crate::graph_routing::RouteNode, other: Point| {
            let dx = other.x - node.center.x;
            let dy = other.y - node.center.y;
            let ratio = (dx.abs() / (node.size.width * 0.5))
                .max(dy.abs() / (node.size.height * 0.5))
                .max(0.001);
            Point {
                x: node.center.x + dx / ratio,
                y: node.center.y + dy / ratio,
            }
        };
        vec![port(a, b.center), port(b, a.center)]
    }
    pub(super) fn node_context_menu(
        &self,
        ui: &mut egui::Ui,
        node: &NetworkNode,
        action: &mut Option<GraphAction>,
    ) {
        if ui.button("Open node").clicked() {
            *action = Some(GraphAction::Open(node.id));
            ui.close();
        }
        if node.role == NodeRole::Client && ui.button("Use client").clicked() {
            *action = Some(GraphAction::Client(node.id));
            ui.close();
        }
        if let Some(peer) = node.peer_id
            && ui
                .add_enabled(
                    self.controls_available(),
                    egui::Button::new(if node.online {
                        "Take offline"
                    } else {
                        "Bring online"
                    }),
                )
                .clicked()
        {
            *action = Some(GraphAction::Toggle {
                peer,
                online: !node.online,
            });
            ui.close();
        }
        ui.separator();
        if ui
            .add_enabled(
                self.controls_available()
                    && self.available()
                    && self
                        .snapshot
                        .as_ref()
                        .is_some_and(|state| state.replication.is_some()),
                egui::Button::new("Repair replicas"),
            )
            .clicked()
        {
            *action = Some(GraphAction::Repair);
            ui.close();
        }
        if ui
            .add_enabled(self.controls_available(), egui::Button::new("Delete node"))
            .clicked()
        {
            *action = Some(GraphAction::Delete(node.id));
            ui.close();
        }
    }
    pub(super) fn canvas_context_menu(
        &self,
        ui: &mut egui::Ui,
        net: &NetworkSnapshot,
        at: egui::Pos2,
        action: &mut Option<GraphAction>,
        fit: bool,
    ) {
        let peers = net
            .nodes
            .iter()
            .filter(|node| node.role == NodeRole::Peer)
            .count();
        let clients = net
            .nodes
            .iter()
            .filter(|node| node.role == NodeRole::Client)
            .count();
        if ui
            .add_enabled(
                self.controls_available() && peers < MAX_PEERS,
                egui::Button::new("Add peer"),
            )
            .clicked()
        {
            *action = Some(GraphAction::AddPeer(at));
            ui.close();
        }
        if ui
            .add_enabled(
                self.controls_available() && clients < fhe_playground::MAX_CLIENTS,
                egui::Button::new("Add client"),
            )
            .clicked()
        {
            *action = Some(GraphAction::AddClient(at));
            ui.close();
        }
        if fit {
            ui.separator();
            if ui.button("Fit view").clicked() {
                *action = Some(GraphAction::Fit);
                ui.close();
            }
        }
        if ui
            .add_enabled(
                self.controls_available()
                    && self.available()
                    && self
                        .snapshot
                        .as_ref()
                        .is_some_and(|state| state.replication.is_some()),
                egui::Button::new("Repair replicas"),
            )
            .clicked()
        {
            *action = Some(GraphAction::Repair);
            ui.close();
        }
    }
    pub(super) fn graph_action(&mut self, action: GraphAction, canvas: egui::Rect) {
        match action {
            GraphAction::Open(id) => self.open_node(id),
            GraphAction::Client(id) => self.active_client = Some(id),
            GraphAction::Delete(id) => {
                self.control(Command::RemoveNode { id }, Control::Delete(id))
            }
            GraphAction::Toggle { peer, online } => {
                self.control(Command::SetPeer { id: peer, online }, Control::Availability)
            }
            GraphAction::AddPeer(position) => {
                let id = self
                    .snapshot
                    .as_ref()
                    .and_then(|s| s.peers.iter().map(|p| p.id).max())
                    .unwrap_or(0)
                    + 1;
                self.control(
                    Command::AddPeer(PeerConfig::numbered(id)),
                    Control::Add { position },
                );
            }
            GraphAction::AddClient(position) => {
                let id = self
                    .network
                    .as_ref()
                    .map_or(1, |n| n.nodes.iter().map(|n| n.id).max().unwrap_or(0) + 1);
                self.control(
                    Command::AddClient {
                        name: format!("Client {id:02}"),
                    },
                    Control::Add { position },
                );
            }
            GraphAction::Fit => {
                self.camera_manipulated = false;
                self.graph_layout.settle();
                self.fit_graph(canvas);
            }
            GraphAction::Repair => self.control(Command::RepairReplicas, Control::Repair),
        }
    }
}
fn point_on_route(path: &[egui::Pos2], progress: f32) -> Option<egui::Pos2> {
    if path.len() < 2 {
        return None;
    }
    let total: f32 = path.windows(2).map(|pair| pair[0].distance(pair[1])).sum();
    let mut remaining = total * progress.clamp(0.0, 1.0);
    for pair in path.windows(2) {
        let length = pair[0].distance(pair[1]);
        if remaining <= length && length > 0.001 {
            return Some(pair[0] + (pair[1] - pair[0]) * (remaining / length));
        }
        remaining -= length;
    }
    path.last().copied()
}
pub(super) fn packet_color(kind: PacketKind) -> Color32 {
    match kind {
        PacketKind::Ping => AMBER,
        PacketKind::Pong => GREEN,
        PacketKind::Ack => MUTED,
        PacketKind::Request => ACCENT,
        PacketKind::Response => Color32::from_rgb(195, 154, 250),
        PacketKind::Cancel => Color32::from_rgb(232, 120, 105),
    }
}

fn copy_counts(state: &LabSnapshot, peer_id: usize) -> Option<(usize, usize)> {
    state.replication.as_ref().map(|replication| {
        replication
            .shards
            .iter()
            .flat_map(|shard| &shard.replicas)
            .filter(|copy| copy.peer_id == peer_id)
            .fold((0, 0), |(current, stale), copy| {
                if copy.current {
                    (current + 1, stale)
                } else {
                    (current, stale + 1)
                }
            })
    })
}

fn row_word(rows: usize) -> &'static str {
    if rows == 1 { "row" } else { "rows" }
}

pub(super) fn storage_tooltip(node: &NetworkNode, state: Option<&LabSnapshot>) -> String {
    let Some((state, peer)) = state.and_then(|state| {
        node.peer_id
            .and_then(|id| state.peers.iter().find(|peer| peer.id == id))
            .map(|peer| (state, peer))
    }) else {
        return format!("{} · Node {} · Double-click to inspect", node.name, node.id);
    };
    let metadata = peer
        .stored_bytes
        .saturating_sub(peer.data_bytes.saturating_add(peer.index_bytes));
    let copies = copy_counts(state, peer.id).map_or(String::new(), |(current, stale)| {
        format!("\nCopies: {current} current / {stale} stale")
    });
    format!(
        "{} · Node {}\nPhysical storage: {} B / {} B quota\nEncrypted data: {} B (includes authentication metadata)\nEncrypted index: {} B\nReplica record metadata: {} B\nLogical payload: {} B / {} stored {}{}\nPayload counts actual stored copies, including stale copies; it is not unique database coverage.\nShared evaluation keys and transient FHE memory are additional.\nDouble-click to inspect",
        node.name,
        node.id,
        peer.stored_bytes,
        peer.config.storage_limit_bytes,
        peer.data_bytes,
        peer.index_bytes,
        metadata,
        peer.logical_bytes,
        peer.rows,
        row_word(peer.rows),
        copies
    )
}

fn draw_node(
    p: &egui::Painter,
    rect: egui::Rect,
    node: &NetworkNode,
    state: Option<&LabSnapshot>,
    connected: bool,
    visuals: egui::style::WidgetVisuals,
    scale: f32,
) {
    p.rect_filled(rect, 7, visuals.weak_bg_fill);
    p.rect_stroke(rect, 7, visuals.bg_stroke, egui::StrokeKind::Inside);
    let p = p.with_clip_rect(rect.shrink(4.0));
    let left = rect.left() + 12.0 * scale;
    let top = rect.top() + 16.0 * scale;
    let color = if !node.online {
        RED
    } else if node.role == NodeRole::Client {
        ACCENT
    } else {
        GREEN
    };
    let font = |size: f32| FontId::proportional((size * scale).clamp(6.0, 20.0));
    let title = if let Some(peer) = node.peer_id {
        format!("P{peer:02}")
    } else {
        format!("C{:02}", node.id)
    };
    p.text(
        egui::pos2(left, top),
        egui::Align2::LEFT_CENTER,
        title,
        font(13.0),
        color,
    );
    p.circle_filled(
        egui::pos2(rect.right() - 14.0 * scale, top),
        3.0 * scale,
        if !node.online {
            RED
        } else if connected {
            GREEN
        } else {
            AMBER
        },
    );
    p.text(
        egui::pos2(left, top + 22.0 * scale),
        egui::Align2::LEFT_CENTER,
        &node.name,
        font(12.0),
        TEXT,
    );
    let status = if !node.online {
        "Offline"
    } else if connected {
        "Connected"
    } else {
        "Discovering…"
    };
    if let Some(peer) = node
        .peer_id
        .and_then(|id| state.and_then(|s| s.peers.iter().find(|p| p.id == id)))
    {
        p.text(
            egui::pos2(left, top + 45.0 * scale),
            egui::Align2::LEFT_CENTER,
            format!(
                "Payload {} B · {} {}",
                peer.logical_bytes,
                peer.rows,
                row_word(peer.rows)
            ),
            font(10.0),
            TEXT,
        );
        p.text(
            egui::pos2(left, top + 63.0 * scale),
            egui::Align2::LEFT_CENTER,
            format!(
                "Stored {} / {} B",
                peer.stored_bytes, peer.config.storage_limit_bytes
            ),
            font(10.0),
            MUTED,
        );
        let ratio = (peer.stored_bytes as f32 / peer.config.storage_limit_bytes.max(1) as f32)
            .clamp(0.0, 1.0);
        let track = egui::Rect::from_min_size(
            egui::pos2(left, top + 75.0 * scale),
            egui::vec2(rect.width() - 24.0 * scale, 5.0 * scale),
        );
        p.rect_filled(track, 2, EDITOR);
        if peer.stored_bytes > 0 {
            let filled = egui::Rect::from_min_size(
                track.min,
                egui::vec2(track.width() * ratio, track.height()),
            );
            p.rect_filled(filled, 2, if ratio >= 0.9 { AMBER } else { GREEN });
        }
        let detail = state
            .and_then(|state| copy_counts(state, peer.id))
            .map_or_else(
                || status.to_string(),
                |(current, stale)| format!("{current} current / {stale} stale · {status}"),
            );
        p.text(
            egui::pos2(left, top + 96.0 * scale),
            egui::Align2::LEFT_CENTER,
            detail,
            font(9.0),
            if node.online { MUTED } else { RED },
        );
    } else {
        p.text(
            egui::pos2(left, top + 45.0 * scale),
            egui::Align2::LEFT_CENTER,
            if node.role == NodeRole::Client {
                "SQL client"
            } else {
                "Storage pending"
            },
            font(10.0),
            MUTED,
        );
        p.text(
            egui::pos2(left, top + 66.0 * scale),
            egui::Align2::LEFT_CENTER,
            status,
            font(10.0),
            if node.online { MUTED } else { RED },
        );
    }
}
