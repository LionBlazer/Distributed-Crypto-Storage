use super::*;
use fhe_playground::PeerInfo;

impl Playground {
    pub(super) fn infrastructure(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("network-toolbar")
            .frame(panel(14))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.heading("Network");
                    badge(ui, "Local simulation", MUTED);
                    if let Some(state) = &self.snapshot {
                        let online = state.peers.iter().filter(|p| p.online).count();
                        ui.label(
                            RichText::new(format!("{online}/{} online", state.peers.len()))
                                .color(GREEN),
                        );
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .add_enabled(
                                self.available()
                                    && self
                                        .snapshot
                                        .as_ref()
                                        .is_some_and(|s| s.peers.len() < MAX_PEERS),
                                primary("Add peer"),
                            )
                            .clicked()
                        {
                            let id = self.snapshot.as_ref().map_or(1, |s| s.peers.len() + 1);
                            self.new_peer = Some(PeerConfig::numbered(id));
                            self.input_error = None;
                        }
                        ui.menu_button("Layout", |ui| {
                            ui.label("Peers");
                            ui.add_enabled(
                                self.available(),
                                egui::DragValue::new(&mut self.draft_peers).range(1..=MAX_PEERS),
                            );
                            if ui
                                .add_enabled(
                                    self.available() && self.snapshot.is_some(),
                                    egui::Button::new("Apply"),
                                )
                                .clicked()
                            {
                                self.apply_layout();
                                ui.close();
                            }
                        });
                    });
                });
            });
        egui::Panel::right("peer-inspector")
            .default_size(300.0)
            .size_range(280.0..=420.0)
            .resizable(true)
            .frame(panel(18))
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("inspector")
                    .show(ui, |ui| self.inspector(ui));
            });
        egui::Panel::bottom("peer-directory")
            .default_size(180.0)
            .size_range(130.0..=320.0)
            .resizable(true)
            .frame(panel(14))
            .show(ui, |ui| self.peer_directory(ui));
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(EDITOR).inner_margin(14))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Client routes").strong());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("Fit").clicked() {
                            self.graph_zoom = 1.0;
                            self.graph_pan = egui::Vec2::ZERO;
                        }
                        if ui.small_button("+").clicked() {
                            self.graph_zoom = (self.graph_zoom * 1.15).min(2.5);
                        }
                        if ui.small_button("-").clicked() {
                            self.graph_zoom = (self.graph_zoom / 1.15).max(0.5);
                        }
                    });
                });
                ui.label(
                    RichText::new("Click a node to inspect  /  drag to pan  /  scroll to zoom")
                        .small()
                        .color(MUTED),
                );
                ui.add_space(8.0);
                self.network_graph(ui);
            });
    }

    fn inspector(&mut self, ui: &mut egui::Ui) {
        if self.new_peer.is_some() {
            ui.heading("New peer");
            ui.label(RichText::new("Join the local layout").small().color(MUTED));
            ui.add_space(10.0);
            let available = self.available();
            ui.add_enabled_ui(available, |ui| {
                peer_form(ui, self.new_peer.as_mut().expect("peer draft"))
            });
            ui.add_space(16.0);
            if ui
                .add_enabled(available, primary("Add and repartition"))
                .clicked()
            {
                let mut profiles =
                    self.profiles_for_count(self.snapshot.as_ref().map_or(0, |s| s.peers.len()));
                profiles.push(self.new_peer.as_ref().expect("peer draft").clone());
                self.submit(
                    Command::ConfigurePeers(profiles),
                    Job::Layout,
                    "Add peer and repartition".into(),
                );
            }
            if ui
                .add_enabled(available, egui::Button::new("Cancel"))
                .clicked()
            {
                self.new_peer = None;
            }
            ui.add_space(12.0);
            ui.label(
                RichText::new("Existing rows are redistributed across the new layout.")
                    .small()
                    .color(MUTED),
            );
            return;
        }
        let peer = self.selected_peer.and_then(|id| {
            self.snapshot
                .as_ref()
                .and_then(|s| s.peers.iter().find(|p| p.id == id))
                .cloned()
        });
        if let Some(peer) = peer {
            ui.horizontal(|ui| {
                ui.heading(format!("P{:02}", peer.id));
                badge(
                    ui,
                    if peer.online { "Online" } else { "Offline" },
                    if peer.online { GREEN } else { RED },
                );
            });
            ui.label(RichText::new(&peer.config.name).color(MUTED));
            let available = self.available();
            if ui
                .add_enabled(
                    available,
                    egui::Button::new(if peer.online {
                        "Take offline"
                    } else {
                        "Bring online"
                    }),
                )
                .clicked()
            {
                self.submit(
                    Command::SetPeer {
                        id: peer.id,
                        online: !peer.online,
                    },
                    Job::Availability,
                    format!(
                        "Peer {}: {}",
                        peer.id,
                        if peer.online { "offline" } else { "online" }
                    ),
                );
            }
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if tab_button(ui, "Shard", self.peer_view == PeerView::Shard).clicked() {
                    self.peer_view = PeerView::Shard;
                }
                if tab_button(ui, "Settings", self.peer_view == PeerView::Settings).clicked() {
                    self.peer_view = PeerView::Settings;
                }
            });
            if self.peer_view == PeerView::Settings {
                if self.peer_edit.is_none() {
                    self.peer_edit = Some(peer.config.clone());
                }
                ui.add_enabled_ui(available, |ui| {
                    peer_form(ui, self.peer_edit.as_mut().expect("selected peer draft"))
                });
                ui.add_space(12.0);
                let dirty = self.peer_edit.as_ref().is_some_and(|c| c != &peer.config);
                if ui
                    .add_enabled(available && dirty, primary("Save settings"))
                    .clicked()
                {
                    self.submit(
                        Command::ConfigurePeer {
                            id: peer.id,
                            config: self.peer_edit.as_ref().expect("peer draft").clone(),
                        },
                        Job::PeerSettings,
                        format!("Configure peer {}", peer.id),
                    );
                }
                return;
            }
            section(ui, "Encrypted shard");
            ui.horizontal(|ui| {
                ui.label(format!("{} rows", peer.rows));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.monospace(bytes(peer.compressed_bytes));
                });
            });
            ui.add(
                egui::ProgressBar::new(
                    peer.compressed_bytes as f32 / peer.config.storage_limit_bytes as f32,
                )
                .fill(ACCENT)
                .desired_height(5.0),
            );
            ui.label(
                RichText::new(format!(
                    "{} of {} quota",
                    bytes(peer.compressed_bytes),
                    bytes(peer.config.storage_limit_bytes)
                ))
                .small()
                .color(MUTED),
            );
            if let Some(timing) = self.peer_timing(peer.id) {
                ui.label(
                    RichText::new(format!("Last request: {timing:.0} ms"))
                        .small()
                        .color(MUTED),
                );
            }
            section(ui, "Shard rows");
            badge(ui, "Owner view", AMBER);
            ui.label(RichText::new("Plaintext is visible to the client owner.").small().color(MUTED))
                .on_hover_text("The inspector uses the owner's fixture. Peer evaluators receive only ciphertexts and evaluation keys.");
            if peer.rows == 0 {
                ui.label(RichText::new("This shard is empty.").color(MUTED));
            } else if let Some(state) = &self.snapshot {
                egui::Grid::new(("shard-rows", peer.id))
                    .striped(true)
                    .min_col_width(64.0)
                    .show(ui, |ui| {
                        for header in ["Row", "age", "amount"] {
                            ui.label(RichText::new(header).color(MUTED));
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
        } else {
            ui.heading("Client");
            badge(ui, "Owner", ACCENT);
            ui.add_space(12.0);
            if let Some(state) = &self.snapshot {
                ui.label(RichText::new(&state.name).strong());
                ui.label(
                    RichText::new(format!(
                        "{} rows  /  revision {}",
                        state.owner_rows.len(),
                        state.revision
                    ))
                    .color(MUTED),
                );
                section(ui, "Routing");
                ui.label(format!("{} direct shard routes", state.peers.len()));
                ui.label(
                    RichText::new("Encrypted requests are evaluated on each required shard.")
                        .small()
                        .color(MUTED),
                );
                if let Some(id) = self.active_peer {
                    badge(ui, &format!("Executing on P{id:02}"), ACCENT);
                }
                let missing = state
                    .peers
                    .iter()
                    .filter(|p| !p.online && p.rows > 0)
                    .count();
                if missing > 0 {
                    ui.colored_label(RED, format!("{missing} required shard(s) offline"));
                }
            }
            ui.add_space(14.0);
            if ui.button("Open SQL").clicked() {
                self.tab = Tab::Sql;
            }
            if ui.button("Open data").clicked() {
                self.tab = Tab::Data;
            }
            section(ui, "Inspect the network");
            ui.label(
                RichText::new(
                    "Select a peer on the map or in the directory to view its shard and settings.",
                )
                .color(MUTED),
            );
        }
    }

    fn peer_timing(&self, id: usize) -> Option<f64> {
        self.history
            .iter()
            .find_map(|record| match &record.outcome {
                Ok(Outcome::Query(QueryOutcome::Aggregate { peers, .. })) => {
                    peers.iter().find(|p| p.id == id).map(|p| p.elapsed_ms)
                }
                _ => None,
            })
    }

    fn peer_directory(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Peers").strong());
            if let Some(state) = &self.snapshot {
                ui.label(
                    RichText::new(format!("{} total", state.peers.len()))
                        .small()
                        .color(MUTED),
                );
            }
        });
        ui.add_space(6.0);
        let peers = self
            .snapshot
            .as_ref()
            .map(|s| s.peers.clone())
            .unwrap_or_default();
        let mut select = None;
        egui::ScrollArea::both().id_salt("infrastructure-table").show(ui, |ui| {
            egui::Grid::new("peers").striped(true).min_row_height(29.0).min_col_width(((ui.available_width() - 70.0) / 6.0).max(65.0)).show(ui, |ui| {
                for header in ["Peer", "Name", "State", "Rows", "Stored", "Request"] { ui.label(RichText::new(header).small().color(MUTED)); }
                ui.end_row();
                for peer in &peers {
                    if ui.selectable_label(self.selected_peer == Some(peer.id), format!("P{:02}", peer.id)).clicked() { select = Some(peer.id); }
                    ui.label(&peer.config.name);
                    ui.colored_label(if peer.online { GREEN } else { RED }, if peer.online { "Online" } else { "Offline" });
                    ui.monospace(peer.rows.to_string());
                    ui.monospace(bytes(peer.compressed_bytes));
                    ui.monospace(self.peer_timing(peer.id).map(|ms| format!("{ms:.0} ms")).unwrap_or_else(|| "-".into()))
                        .on_hover_text("FHE evaluation, owner decryption and configured artificial delay; not network ping.");
                    ui.end_row();
                }
            });
        });
        if let Some(id) = select {
            self.select_peer(Some(id));
        }
    }

    fn network_graph(&mut self, ui: &mut egui::Ui) {
        let size = ui.available_size().max(egui::vec2(100.0, 100.0));
        let (canvas, response) = ui.allocate_exact_size(size, egui::Sense::drag());
        if response.dragged() {
            self.graph_pan += response.drag_delta();
        }
        if response.hovered() {
            let scroll = ui.input_mut(|i| {
                let delta = i.smooth_scroll_delta.y;
                i.smooth_scroll_delta.y = 0.0;
                delta
            });
            self.graph_zoom = (self.graph_zoom * (scroll * 0.002).exp()).clamp(0.5, 2.5);
        }
        let p = ui.painter().with_clip_rect(canvas);
        p.rect_filled(canvas, 8, Color32::from_rgb(18, 23, 32));
        let step = 22.0;
        for x in 0..(canvas.width() / step) as usize {
            for y in 0..(canvas.height() / step) as usize {
                p.circle_filled(
                    canvas.min + egui::vec2(x as f32 * step + 11.0, y as f32 * step + 11.0),
                    0.8,
                    BORDER.gamma_multiply(0.65),
                );
            }
        }
        let peers = self
            .snapshot
            .as_ref()
            .map(|s| s.peers.clone())
            .unwrap_or_default();
        let columns = peers.len().clamp(1, 4);
        let rows = peers.len().div_ceil(columns);
        let horizontal = peers.len() > 8;
        let world_size = if horizontal {
            egui::vec2(columns as f32 * 158.0 + 180.0, rows as f32 * 82.0 + 24.0)
        } else {
            egui::vec2(
                (columns as f32 * 158.0).max(300.0),
                rows as f32 * 105.0 + 140.0,
            )
        };
        let fit = ((canvas.width() - 36.0) / world_size.x)
            .min((canvas.height() - 36.0) / world_size.y)
            .clamp(0.1, 1.1);
        let scale = fit * self.graph_zoom;
        let origin = canvas.center()
            - egui::vec2(
                if horizontal { world_size.x / 2.0 } else { 0.0 },
                world_size.y / 2.0,
            ) * scale
            + self.graph_pan;
        let client_center = origin
            + if horizontal {
                egui::vec2(72.0, world_size.y / 2.0) * scale
            } else {
                egui::vec2(0.0, 46.0 * scale)
            };
        let client_rect =
            egui::Rect::from_center_size(client_center, egui::vec2(142.0, 66.0) * scale);
        let positions: Vec<_> = peers
            .iter()
            .enumerate()
            .map(|(index, _)| {
                let row_count = (peers.len() - (index / columns) * columns).min(columns);
                let x = ((index % columns) as f32 - (row_count as f32 - 1.0) / 2.0) * 158.0;
                let center = if horizontal {
                    egui::vec2(
                        230.0 + (index % columns) as f32 * 158.0,
                        52.0 + (index / columns) as f32 * 82.0,
                    )
                } else {
                    egui::vec2(x, 170.0 + (index / columns) as f32 * 105.0)
                };
                egui::Rect::from_center_size(
                    origin + center * scale,
                    egui::vec2(136.0, 72.0) * scale,
                )
            })
            .collect();
        for (peer, rect) in peers.iter().zip(&positions) {
            let active = self.active_peer == Some(peer.id);
            let color = if active {
                ACCENT
            } else if peer.online {
                Color32::from_rgb(58, 89, 116)
            } else {
                RED.gamma_multiply(0.4)
            };
            let start = if horizontal {
                client_rect.right_center()
            } else {
                client_rect.center_bottom()
            };
            let end = if horizontal {
                rect.left_center()
            } else {
                rect.center_top()
            };
            let direction = if horizontal {
                egui::vec2(1.0, 0.0)
            } else {
                egui::vec2(0.0, 1.0)
            };
            p.add(egui::epaint::CubicBezierShape::from_points_stroke(
                [
                    start,
                    start + direction * 32.0 * scale,
                    end - direction * 42.0 * scale,
                    end,
                ],
                false,
                Color32::TRANSPARENT,
                Stroke::new(if active { 2.5 } else { 1.2 }, color),
            ));
            let a = 4.0 * scale;
            let sideways = egui::vec2(-direction.y, direction.x);
            p.add(egui::Shape::convex_polygon(
                vec![
                    end,
                    end - direction * a * 1.8 + sideways * a,
                    end - direction * a * 1.8 - sideways * a,
                ],
                color,
                Stroke::NONE,
            ));
        }
        draw_client(
            &p,
            client_rect,
            self.selected_peer.is_none() && self.new_peer.is_none(),
            scale,
        );
        let client_response = ui.interact(
            client_rect.intersect(canvas),
            ui.id().with("client-node"),
            egui::Sense::click(),
        );
        if client_response.clicked() {
            self.select_peer(None);
        }
        let mut select = None;
        for (peer, rect) in peers.iter().zip(positions) {
            let hit = ui.interact(
                rect.intersect(canvas),
                ui.id().with(("peer-node", peer.id)),
                egui::Sense::click(),
            );
            draw_peer(
                &p,
                rect,
                peer,
                self.selected_peer == Some(peer.id),
                self.active_peer == Some(peer.id),
                hit.hovered(),
                scale,
            );
            if hit.clicked() {
                select = Some(peer.id);
            }
        }
        if let Some(id) = select {
            self.select_peer(Some(id));
        }
    }
}

fn peer_form(ui: &mut egui::Ui, config: &mut PeerConfig) {
    section(ui, "Name");
    ui.add(
        egui::TextEdit::singleline(&mut config.name)
            .char_limit(48)
            .desired_width(f32::INFINITY),
    );
    section(ui, "Storage quota");
    let mut kib = config.storage_limit_bytes / 1024;
    if ui
        .add(
            egui::DragValue::new(&mut kib)
                .range(1..=65_536)
                .suffix(" KiB")
                .speed(64),
        )
        .changed()
    {
        config.storage_limit_bytes = kib * 1024;
    }
    section(ui, "Simulated delay");
    ui.add(
        egui::DragValue::new(&mut config.delay_ms)
            .range(0..=1000)
            .suffix(" ms"),
    );
    ui.label(
        RichText::new("Added to each nonempty shard request.")
            .small()
            .color(MUTED),
    );
}

fn draw_client(p: &egui::Painter, rect: egui::Rect, selected: bool, scale: f32) {
    p.rect_filled(rect.expand(3.0), 11, ACCENT.gamma_multiply(0.06));
    p.rect_filled(rect, 8, Color32::from_rgb(29, 44, 62));
    p.rect_stroke(
        rect,
        8,
        Stroke::new(if selected { 1.8 } else { 1.0 }, ACCENT.gamma_multiply(0.7)),
        egui::StrokeKind::Inside,
    );
    p.text(
        rect.center() - egui::vec2(0.0, 9.0 * scale),
        egui::Align2::CENTER_CENTER,
        "Client",
        FontId::proportional((16.0 * scale).clamp(11.0, 22.0)),
        TEXT,
    );
    p.text(
        rect.center() + egui::vec2(0.0, 14.0 * scale),
        egui::Align2::CENTER_CENTER,
        "owner / SQL",
        FontId::proportional((11.0 * scale).clamp(9.0, 16.0)),
        ACCENT,
    );
}

fn draw_peer(
    p: &egui::Painter,
    rect: egui::Rect,
    peer: &PeerInfo,
    selected: bool,
    active: bool,
    hovered: bool,
    scale: f32,
) {
    let accent = if active || selected {
        ACCENT
    } else if peer.online {
        GREEN
    } else {
        RED
    };
    p.rect_filled(
        rect,
        8,
        if selected || hovered {
            Color32::from_rgb(35, 47, 63)
        } else {
            CARD
        },
    );
    p.rect_stroke(
        rect,
        8,
        Stroke::new(
            if selected || active { 1.8 } else { 1.0 },
            if selected || active { accent } else { BORDER },
        ),
        egui::StrokeKind::Inside,
    );
    let left = rect.left() + 12.0 * scale;
    let top = rect.top() + 15.0 * scale;
    let font = |size: f32| FontId::proportional((size * scale).clamp(9.0, 18.0));
    p.text(
        egui::pos2(left, top),
        egui::Align2::LEFT_CENTER,
        format!("P{:02}", peer.id),
        font(13.0),
        accent,
    );
    p.circle_filled(
        egui::pos2(rect.right() - 14.0 * scale, top),
        3.0 * scale,
        if peer.online { GREEN } else { RED },
    );
    let p = p.with_clip_rect(rect.shrink(4.0));
    let name: String = peer.config.name.chars().take(16).collect();
    p.text(
        egui::pos2(left, top + 21.0 * scale),
        egui::Align2::LEFT_CENTER,
        name,
        font(12.0),
        TEXT,
    );
    p.text(
        egui::pos2(left, top + 41.0 * scale),
        egui::Align2::LEFT_CENTER,
        if active {
            "Executing...".into()
        } else if !peer.online {
            "Offline".into()
        } else {
            if scale < 0.7 {
                format!("{} rows", peer.rows)
            } else {
                format!("{} rows / {}", peer.rows, bytes(peer.compressed_bytes))
            }
        },
        font(10.0),
        if peer.online { MUTED } else { RED },
    );
}
