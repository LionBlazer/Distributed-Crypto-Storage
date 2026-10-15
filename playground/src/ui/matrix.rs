//! Dense-network view of the same snapshot used by the map; no topology policy.
use super::infrastructure::{GraphAction, packet_color};
use super::*;
use fhe_playground::{NetworkNode, NetworkPacket};
use std::collections::{BTreeMap, BTreeSet};

impl Playground {
    pub(super) fn uses_matrix(&self) -> bool {
        self.network_view == NetworkView::Matrix
    }

    pub(super) fn network_matrix(&mut self, ui: &mut egui::Ui) {
        let Some(net) = self.display_network() else {
            ui.label("Starting network...");
            return;
        };
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Connections").strong());
            ui.label(
                RichText::new("Rows send -> columns receive")
                    .small()
                    .color(MUTED),
            );
        });
        let nodes = matrix_nodes(&net);
        let links = matrix_links(&net);
        let mut traffic = BTreeMap::<(NodeId, NodeId), Vec<&NetworkPacket>>::new();
        for packet in &net.packets {
            traffic
                .entry((packet.from, packet.to))
                .or_default()
                .push(packet);
        }
        let mut action = None;
        let width = ui.available_width();
        let row_label_width = 132.0;
        let count = nodes.len().max(1) as f32;
        let cell = ((width - row_label_width - 12.0) / count)
            .min((ui.available_height() - 82.0) / count)
            .clamp(22.0, 32.0);
        let selected = self.selected_node.or(self.active_client);
        let outer_canvas = ui.available_rect_before_wrap();
        egui::ScrollArea::both()
            .id_salt("connection-matrix-scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let size = egui::vec2(
                    row_label_width + nodes.len() as f32 * cell + 12.0,
                    42.0 + nodes.len() as f32 * cell + 38.0,
                )
                .max(outer_canvas.size());
                let (canvas, background) = ui.allocate_exact_size(size, egui::Sense::click());
                let p = ui.painter().with_clip_rect(ui.clip_rect());
                let origin = canvas.min + egui::vec2(row_label_width, 42.0);
                let clip = ui.clip_rect();
                let rows = visible_range(origin.y, cell, nodes.len(), clip.top(), clip.bottom());
                let columns = visible_range(origin.x, cell, nodes.len(), clip.left(), clip.right());
                let pointer = ui.input(|i| i.pointer.hover_pos());
                let mut over_node = false;
                let matrix_rect =
                    egui::Rect::from_min_size(origin, egui::Vec2::splat(nodes.len() as f32 * cell));
                let hovered = pointer.filter(|pos| matrix_rect.contains(*pos)).map(|pos| {
                    (
                        ((pos.y - origin.y) / cell) as usize,
                        ((pos.x - origin.x) / cell) as usize,
                    )
                });
                let labels: BTreeSet<_> = rows.clone().chain(columns.clone()).collect();
                for index in labels {
                    let node = nodes[index];
                    let row = egui::Rect::from_min_size(
                        egui::pos2(canvas.left(), origin.y + index as f32 * cell),
                        egui::vec2(row_label_width - 8.0, cell - 2.0),
                    );
                    let column = egui::Rect::from_min_size(
                        egui::pos2(origin.x + index as f32 * cell, canvas.top() + 6.0),
                        egui::vec2(cell - 2.0, 32.0),
                    );
                    for (axis, rect) in [("row", row), ("column", column)] {
                        if (axis == "row" && !rows.contains(&index))
                            || (axis == "column" && !columns.contains(&index))
                        {
                            continue;
                        }
                        over_node |= pointer.is_some_and(|pos| rect.contains(pos));
                        let hit = ui
                            .interact(rect, ui.id().with((axis, node.id)), egui::Sense::click())
                            .on_hover_cursor(egui::CursorIcon::PointingHand)
                            .on_hover_text(super::infrastructure::storage_tooltip(
                                node,
                                self.snapshot.as_ref(),
                            ));
                        let highlighted = selected == Some(node.id)
                            || hovered.is_some_and(|(r, c)| r == index || c == index);
                        let visuals = control_visuals(ui, &hit, highlighted);
                        p.rect_filled(rect, 4, visuals.weak_bg_fill);
                        if highlighted || hit.hovered() || hit.is_pointer_button_down_on() {
                            p.rect_stroke(rect, 4, visuals.bg_stroke, egui::StrokeKind::Inside);
                        }
                        let color = if !node.online {
                            RED
                        } else if node.role == NodeRole::Client {
                            ACCENT
                        } else {
                            GREEN
                        };
                        let title = node_code(node);
                        if axis == "column" {
                            p.text(
                                rect.center(),
                                egui::Align2::CENTER_CENTER,
                                title,
                                FontId::monospace(10.0),
                                color,
                            );
                        } else {
                            p.text(
                                rect.left_center() + egui::vec2(6.0, 0.0),
                                egui::Align2::LEFT_CENTER,
                                title,
                                FontId::monospace(11.0),
                                color,
                            );
                            let name_rect = rect.shrink2(egui::vec2(4.0, 0.0));
                            p.with_clip_rect(name_rect.intersect(ui.clip_rect())).text(
                                rect.left_center() + egui::vec2(38.0, 0.0),
                                egui::Align2::LEFT_CENTER,
                                &node.name,
                                FontId::proportional(11.0),
                                TEXT,
                            );
                        }
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
                }
                for row in rows {
                    let from = nodes[row];
                    for column in columns.clone() {
                        let to = nodes[column];
                        let rect = egui::Rect::from_min_size(
                            origin + egui::vec2(column as f32 * cell, row as f32 * cell),
                            egui::Vec2::splat(cell - 2.0),
                        );
                        let hit = ui.interact(
                            rect,
                            ui.id().with(("connection", from.id, to.id)),
                            egui::Sense::click(),
                        );
                        let connected = links.contains(&(from.id, to.id));
                        let packets = traffic
                            .get(&(from.id, to.id))
                            .map_or(&[][..], Vec::as_slice);
                        let highlighted = selected == Some(from.id)
                            || selected == Some(to.id)
                            || hovered.is_some_and(|(r, c)| r == row || c == column);
                        let fill = if from.id == to.id {
                            BORDER.gamma_multiply(0.15)
                        } else if connected {
                            if highlighted {
                                Color32::from_rgb(40, 78, 108)
                            } else {
                                Color32::from_rgb(30, 47, 64)
                            }
                        } else {
                            Color32::from_rgb(21, 27, 35)
                        };
                        p.rect_filled(rect, 3, fill);
                        if connected {
                            p.circle_filled(
                                rect.center(),
                                2.0,
                                if highlighted {
                                    ACCENT
                                } else {
                                    Color32::from_rgb(90, 120, 145)
                                },
                            );
                        }
                        if hit.hovered() || hit.is_pointer_button_down_on() {
                            let visuals = control_visuals(ui, &hit, false);
                            p.rect_stroke(
                                rect,
                                3,
                                Stroke::new(1.5, visuals.fg_stroke.color),
                                egui::StrokeKind::Inside,
                            );
                        }
                        paint_packets(&p, rect, packets);
                        if hit.clicked() {
                            self.selected_node = Some(from.id);
                        }
                        if hit.hovered() {
                            hit.on_hover_ui(|ui| {
                                ui.strong(format!("{} → {}", from.name, to.name));
                                ui.label(if from.id == to.id {
                                    "Same node"
                                } else if connected {
                                    "Connected · mirrored in the opposite cell"
                                } else {
                                    "No established connection"
                                });
                                for packet in packets {
                                    ui.label(format!(
                                        "{:?} #{} · {:.0}%{}",
                                        packet.kind,
                                        packet.id,
                                        packet.progress * 100.0,
                                        packet
                                            .request_id
                                            .map_or(String::new(), |id| format!(" · request {id}"))
                                    ));
                                }
                            });
                        }
                    }
                }
                p.text(
                    canvas.left_bottom() - egui::vec2(-4.0, 14.0),
                    egui::Align2::LEFT_CENTER,
                    "Dot = connection · color = packet · double-click a node to inspect",
                    FontId::proportional(11.0),
                    MUTED,
                );
                if !over_node || background.context_menu_opened() {
                    background.context_menu(|ui| {
                        self.canvas_context_menu(ui, &net, egui::Pos2::ZERO, &mut action, false)
                    });
                }
            });
        if net.nodes.is_empty() {
            ui.label("Right-click to add a client or peer");
        }
        if self.playback.playing() {
            ui.ctx().request_repaint();
        }
        if let Some(action) = action {
            self.graph_action(action, outer_canvas);
        }
    }
}

fn visible_range(
    origin: f32,
    cell: f32,
    count: usize,
    min: f32,
    max: f32,
) -> std::ops::Range<usize> {
    let first = ((min - origin) / cell).floor().max(0.0) as usize;
    let last = ((max - origin) / cell).ceil().max(0.0) as usize;
    first.min(count)..last.min(count)
}

fn matrix_nodes(net: &NetworkSnapshot) -> Vec<&NetworkNode> {
    let mut nodes: Vec<_> = net.nodes.iter().collect();
    nodes.sort_by_key(|node| (node.role != NodeRole::Client, node.id));
    nodes
}
fn matrix_links(net: &NetworkSnapshot) -> BTreeSet<(NodeId, NodeId)> {
    net.links
        .iter()
        .flat_map(|link| [(link.from, link.to), (link.to, link.from)])
        .collect()
}
fn node_code(node: &NetworkNode) -> String {
    if let Some(peer) = node.peer_id {
        format!("P{peer:02}")
    } else {
        format!("C{:02}", node.id)
    }
}
fn paint_packets(p: &egui::Painter, rect: egui::Rect, packets: &[&NetworkPacket]) {
    for (index, packet) in packets.iter().take(3).enumerate() {
        let color = packet_color(packet.kind);
        let top = rect.top() + 4.0 + index as f32 * 5.0;
        let start = egui::pos2(rect.left() + 3.0, top);
        let end = egui::pos2(rect.right() - 3.0, top);
        p.line_segment([start, end], Stroke::new(1.0, color.gamma_multiply(0.35)));
        p.circle_filled(
            start + (end - start) * packet.progress.clamp(0.0, 1.0),
            2.2,
            color,
        );
    }
    if packets.len() > 1 {
        p.text(
            rect.right_bottom() - egui::vec2(3.0, 2.0),
            egui::Align2::RIGHT_BOTTOM,
            packets.len().to_string(),
            FontId::monospace(9.0),
            TEXT,
        );
    }
}
