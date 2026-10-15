//! Level-of-detail presentation of observed topology, never a protocol cluster.
use super::infrastructure::GraphAction;
use super::*;
use fhe_playground::NetworkNode;
use std::collections::{BTreeMap, BTreeSet};

const MAP_LIMIT: usize = 64;
const MAX_GROUPS: usize = 64;

pub(super) fn connections(net: &NetworkSnapshot) -> BTreeSet<(NodeId, NodeId)> {
    net.links
        .iter()
        .filter(|link| link.from != link.to)
        .map(|link| (link.from.min(link.to), link.from.max(link.to)))
        .collect()
}
impl Playground {
    pub(super) fn uses_overview(&self) -> bool {
        self.network_view == NetworkView::Overview
            || (self.network_view != NetworkView::Matrix
                && self
                    .network
                    .as_ref()
                    .is_some_and(|net| net.nodes.len() > MAP_LIMIT))
    }
    pub(super) fn display_network(&mut self) -> Option<NetworkSnapshot> {
        let mut network = self.network.clone()?;
        for packet in &network.packets {
            self.playback.observe(packet);
        }
        let ids: BTreeSet<_> = network.nodes.iter().map(|node| node.id).collect();
        network.packets = self
            .playback
            .packets()
            .into_iter()
            .filter(|packet| ids.contains(&packet.from) && ids.contains(&packet.to))
            .collect();
        Some(network)
    }
    pub(super) fn network_overview(&mut self, ui: &mut egui::Ui) {
        let Some(net) = self.display_network() else {
            ui.label("Starting network...");
            return;
        };
        let mut nodes: Vec<_> = net.nodes.iter().collect();
        nodes.sort_by_key(|node| (node.role != NodeRole::Client, node.id));
        let links = connections(&net);
        let mut degree = BTreeMap::<NodeId, usize>::new();
        for (a, b) in &links {
            *degree.entry(*a).or_default() += 1;
            *degree.entry(*b).or_default() += 1;
        }
        ui.horizontal(|ui| {
            if self.overview_members.is_some() && ui.button("All groups").clicked() {
                self.overview_members = None;
            }
            ui.add(
                egui::TextEdit::singleline(&mut self.overview_search)
                    .hint_text("Find node, name or PID…")
                    .desired_width(ui.available_width()),
            );
        });
        let search = self.overview_search.trim().to_lowercase();
        let membership: Option<BTreeSet<_>> = self
            .overview_members
            .as_ref()
            .map(|ids| ids.iter().copied().collect());
        let listing = membership.is_some() || !search.is_empty();
        if listing {
            let matches: Vec<_> = nodes
                .iter()
                .copied()
                .filter(|node| {
                    membership.as_ref().is_none_or(|ids| ids.contains(&node.id))
                        && (search.is_empty()
                            || format!(
                                "{} {} {}",
                                node_code(node),
                                node.name,
                                node.process_id.map_or(String::new(), |id| id.to_string())
                            )
                            .to_lowercase()
                            .contains(&search))
                })
                .collect();
            ui.label(
                RichText::new(format!("{} nodes · double-click to inspect", matches.len()))
                    .small()
                    .color(MUTED),
            );
            let mut action = None;
            let canvas = ui.available_rect_before_wrap();
            egui::ScrollArea::vertical()
                .id_salt("overview-members")
                .auto_shrink([false, false])
                .show_rows(ui, 48.0, matches.len(), |ui, rows| {
                    for index in rows {
                        let node = matches[index];
                        let (rect, hit) = ui.allocate_exact_size(
                            egui::vec2(ui.available_width(), 44.0),
                            egui::Sense::click(),
                        );
                        let selected = self.selected_node == Some(node.id);
                        let visuals = control_visuals(ui, &hit, selected);
                        ui.painter().rect_filled(rect, 5, visuals.weak_bg_fill);
                        ui.painter().circle_filled(
                            rect.left_center() + egui::vec2(12.0, 0.0),
                            3.0,
                            if node.online { GREEN } else { RED },
                        );
                        let painter = ui.painter().with_clip_rect(rect.shrink(3.0));
                        painter.text(
                            rect.left_top() + egui::vec2(24.0, 6.0),
                            egui::Align2::LEFT_TOP,
                            format!("{}  {}", node_code(node), node.name),
                            FontId::proportional(13.0),
                            TEXT,
                        );
                        painter.text(
                            rect.left_bottom() + egui::vec2(24.0, -6.0),
                            egui::Align2::LEFT_BOTTOM,
                            format!(
                                "{} connections · {}",
                                degree.get(&node.id).copied().unwrap_or(0),
                                node.process_id.map_or_else(
                                    || "PID unavailable".to_string(),
                                    |pid| format!("PID {pid}")
                                )
                            ),
                            FontId::proportional(11.0),
                            MUTED,
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
                        hit.on_hover_cursor(egui::CursorIcon::PointingHand)
                            .context_menu(|ui| self.node_context_menu(ui, node, &mut action));
                    }
                });
            if let Some(action) = action {
                self.graph_action(action, canvas);
            }
            return;
        }
        ui.label(
            RichText::new("Visual groups · click to expand · Matrix contains every connection")
                .small()
                .color(MUTED),
        );
        let size = group_size(nodes.len());
        let groups: Vec<_> = nodes.chunks(size).collect();
        let group_of: BTreeMap<_, _> = groups
            .iter()
            .enumerate()
            .flat_map(|(index, group)| group.iter().map(move |node| (node.id, index)))
            .collect();
        let mut group_links = vec![0_usize; groups.len()];
        let mut group_traffic = vec![0_usize; groups.len()];
        for (a, b) in &links {
            if let Some(&group) = group_of.get(a) {
                group_links[group] += 1;
            }
            if group_of.get(a) != group_of.get(b)
                && let Some(&group) = group_of.get(b)
            {
                group_links[group] += 1;
            }
        }
        for packet in &net.packets {
            if let Some(&group) = group_of.get(&packet.from) {
                group_traffic[group] += 1;
            }
            if group_of.get(&packet.from) != group_of.get(&packet.to)
                && let Some(&group) = group_of.get(&packet.to)
            {
                group_traffic[group] += 1;
            }
        }
        let columns = (ui.available_width() / 210.0).floor().max(1.0) as usize;
        let width = (ui.available_width() - (columns - 1) as f32 * 8.0) / columns as f32;
        egui::ScrollArea::vertical().id_salt("overview-groups").auto_shrink([false,false]).show_rows(ui, 116.0, groups.len().div_ceil(columns), |ui, rows| {
            for row in rows {ui.horizontal(|ui| {
                for index in row*columns..((row+1)*columns).min(groups.len()) {
                    let group=groups[index];
                    let online=group.iter().filter(|node|node.online).count();
                    let title=format!("Group {:02} · {} nodes\n{} online · {} connections\n{} observed frames",index+1,group.len(),online,group_links[index],group_traffic[index]);
                    let mut button=egui::Button::new(RichText::new(title).size(12.0)).min_size(egui::vec2(width,104.0));
                    if group_traffic[index]>0 {button=button.stroke(Stroke::new(1.5,ACCENT));}
                    if ui.add(button).on_hover_text("Visual grouping by stable node ID. This does not change membership, routing, replicas or protocol connections.").clicked() {self.overview_members=Some(group.iter().map(|node|node.id).collect());}
                }
            });}
        });
    }
}
fn group_size(nodes: usize) -> usize {
    nodes.div_ceil(MAX_GROUPS).max(16)
}
fn node_code(node: &NetworkNode) -> String {
    node.peer_id
        .map_or_else(|| format!("C{:02}", node.id), |id| format!("P{id:02}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ten_thousand_nodes_have_a_bounded_number_of_groups_without_omitting_members() {
        let ids: Vec<_> = (0..10_000).collect();
        let groups: Vec<_> = ids.chunks(group_size(ids.len())).collect();
        assert!(groups.len() <= MAX_GROUPS);
        assert_eq!(
            groups.into_iter().flatten().copied().collect::<Vec<_>>(),
            ids
        );
    }
}
