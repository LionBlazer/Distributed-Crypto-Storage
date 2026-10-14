use super::*;

impl Playground {
    pub(super) fn explorer(&mut self, ui: &mut egui::Ui) {
        egui::Panel::left("database-tree")
            .default_size(235.0)
            .size_range(210.0..=340.0)
            .resizable(true)
            .frame(panel(14))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    icon(ui, Icon::Database, ACCENT);
                    ui.label(RichText::new("Database").strong());
                });
                ui.add_space(8.0);
                ui.add(
                    egui::TextEdit::singleline(&mut self.explorer_filter)
                        .hint_text("Filter objects...")
                        .desired_width(f32::INFINITY),
                );
                ui.add_space(12.0);
                if let Some(state) = &self.snapshot {
                    egui::Frame::new()
                        .fill(CARD)
                        .corner_radius(6)
                        .inner_margin(10)
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());
                            ui.horizontal(|ui| {
                                icon(ui, Icon::Database, ACCENT);
                                ui.label(RichText::new(&state.name).strong());
                            });
                            ui.horizontal(|ui| {
                                ui.add_space(25.0);
                                ui.label(RichText::new("Local database").small().color(MUTED));
                            });
                        });
                    section(ui, "Tables");
                    let filter = self.explorer_filter.trim().to_ascii_lowercase();
                    let matches_table = filter.is_empty() || "records".contains(&filter);
                    if matches_table || ["age", "amount"].iter().any(|name| name.contains(&filter))
                    {
                        ui.horizontal(|ui| {
                            icon(ui, Icon::Table, GREEN);
                            if ui.selectable_label(true, "records").clicked() {
                                self.tab = Tab::Data;
                            }
                            ui.label(
                                RichText::new(state.owner_rows.len().to_string())
                                    .small()
                                    .color(MUTED),
                            );
                        });
                        for (name, datatype) in [("age", "u8"), ("amount", "u16")] {
                            if matches_table || name.contains(&filter) {
                                ui.horizontal(|ui| {
                                    ui.add_space(22.0);
                                    icon(ui, Icon::Column, MUTED);
                                    ui.label(name);
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| badge(ui, datatype, MUTED),
                                    );
                                });
                            }
                        }
                    } else {
                        ui.label(RichText::new("No matching objects").small().color(MUTED));
                    }
                    ui.add_space(18.0);
                    ui.separator();
                    ui.label(
                        RichText::new(format!(
                            "{} rows  /  v{}",
                            state.owner_rows.len(),
                            state.revision
                        ))
                        .small()
                        .color(MUTED),
                    );
                    ui.label(
                        RichText::new(format!("{} encrypted shards", state.peers.len()))
                            .small()
                            .color(MUTED),
                    );
                } else {
                    ui.label(RichText::new("Preparing database...").color(MUTED));
                }
                ui.add_space(8.0);
                if ui.button("Edit data").clicked() {
                    self.tab = Tab::Data;
                }
            });
    }
}
