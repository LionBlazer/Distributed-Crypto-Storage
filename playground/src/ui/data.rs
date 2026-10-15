use super::*;
use fhe_playground::PlainRow;
#[path = "data_import.rs"]
mod import;
pub(super) use import::DataImport;
impl Playground {
    pub(super) fn data_editor(&mut self, ui: &mut egui::Ui) {
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(EDITOR).inner_margin(12))
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("data-workspace")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if let Some(rows) = self.data_import.show(ui) {
                            self.draft_rows = format_rows(&rows);
                        }
                        ui.add_space(8.0);
                        ui.separator();
                        self.data_draft(ui);
                    });
            });
    }
    fn data_draft(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Database");
            ui.add_enabled(
                self.available(),
                egui::TextEdit::singleline(&mut self.draft_name)
                    .desired_width(ui.available_width()),
            );
        });
        let valid_name = !self.draft_name.trim().is_empty()
            && self.draft_name.trim().len() <= 64
            && !self.draft_name.chars().any(char::is_control);
        ui.horizontal_wrapped(|ui| {
            if primary_button(
                ui,
                "Create / replace",
                self.available()
                    && self.controls_available()
                    && !self.data_import.blocks_creation()
                    && valid_name
                    && parse_rows(&self.draft_rows).is_ok(),
            )
            .on_hover_text("Encrypt this owner draft and create it on real peer processes")
            .clicked()
            {
                self.create_database();
            }
            if let Ok(rows) = parse_rows(&self.draft_rows) {
                ui.label(
                    RichText::new(format!("{} / {MAX_LAB_ROWS} rows", rows.len()))
                        .small()
                        .color(MUTED),
                );
            }
        });
        if !valid_name {
            ui.colored_label(
                RED,
                "Database name: 1..64 bytes, without control characters.",
            );
        }
        if let Err(error) = parse_rows(&self.draft_rows) {
            ui.colored_label(RED, error.to_string());
        }
        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            icon(ui, Icon::Table, GREEN);
            ui.label("records").on_hover_text(
                "Owner draft / age:u8 / amount:u16. Edits apply only on Create / replace.",
            );
            if tab_button(ui, "Grid", self.data_view == DataView::Grid).clicked() {
                self.data_view = DataView::Grid;
            }
            if tab_button(ui, "CSV", self.data_view == DataView::Csv).clicked() {
                self.data_view = DataView::Csv;
            }
            if action_button(
                ui,
                "Add row",
                self.available()
                    && parse_rows(&self.draft_rows).is_ok_and(|rows| rows.len() < MAX_LAB_ROWS),
            )
            .clicked()
            {
                let mut rows = parse_rows(&self.draft_rows).expect("valid owner draft");
                rows.push(PlainRow { age: 0, amount: 0 });
                self.draft_rows = format_rows(&rows);
            }
        });
        ui.separator();
        ui.add_enabled_ui(self.available(), |ui| {
            if self.data_view == DataView::Csv {
                ui.label(RichText::new("age,amount").monospace().color(MUTED));
                ui.add(
                    egui::TextEdit::multiline(&mut self.draft_rows)
                        .code_editor()
                        .desired_width(f32::INFINITY)
                        .desired_rows(10),
                );
            } else {
                self.data_grid(ui);
            }
        });
    }
    fn data_grid(&mut self, ui: &mut egui::Ui) {
        let mut rows = match parse_rows(&self.draft_rows) {
            Ok(rows) => rows,
            Err(error) => {
                ui.colored_label(RED, error.to_string());
                if ui.button("Edit CSV").clicked() {
                    self.data_view = DataView::Csv;
                }
                return;
            }
        };
        if rows.is_empty() {
            ui.label(
                RichText::new("No records. Add rows or open a compatible SQL dump.").color(MUTED),
            );
        }
        let mut changed = false;
        let mut delete = None;
        egui::ScrollArea::vertical()
            .id_salt("data-grid")
            .max_height(360.0)
            .show(ui, |ui| {
                egui::Grid::new("editable-records")
                    .striped(true)
                    .min_row_height(36.0)
                    .min_col_width((ui.available_width() - 70.0).max(100.0) / 4.0)
                    .show(ui, |ui| {
                        for header in ["Row", "age", "amount", ""] {
                            ui.label(RichText::new(header).strong().color(MUTED));
                        }
                        ui.end_row();
                        for (index, row) in rows.iter_mut().enumerate() {
                            ui.label(
                                RichText::new(format!("{:03}", index + 1))
                                    .monospace()
                                    .color(MUTED),
                            );
                            changed |= ui
                                .push_id((index, "age"), |ui| {
                                    ui.add(
                                        egui::DragValue::new(&mut row.age)
                                            .range(0..=u8::MAX)
                                            .speed(1.0),
                                    )
                                })
                                .inner
                                .changed();
                            changed |= ui
                                .push_id((index, "amount"), |ui| {
                                    ui.add(
                                        egui::DragValue::new(&mut row.amount)
                                            .range(0..=u16::MAX)
                                            .speed(1.0),
                                    )
                                })
                                .inner
                                .changed();
                            if ui
                                .push_id((index, "delete"), |ui| {
                                    ui.small_button("-").on_hover_text("Delete draft row")
                                })
                                .inner
                                .clicked()
                            {
                                delete = Some(index);
                            }
                            ui.end_row();
                        }
                    });
            });
        if let Some(index) = delete {
            rows.remove(index);
            changed = true;
        }
        if changed {
            self.draft_rows = format_rows(&rows);
        }
    }
}
