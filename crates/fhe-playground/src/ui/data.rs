use super::*;
use fhe_prototype::PlainRow;

impl Playground {
    pub(super) fn data_editor(&mut self, ui: &mut egui::Ui) {
        egui::Panel::right("data-settings")
            .default_size(280.0)
            .size_range(260.0..=350.0)
            .frame(panel(18))
            .show(ui, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.label(RichText::new("Database settings").strong());
                    section(ui, "Name");
                    ui.add_enabled(
                        self.available(),
                        egui::TextEdit::singleline(&mut self.draft_name)
                            .desired_width(f32::INFINITY),
                    );
                    section(ui, "Schema");
                    for (name, datatype) in [("age", "u8 / 0..255"), ("amount", "u16 / 0..65535")] {
                        ui.horizontal(|ui| {
                            icon(ui, Icon::Column, MUTED);
                            ui.label(name);
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    ui.label(RichText::new(datatype).small().color(MUTED));
                                },
                            );
                        });
                    }
                    section(ui, "Fixtures");
                    ui.add_enabled_ui(self.available(), |ui| {
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::DragValue::new(&mut self.generate_rows)
                                    .range(0..=MAX_LAB_ROWS)
                                    .suffix(" rows"),
                            );
                            if ui.button("Generate").clicked() {
                                self.draft_rows = format_rows(
                                    &sample_rows(self.generate_rows).expect("bounded generator"),
                                );
                            }
                        });
                        ui.horizontal(|ui| {
                            if ui.button("Demo").clicked() {
                                self.draft_rows =
                                    format_rows(&sample_rows(4).expect("bounded fixture"));
                            }
                            if ui.button("Overflow").clicked() {
                                self.draft_rows = "18,65535\n19,10".into();
                            }
                            if ui.button("Empty").clicked() {
                                self.draft_rows.clear();
                            }
                        });
                    });
                    ui.add_space(16.0);
                    ui.separator();
                    match parse_rows(&self.draft_rows) {
                        Ok(rows) => {
                            ui.label(
                                RichText::new(format!("{} / {MAX_LAB_ROWS} rows", rows.len()))
                                    .color(MUTED),
                            );
                        }
                        Err(error) => {
                            ui.colored_label(RED, error.to_string());
                        }
                    }
                    ui.label(
                        RichText::new(format!("{} peers on creation", self.draft_peers))
                            .small()
                            .color(MUTED),
                    );
                    ui.label(
                        RichText::new("Changes stay in the draft until applied.")
                            .small()
                            .color(MUTED),
                    );
                });
            });
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(EDITOR).inner_margin(18))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    icon(ui, Icon::Table, GREEN);
                    ui.heading("records");
                    badge(ui, "Owner view", ACCENT);
                    let modified = self.snapshot.as_ref().is_none_or(|s| {
                        s.name != self.draft_name.trim()
                            || format_rows(&s.owner_rows) != self.draft_rows
                    });
                    if modified {
                        badge(ui, "Draft", AMBER);
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .add_enabled(
                                self.available() && parse_rows(&self.draft_rows).is_ok(),
                                primary("Create / replace"),
                            )
                            .clicked()
                        {
                            self.create_database();
                        }
                    });
                });
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if tab_button(ui, "Grid", self.data_view == DataView::Grid).clicked() {
                        self.data_view = DataView::Grid;
                    }
                    if tab_button(ui, "CSV", self.data_view == DataView::Csv).clicked() {
                        self.data_view = DataView::Csv;
                    }
                    if self.data_view == DataView::Grid
                        && ui
                            .add_enabled(
                                self.available()
                                    && parse_rows(&self.draft_rows)
                                        .is_ok_and(|r| r.len() < MAX_LAB_ROWS),
                                egui::Button::new("Add row"),
                            )
                            .clicked()
                    {
                        let mut rows = parse_rows(&self.draft_rows).expect("validated draft");
                        rows.push(PlainRow { age: 0, amount: 0 });
                        self.draft_rows = format_rows(&rows);
                    }
                });
                ui.add_space(10.0);
                ui.separator();
                ui.add_enabled_ui(self.available(), |ui| {
                    if self.data_view == DataView::Csv {
                        ui.label(RichText::new("age,amount").monospace().color(MUTED));
                        egui::ScrollArea::both()
                            .id_salt("fixture-editor")
                            .show(ui, |ui| {
                                ui.add(
                                    egui::TextEdit::multiline(&mut self.draft_rows)
                                        .code_editor()
                                        .desired_width(f32::INFINITY)
                                        .min_size(egui::vec2(
                                            ui.available_width(),
                                            ui.available_height().max(100.0),
                                        )),
                                );
                            });
                    } else {
                        self.data_grid(ui);
                    }
                });
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
            ui.label(RichText::new("No records. Add a row or load a fixture.").color(MUTED));
        }
        let mut changed = false;
        let mut delete = None;
        egui::ScrollArea::vertical()
            .id_salt("data-grid")
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
