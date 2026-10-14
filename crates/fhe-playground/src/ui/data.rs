use super::*;
use fhe_prototype::PlainRow;
impl Playground {
    pub(super) fn data_editor(&mut self, ui: &mut egui::Ui) {
        egui::CentralPanel::default().frame(egui::Frame::new().fill(EDITOR).inner_margin(12)).show(ui,|ui|{
            ui.horizontal(|ui|{
                ui.label("Database");ui.add_enabled(self.available(),egui::TextEdit::singleline(&mut self.draft_name).desired_width(ui.available_width()));
            });
            ui.horizontal_wrapped(|ui|{
                let valid_name=!self.draft_name.trim().is_empty()&&self.draft_name.trim().len()<=64&&!self.draft_name.chars().any(char::is_control);
                if primary_button(ui,"Create / replace",self.available()&&self.controls_available()&&valid_name&&parse_rows(&self.draft_rows).is_ok()).clicked(){self.create_database();}
                ui.menu_button("Fixtures",|ui|{
                    ui.add_enabled_ui(self.available(),|ui|{
                        ui.horizontal(|ui|{
                            ui.add(egui::DragValue::new(&mut self.generate_rows).range(0..=MAX_LAB_ROWS).suffix(" rows"));
                            if ui.button("Generate").clicked(){self.draft_rows=format_rows(&sample_rows(self.generate_rows).expect("bounded generator"));ui.close();}
                        });
                        for (name,text)in [("Demo",format_rows(&sample_rows(4).expect("public fixture"))),("Overflow","18,65535\n19,10".into()),("Empty",String::new())]{
                            if ui.button(name).clicked(){self.draft_rows=text;ui.close();}
                        }
                    });
                });
                if let Ok(rows)=parse_rows(&self.draft_rows){ui.label(RichText::new(format!("{} / {MAX_LAB_ROWS} rows",rows.len())).small().color(MUTED));}
            });
            if self.draft_name.trim().is_empty() || self.draft_name.trim().len()>64 || self.draft_name.chars().any(char::is_control) {ui.colored_label(RED,"Database name: 1..64 bytes, without control characters.");}
            if let Err(error)=parse_rows(&self.draft_rows) {ui.colored_label(RED,error.to_string());}
            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui|{
                icon(ui,Icon::Table,GREEN);
                ui.label("records").on_hover_text("Owner's draft / age:u8 / amount:u16. Edits apply only on Create / replace.");
                if tab_button(ui,"Grid",self.data_view==DataView::Grid).clicked(){self.data_view=DataView::Grid;}
                if tab_button(ui,"CSV",self.data_view==DataView::Csv).clicked(){self.data_view=DataView::Csv;}
                if action_button(ui,"Add row",self.available()&&parse_rows(&self.draft_rows).is_ok_and(|r|r.len()<MAX_LAB_ROWS)).clicked(){
                    let mut rows=parse_rows(&self.draft_rows).expect("valid draft");rows.push(PlainRow{age:0,amount:0});self.draft_rows=format_rows(&rows);
                }
            });
            ui.separator();
            ui.add_enabled_ui(self.available(),|ui|{
                if self.data_view==DataView::Csv{
                    ui.label(RichText::new("age,amount").monospace().color(MUTED));
                    egui::ScrollArea::both().id_salt("fixture-editor").show(ui,|ui|{
                        ui.add(egui::TextEdit::multiline(&mut self.draft_rows).code_editor().desired_width(f32::INFINITY).min_size(egui::vec2(ui.available_width(),ui.available_height().max(100.0))));
                    });
                }else{self.data_grid(ui);}
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
