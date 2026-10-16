use super::*;
impl Playground {
    pub(super) fn select_catalog_table(&mut self, index: usize) {
        if let Some((schema, _)) = self.catalog.get(index) {
            self.selected_table = index;
            self.sql = format!(
                "SELECT * FROM {} LIMIT 100;",
                quoted_identifier(&schema.name)
            );
        }
    }
    pub(super) fn catalog_presets(&mut self, ui: &mut egui::Ui) {
        let Some((schema, _)) = self.catalog.get(self.selected_table) else {
            return;
        };
        let table = quoted_identifier(&schema.name);
        let mut presets = vec![
            ("All rows", format!("SELECT * FROM {table};")),
            (
                "First 100 rows",
                format!("SELECT * FROM {table} LIMIT 100;"),
            ),
        ];
        if let Some(column) = schema.columns.first() {
            let name = quoted_identifier(&column.name);
            presets.push(("One column", format!("SELECT {name} FROM {table};")));
            let literal = match &column.data_type {
                relational_types::DataType::Integer { .. } => Some("1"),
                relational_types::DataType::Text { .. } => Some("''"),
                _ => None,
            };
            if let Some(literal) = literal {
                presets.push((
                    "Equality filter",
                    format!("SELECT * FROM {table}\nWHERE {name} = {literal};"),
                ));
            }
        }
        let mut selected = None;
        for (label, sql) in &presets {
            if ui.button(*label).on_hover_text(sql).clicked() {
                selected = Some(sql.clone());
                ui.close();
            }
        }
        if let Some(sql) = selected {
            self.insert_preset(&sql);
        }
    }
    pub(super) fn database_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            icon(ui, Icon::Database, ACCENT);
            if !self.catalog.is_empty() {
                if let Some(state) = &self.snapshot {
                    ui.label(RichText::new(&state.name).strong());
                }
                let mut selected = self.selected_table.min(self.catalog.len() - 1);
                egui::ComboBox::from_id_salt("sql-selected-table")
                    .selected_text(&self.catalog[selected].0.name)
                    .width(160.0)
                    .show_ui(ui, |ui| {
                        for (index, (schema, rows)) in self.catalog.iter().enumerate() {
                            ui.selectable_value(&mut selected, index, format!("{} · {} rows", schema.name, rows));
                        }
                    });
                if selected != self.selected_table {
                    self.select_catalog_table(selected);
                }
                ui.label(RichText::new(format!("{} tables", self.catalog.len())).small().color(MUTED));
            } else if let Some(state) = &self.snapshot {
                ui.label(RichText::new(&state.name).strong());
                ui.label(RichText::new("records").color(MUTED))
                    .on_hover_text("age: u8 / amount: u16");
                ui.label(
                    RichText::new(format!(
                        "{} rows / v{}",
                        state.owner_rows.len(),
                        state.revision
                    ))
                    .small()
                    .color(MUTED),
                );
            } else {
                ui.label("No tables").on_hover_text("Run CREATE TABLE to initialize encrypted storage. SQL errors appear in Output.");
            }
        });
    }
}

fn quoted_identifier(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}
