use super::*;
impl Playground {
    pub(super) fn database_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            icon(ui, Icon::Database, ACCENT);
            if let Some(state) = &self.snapshot {
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
                ui.label("No database");
                if ui.small_button("Open Data").clicked() {
                    self.navigate(Tab::Data, self.right_tab);
                }
            }
        });
    }
}
