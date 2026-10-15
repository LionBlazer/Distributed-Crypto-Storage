//! Client acquisition and complete preflight. Only an explicit Import creates state.
use super::super::*;
use crate::samples::{
    CATALOG, DownloadedDump, PreparedImport, download_sample, load_local_dump, prepare_import,
};
use relational_types::ImportedDatabase;
use std::sync::mpsc::{self, Receiver, TryRecvError};

const MAX_SQL_PREVIEW_BYTES: usize = 64 * 1024;

#[derive(Default)]
pub(in crate::ui) struct DataImport {
    selected: usize,
    local_path: String,
    downloading: Option<Receiver<Result<DownloadedDump, String>>>,
    loaded: Option<LoadedDump>,
    error: Option<String>,
}

struct LoadedDump {
    sample_id: String,
    bytes: usize,
    preview: String,
    truncated: bool,
    prepared: Result<PreparedImport, String>,
}

enum DumpSource {
    Sample(String),
    Local(String),
}

impl DataImport {
    fn start(&mut self, source: DumpSource, context: egui::Context) {
        if self.downloading.is_some() {
            return;
        }
        let (sender, receiver) = mpsc::sync_channel(1);
        self.error = None;
        self.loaded = None;
        match std::thread::Builder::new()
            .name("dcs-client-sql-download".into())
            .spawn(move || {
                let result = match source {
                    DumpSource::Sample(id) => download_sample(&id),
                    DumpSource::Local(path) => load_local_dump(&path),
                };
                let _ = sender.send(result);
                context.request_repaint();
            }) {
            Ok(_) => self.downloading = Some(receiver),
            Err(error) => self.error = Some(format!("Cannot start SQL loader: {error}")),
        }
    }

    fn poll(&mut self) {
        let Some(receiver) = self.downloading.as_ref() else {
            return;
        };
        let result = match receiver.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => Err("SQL loader stopped without a result".into()),
        };
        self.downloading = None;
        match result {
            Ok(dump) => {
                let prepared = prepare_import(&dump.sql);
                let sql = prepared
                    .as_ref()
                    .map_or(dump.sql.as_str(), |prepared| prepared.sql.as_str());
                let mut end = sql.len().min(MAX_SQL_PREVIEW_BYTES);
                while !sql.is_char_boundary(end) {
                    end -= 1;
                }
                self.loaded = Some(LoadedDump {
                    sample_id: dump.sample_id,
                    bytes: dump.bytes,
                    preview: sql[..end].into(),
                    truncated: end < sql.len(),
                    prepared,
                });
                self.error = None;
            }
            Err(error) => {
                self.loaded = None;
                self.error = Some(error);
            }
        }
    }

    pub(super) fn show(
        &mut self,
        ui: &mut egui::Ui,
        can_import: bool,
    ) -> Option<(ImportedDatabase, String)> {
        self.poll();
        let mut import = None;
        egui::CollapsingHeader::new("Import SQL")
            .id_salt("sql-import")
            .default_open(can_import)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let loading = self.downloading.is_some();
                    let width = (ui.available_width() - 76.0).max(80.0);
                    ui.add_enabled(
                        !loading,
                        egui::TextEdit::singleline(&mut self.local_path)
                            .hint_text("Local .sql file path")
                            .desired_width(width),
                    )
                    .on_hover_text("A UTF-8 SQL dump with typed CREATE TABLE and literal INSERT statements. Import encrypts every validated table on real peer processes. Existing databases are preserved.");
                    if action_button(
                        ui,
                        "Open SQL",
                        !loading && !self.local_path.trim().is_empty(),
                    )
                    .clicked()
                    {
                        self.start(
                            DumpSource::Local(self.local_path.trim().into()),
                            ui.ctx().clone(),
                        );
                    }
                });
                if self.downloading.is_some() {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Reading SQL on the client…");
                    });
                }
                if let Some(error) = &self.error {
                    ui.colored_label(RED, error);
                }
                if let Some(loaded) = &mut self.loaded {
                    ui.label(
                        RichText::new(format!(
                            "{} · {} bytes",
                            loaded.sample_id, loaded.bytes
                        ))
                        .small()
                        .color(MUTED),
                    );
                    match &loaded.prepared {
                        Ok(prepared) => {
                            ui.horizontal_wrapped(|ui| {
                                if primary_button(ui, "Import", can_import)
                                    .on_hover_text(
                                        "Encrypt the validated rows and create a new database on real peer processes",
                                    )
                                    .on_disabled_hover_text(
                                        "Import needs a new database, an active client and an idle workspace. Existing encrypted databases are preserved.",
                                    )
                                    .clicked()
                                {
                                    import = Some((prepared.database.clone(), loaded.sample_id.clone()));
                                }
                                ui.label(
                                    RichText::new(format!(
                                        "{} tables · {} rows ready",
                                        prepared.database.tables.len(), prepared.database.row_count()
                                    ))
                                    .small()
                                    .color(GREEN),
                                ).on_hover_text(format!("{} validated table and row items", prepared.statements));
                            });
                            if !prepared.database.notices.is_empty() {
                                egui::CollapsingHeader::new("Import notes")
                                    .id_salt("sql-import-notices")
                                    .show(ui, |ui| {
                                        for notice in &prepared.database.notices {
                                            ui.label(RichText::new(notice).small().color(MUTED));
                                        }
                                    });
                            }
                        }
                        Err(error) => {
                            ui.colored_label(RED, error);
                        }
                    }
                    egui::CollapsingHeader::new("SQL preview")
                        .id_salt("loaded-sql-preview")
                        .show(ui, |ui| {
                            if loaded.truncated {
                                ui.label(
                                    RichText::new(
                                        "Preview: first 64 KiB. Preflight checks the entire file.",
                                    )
                                    .small()
                                    .color(MUTED),
                                );
                            }
                            egui::ScrollArea::both()
                                .id_salt("sql-dump-preview")
                                .max_height(220.0)
                                .show(ui, |ui| {
                                    let mut preview = loaded.preview.as_str();
                                    ui.add(
                                        egui::TextEdit::multiline(&mut preview)
                                            .code_editor()
                                            .desired_rows(8)
                                            .desired_width(ui.available_width()),
                                    );
                                });
                        });
                }
                self.sources(ui);
            });
        import
    }

    fn sources(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new("Public sample databases")
            .id_salt("sql-sample-sources")
            .show(ui, |ui| {
                let selected = &CATALOG[self.selected.min(CATALOG.len() - 1)];
                ui.horizontal_wrapped(|ui| {
                    egui::ComboBox::from_id_salt("sample-sql-source")
                        .selected_text(selected.name)
                        .width(180.0)
                        .show_ui(ui, |ui| {
                            for (index, sample) in CATALOG.iter().enumerate() {
                                ui.selectable_value(&mut self.selected, index, sample.name);
                            }
                        });
                    if action_button(ui, "Download SQL", self.downloading.is_none()).clicked() {
                        self.start(
                            DumpSource::Sample(CATALOG[self.selected].id.into()),
                            ui.ctx().clone(),
                        );
                    }
                });
                let selected = &CATALOG[self.selected];
                ui.horizontal_wrapped(|ui| {
                    ui.hyperlink_to("Source", selected.source_url);
                    ui.label(
                        RichText::new(selected.approximate_size)
                            .small()
                            .color(MUTED),
                    );
                    ui.hyperlink_to(
                        "AdventureWorks (.bak)",
                        crate::samples::ADVENTUREWORKS_SOURCE,
                    )
                    .on_hover_text("Microsoft SQL Server binary backup, not a SQL text file.");
                });
                ui.label(
                    RichText::new("Download SQL, validate the full schema, then import.")
                        .small()
                        .color(AMBER),
                )
                .on_hover_text(format!(
                    "{}\n{}",
                    selected.description, selected.support_note
                ));
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::{Command, Worker};
    use fhe_playground::PlainRow;

    fn completed_loader(app: &mut Playground, sql: String) {
        let (sender, receiver) = mpsc::sync_channel(1);
        sender
            .send(Ok(DownloadedDump {
                sample_id: "public-test.sql".into(),
                bytes: sql.len(),
                sql,
            }))
            .unwrap();
        app.data_import.downloading = Some(receiver);
    }

    fn draw_data(
        app: &mut Playground,
        context: &egui::Context,
        events: Vec<egui::Event>,
    ) -> Vec<(String, egui::Rect)> {
        context.global_style_mut(|style| style.animation_time = 0.0);
        let output = context.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(900.0, 700.0),
                )),
                events,
                ..Default::default()
            },
            |ui| app.data_editor(ui),
        );
        fn collect(shape: &egui::Shape, items: &mut Vec<(String, egui::Rect)>) {
            match shape {
                egui::Shape::Text(text) => items.push((
                    text.galley.job.text.clone(),
                    text.galley.rect.translate(text.pos.to_vec2()),
                )),
                egui::Shape::Vec(shapes) => {
                    for shape in shapes {
                        collect(shape, items);
                    }
                }
                _ => {}
            }
        }
        let mut text = vec![];
        for shape in &output.shapes {
            collect(&shape.shape, &mut text);
        }
        output.drop_without_applying_deltas();
        text
    }

    fn click(app: &mut Playground, context: &egui::Context, label: &str) {
        let text = draw_data(app, context, vec![]);
        let point = text
            .iter()
            .find(|(text, _)| text == label)
            .unwrap_or_else(|| panic!("missing control {label}: {text:?}"))
            .1
            .center();
        for pressed in [true, false] {
            draw_data(
                app,
                context,
                vec![
                    egui::Event::PointerMoved(point),
                    egui::Event::PointerButton {
                        pos: point,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
            );
        }
    }

    fn supported_sql() -> String {
        "CREATE TABLE Customers (CustomerID INT NOT NULL, CompanyName NVARCHAR(80) NOT NULL);\nINSERT INTO Customers VALUES (18, 'Alfreds'), (42, 'Berglunds');".into()
    }

    #[test]
    fn loading_supported_sql_preserves_the_draft_until_explicit_import() {
        let (worker, commands, _events) = Worker::test_channel();
        let mut app = Playground::with_worker(worker);
        app.active_client = Some(1);
        app.draft_rows = "19,42".into();
        completed_loader(&mut app, supported_sql());
        let context = egui::Context::default();
        set_theme(&context);

        let text = draw_data(&mut app, &context, vec![]);

        assert_eq!(app.draft_rows, "19,42");
        assert!(app.pending.is_none());
        assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
        assert!(text.iter().any(|(text, _)| text == "Import"));
        assert!(!text.iter().any(|(text, _)| text == "Create / replace"));

        click(&mut app, &context, "Import");

        assert!(
            matches!(commands.try_recv(), Ok(Command::ImportRelational(database)) if database.tables.len() == 1 && database.row_count() == 2 && database.tables[0].schema.name == "Customers")
        );
    }

    #[test]
    fn unsupported_sql_is_rejected_without_replacing_a_draft_or_creating_state() {
        let (worker, commands, _events) = Worker::test_channel();
        let mut app = Playground::with_worker(worker);
        app.active_client = Some(1);
        app.draft_rows = "19,42".into();
        completed_loader(&mut app, "CREATE TABLE Customers (Shape GEOMETRY);".into());
        let context = egui::Context::default();

        let text = draw_data(&mut app, &context, vec![]);

        assert_eq!(app.draft_rows, "19,42");
        let loaded = app.data_import.loaded.as_ref().unwrap();
        assert!(loaded.preview.contains("Customers"));
        assert!(loaded.prepared.is_err());
        assert!(!text.iter().any(|(text, _)| text == "Import"));
        assert!(app.pending.is_none());
        assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn a_valid_dump_cannot_import_over_an_existing_database() {
        let (worker, commands, _events) = Worker::test_channel();
        let mut app = Playground::with_worker(worker);
        app.active_client = Some(1);
        app.snapshot = Some(LabSnapshot {
            name: "existing".into(),
            revision: 4,
            owner_rows: vec![PlainRow {
                age: 20,
                amount: 33,
            }],
            peers: vec![],
            replication: None,
        });
        completed_loader(&mut app, supported_sql());
        let context = egui::Context::default();
        set_theme(&context);
        click(&mut app, &context, "Import SQL");

        click(&mut app, &context, "Import");

        assert_eq!(app.snapshot.as_ref().unwrap().revision, 4);
        assert_eq!(app.snapshot.as_ref().unwrap().owner_rows[0].amount, 33);
        assert!(app.pending.is_none());
        assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn primary_data_view_shows_current_rows_and_hides_manual_draft_controls() {
        let (worker, _commands, _events) = Worker::test_channel();
        let mut app = Playground::with_worker(worker);
        app.draft_rows = "99,65535".into();
        app.snapshot = Some(LabSnapshot {
            name: "current database".into(),
            revision: 4,
            owner_rows: vec![PlainRow {
                age: 20,
                amount: 33,
            }],
            peers: vec![],
            replication: None,
        });
        let context = egui::Context::default();

        let text = draw_data(&mut app, &context, vec![]);

        for expected in ["current database", "records", "20", "33"] {
            assert!(text.iter().any(|(text, _)| text == expected));
        }
        for hidden in ["65535", "Create / replace", "Add row", "Download SQL"] {
            assert!(!text.iter().any(|(text, _)| text == hidden));
        }
    }

    #[test]
    fn sql_preview_is_bounded_without_splitting_a_unicode_character() {
        let mut import = DataImport::default();
        let sql = format!("-- {}", "🙂".repeat(MAX_SQL_PREVIEW_BYTES));
        let (sender, receiver) = mpsc::sync_channel(1);
        sender
            .send(Ok(DownloadedDump {
                sample_id: "public-unicode.sql".into(),
                bytes: sql.len(),
                sql,
            }))
            .unwrap();
        import.downloading = Some(receiver);

        import.poll();

        let loaded = import.loaded.as_ref().unwrap();
        assert!(loaded.truncated);
        assert!(loaded.preview.len() <= MAX_SQL_PREVIEW_BYTES);
        assert!(loaded.preview.ends_with('🙂'));
    }
}
