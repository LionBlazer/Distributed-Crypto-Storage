//! Client-only acquisition and strict preflight; actual creation stays in the worker.
use super::super::*;
use crate::samples::{CATALOG, DownloadedDump, download_sample, load_local_dump, parse_dump};
use fhe_playground::PlainRow;
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
    validation: Result<usize, String>,
}

enum DumpSource {
    Sample(String),
    Local(String),
}

impl DataImport {
    pub(in crate::ui) fn blocks_creation(&self) -> bool {
        self.downloading.is_some()
            || self.error.is_some()
            || self
                .loaded
                .as_ref()
                .is_some_and(|dump| dump.validation.is_err())
    }

    fn start(&mut self, source: DumpSource, context: egui::Context) {
        if self.downloading.is_some() {
            return;
        }
        let (sender, receiver) = mpsc::sync_channel(1);
        self.error = None;
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

    fn poll(&mut self) -> Option<Vec<PlainRow>> {
        let result = match self.downloading.as_ref()?.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return None,
            Err(TryRecvError::Disconnected) => Err("SQL loader stopped without a result".into()),
        };
        self.downloading = None;
        match result {
            Ok(dump) => {
                let rows = parse_dump(&dump.sql);
                let mut end = dump.sql.len().min(MAX_SQL_PREVIEW_BYTES);
                while !dump.sql.is_char_boundary(end) {
                    end -= 1;
                }
                self.loaded = Some(LoadedDump {
                    sample_id: dump.sample_id,
                    bytes: dump.bytes,
                    preview: dump.sql[..end].into(),
                    truncated: end < dump.sql.len(),
                    validation: rows.as_ref().map(Vec::len).map_err(Clone::clone),
                });
                rows.ok()
            }
            Err(error) => {
                self.error = Some(error);
                None
            }
        }
    }

    pub(super) fn show(&mut self, ui: &mut egui::Ui) -> Option<Vec<PlainRow>> {
        let ready = self.poll();
        ui.label(RichText::new("SQL dump").strong());
        let selected = &CATALOG[self.selected.min(CATALOG.len() - 1)];
        let loading = self.downloading.is_some();
        ui.horizontal_wrapped(|ui| {
            egui::ComboBox::from_id_salt("sample-sql-source")
                .selected_text(selected.name)
                .width(180.0)
                .show_ui(ui, |ui| {
                    for (index, sample) in CATALOG.iter().enumerate() {
                        ui.selectable_value(&mut self.selected, index, sample.name);
                    }
                });
            if action_button(ui, "Download SQL", !loading).clicked() {
                self.start(
                    DumpSource::Sample(CATALOG[self.selected].id.into()),
                    ui.ctx().clone(),
                );
            }
        });
        let selected = &CATALOG[self.selected];
        ui.horizontal_wrapped(|ui| {
            ui.hyperlink_to("Source", selected.source_url);
            ui.label(RichText::new(selected.approximate_size).small().color(MUTED));
            ui.hyperlink_to("AdventureWorks (.bak)", crate::samples::ADVENTUREWORKS_SOURCE)
                .on_hover_text("Microsoft SQL Server backup, not a SQL text dump; cannot be loaded by this importer.");
        });
        ui.label(
            RichText::new("Download and inspect; full schema import unavailable").color(AMBER),
        )
        .on_hover_text(format!(
            "{}\n{}",
            selected.description, selected.support_note
        ));
        ui.horizontal(|ui| {
            let width = (ui.available_width() - 92.0).max(80.0);
            ui.add_enabled(
                !loading,
                egui::TextEdit::singleline(&mut self.local_path)
                    .hint_text("Local .sql file path")
                    .desired_width(width),
            );
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
        if loading {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Reading SQL on the client…");
            });
        }
        if let Some(error) = &self.error {
            ui.colored_label(RED, error);
        }
        if !loading && self.blocks_creation() && ui.button("Use manual draft").clicked() {
            self.loaded = None;
            self.error = None;
        }
        if let Some(loaded) = &mut self.loaded {
            ui.label(
                RichText::new(format!(
                    "{} · {} bytes read",
                    loaded.sample_id, loaded.bytes
                ))
                .small()
                .color(MUTED),
            );
            match &loaded.validation {
                Ok(rows) => {
                    ui.colored_label(
                        GREEN,
                        format!("Validated {rows} rows. Review below, then Create / replace."),
                    );
                }
                Err(error) => {
                    ui.colored_label(AMBER, format!("Not imported: {error}"));
                }
            }
            egui::CollapsingHeader::new("SQL preview")
                .id_salt("loaded-sql-preview")
                .show(ui, |ui| {
                    if loaded.truncated {
                        ui.label(
                            RichText::new(
                                "Preview: first 64 KiB. Preflight checks the entire dump.",
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
        ui.add_space(4.0);
        ui.label(RichText::new("Supported import: records(age, amount), up to 128 rows.").color(MUTED))
            .on_hover_text(format!("{}\nFollow with INSERT INTO records VALUES (...);\nOther schemas are inspected, never converted or partially applied. The complete dump must pass preflight before any database changes.", crate::samples::SUPPORTED_SCHEMA));
        ready
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::{Command, Worker};

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

    fn draw_data(app: &mut Playground) {
        let context = egui::Context::default();
        context
            .run_ui(egui::RawInput::default(), |ui| app.data_editor(ui))
            .drop_without_applying_deltas();
    }

    #[test]
    fn compatible_sql_stages_owner_rows_without_creating_until_explicit_action() {
        let (worker, commands, _events) = Worker::test_channel();
        let mut app = Playground::with_worker(worker);
        let sql = format!(
            "{}\nINSERT INTO records VALUES (18, 10), (42, 20);",
            crate::samples::SUPPORTED_SCHEMA
        );
        completed_loader(&mut app, sql);

        draw_data(&mut app);

        assert_eq!(app.draft_rows, "18,10\n42,20");
        assert!(app.pending.is_none());
        assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
        app.create_database();
        assert!(
            matches!(commands.try_recv(), Ok(Command::Create(draft)) if draft.rows == vec![PlainRow {age:18, amount:10}, PlainRow {age:42, amount:20}])
        );
    }

    #[test]
    fn unsupported_schema_is_inspected_without_replacing_owner_draft_or_creating() {
        let (worker, commands, _events) = Worker::test_channel();
        let mut app = Playground::with_worker(worker);
        app.draft_rows = "19,42".into();
        completed_loader(&mut app, "CREATE TABLE Customers (CustomerID TEXT);".into());

        draw_data(&mut app);

        assert_eq!(app.draft_rows, "19,42");
        let loaded = app.data_import.loaded.as_ref().unwrap();
        assert!(loaded.preview.contains("Customers"));
        assert!(loaded.validation.is_err());
        assert!(app.pending.is_none());
        assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
        app.create_database();
        assert!(
            app.input_error
                .as_ref()
                .is_some_and(|error| error.contains("not ready"))
        );
        assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
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

        assert!(import.poll().is_none());

        let loaded = import.loaded.as_ref().unwrap();
        assert!(loaded.truncated);
        assert!(loaded.preview.len() <= MAX_SQL_PREVIEW_BYTES);
        assert!(loaded.preview.ends_with('🙂'));
    }
}
