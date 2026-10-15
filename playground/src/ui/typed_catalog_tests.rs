use super::*;

fn catalog() -> Vec<(TableSchema, usize)> {
    // Explicitly public schema fixture. No live query result or participant data.
    relational_types::import_database_dump(
        "CREATE TABLE Customers (CustomerID INT NOT NULL, CompanyName NVARCHAR(80) NULL); INSERT INTO Customers VALUES (1,'Alfreds'); CREATE TABLE [Order Details] (OrderID INT NOT NULL, UnitPrice MONEY NULL);",
        relational_types::ImportLimits::default(),
    )
    .unwrap()
    .tables
    .into_iter()
    .map(|table| (table.schema, table.rows.len()))
    .collect()
}

fn rendered_text(draw: impl FnMut(&mut egui::Ui)) -> Vec<String> {
    let context = egui::Context::default();
    set_theme(&context);
    let output = context.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(900.0, 700.0),
            )),
            ..Default::default()
        },
        draw,
    );
    fn collect(shape: &egui::Shape, text: &mut Vec<String>) {
        match shape {
            egui::Shape::Text(item) => text.push(item.galley.job.text.clone()),
            egui::Shape::Vec(items) => {
                for item in items {
                    collect(item, text);
                }
            }
            _ => {}
        }
    }
    let mut text = Vec::new();
    for shape in &output.shapes {
        collect(&shape.shape, &mut text);
    }
    output.drop_without_applying_deltas();
    text
}

#[test]
fn observed_typed_catalog_prepares_a_real_table_query_without_automatic_execution() {
    let (worker, commands, _events) = Worker::test_channel();
    let mut app = Playground::with_worker(worker);

    app.apply_display_event(Event::Catalog(catalog()));

    assert_eq!(app.catalog.len(), 2);
    assert_eq!(app.sql, "SELECT TOP 100 * FROM [Customers];");
    assert!(matches!(
        commands.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    app.select_catalog_table(1);
    assert_eq!(app.sql, "SELECT TOP 100 * FROM [Order Details];");
    app.sql = "SELECT OrderID FROM [Order Details] WHERE OrderID = 7;".into();
    app.apply_display_event(Event::Catalog(catalog()));
    assert_eq!(
        app.sql,
        "SELECT OrderID FROM [Order Details] WHERE OrderID = 7;"
    );
}

#[test]
fn typed_data_view_shows_the_catalog_instead_of_the_historical_fixed_schema() {
    let (worker, _commands, _events) = Worker::test_channel();
    let mut app = Playground::with_worker(worker);
    app.catalog = catalog();

    let text = rendered_text(|ui| app.data_editor(ui));

    assert!(text.iter().any(|text| text == "2 encrypted tables"));
    assert!(text.iter().any(|text| text.contains("Customers · 1 rows")));
    assert!(
        text.iter()
            .any(|text| text.contains("Order Details · 0 rows"))
    );
    for fixed_schema in ["records", "age", "amount", "Manual data draft"] {
        assert!(!text.iter().any(|text| text == fixed_schema));
    }
}

#[test]
fn typed_result_grid_formats_null_money_text_and_large_binary_without_expanding_hex() {
    let rows = vec![vec![
        Value::Text("Alfreds".into()),
        Value::Null,
        Value::Decimal {
            unscaled: 185000,
            scale: 4,
        },
        Value::Binary(vec![0xff; 65536]),
    ]];
    let columns = ["CompanyName", "Region", "UnitPrice", "Picture"].map(str::to_string);

    let text = rendered_text(|ui| typed_result_table(ui, &columns, &rows));

    for value in [
        "CompanyName",
        "Alfreds",
        "NULL",
        "18.5000",
        "BINARY · 65536 bytes",
    ] {
        assert!(
            text.iter().any(|text| text == value),
            "missing typed display {value}"
        );
    }
    assert!(!text.iter().any(|text| text.starts_with("0xffff")));
}
