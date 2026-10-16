//! Public synthetic catalogs and SQL. No plaintext query evaluator is used here.
use relational_types::{
    CheckConstraint, Column, DataType, ImportedDatabase, ImportedTable, TableSchema, Value,
    import_database_dump, plan_select, validate_database, validate_postgresql_catalog,
};
fn table(name: &str, columns: &[&str]) -> ImportedTable {
    ImportedTable {
        schema: TableSchema {
            name: name.into(),
            columns: columns
                .iter()
                .map(|name| Column {
                    name: (*name).into(),
                    data_type: DataType::Integer {
                        bits: 32,
                        signed: true,
                    },
                    nullable: false,
                    default: None,
                    identity: None,
                })
                .collect(),
            primary_key: vec![],
            foreign_keys: vec![],
            checks: vec![],
            indexes: vec![],
        },
        rows: vec![
            columns
                .iter()
                .enumerate()
                .map(|(i, _)| Value::Integer(i as i64))
                .collect(),
        ],
    }
}
fn catalog(tables: Vec<ImportedTable>) -> ImportedDatabase {
    ImportedDatabase {
        name: "public-fixture".into(),
        tables,
        objects: vec![],
        notices: vec![],
    }
}
#[test]
fn canonical_case_distinct_names_and_quoted_aliases_bind_exactly() {
    let database = catalog(vec![
        table("foo", &["id", "ID"]),
        table("Foo", &["id", "ID"]),
    ]);
    validate_database(&database).unwrap();
    for (sql, table, column) in [
        ("SELECT ID FROM FOO", 0, 0),
        ("SELECT \"ID\" FROM \"foo\"", 0, 1),
        ("SELECT id FROM public.\"Foo\"", 1, 0),
        (
            "SELECT \"P\".\"ID\" FROM \"Foo\" AS \"P\" WHERE \"P\".id = 0 ORDER BY \"P\".id",
            1,
            1,
        ),
        ("SELECT PUBLIC.foo.ID FROM foo", 0, 0),
    ] {
        let plan = plan_select(&database, sql).unwrap();
        assert_eq!(
            (plan.table, plan.projection),
            (table, vec![column]),
            "{sql}"
        );
    }
    for sql in [
        "SELECT id FROM \"FOO\"",
        "SELECT p.id FROM \"Foo\" AS \"P\"",
        "SELECT \"Foo\".id FROM \"Foo\" AS p",
        "SELECT id FROM \"Public\".foo",
        "SELECT id FROM dbo.foo",
        "SELECT id FROM [foo]",
    ] {
        assert!(plan_select(&database, sql).is_err(), "{sql}");
    }
}
#[test]
fn utf8_folding_escaped_quotes_keywords_and_clipping_follow_pg18() {
    let exact63 = format!("{}海", "a".repeat(60));
    let database = catalog(vec![
        table("Éfoo", &["a\"b", "select", "between", "authorization"]),
        table(&exact63, &["id"]),
    ]);
    for (sql, column) in [
        ("SELECT \"a\"\"b\" FROM ÉFOO", 0),
        ("SELECT t.select FROM Éfoo AS t", 1),
        ("SELECT between FROM Éfoo", 2),
        ("SELECT t.authorization FROM Éfoo AS t", 3),
    ] {
        assert_eq!(
            plan_select(&database, sql).unwrap().projection,
            vec![column]
        );
    }
    for sql in [
        "SELECT \"a\"\"b\" FROM éfoo",
        "SELECT select FROM Éfoo",
        "SELECT authorization FROM Éfoo",
        "SELECT \"\" FROM Éfoo",
        "SELECT @id FROM Éfoo",
        "SELECT \"a\0b\" FROM Éfoo",
        "SELECT U&\"a\" FROM Éfoo",
    ] {
        assert!(plan_select(&database, sql).is_err(), "{sql}");
    }
    for name in [format!("{exact63}x"), format!("{exact63}海")] {
        assert_eq!(
            plan_select(&database, &format!("SELECT id FROM \"{name}\""))
                .unwrap()
                .table,
            1
        );
    }
    let wide = catalog(vec![table(&format!("{}海", "a".repeat(61)), &["id"])]);
    assert!(
        validate_postgresql_catalog(&wide.schemas())
            .unwrap_err()
            .message
            .contains("63-byte")
    );
    assert_eq!(wide.tables[0].schema.name.len(), 64);
}
#[test]
fn source_checks_keep_raw_text_and_source_binding_while_pg_checks_are_exact() {
    let source = " /* keep */ [Unit Price] > 0 AND [Label] <> N'a''b' /* tail */ ";
    let sql = format!(
        "CREATE TABLE [Items] ([Unit Price] int NOT NULL, [Label] nvarchar(10) NOT NULL, CHECK ({source})); INSERT INTO items ([unit price],[label]) VALUES (1,N'ok');"
    );
    let imported = import_database_dump(&sql, Default::default()).unwrap();
    assert_eq!(imported.tables[0].schema.name, "Items");
    assert_eq!(
        imported.tables[0].schema.checks,
        vec![CheckConstraint::SqlServerDumpAsciiCi {
            source: source.into()
        }]
    );
    validate_database(&imported).unwrap();
    let mut canonical = catalog(vec![table("checks", &["foo", "Foo"])]);
    canonical.tables[0]
        .schema
        .checks
        .push(CheckConstraint::PostgreSql18Utf8 {
            source: "foo = 0 AND \"Foo\" = 1".into(),
        });
    validate_database(&canonical).unwrap();
    canonical.tables[0].schema.checks[0] = CheckConstraint::PostgreSql18Utf8 {
        source: "\"foo\" = 1".into(),
    };
    assert!(
        validate_database(&canonical)
            .unwrap_err()
            .message
            .contains("CHECK violation")
    );
    canonical.tables[0].schema.checks[0] = CheckConstraint::SqlServerDumpAsciiCi {
        source: "foo = 0".into(),
    };
    assert!(
        validate_database(&canonical)
            .unwrap_err()
            .message
            .contains("ambiguous")
    );
}
#[test]
fn source_foreign_references_bind_once_to_exact_catalog_names_without_renaming_objects() {
    let sql = "CREATE TABLE [Parents] ([ID] int NOT NULL PRIMARY KEY); CREATE TABLE [Children] ([ParentID] int NOT NULL, FOREIGN KEY(parentid) REFERENCES dbo.parents(id)); INSERT INTO parents VALUES(1); INSERT INTO children VALUES(1);";
    let imported = import_database_dump(sql, Default::default()).unwrap();
    let key = &imported.tables[1].schema.foreign_keys[0];
    assert_eq!(
        (&key.referenced_table, &key.referenced_columns),
        (&"Parents".into(), &vec!["ID".into()])
    );
    validate_database(&imported).unwrap();
    let mut wrong = imported.clone();
    wrong.tables[1].schema.foreign_keys[0].referenced_table = "parents".into();
    assert!(
        validate_database(&wrong)
            .unwrap_err()
            .message
            .contains("unknown referenced table")
    );
    assert!(
        import_database_dump(
            "CREATE TABLE foo(id int); CREATE TABLE Foo(id int);",
            Default::default()
        )
        .is_err()
    );
}
#[test]
fn check_language_is_explicit_serialized_metadata_without_old_or_unknown_defaults() {
    let pg = CheckConstraint::PostgreSql18Utf8 {
        source: "foo = 0".into(),
    };
    let source = CheckConstraint::SqlServerDumpAsciiCi {
        source: "foo = 0".into(),
    };
    let encoded = serde_json::to_string(&pg).unwrap();
    assert_eq!(
        encoded,
        r#"{"dialect":"PostgreSql18Utf8","source":"foo = 0"}"#
    );
    assert_eq!(
        serde_json::from_str::<CheckConstraint>(&encoded).unwrap(),
        pg
    );
    assert_ne!(encoded, serde_json::to_string(&source).unwrap());
    for invalid in [
        "\"foo = 0\"",
        "{}",
        r#"{"dialect":"PostgreSql18Utf8","source":"foo=0","extra":1}"#,
        "{\"source\":\"foo=0\"}",
        "{\"dialect\":\"Unknown\",\"source\":\"foo=0\"}",
    ] {
        assert!(serde_json::from_str::<CheckConstraint>(invalid).is_err());
    }
}

#[test]
fn source_datetime_binary_operands_and_comments_are_not_rewritten_as_query_text() {
    let expression = " /* before */ born <= GETDATE() AND payload = 0x00ff /* after */ ";
    let database=import_database_dump(&format!("CREATE TABLE history (born DATETIME NOT NULL, payload VARBINARY(2) NOT NULL, CHECK ({expression})); INSERT INTO history VALUES('7/4/1996',0x00ff);"), Default::default()).unwrap();
    assert_eq!(
        database.tables[0].schema.checks,
        vec![CheckConstraint::SqlServerDumpAsciiCi {
            source: expression.into()
        }]
    );
    validate_database(&database).unwrap();
    let mut pg = database.clone();
    pg.tables[0].schema.checks[0] = CheckConstraint::PostgreSql18Utf8 {
        source: expression.into(),
    };
    assert!(
        validate_database(&pg).is_err(),
        "GETDATE must not silently become a PG CHECK intrinsic"
    );
}
