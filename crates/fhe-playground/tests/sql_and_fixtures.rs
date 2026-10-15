use fhe_playground::{
    MAX_LAB_ROWS, PRESETS, QueryPlan, format_rows, parse_rows, parse_sql, sample_rows,
};

#[test]
fn every_one_click_preset_has_a_supported_plan() {
    for preset in PRESETS {
        assert!(
            parse_sql(preset.sql).is_ok(),
            "{}: {}",
            preset.name,
            preset.sql
        );
    }
}

#[test]
fn keywords_are_case_insensitive_and_whitespace_is_optional_around_symbols() {
    let plan = parse_sql("select count(*),sum(amount) from records where age>=18;").unwrap();

    assert_eq!(
        plan,
        parse_sql("SELECT COUNT(*), SUM(amount) FROM records WHERE age >= 18").unwrap()
    );
    assert!(matches!(
        parse_sql("UPDATE records SET amount=amount+0"),
        Ok(QueryPlan::AddAmount { delta: 0, .. })
    ));
}

#[test]
fn unsupported_clauses_and_extra_statements_are_never_ignored() {
    for sql in [
        "SELECT unknown FROM records",
        "SELECT COUNT(*), SUM(amount) FROM other",
        "SELECT COUNT(*), SUM(amount) FROM records LIMIT 1",
        "SELECT COUNT(*), SUM(amount) FROM records ORDER BY age",
        "SELECT COUNT(*), SUM(amount) FROM records WHERE age >= 18 OR age = 7",
        "SELECT COUNT(*), SUM(amount) FROM records; UPDATE records SET amount = amount + 1",
        "UPDATE records SET amount = 5",
        "UPDATE records SET amount = amount + 5, age = 18",
        "UPDATE records SET amount = amount + 5 -- ignored?",
        "SELECT COUNT(*), SUM(amount) FROM records;;",
        "SELECT COUNT(*), SUM(amount) FROM records WHERE age <> 18",
        "SELECT COUNT(*), SUM(amount) FROM records WHERE age < = 18",
        "SELECT COUNT(*), SUM(amount) FROM records WHERE age BETWEEN 18 42",
        "SELECT COUNT(*), SUM(amount) FROM records WHERE age BETWEEN 18 AND",
        "SELECT COUNT(*), SUM(amount) FROM records WHERE age BETWEEN 18 OR 42",
        "SELECT COUNT(*), SUM(amount) FROM records WHERE age BETWEEN 18 AND 42 AND age = 19",
        "SELECT COUNT(*), SUM(amount) FROM records WHERE age <= 18 AND age > 0",
        "SELECT COUNT(*), SUM(amount) FROM records WHERE age = 1e2",
        "SELECT age, age FROM records",
        "SELECT age, amount, age FROM records",
        "SELECT amount AS total FROM records",
        "SELECT * FROM records LIMIT 129",
        "SELECT * FROM records LIMIT -1",
        "SELECT * FROM records LIMIT 1 OFFSET 1",
        "SELECT * FROM records LIMIT 1 WHERE age = 18",
        "SELECT age, SUM(amount) FROM records",
        "SELECT SUM(age) FROM records",
        "SELECT SUM(amount), COUNT(*) FROM records",
        "SELECT COUNT(age) FROM records",
        "SELECT * FROM records WHERE amount = 1",
        "SELECT * FROM records JOIN other ON age = age",
        "",
    ] {
        assert!(
            parse_sql(sql).is_err(),
            "unsupported SQL was accepted: {sql}"
        );
    }
}

#[test]
fn row_projections_and_limits_have_explicit_plans_and_requested_column_order() {
    use fhe_playground::{Predicate, Projection};
    for (sql, projection, limit) in [
        ("SELECT * FROM records", Projection::AgeAmount, None),
        (
            "SELECT age, amount FROM records LIMIT 0",
            Projection::AgeAmount,
            Some(0),
        ),
        (
            "SELECT amount, age FROM records LIMIT 128",
            Projection::AmountAge,
            Some(128),
        ),
        ("SELECT age FROM records LIMIT 1", Projection::Age, Some(1)),
        ("SELECT amount FROM records", Projection::Amount, None),
    ] {
        assert_eq!(
            parse_sql(sql).unwrap(),
            QueryPlan::Select {
                predicate: Predicate::default(),
                projection,
                limit,
            },
            "{sql}"
        );
    }
    assert!(matches!(
        parse_sql("SELECT COUNT(*) FROM records WHERE age > 18"),
        Ok(QueryPlan::Count { .. })
    ));
    assert!(matches!(
        parse_sql("SELECT SUM(amount) FROM records WHERE age BETWEEN 18 AND 42"),
        Ok(QueryPlan::Sum { .. })
    ));
}

#[test]
fn sql_values_must_fit_the_encrypted_column_types() {
    for sql in [
        "SELECT COUNT(*), SUM(amount) FROM records WHERE age = 256",
        "SELECT COUNT(*), SUM(amount) FROM records WHERE age = -1",
        "SELECT COUNT(*), SUM(amount) FROM records WHERE age < 256",
        "SELECT COUNT(*), SUM(amount) FROM records WHERE age BETWEEN 0 AND 256",
        "SELECT COUNT(*), SUM(amount) FROM records WHERE age BETWEEN -1 AND 18",
        "UPDATE records SET amount = amount + 65536",
        "UPDATE records SET amount = amount + 1.5",
    ] {
        assert!(
            parse_sql(sql).is_err(),
            "out-of-range SQL was accepted: {sql}"
        );
    }
    assert!(parse_sql("UPDATE records SET amount = amount + 65535 WHERE age = 255").is_ok());
}

#[test]
fn age_comparisons_normalize_exact_endpoints_without_unsigned_wrap() {
    for (clause, bounds) in [
        ("age = 18", Some((18, 18))),
        ("age >= 18", Some((18, 255))),
        ("age < 18", Some((0, 17))),
        ("age <= 18", Some((0, 18))),
        ("age > 18", Some((19, 255))),
        ("age<=0", Some((0, 0))),
        ("age<1", Some((0, 0))),
        ("age>254", Some((255, 255))),
        ("age<=255", Some((0, 255))),
        ("age>=0", Some((0, 255))),
        ("age between 18 and 42", Some((18, 42))),
        ("age BETWEEN 0 AND 0", Some((0, 0))),
        ("age BETWEEN 255 AND 255", Some((255, 255))),
        ("age < 0", None),
        ("age > 255", None),
        ("age BETWEEN 42 AND 18", None),
    ] {
        let sql = format!("SELECT COUNT(*), SUM(amount) FROM records WHERE {clause}");
        let QueryPlan::Aggregate { predicate } = parse_sql(&sql).unwrap() else {
            panic!("expected aggregate for {sql}");
        };

        assert_eq!(
            predicate
                .age_range()
                .map(|range| (range.lower, range.upper)),
            bounds,
            "{sql}"
        );
    }
}

#[test]
fn updates_accept_the_same_age_range_grammar_as_reads() {
    for clause in ["age < 18", "age <= 18", "age > 18", "age BETWEEN 18 AND 42"] {
        let QueryPlan::Aggregate { predicate: read } = parse_sql(&format!(
            "SELECT COUNT(*), SUM(amount) FROM records WHERE {clause}"
        ))
        .unwrap() else {
            panic!("expected read");
        };

        let update = parse_sql(&format!(
            "UPDATE records SET amount=amount+65535 WHERE {clause};"
        ))
        .unwrap();

        assert_eq!(
            update,
            QueryPlan::AddAmount {
                predicate: read,
                delta: 65535
            }
        );
    }
}

#[test]
fn oversized_sql_is_rejected_before_tokenization() {
    assert!(parse_sql(&" ".repeat(4097)).is_err());
}
#[test]
fn insert_has_bounded_typed_values_and_never_ignores_extra_rows_or_clauses() {
    use fhe_playground::PlainRow;
    assert_eq!(
        parse_sql("INSERT INTO records (age, amount) VALUES (255,65535);").unwrap(),
        QueryPlan::Insert {
            row: PlainRow {
                age: 255,
                amount: 65535
            }
        }
    );
    assert_eq!(
        parse_sql("insert into records values(0,0)").unwrap(),
        QueryPlan::Insert {
            row: PlainRow { age: 0, amount: 0 }
        }
    );
    for sql in [
        "INSERT INTO records VALUES (256,1)",
        "INSERT INTO records VALUES (1,65536)",
        "INSERT INTO records VALUES (-1,1)",
        "INSERT INTO records VALUES (1,1),(2,2)",
        "INSERT INTO records (amount,age) VALUES (1,2)",
        "INSERT INTO records VALUES (1,1) WHERE age=1",
        "INSERT INTO other VALUES (1,1)",
        "INSERT INTO records VALUES (1)",
        "INSERT INTO records SELECT * FROM records",
    ] {
        assert!(parse_sql(sql).is_err(), "{sql}");
    }
}
#[test]
fn presets_progress_from_reading_to_filtering_and_summary_then_real_writes() {
    use fhe_playground::PresetGroup;
    assert!(matches!(
        parse_sql(PRESETS.first().unwrap().sql),
        Ok(QueryPlan::Select { .. })
    ));
    let groups: Vec<_> =
        PRESETS
            .iter()
            .map(|preset| preset.group)
            .fold(Vec::new(), |mut groups, group| {
                if groups.last() != Some(&group) {
                    groups.push(group)
                }
                groups
            });
    assert_eq!(
        groups,
        vec![
            PresetGroup::Select,
            PresetGroup::Filter,
            PresetGroup::Aggregate,
            PresetGroup::Insert,
            PresetGroup::Update
        ]
    );
    let insert = PRESETS
        .iter()
        .find(|preset| preset.group == PresetGroup::Insert)
        .unwrap();
    assert!(matches!(
        parse_sql(insert.sql),
        Ok(QueryPlan::Insert { .. })
    ));
}

#[test]
fn owner_fixtures_round_trip_and_allow_an_empty_database() {
    let rows = parse_rows(" 0,0\n255,65535\n\n18,20 ").unwrap();

    assert_eq!(parse_rows(&format_rows(&rows)).unwrap(), rows);
    assert!(parse_rows(" \n").unwrap().is_empty());
    assert_eq!(sample_rows(4).unwrap().len(), 4);
}

#[test]
fn invalid_fixture_values_or_resource_limits_are_rejected() {
    for text in ["256,1", "1,65536", "-1,1", "18", "18,1,2", "age,amount"] {
        assert!(
            parse_rows(text).is_err(),
            "invalid fixture was accepted: {text}"
        );
    }
    assert!(parse_rows(&"18,1\n".repeat(MAX_LAB_ROWS + 1)).is_err());
    assert!(parse_rows(&" ".repeat(16385)).is_err());
    assert!(sample_rows(MAX_LAB_ROWS + 1).is_err());
}
