use sql_plan::{Error, MAX_SQL_BYTES, SavepointName, StatementPlan, parse_sql, parse_statement};

fn name(sql: &str) -> SavepointName {
    let StatementPlan::Savepoint { name } = parse_statement(sql).unwrap() else {
        panic!("SAVEPOINT plan expected: {sql}");
    };
    name
}

#[test]
fn named_commands_keep_distinct_variants_and_normalize_optional_spelling() {
    let target = name("SAVEPOINT Target");
    assert_eq!(target.as_str(), "target");
    for sql in ["SAVEPOINT target", "sAvEpOiNt TARGET;"] {
        assert_eq!(
            parse_statement(sql).unwrap(),
            StatementPlan::Savepoint {
                name: target.clone()
            }
        );
    }
    for sql in ["RELEASE target", "RELEASE SAVEPOINT Target;"] {
        assert_eq!(
            parse_statement(sql).unwrap(),
            StatementPlan::Release {
                name: target.clone()
            }
        );
    }
    for sql in [
        "ROLLBACK TO target",
        "ROLLBACK TO SAVEPOINT target;",
        "ROLLBACK WORK TO target",
        "ROLLBACK WORK TO SAVEPOINT target",
        "ROLLBACK TRANSACTION TO target",
        "ROLLBACK TRANSACTION TO SAVEPOINT Target;",
    ] {
        assert_eq!(
            parse_statement(sql).unwrap(),
            StatementPlan::RollbackTo {
                name: target.clone()
            }
        );
    }
    for sql in ["SAVEPOINT target", "RELEASE target", "ROLLBACK TO target"] {
        assert!(
            matches!(parse_sql(sql), Err(Error::UnsupportedSql(_))),
            "{sql}"
        );
    }
}

#[test]
fn savepoint_keyword_is_a_name_at_end_and_a_marker_before_another_name() {
    let keyword_name = name("SAVEPOINT SAVEPOINT");
    assert_eq!(keyword_name.as_str(), "savepoint");
    for sql in [
        "RELEASE SAVEPOINT",
        "RELEASE SAVEPOINT;",
        "RELEASE SAVEPOINT SAVEPOINT",
    ] {
        assert_eq!(
            parse_statement(sql).unwrap(),
            StatementPlan::Release {
                name: keyword_name.clone()
            }
        );
    }
    for sql in [
        "ROLLBACK TO SAVEPOINT",
        "ROLLBACK WORK TO SAVEPOINT;",
        "ROLLBACK TO SAVEPOINT SAVEPOINT",
    ] {
        assert_eq!(
            parse_statement(sql).unwrap(),
            StatementPlan::RollbackTo {
                name: keyword_name.clone()
            }
        );
    }
    assert_eq!(
        parse_statement("RELEASE SAVEPOINT other").unwrap(),
        StatementPlan::Release {
            name: name("SAVEPOINT other")
        }
    );
    assert_eq!(
        parse_statement("ROLLBACK TO SAVEPOINT other").unwrap(),
        StatementPlan::RollbackTo {
            name: name("SAVEPOINT other")
        }
    );
    assert_eq!(
        parse_statement("RELEASE \"SAVEPOINT\"").unwrap(),
        StatementPlan::Release {
            name: name("SAVEPOINT \"SAVEPOINT\"")
        }
    );
}

#[test]
fn quoted_spelling_and_doubled_quotes_remain_distinct_from_ascii_folding() {
    assert_eq!(name("SAVEPOINT MiXeD").as_str(), "mixed");
    assert_eq!(name("SAVEPOINT \"mixed\""), name("SAVEPOINT MiXeD"));
    assert_ne!(name("SAVEPOINT \"MiXeD\""), name("SAVEPOINT mixed"));
    assert_eq!(name("SAVEPOINT \"a\"\"B\"").as_str(), "a\"B");
    assert_eq!(
        name("SAVEPOINT \"space ; -- /*\"").as_str(),
        "space ; -- /*"
    );
    assert_eq!(name(r#"SAVEPOINT "back\slash""#).as_str(), r"back\slash");
    assert_eq!(name("SAVEPOINT _A$2").as_str(), "_a$2");
    assert_eq!(name("SAVEPOINT ÉCOLE_Ж").as_str(), "École_Ж");
    assert_eq!(name("SAVEPOINT \"ÉCOLE_Ж\"").as_str(), "ÉCOLE_Ж");
    assert_ne!(name("SAVEPOINT é"), name("SAVEPOINT e\u{0301}"));
}

#[test]
fn colid_keyword_categories_are_checked_without_treating_all_keywords_as_reserved() {
    for spelling in [
        "begin",
        "abort",
        "commit",
        "rollback",
        "release",
        "savepoint",
        "work",
        "transaction",
        "between",
        "bigint",
        "boolean",
        "coalesce",
        "exists",
        "json_array",
        "xmltable",
    ] {
        assert_eq!(
            name(&format!("SAVEPOINT {spelling}")).as_str(),
            spelling,
            "{spelling}"
        );
    }
    for spelling in [
        "select",
        "end",
        "deferrable",
        "current_user",
        "true",
        "authorization",
        "concurrently",
        "current_schema",
        "inner",
        "like",
        "overlaps",
    ] {
        assert!(
            matches!(
                parse_statement(&format!("SAVEPOINT {spelling}")),
                Err(Error::UnsupportedSql(_))
            ),
            "{spelling}"
        );
        assert_eq!(
            name(&format!("SAVEPOINT \"{spelling}\"")).as_str(),
            spelling,
            "{spelling}"
        );
    }
}

#[test]
fn long_names_clip_after_decoding_at_a_utf8_character_boundary() {
    assert_eq!(SavepointName::MAX_BYTES, 63);
    let ascii = "a".repeat(63);
    assert_eq!(name(&format!("SAVEPOINT {ascii}X")).as_str(), ascii);
    assert_eq!(
        name(&format!("SAVEPOINT {ascii}X")),
        name(&format!("SAVEPOINT {ascii}Y"))
    );

    let prefix = "x".repeat(61);
    assert_eq!(name(&format!("SAVEPOINT {prefix}界tail")).as_str(), prefix);
    let exact = format!("{}界", "x".repeat(60));
    assert_eq!(name(&format!("SAVEPOINT {exact}tail")).as_str(), exact);
    let supplementary = format!("{}😀", "x".repeat(59));
    assert_eq!(
        name(&format!("SAVEPOINT \"{supplementary}tail\"")).as_str(),
        supplementary
    );
    let split_supplementary = "x".repeat(60);
    assert_eq!(
        name(&format!("SAVEPOINT \"{split_supplementary}😀\"")).as_str(),
        split_supplementary
    );
    let quoted = format!("SAVEPOINT \"{}\"\"tail\"", "x".repeat(62));
    assert_eq!(name(&quoted).as_str(), format!("{}\"", "x".repeat(62)));
}

#[test]
fn malformed_named_commands_and_ignored_suffixes_reject_as_whole_statements() {
    for sql in [
        "SAVEPOINT",
        "RELEASE",
        "ROLLBACK TO",
        "ROLLBACK WORK TO",
        "ROLLBACK TRANSACTION TO SAVEPOINT x y",
        "SAVEPOINT x y",
        "RELEASE x CASCADE",
        "RELEASE WORK x",
        "ROLLBACK SAVEPOINT x",
        "ABORT TO x",
        "ABORT WORK TO x",
        "ROLLBACK TO x AND CHAIN",
        "ROLLBACK TO x AND NO CHAIN",
        "SAVEPOINT x; COMMIT",
        "SAVEPOINT x;;",
        "SAVEPOINT 123",
        "SAVEPOINT 1name",
        "SAVEPOINT $name",
        "SAVEPOINT a.b",
        "SAVEPOINT a-b",
        "SAVEPOINT a,b",
        "SAVEPOINT ''",
        "SAVEPOINT \"\"",
        "SAVEPOINT \"unterminated",
        "SAVEPOINT \"a\0b\"",
        "SAVEPOINT a\0b",
        "SAVEPOINT a -- comment",
        "SAVEPOINT a /* comment */",
        "SAVEPOINT U&\"d\\0061t\"",
        "SAVEPOINT U&\"d\" UESCAPE '!'",
        "SAVEPOINT $tag$name$tag$",
        "SAVEPOINT a UESCAPE '!'",
    ] {
        assert!(
            matches!(parse_statement(sql), Err(Error::UnsupportedSql(_))),
            "{sql:?}"
        );
    }
}

#[test]
fn quoted_tokens_never_become_query_keywords_operators_literals_or_columns() {
    for sql in [
        "\"BEGIN\"",
        "BEGIN \"READ\" ONLY",
        "COMMIT AND \"CHAIN\"",
        "\"SAVEPOINT\" x",
        "\"SELECT\" * FROM records",
        "SELECT \"age\" FROM records",
        "SELECT age FROM \"records\"",
        "SELECT age FROM records \"WHERE\" age=1",
        "SELECT age FROM records WHERE \"TRUE\"",
        "SELECT age FROM records WHERE age \"IN\" (1)",
        "SELECT age FROM records WHERE age=\"1\"",
        "SELECT age FROM records WHERE TRUE \"OR\" FALSE",
        "SELECT age FROM records LIMIT \"1\"",
        "UPDATE records SET amount=amount+1WHERE age=0",
        "SELECT * FROM records LIMIT 1OFFSET 1",
    ] {
        assert!(
            matches!(parse_statement(sql), Err(Error::UnsupportedSql(_))),
            "{sql}"
        );
        assert!(
            matches!(parse_sql(sql), Err(Error::UnsupportedSql(_))),
            "{sql}"
        );
    }
}

#[test]
fn entire_sql_budget_is_checked_before_name_clipping_and_complete_input_parsing() {
    let prefix = "SAVEPOINT \"";
    let exact = format!(
        "{prefix}{}\"",
        "é".repeat((MAX_SQL_BYTES - prefix.len() - 1) / 2)
    );
    let exact = format!("{exact}{}", " ".repeat(MAX_SQL_BYTES - exact.len()));
    assert_eq!(exact.len(), MAX_SQL_BYTES);
    let clipped = name(&exact);
    assert_eq!(clipped.as_str(), "é".repeat(31));
    assert_eq!(clipped.as_str().len(), 62);
    let oversized = format!("{exact}\0");
    assert!(matches!(
        parse_statement(&oversized),
        Err(Error::InvalidInput(_))
    ));
    assert!(matches!(parse_sql(&oversized), Err(Error::InvalidInput(_))));
}
