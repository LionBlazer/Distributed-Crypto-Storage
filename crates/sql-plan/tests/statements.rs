use sql_plan::{
    Deferrability, Error, IsolationLevel, MAX_SQL_BYTES, StatementPlan, TransactionAccess,
    TransactionChain, TransactionMode, parse_sql, parse_statement,
};

#[test]
fn begin_and_start_transaction_aliases_leave_unspecified_modes_empty() {
    for sql in [
        "BEGIN",
        "begin;",
        " BEGIN WORK ; ",
        "BEGIN TRANSACTION",
        "START TRANSACTION",
        "sTaRt\tTrAnSaCtIoN\n;",
    ] {
        assert_eq!(
            parse_statement(sql).unwrap(),
            StatementPlan::Begin { modes: vec![] },
            "{sql}"
        );
    }
}

#[test]
fn every_isolation_level_remains_the_requested_level() {
    for (syntax, level) in [
        ("SERIALIZABLE", IsolationLevel::Serializable),
        ("REPEATABLE READ", IsolationLevel::RepeatableRead),
        ("READ COMMITTED", IsolationLevel::ReadCommitted),
        ("READ UNCOMMITTED", IsolationLevel::ReadUncommitted),
    ] {
        let sql = format!("BEGIN TRANSACTION ISOLATION LEVEL {syntax};");
        assert_eq!(
            parse_statement(&sql).unwrap(),
            StatementPlan::Begin {
                modes: vec![TransactionMode::Isolation(level)]
            },
            "{sql}"
        );
    }
}

#[test]
fn access_and_deferrability_are_explicit_even_without_isolation() {
    for (syntax, mode) in [
        (
            "READ ONLY",
            TransactionMode::Access(TransactionAccess::ReadOnly),
        ),
        (
            "READ WRITE",
            TransactionMode::Access(TransactionAccess::ReadWrite),
        ),
        (
            "DEFERRABLE",
            TransactionMode::Deferrability(Deferrability::Deferrable),
        ),
        (
            "NOT DEFERRABLE",
            TransactionMode::Deferrability(Deferrability::NotDeferrable),
        ),
    ] {
        let sql = format!("START TRANSACTION {syntax}");
        assert_eq!(
            parse_statement(&sql).unwrap(),
            StatementPlan::Begin { modes: vec![mode] },
            "{sql}"
        );
    }
}

#[test]
fn comma_and_adjacent_modes_preserve_the_same_original_order() {
    let expected = StatementPlan::Begin {
        modes: vec![
            TransactionMode::Access(TransactionAccess::ReadOnly),
            TransactionMode::Isolation(IsolationLevel::Serializable),
            TransactionMode::Deferrability(Deferrability::NotDeferrable),
        ],
    };
    for sql in [
        "BEGIN READ ONLY, ISOLATION LEVEL SERIALIZABLE, NOT DEFERRABLE",
        "START TRANSACTION READ ONLY ISOLATION LEVEL SERIALIZABLE NOT DEFERRABLE",
        "BEGIN WORK READ ONLY, ISOLATION LEVEL SERIALIZABLE NOT DEFERRABLE;",
    ] {
        assert_eq!(parse_statement(sql).unwrap(), expected, "{sql}");
    }
}

#[test]
fn repeated_and_conflicting_modes_are_retained_instead_of_overwritten() {
    // This is an ordered syntax list, not a claim about effective backend settings.
    let sql = "BEGIN READ ONLY READ WRITE, READ ONLY, ISOLATION LEVEL READ UNCOMMITTED \
        ISOLATION LEVEL SERIALIZABLE DEFERRABLE NOT DEFERRABLE DEFERRABLE";
    assert_eq!(
        parse_statement(sql).unwrap(),
        StatementPlan::Begin {
            modes: vec![
                TransactionMode::Access(TransactionAccess::ReadOnly),
                TransactionMode::Access(TransactionAccess::ReadWrite),
                TransactionMode::Access(TransactionAccess::ReadOnly),
                TransactionMode::Isolation(IsolationLevel::ReadUncommitted),
                TransactionMode::Isolation(IsolationLevel::Serializable),
                TransactionMode::Deferrability(Deferrability::Deferrable),
                TransactionMode::Deferrability(Deferrability::NotDeferrable),
                TransactionMode::Deferrability(Deferrability::Deferrable),
            ]
        }
    );
}

#[test]
fn end_aliases_preserve_omitted_chain_and_both_explicit_chain_options() {
    for (suffix, chain) in [
        ("", TransactionChain::Unspecified),
        (" AND CHAIN", TransactionChain::Chain),
        (" AND NO CHAIN", TransactionChain::NoChain),
    ] {
        for keyword in ["COMMIT", "END", "ROLLBACK", "ABORT"] {
            for optional in ["", " WORK", " TRANSACTION"] {
                let sql = format!("{keyword}{optional}{suffix};");
                let expected = if matches!(keyword, "COMMIT" | "END") {
                    StatementPlan::Commit { chain }
                } else {
                    StatementPlan::Rollback { chain }
                };
                assert_eq!(parse_statement(&sql).unwrap(), expected, "{sql}");
            }
        }
    }
}

#[test]
fn query_entry_points_share_existing_plans_and_complete_input_errors() {
    for sql in [
        "SELECT age,amount FROM records WHERE age IN(0,255,NULL) OFFSET 1 LIMIT 1 FOR UPDATE SKIP LOCKED",
        "SELECT COUNT(*),SUM(amount) FROM records WHERE NOT(age BETWEEN NULL AND 10)",
        "INSERT INTO records(age,amount) VALUES(255,65535),(0,0);",
        "UPDATE records SET amount=amount+65535 WHERE age<18",
    ] {
        assert_eq!(
            parse_statement(sql).unwrap(),
            StatementPlan::Query(parse_sql(sql).unwrap()),
            "{sql}"
        );
    }
    for sql in [
        "SELECT * FROM records FOR UPDATE WAIT",
        "SELECT * FROM records LIMIT 1 FOR UPDATE OFFSET 1",
        "INSERT INTO records VALUES(1,1),(256,2)",
        "UPDATE records SET amount=amount+1; BEGIN",
        "SELECT * FROM records;;",
    ] {
        assert_eq!(
            parse_statement(sql).unwrap_err(),
            parse_sql(sql).unwrap_err(),
            "{sql}"
        );
    }
}

#[test]
fn query_only_api_still_rejects_every_transaction_family() {
    for sql in [
        "BEGIN",
        "START TRANSACTION ISOLATION LEVEL SERIALIZABLE",
        "COMMIT AND CHAIN",
        "END WORK",
        "ROLLBACK",
        "ABORT TRANSACTION AND NO CHAIN",
    ] {
        assert!(
            matches!(parse_sql(sql), Err(Error::UnsupportedSql(_))),
            "{sql}"
        );
    }
}

#[test]
fn incomplete_or_malformed_modes_keywords_and_chain_reject_the_whole_statement() {
    for sql in [
        "START",
        "START WORK",
        "START TRANSACTION WORK",
        "BEGIN WORK TRANSACTION",
        "BEGIN ISOLATION",
        "BEGIN ISOLATION SERIALIZABLE",
        "BEGIN ISOLATION LEVEL",
        "BEGIN ISOLATION LEVEL REPEATABLE",
        "BEGIN ISOLATION LEVEL READ",
        "BEGIN ISOLATION LEVEL SNAPSHOT",
        "BEGIN READ",
        "BEGIN READ COMMITTED",
        "BEGIN READ MAYBE",
        "BEGIN NOT",
        "BEGIN NOT READ ONLY",
        "BEGIN , READ ONLY",
        "BEGIN READ ONLY,",
        "BEGIN READ ONLY,,DEFERRABLE",
        "BEGIN READ ONLY,AND CHAIN",
        "BEGIN AND CHAIN",
        "COMMIT AND",
        "COMMIT AND NO",
        "COMMIT CHAIN",
        "COMMIT NO CHAIN",
        "END AND NO NO CHAIN",
        "ROLLBACK AND CHAIN AND CHAIN",
        "ABORT WORK TRANSACTION",
        "COMMIT READ ONLY",
    ] {
        assert!(
            matches!(parse_statement(sql), Err(Error::UnsupportedSql(_))),
            "{sql}"
        );
    }
}

#[test]
fn multiple_statements_savepoints_and_other_transaction_commands_never_become_end() {
    for sql in [
        "",
        ";",
        "BEGIN;;",
        "BEGIN; COMMIT",
        "COMMIT; SELECT * FROM records",
        "ROLLBACK ABORT",
        "SAVEPOINT s",
        "RELEASE SAVEPOINT s",
        "ROLLBACK TO SAVEPOINT s",
        "ROLLBACK TRANSACTION TO s",
        "SET TRANSACTION READ ONLY",
        "PREPARE TRANSACTION x",
        "COMMIT PREPARED x",
        "ROLLBACK PREPARED x",
        "BEGIN -- comment",
        "COMMIT /* comment */",
        "\"BEGIN\"",
        "BEGIN\0",
        "BEGIN é",
    ] {
        assert!(
            matches!(parse_statement(sql), Err(Error::UnsupportedSql(_))),
            "{sql}"
        );
    }
}

#[test]
fn whole_statement_byte_cap_applies_before_tokenization_to_both_entry_points() {
    let at_limit = format!("BEGIN{}", " ".repeat(MAX_SQL_BYTES - "BEGIN".len()));
    assert_eq!(at_limit.len(), MAX_SQL_BYTES);
    assert_eq!(
        parse_statement(&at_limit).unwrap(),
        StatementPlan::Begin { modes: vec![] }
    );

    // The unsupported NUL must not be reached by the tokenizer above the byte cap.
    let oversized = format!("{at_limit}\0");
    assert!(matches!(
        parse_statement(&oversized),
        Err(Error::InvalidInput(_))
    ));
    assert!(matches!(parse_sql(&oversized), Err(Error::InvalidInput(_))));

    let many_modes = " READ ONLY".repeat((MAX_SQL_BYTES - "BEGIN".len()) / " READ ONLY".len());
    let sql = format!("BEGIN{many_modes}");
    let StatementPlan::Begin { modes } = parse_statement(&sql).unwrap() else {
        panic!("BEGIN expected")
    };
    assert_eq!(
        modes,
        vec![
            TransactionMode::Access(TransactionAccess::ReadOnly);
            many_modes.len() / " READ ONLY".len()
        ]
    );
}
