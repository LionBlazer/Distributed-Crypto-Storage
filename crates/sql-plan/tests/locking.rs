use sql_plan::{
    LockStrength, LockWait, LockingClause, Projection, QueryPlan, RowWindow, parse_sql,
};

#[test]
fn all_strengths_and_wait_policies_produce_distinct_locking_plans() {
    for (sql_strength, strength) in [
        ("KEY SHARE", LockStrength::KeyShare),
        ("SHARE", LockStrength::Share),
        ("NO KEY UPDATE", LockStrength::NoKeyUpdate),
        ("UPDATE", LockStrength::Update),
    ] {
        for (option, wait) in [
            ("", LockWait::Wait),
            ("NOWAIT", LockWait::NoWait),
            ("SKIP LOCKED", LockWait::SkipLocked),
        ] {
            let sql = format!(
                "SELECT amount,age FROM records WHERE age IN(0,255,NULL) FOR {sql_strength} {option}"
            );
            let QueryPlan::LockingSelect {
                predicate,
                projection,
                window,
                locking,
            } = parse_sql(&sql).unwrap()
            else {
                panic!("A lock cannot be an ordinary SELECT")
            };
            assert_eq!(locking, LockingClause { strength, wait });
            assert_eq!(projection, Projection::AmountAge);
            assert_eq!(window, RowWindow::default());
            let mut expected = [0u8; 32];
            expected[0] = 1;
            expected[31] = 128;
            assert_eq!(predicate.age_mask(), expected);
        }
    }
}
#[test]
fn locking_may_precede_or_follow_the_entire_row_window() {
    let a = parse_sql("SELECT age FROM records FOR SHARE NOWAIT OFFSET 1 LIMIT 2").unwrap();
    let b = parse_sql("SELECT age FROM records LIMIT 2 OFFSET 1 FOR SHARE NOWAIT").unwrap();
    assert_eq!(a, b);
    assert!(matches!(
        a,
        QueryPlan::LockingSelect {
            window: RowWindow {
                offset: 1,
                limit: Some(2)
            },
            ..
        }
    ));
    for sql in [
        "SELECT * FROM records LIMIT 1 FOR UPDATE OFFSET 1",
        "SELECT * FROM records OFFSET 1 FOR UPDATE LIMIT 1",
    ] {
        assert!(
            parse_sql(sql).is_err(),
            "The PG18 grammar does not split its window: {sql}"
        );
    }
    assert!(matches!(
        parse_sql("SELECT * FROM records OFFSET NULL LIMIT ALL FOR KEY SHARE").unwrap(),
        QueryPlan::LockingSelect {
            window: RowWindow {
                offset: 0,
                limit: None
            },
            ..
        }
    ));
}
#[test]
fn unsupported_or_conflicting_lock_syntax_rejects_the_whole_statement() {
    for sql in [
        "SELECT * FROM records FOR UPDATE OF records",
        "SELECT * FROM records FOR SHARE FOR UPDATE",
        "SELECT * FROM records FOR UPDATE NOWAIT SKIP LOCKED",
        "SELECT * FROM records FOR UPDATE WAIT",
        "SELECT * FROM records FOR KEY UPDATE",
        "SELECT * FROM records FOR NO KEY SHARE",
        "SELECT * FROM records FOR UPDATE LIMIT 1 LIMIT 2",
        "SELECT * FROM records FOR UPDATE OFFSET -1",
        "SELECT * FROM records FOR UPDATE LIMIT 9223372036854775808",
        "SELECT * FROM records FOR UPDATE OFFSET NULL OFFSET 1",
        "SELECT COUNT(*) FROM records FOR UPDATE",
        "SELECT SUM(amount) FROM records FOR SHARE",
        "SELECT * FROM records JOIN records b ON TRUE FOR UPDATE",
        "SELECT * FROM records ORDER BY age FOR UPDATE",
        "SELECT * FROM records FETCH FIRST ROW ONLY FOR UPDATE",
        "SELECT * FROM records FOR UPDATE; SELECT * FROM records",
    ] {
        assert!(parse_sql(sql).is_err(), "{sql}");
    }
}
#[test]
fn existing_statement_and_expression_budgets_apply_to_locking_plans() {
    assert!(
        parse_sql(&format!(
            "SELECT * FROM records FOR UPDATE{}",
            " ".repeat(4096)
        ))
        .is_err()
    );
    assert!(
        parse_sql(&format!(
            "SELECT * FROM records WHERE {}TRUE FOR UPDATE",
            "NOT ".repeat(130)
        ))
        .is_err()
    );
    assert!(matches!(
        parse_sql("SELECT * FROM records").unwrap(),
        QueryPlan::Select { .. }
    ));
}
