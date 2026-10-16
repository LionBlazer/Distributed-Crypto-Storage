use sql_plan::{QueryPlan, RowWindow, parse_sql};

fn window(clause: &str) -> RowWindow {
    let QueryPlan::Select { window, .. } =
        parse_sql(&format!("SELECT amount, age FROM records {clause}")).unwrap()
    else {
        panic!("row selection expected")
    };
    window
}

#[test]
fn limit_and_offset_literals_preserve_the_same_window_in_either_order() {
    for clause in ["LIMIT 3 OFFSET 2", "OFFSET 2 LIMIT 3", "LIMIT +3 OFFSET +2"] {
        assert_eq!(
            window(clause),
            RowWindow {
                offset: 2,
                limit: Some(3)
            }
        );
    }
    assert_eq!(
        window("OFFSET 7"),
        RowWindow {
            offset: 7,
            limit: None
        }
    );
    assert_eq!(
        window("LIMIT 0 OFFSET 7"),
        RowWindow {
            offset: 7,
            limit: Some(0)
        }
    );
    assert_eq!(
        window("LIMIT -0 OFFSET -0"),
        RowWindow {
            offset: 0,
            limit: Some(0)
        }
    );
}

#[test]
fn all_and_null_have_postgresql_unbounded_and_zero_semantics() {
    for clause in [
        "",
        "LIMIT ALL",
        "LIMIT NULL",
        "OFFSET NULL",
        "OFFSET NULL LIMIT ALL",
    ] {
        assert_eq!(window(clause), RowWindow::default(), "{clause}");
    }
    for clause in ["LIMIT ALL OFFSET 4", "OFFSET 4 LIMIT NULL"] {
        assert_eq!(
            window(clause),
            RowWindow {
                offset: 4,
                limit: None
            }
        );
    }
}

#[test]
fn malformed_duplicate_and_unsupported_clauses_never_disappear() {
    for clause in [
        "LIMIT",
        "OFFSET",
        "LIMIT NULL LIMIT 1",
        "LIMIT ALL LIMIT NULL",
        "OFFSET NULL OFFSET 1",
        "OFFSET 1 LIMIT 2 OFFSET 3",
        "OFFSET ALL",
        "LIMIT 1 WHERE age = 18",
        "LIMIT 2 ORDER BY age",
        "FETCH FIRST 1 ROW ONLY",
        "LIMIT (1 + 2)",
        "LIMIT 1.5",
        "OFFSET 1e2",
        "LIMIT --1",
        "OFFSET +-1",
    ] {
        assert!(
            parse_sql(&format!("SELECT * FROM records {clause}")).is_err(),
            "{clause}"
        );
    }
    for sql in [
        "SELECT COUNT(*) FROM records OFFSET 1",
        "SELECT SUM(amount) FROM records LIMIT ALL",
    ] {
        assert!(
            parse_sql(sql).is_err(),
            "Aggregate pagination is outside this fixed-row stage: {sql}"
        );
    }
}

#[test]
fn pagination_counts_have_explicit_signed_bigint_and_platform_bounds() {
    for clause in [
        "LIMIT -1",
        "OFFSET -1",
        "LIMIT 9223372036854775808",
        "OFFSET 18446744073709551615",
    ] {
        assert!(
            parse_sql(&format!("SELECT * FROM records {clause}")).is_err(),
            "{clause}"
        );
    }
    if usize::BITS >= 64 {
        assert_eq!(
            window("OFFSET 9223372036854775807").offset,
            i64::MAX as usize
        );
    } else {
        assert!(parse_sql("SELECT * FROM records OFFSET 4294967296").is_err());
    }
}

#[test]
fn shard_prefix_is_checked_before_executor_policy_and_zero_needs_no_offset_addition() {
    assert_eq!(window("LIMIT 3 OFFSET 2").prefix_limit().unwrap(), Some(5));
    assert_eq!(window("LIMIT ALL OFFSET 2").prefix_limit().unwrap(), None);
    assert_eq!(
        RowWindow {
            offset: usize::MAX,
            limit: Some(0)
        }
        .prefix_limit()
        .unwrap(),
        Some(0)
    );
    assert!(
        RowWindow {
            offset: usize::MAX,
            limit: Some(1)
        }
        .prefix_limit()
        .is_err()
    );
}
