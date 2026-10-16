//! Finite-domain SQL semantics: these tests inspect only query plans, never stored rows.
use sql_plan::{Predicate, QueryPlan, parse_sql};

fn predicate(sql: &str) -> Predicate {
    let QueryPlan::Select { predicate, .. } =
        parse_sql(&format!("SELECT * FROM records WHERE {sql}")).unwrap()
    else {
        panic!("SELECT expected")
    };
    predicate
}
fn selected(predicate: Predicate, age: u8) -> bool {
    predicate.age_mask()[usize::from(age) / 8] & (1 << (age % 8)) != 0
}
#[test]
fn all_age_values_follow_comparison_domain_precedence_and_null_semantics() {
    type ExpectedAges = fn(u8) -> bool;
    let cases: &[(&str, ExpectedAges)] = &[
        ("age=7 OR age>=18 AND age<=42", |a| {
            a == 7 || (18..=42).contains(&a)
        }),
        ("(age=7 OR age>=18) AND age<=42", |a| {
            (a == 7 || a >= 18) && a <= 42
        }),
        ("NOT NOT age=42", |a| a == 42),
        ("NOT(age BETWEEN NULL AND 10)", |a| a > 10),
        ("NOT(age BETWEEN 10 AND NULL)", |a| a < 10),
        ("age BETWEEN NULL AND 10", |_| false),
        ("age NOT BETWEEN 42 AND 18", |_| true),
        ("age IN(7,42,7,NULL)", |a| a == 7 || a == 42),
        ("age NOT IN(7,42,NULL)", |_| false),
        ("NOT(age IN(7,NULL) AND age=42)", |a| a != 42),
        ("NOT(age=NULL)", |_| false),
        ("NOT NULL OR age=42", |a| a == 42),
        ("NULL AND FALSE OR TRUE", |_| true),
        ("NULL OR NOT TRUE", |_| false),
        ("age IS NULL", |_| false),
        ("age IS NOT NULL", |_| true),
        ("age<300 AND age>=-1", |_| true),
        ("age=-1 OR age=256", |_| false),
        (
            "age BETWEEN -9223372036854775808 AND +9223372036854775807",
            |_| true,
        ),
        ("age != 42", |a| a != 42),
        ("NOT(age<>42)", |a| a == 42),
        ("age BETWEEN 18 AND 42 AND NOT age IN(19,41)", |a| {
            (18..=42).contains(&a) && a != 19 && a != 41
        }),
    ];
    for &(sql, expected) in cases {
        let predicate = predicate(sql);
        for age in 0..=u8::MAX {
            assert_eq!(selected(predicate, age), expected(age), "{sql}, age={age}");
        }
    }
}
#[test]
fn sql_three_valued_truth_tables_hold_under_every_boolean_operator() {
    // Independent truth tables: index 0/1/2 means FALSE/TRUE/UNKNOWN.
    let atoms = ["FALSE", "TRUE", "NULL"];
    let not = [1, 0, 2];
    let and = [[0, 0, 0], [0, 1, 2], [0, 2, 2]];
    let or = [[0, 1, 2], [1, 1, 1], [2, 1, 2]];
    for (a, left) in atoms.iter().enumerate() {
        for (b, right) in atoms.iter().enumerate() {
            for (op, truth) in [("AND", and[a][b]), ("OR", or[a][b])] {
                for (prefix, expected) in [("", truth), ("NOT", not[truth])] {
                    let compiled = predicate(&format!("{prefix}({left} {op} {right})"));
                    for age in 0..=u8::MAX {
                        assert_eq!(selected(compiled, age), expected == 1);
                    }
                }
            }
        }
    }
}
#[test]
fn unsupported_or_excessive_conditions_fail_closed_instead_of_becoming_partial_masks() {
    for clause in [
        "age IN()",
        "age NOT IN(1,)",
        "age IN(1",
        "age NOT =1",
        "age BETWEEN 1 OR 2",
        "age IS UNKNOWN",
        "amount=1",
        "age=age",
        "age<9223372036854775808",
        "age>-9223372036854775809",
        "age<--1",
        "age<+NULL",
        "age=1 OR",
        "(age=1",
        "age=1)",
        "TRUE UNKNOWN",
        "TRUE OR amount=1",
        "FALSE AND amount=1",
    ] {
        assert!(
            parse_sql(&format!("SELECT * FROM records WHERE {clause}")).is_err(),
            "{clause}"
        );
    }
    for clause in [
        format!("{}TRUE", "NOT ".repeat(129)),
        format!("{}TRUE{}", "(".repeat(129), ")".repeat(129)),
        format!(
            "age IN({})",
            std::iter::repeat_n("1", 129).collect::<Vec<_>>().join(",")
        ),
    ] {
        assert!(parse_sql(&format!("SELECT * FROM records WHERE {clause}")).is_err());
    }
}
#[test]
fn read_aggregate_and_update_share_the_identical_compiled_where_contract() {
    let clause = "NOT(age BETWEEN NULL AND 10) OR age IN(0,7,NULL)";
    let expected = predicate(clause);
    for statement in [
        "SELECT COUNT(*) FROM records",
        "SELECT SUM(amount) FROM records",
        "SELECT COUNT(*),SUM(amount) FROM records",
        "UPDATE records SET amount=amount+1",
    ] {
        let plan = parse_sql(&format!("{statement} WHERE {clause}")).unwrap();
        let actual = match plan {
            QueryPlan::Count { predicate }
            | QueryPlan::Sum { predicate }
            | QueryPlan::Aggregate { predicate }
            | QueryPlan::AddAmount { predicate, .. } => predicate,
            _ => panic!("wrong statement"),
        };
        assert_eq!(actual, expected);
    }
}
