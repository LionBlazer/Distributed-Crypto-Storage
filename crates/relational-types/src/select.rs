use crate::{
    Error, ImportedDatabase, TableSchema,
    lexer::{Parser, TokenKind, lex},
    names::{self, Rules, Scope},
    predicate::{self, Expr},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderBy {
    pub column: usize,
    pub descending: bool,
    /// Resolved independently of direction: PostgreSQL defaults to DESC's value.
    pub nulls_first: bool,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RowWindow {
    /// Rows skipped after filtering and ordering, before counting the result.
    pub offset: usize,
    /// None means unbounded (LIMIT ALL/NULL or a NULL FETCH count).
    pub limit: Option<usize>,
    /// Extend a nonempty limit to the last row's ORDER BY peers, excluding OFFSET.
    pub with_ties: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectPlan {
    pub table: usize,
    pub projection: Vec<usize>,
    pub predicate: Option<Expr>,
    pub order_by: Vec<OrderBy>,
    pub window: RowWindow,
}

pub fn plan_select(database: &ImportedDatabase, sql: &str) -> Result<SelectPlan, Error> {
    plan_select_schemas(&database.schemas(), sql)
}

/// Schema-bound AST construction only. The caller must obtain a proof-backed answer.
pub fn plan_select_schemas(schemas: &[TableSchema], sql: &str) -> Result<SelectPlan, Error> {
    if sql.len() > 64 * 1024 {
        return Err(Error::new("SELECT exceeds the 64 KiB planning budget"));
    }
    names::validate_postgresql_catalog(schemas)?;
    let tokens = lex(sql)?;
    let mut parser = Parser::new(&tokens);
    parser.expect_word("SELECT")?;
    let mut limit = None;
    if parser.eat_word("TOP") {
        let parens = parser.eat_symbol('(');
        limit = Some(nonnegative_count(&mut parser)?);
        if parens {
            parser.expect_symbol(')')?;
        }
    }
    let all = parser.eat_symbol('*');
    let mut columns = Vec::new();
    if !all {
        loop {
            let start = parser.position;
            Rules::PostgreSql.ident(&mut parser, false)?;
            let mut parts = 1;
            while parser.eat_symbol('.') {
                parts += 1;
                if parts > 3 {
                    return Err(Error::new(
                        "column qualification exceeds schema/table/column",
                    ));
                }
                Rules::PostgreSql.ident(&mut parser, true)?;
            }
            columns.push(&tokens[start..parser.position]);
            if !parser.eat_symbol(',') {
                break;
            }
        }
    }
    parser.expect_word("FROM")?;
    let table_name = names::relation(&mut parser)?;
    let table = schemas
        .iter()
        .position(|schema| schema.name == table_name)
        .ok_or_else(|| Error::new(format!("unknown table {table_name:?}")))?;
    let schema = &schemas[table];
    crate::validate_schema(schema)?;
    let alias = if parser.eat_word("AS")
        || matches!(parser.peek(), Some(TokenKind::Quoted(_)))
        || matches!(parser.peek(),Some(TokenKind::Word(word)) if !["WHERE","ORDER","LIMIT","OFFSET","FETCH"].iter().any(|keyword|word.eq_ignore_ascii_case(keyword)))
    {
        Some(Rules::PostgreSql.ident(&mut parser, false)?)
    } else {
        None
    };
    // As in SQL, an explicit source alias becomes the qualifier in this scope.
    let scope = Scope {
        schema,
        alias: alias.as_deref(),
        rules: Rules::PostgreSql,
    };
    let projection = if all {
        (0..schema.columns.len()).collect()
    } else {
        columns
            .iter()
            .map(|column| scope.column(&mut Parser::new(column)))
            .collect::<Result<_, _>>()?
    };
    let predicate = if parser.eat_word("WHERE") {
        Some(predicate::parse(&mut parser, &scope, None)?)
    } else {
        None
    };
    let mut order_by = Vec::new();
    if parser.eat_word("ORDER") {
        parser.expect_word("BY")?;
        let mut ordered_columns = vec![false; schema.columns.len()];
        loop {
            let column = scope.column(&mut parser)?;
            let descending = parser.eat_word("DESC");
            if !descending {
                parser.eat_word("ASC");
            }
            let nulls_first = if parser.eat_word("NULLS") {
                if parser.eat_word("FIRST") {
                    true
                } else {
                    parser.expect_word("LAST")?;
                    false
                }
            } else {
                descending
            };
            // Later keys are consulted only when earlier values compare equal.
            // Repeating the same column cannot break that tie, even with another
            // direction or NULL placement. Bound executor work to distinct columns.
            if !ordered_columns[column] {
                ordered_columns[column] = true;
                order_by.push(OrderBy {
                    column,
                    descending,
                    nulls_first,
                });
            }
            if !parser.eat_symbol(',') {
                break;
            }
        }
    }
    let window = row_window(&mut parser, limit, !order_by.is_empty())?;
    parser.eat_symbol(';');
    if !parser.done() {
        return Err(Error::new(format!(
            "unsupported SELECT syntax after {:?}; joins, aggregates, locks and multiple statements require their own proof circuits",
            parser.peek()
        )));
    }
    Ok(SelectPlan {
        table,
        projection,
        predicate,
        order_by,
        window,
    })
}

fn nonnegative_count(parser: &mut Parser<'_>) -> Result<usize, Error> {
    parser
        .number()?
        .parse::<i64>()
        .ok()
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| {
            Error::new("row count must be a nonnegative integer fitting SQL bigint and usize")
        })
}
fn nullable_count(parser: &mut Parser<'_>) -> Result<Option<usize>, Error> {
    let parens = parser.eat_symbol('(');
    let count = if parser.eat_word("NULL") {
        None
    } else {
        Some(nonnegative_count(parser)?)
    };
    if parens {
        parser.expect_symbol(')')?;
    }
    Ok(count)
}
fn row_window(
    parser: &mut Parser<'_>,
    top: Option<usize>,
    ordered: bool,
) -> Result<RowWindow, Error> {
    let mut window = RowWindow {
        limit: top,
        ..RowWindow::default()
    };
    let mut limited = top.is_some();
    let mut offset = false;
    // PostgreSQL accepts OFFSET before or after either LIMIT or FETCH. Keep
    // occurrence flags separate from NULL/unbounded values to reject duplicates.
    loop {
        if parser.eat_word("LIMIT") {
            if limited {
                return Err(Error::new("duplicate or conflicting TOP/LIMIT/FETCH"));
            }
            limited = true;
            window.limit = if parser.eat_word("ALL") {
                None
            } else {
                nullable_count(parser)?
            };
        } else if parser.eat_word("OFFSET") {
            if offset {
                return Err(Error::new("duplicate OFFSET"));
            }
            offset = true;
            window.offset = nullable_count(parser)?.unwrap_or(0);
            if !parser.eat_word("ROW") {
                parser.eat_word("ROWS");
            }
        } else if parser.eat_word("FETCH") {
            if limited {
                return Err(Error::new("duplicate or conflicting TOP/LIMIT/FETCH"));
            }
            limited = true;
            if !parser.eat_word("FIRST") {
                parser.expect_word("NEXT")?;
            }
            window.limit = if parser
                .peek()
                .is_some_and(|token| token.word_is("ROW") || token.word_is("ROWS"))
            {
                Some(1)
            } else {
                nullable_count(parser)?
            };
            if !parser.eat_word("ROW") {
                parser.expect_word("ROWS")?;
            }
            if parser.eat_word("WITH") {
                parser.expect_word("TIES")?;
                window.with_ties = true;
            } else {
                parser.expect_word("ONLY")?;
            }
        } else {
            break;
        }
    }
    if window.with_ties && !ordered {
        return Err(Error::new("FETCH WITH TIES requires ORDER BY"));
    }
    Ok(window)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CompareOp, Value, import_database_dump};
    #[test]
    fn row_windows_bind_null_defaults_offsets_and_fetch_peer_groups() {
        let database =
            import_database_dump("CREATE TABLE ranks (id INT NOT NULL);", Default::default())
                .unwrap();
        for (clause, offset, limit, with_ties) in [
            ("", 0, None, false),
            ("OFFSET 3", 3, None, false),
            ("LIMIT ALL OFFSET 3 ROWS", 3, None, false),
            ("OFFSET NULL ROW LIMIT NULL", 0, None, false),
            ("LIMIT (2) OFFSET (+3)", 3, Some(2), false),
            ("OFFSET -0 LIMIT +2", 0, Some(2), false),
            ("FETCH FIRST ROW ONLY", 0, Some(1), false),
            ("FETCH NEXT ROWS ONLY OFFSET 3", 3, Some(1), false),
            ("OFFSET 3 ROWS FETCH NEXT 2 ROWS ONLY", 3, Some(2), false),
            (
                "FETCH FIRST (2) ROWS WITH TIES OFFSET (3)",
                3,
                Some(2),
                true,
            ),
            ("FETCH FIRST NULL ROWS WITH TIES", 0, None, true),
            ("FETCH FIRST 0 ROWS WITH TIES", 0, Some(0), true),
            (
                "LIMIT 9223372036854775807 OFFSET 9223372036854775807",
                i64::MAX as usize,
                Some(i64::MAX as usize),
                false,
            ),
        ] {
            let sql = format!("SELECT id FROM ranks ORDER BY id {clause};");
            assert_eq!(
                plan_select(&database, &sql).unwrap().window,
                RowWindow {
                    offset,
                    limit,
                    with_ties
                },
                "{sql}"
            );
        }
    }

    #[test]
    fn incomplete_duplicate_or_out_of_range_row_windows_reject_without_a_plan() {
        let database =
            import_database_dump("CREATE TABLE ranks (id INT NOT NULL);", Default::default())
                .unwrap();
        for clause in [
            "LIMIT",
            "LIMIT -1",
            "LIMIT 1.5",
            "LIMIT 9223372036854775808",
            "LIMIT ALL LIMIT 1",
            "LIMIT NULL FETCH FIRST ROW ONLY",
            "OFFSET",
            "OFFSET -1",
            "OFFSET ALL",
            "OFFSET 9223372036854775808",
            "OFFSET NULL OFFSET 1",
            "OFFSET 1 ROW ROWS",
            "OFFSET 1 + 1",
            "FETCH",
            "FETCH ROW ONLY",
            "FETCH FIRST",
            "FETCH FIRST 2 ONLY",
            "FETCH FIRST 2 ROWS",
            "FETCH FIRST -1 ROWS ONLY",
            "FETCH FIRST 9223372036854775808 ROWS ONLY",
            "FETCH NEXT ALL ROWS ONLY",
            "FETCH FIRST ROW WITH",
            "FETCH FIRST ROW WITH TIES FETCH NEXT ROW ONLY",
            "FETCH FIRST ROW ONLY LIMIT ALL",
            "LIMIT 1 OFFSET 2 WHERE id = 1",
            "LIMIT 1; SELECT id FROM ranks",
            "FETCH FIRST ROW ONLY FOR UPDATE SKIP LOCKED",
        ] {
            assert!(
                plan_select(
                    &database,
                    &format!("SELECT id FROM ranks ORDER BY id {clause}")
                )
                .is_err(),
                "{clause}"
            );
        }
        assert!(
            plan_select(&database, "SELECT id FROM ranks FETCH FIRST ROW WITH TIES")
                .unwrap_err()
                .message
                .contains("requires ORDER BY")
        );
        assert!(plan_select(&database, "SELECT TOP 1 id FROM ranks FETCH FIRST ROW ONLY").is_err());
        assert!(plan_select(&database, "SELECT TOP 1 id FROM ranks LIMIT NULL").is_err());
    }

    #[test]
    fn comparison_text_literals_do_not_inherit_the_columns_storage_width() {
        for sql_type in ["VARCHAR(1)", "NVARCHAR(1)", "CHAR(1)", "NCHAR(1)"] {
            let source = format!("CREATE TABLE labels (label {sql_type});");
            let database = import_database_dump(&source, Default::default()).unwrap();
            for text in ["a", "a ", "longer than one", "海🌊"] {
                let sql = format!("SELECT label FROM labels WHERE label = '{text}'");
                let plan = plan_select(&database, &sql).unwrap();
                assert_eq!(
                    plan.predicate,
                    Some(Expr::Compare {
                        column: 0,
                        op: CompareOp::Eq,
                        value: Value::Text(text.into()),
                    }),
                    "{sql_type}: {sql}"
                );
            }
            assert!(
                import_database_dump(
                    &format!("{source} INSERT INTO labels VALUES ('longer than one');"),
                    Default::default(),
                )
                .is_err(),
                "storage validation remains mandatory"
            );
        }
    }
    #[test]
    fn names_types_and_boolean_precedence_bind_to_the_selected_schema() {
        let database=import_database_dump("CREATE TABLE [Products] ([ProductID] int NOT NULL,[ProductName] nvarchar(40) NOT NULL,[UnitPrice] money NULL);",Default::default()).unwrap();
        let plan=plan_select(&database,"SELECT TOP (20) \"ProductName\", \"UnitPrice\" FROM public.\"Products\" WHERE \"UnitPrice\" BETWEEN 10 AND 20 OR \"ProductID\" IN (1, 2) ORDER BY \"UnitPrice\" DESC;").unwrap();
        assert_eq!(plan.projection, vec![1, 2]);
        assert_eq!(plan.window.limit, Some(20));
        assert_eq!(
            plan.order_by,
            vec![OrderBy {
                column: 2,
                descending: true,
                nulls_first: true,
            }]
        );
        assert!(matches!(plan.predicate, Some(Expr::Or(_, _))));
        assert!(plan_select(&database, "SELECT age FROM \"Products\"").is_err());
        assert!(plan_select(&database, "SELECT * FROM \"Products\" FOR UPDATE").is_err());
        assert!(plan_select(&database, "SELECT COUNT(*) FROM \"Products\"").is_err());
    }

    #[test]
    fn hostile_predicate_depth_and_left_deep_boolean_chains_are_rejected_before_execution() {
        let database =
            import_database_dump("CREATE TABLE Items(id int NOT NULL);", Default::default())
                .unwrap();
        for predicate in [
            format!("{}id = 1", "NOT ".repeat(500)),
            format!("{}id = 1{}", "(".repeat(500), ")".repeat(500)),
            std::iter::repeat_n("id = 1", 500)
                .collect::<Vec<_>>()
                .join(" OR "),
            format!(
                "id IN ({})",
                std::iter::repeat_n("1", 500).collect::<Vec<_>>().join(",")
            ),
        ] {
            let error = plan_select(
                &database,
                &format!("SELECT * FROM \"Items\" WHERE {predicate}"),
            )
            .unwrap_err();
            assert!(error.message.contains("budget"), "{}", error.message);
        }
        assert!(
            plan_select(
                &database,
                "SELECT * FROM \"Items\" WHERE NOT (id = 1 OR id BETWEEN 2 AND 3)"
            )
            .is_ok()
        );
    }

    #[test]
    fn source_qualifiers_and_aliases_bind_projection_predicates_and_ordering() {
        let database = import_database_dump(
            "CREATE TABLE Items(id int NOT NULL, label nvarchar(20) NULL);",
            Default::default(),
        )
        .unwrap();
        for sql in [
            "SELECT \"Items\".id FROM public.\"Items\" WHERE \"Items\".id = 1 ORDER BY \"Items\".label;",
            "SELECT i.id FROM \"Items\" AS i WHERE i.id = 1 ORDER BY i.label;",
            "SELECT i.id FROM \"Items\" i WHERE i.id = 1 ORDER BY i.label;",
            "SELECT \"picked source\".id FROM \"Items\" \"picked source\" WHERE \"picked source\".id = 1 ORDER BY \"picked source\".label;",
            "SELECT id FROM \"Items\" AS i WHERE id = 1 ORDER BY label;",
        ] {
            let plan = plan_select(&database, sql).unwrap();
            assert_eq!(plan.projection, vec![0], "{sql}");
            assert_eq!(
                plan.predicate,
                Some(Expr::Compare {
                    column: 0,
                    op: CompareOp::Eq,
                    value: Value::Integer(1)
                }),
                "{sql}"
            );
            assert_eq!(
                plan.order_by,
                vec![OrderBy {
                    column: 1,
                    descending: false,
                    nulls_first: false,
                }],
                "{sql}"
            );
        }
        for sql in [
            "SELECT wrong.id FROM \"Items\";",
            "SELECT id FROM \"Items\" WHERE wrong.id = 1;",
            "SELECT id FROM \"Items\" ORDER BY wrong.id;",
            "SELECT \"Items\".id FROM \"Items\" AS i;",
            "SELECT id FROM \"Items\" AS i WHERE \"Items\".id = 1;",
            "SELECT id FROM \"Items\" AS i ORDER BY \"Items\".id;",
            "SELECT other.id FROM \"Items\" AS i;",
        ] {
            assert!(
                plan_select(&database, sql)
                    .unwrap_err()
                    .message
                    .contains("qualifier"),
                "{sql}"
            );
        }
    }

    #[test]
    fn null_ordering_options_bind_each_key_and_reject_incomplete_clauses() {
        let database = import_database_dump(
            "CREATE TABLE ranks (id INT NOT NULL, score INT NULL);",
            Default::default(),
        )
        .unwrap();
        for (tail, descending, nulls_first) in [
            ("", false, false),
            ("ASC", false, false),
            ("DESC", true, true),
            ("NULLS FIRST", false, true),
            ("ASC NULLS FIRST", false, true),
            ("DESC NULLS FIRST", true, true),
            ("ASC NULLS LAST", false, false),
            ("DESC NULLS LAST", true, false),
        ] {
            let sql = format!("SELECT id FROM ranks ORDER BY score {tail}, id DESC NULLS LAST");
            let plan = plan_select(&database, &sql).unwrap();
            assert_eq!(
                plan.order_by,
                [
                    OrderBy {
                        column: 1,
                        descending,
                        nulls_first,
                    },
                    OrderBy {
                        column: 0,
                        descending: true,
                        nulls_first: false,
                    },
                ],
                "{sql}"
            );
        }
        for tail in ["NULLS", "NULLS MIDDLE", "NULLS FIRST LAST", "ASC DESC"] {
            assert!(
                plan_select(
                    &database,
                    &format!("SELECT id FROM ranks ORDER BY score {tail}")
                )
                .is_err(),
                "{tail}"
            );
        }
    }

    #[test]
    fn repeated_ordering_columns_do_not_expand_the_executor_working_set() {
        let database = import_database_dump(
            "CREATE TABLE ranks (id INT NOT NULL, score INT NULL);",
            Default::default(),
        )
        .unwrap();
        let repeated = std::iter::repeat_n("score ASC NULLS LAST", 2_000)
            .collect::<Vec<_>>()
            .join(", ");
        let sql =
            format!("SELECT id FROM ranks ORDER BY {repeated}, id DESC, score DESC NULLS FIRST");
        let plan = plan_select(&database, &sql).unwrap();
        assert_eq!(plan.order_by.len(), 2);
        assert_eq!(
            plan.order_by,
            [
                OrderBy {
                    column: 1,
                    descending: false,
                    nulls_first: false,
                },
                OrderBy {
                    column: 0,
                    descending: true,
                    nulls_first: true,
                },
            ]
        );
        assert!(
            plan_select(
                &database,
                "SELECT id FROM ranks ORDER BY score, score NULLS MIDDLE"
            )
            .is_err(),
            "Eliminating a redundant key must not skip validation of its syntax"
        );
    }
}
