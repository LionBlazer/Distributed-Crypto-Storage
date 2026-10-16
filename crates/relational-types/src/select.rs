use crate::{
    Error, ImportedDatabase, TableSchema, Value,
    lexer::{Parser, TokenKind, lex},
    literal_for_type,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompareOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Expr {
    Compare {
        column: usize,
        op: CompareOp,
        value: Value,
    },
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    IsNull {
        column: usize,
        negated: bool,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderBy {
    pub column: usize,
    pub descending: bool,
    /// Resolved independently of direction: PostgreSQL defaults to DESC's value.
    pub nulls_first: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectPlan {
    pub table: usize,
    pub projection: Vec<usize>,
    pub predicate: Option<Expr>,
    pub order_by: Vec<OrderBy>,
    pub limit: Option<usize>,
}

pub fn plan_select(database: &ImportedDatabase, sql: &str) -> Result<SelectPlan, Error> {
    plan_select_schemas(&database.schemas(), sql)
}

/// Schema-bound AST construction only. The caller must obtain a proof-backed answer.
pub fn plan_select_schemas(schemas: &[TableSchema], sql: &str) -> Result<SelectPlan, Error> {
    if sql.len() > 64 * 1024 {
        return Err(Error::new("SELECT exceeds the 64 KiB planning budget"));
    }
    let tokens = lex(sql)?;
    let mut parser = Parser::new(&tokens);
    parser.expect_word("SELECT")?;
    let mut limit = None;
    if parser.eat_word("TOP") {
        let parens = parser.eat_symbol('(');
        limit = Some(positive_limit(&mut parser)?);
        if parens {
            parser.expect_symbol(')')?;
        }
    }
    let all = parser.eat_symbol('*');
    let mut columns = Vec::new();
    if !all {
        loop {
            columns.push(column_name(&mut parser)?);
            if !parser.eat_symbol(',') {
                break;
            }
        }
    }
    parser.expect_word("FROM")?;
    let table_name = parser.object_name()?;
    let table = schemas
        .iter()
        .position(|schema| schema.name.eq_ignore_ascii_case(&table_name))
        .ok_or_else(|| Error::new(format!("unknown table {table_name:?}")))?;
    let schema = &schemas[table];
    crate::validate_schema(schema)?;
    let alias = if parser.eat_word("AS")
        || matches!(parser.peek(), Some(TokenKind::Quoted(_)))
        || matches!(parser.peek(),Some(TokenKind::Word(word)) if !["WHERE","ORDER","LIMIT"].iter().any(|keyword|word.eq_ignore_ascii_case(keyword)))
    {
        Some(parser.ident()?)
    } else {
        None
    };
    // As in SQL, an explicit source alias becomes the qualifier in this scope.
    let qualifier = alias.as_deref().unwrap_or(&table_name);
    let projection = if all {
        (0..schema.columns.len()).collect()
    } else {
        columns
            .iter()
            .map(|column| column.resolve(schema, qualifier))
            .collect::<Result<_, _>>()?
    };
    let predicate = if parser.eat_word("WHERE") {
        Some(parse_or(&mut parser, schema, qualifier, &mut 0)?)
    } else {
        None
    };
    let mut order_by = Vec::new();
    if parser.eat_word("ORDER") {
        parser.expect_word("BY")?;
        loop {
            let column = column_name(&mut parser)?.resolve(schema, qualifier)?;
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
            order_by.push(OrderBy {
                column,
                descending,
                nulls_first,
            });
            if !parser.eat_symbol(',') {
                break;
            }
        }
    }
    if parser.eat_word("LIMIT") {
        if limit.is_some() {
            return Err(Error::new("cannot combine TOP and LIMIT"));
        }
        limit = Some(positive_limit(&mut parser)?);
    }
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
        limit,
    })
}

fn positive_limit(parser: &mut Parser<'_>) -> Result<usize, Error> {
    parser
        .number()?
        .parse::<usize>()
        .map_err(|_| Error::new("TOP/LIMIT must be a nonnegative integer"))
}
struct ColumnRef {
    qualifier: Option<String>,
    name: String,
}
impl ColumnRef {
    fn resolve(&self, schema: &TableSchema, qualifier: &str) -> Result<usize, Error> {
        if self
            .qualifier
            .as_ref()
            .is_some_and(|candidate| !candidate.eq_ignore_ascii_case(qualifier))
        {
            return Err(Error::new(format!(
                "unknown column qualifier {:?}; expected {qualifier:?}",
                self.qualifier
            )));
        }
        schema.column_index(&self.name)
    }
}
fn column_name(parser: &mut Parser<'_>) -> Result<ColumnRef, Error> {
    let first = parser.ident()?;
    if parser.eat_symbol('.') {
        Ok(ColumnRef {
            qualifier: Some(first),
            name: parser.ident()?,
        })
    } else {
        Ok(ColumnRef {
            qualifier: None,
            name: first,
        })
    }
}
fn parse_or(
    parser: &mut Parser<'_>,
    schema: &TableSchema,
    qualifier: &str,
    budget: &mut usize,
) -> Result<Expr, Error> {
    let mut expr = parse_and(parser, schema, qualifier, budget)?;
    while parser.eat_word("OR") {
        use_budget(budget)?;
        expr = Expr::Or(
            Box::new(expr),
            Box::new(parse_and(parser, schema, qualifier, budget)?),
        );
    }
    Ok(expr)
}
fn parse_and(
    parser: &mut Parser<'_>,
    schema: &TableSchema,
    qualifier: &str,
    budget: &mut usize,
) -> Result<Expr, Error> {
    let mut expr = parse_atom(parser, schema, qualifier, budget)?;
    while parser.eat_word("AND") {
        use_budget(budget)?;
        expr = Expr::And(
            Box::new(expr),
            Box::new(parse_atom(parser, schema, qualifier, budget)?),
        );
    }
    Ok(expr)
}
fn parse_atom(
    parser: &mut Parser<'_>,
    schema: &TableSchema,
    qualifier: &str,
    budget: &mut usize,
) -> Result<Expr, Error> {
    use_budget(budget)?;
    if parser.eat_word("NOT") {
        return Ok(Expr::Not(Box::new(parse_atom(
            parser, schema, qualifier, budget,
        )?)));
    }
    if parser.eat_symbol('(') {
        let expr = parse_or(parser, schema, qualifier, budget)?;
        parser.expect_symbol(')')?;
        return Ok(expr);
    }
    let column = column_name(parser)?.resolve(schema, qualifier)?;
    if parser.eat_word("IS") {
        let negated = parser.eat_word("NOT");
        parser.expect_word("NULL")?;
        return Ok(Expr::IsNull { column, negated });
    }
    let negated = parser.eat_word("NOT");
    if parser.eat_word("BETWEEN") {
        let lower = typed_literal(parser, schema, column)?;
        parser.expect_word("AND")?;
        let upper = typed_literal(parser, schema, column)?;
        use_budget(budget)?;
        let expr = Expr::And(
            Box::new(Expr::Compare {
                column,
                op: CompareOp::Ge,
                value: lower,
            }),
            Box::new(Expr::Compare {
                column,
                op: CompareOp::Le,
                value: upper,
            }),
        );
        return Ok(if negated {
            Expr::Not(Box::new(expr))
        } else {
            expr
        });
    }
    if parser.eat_word("IN") {
        parser.expect_symbol('(')?;
        let mut expr = Expr::Compare {
            column,
            op: CompareOp::Eq,
            value: typed_literal(parser, schema, column)?,
        };
        while parser.eat_symbol(',') {
            use_budget(budget)?;
            expr = Expr::Or(
                Box::new(expr),
                Box::new(Expr::Compare {
                    column,
                    op: CompareOp::Eq,
                    value: typed_literal(parser, schema, column)?,
                }),
            );
        }
        parser.expect_symbol(')')?;
        return Ok(if negated {
            Expr::Not(Box::new(expr))
        } else {
            expr
        });
    }
    if negated {
        return Err(Error::new("NOT after a column requires BETWEEN or IN"));
    }
    let op = match parser.take()? {
        TokenKind::Operator(op) => match op.as_str() {
            "=" => CompareOp::Eq,
            "<>" | "!=" => CompareOp::Ne,
            "<" => CompareOp::Lt,
            "<=" => CompareOp::Le,
            ">" => CompareOp::Gt,
            ">=" => CompareOp::Ge,
            _ => return Err(Error::new("unsupported comparison")),
        },
        _ => {
            return Err(Error::new(
                "expected a typed comparison, IN, BETWEEN or IS NULL",
            ));
        }
    };
    Ok(Expr::Compare {
        column,
        op,
        value: typed_literal(parser, schema, column)?,
    })
}
fn use_budget(budget: &mut usize) -> Result<(), Error> {
    *budget += 1;
    if *budget > 128 {
        Err(Error::new("predicate exceeds the 128-node planning budget"))
    } else {
        Ok(())
    }
}
fn typed_literal(
    parser: &mut Parser<'_>,
    schema: &TableSchema,
    column: usize,
) -> Result<Value, Error> {
    let literal = parser.literal()?;
    let value = literal_for_type(&schema.columns[column].data_type, &literal)?;
    if !matches!(value, Value::Null) {
        crate::validate_value(&schema.columns[column], &value)?;
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import_database_dump;
    #[test]
    fn names_types_and_boolean_precedence_bind_to_the_selected_schema() {
        let database=import_database_dump("CREATE TABLE [Products] ([ProductID] int NOT NULL,[ProductName] nvarchar(40) NOT NULL,[UnitPrice] money NULL);",Default::default()).unwrap();
        let plan=plan_select(&database,"SELECT TOP (20) ProductName, UnitPrice FROM dbo.Products WHERE UnitPrice BETWEEN 10 AND 20 OR ProductID IN (1, 2) ORDER BY UnitPrice DESC;").unwrap();
        assert_eq!(plan.projection, vec![1, 2]);
        assert_eq!(plan.limit, Some(20));
        assert_eq!(
            plan.order_by,
            vec![OrderBy {
                column: 2,
                descending: true,
                nulls_first: true,
            }]
        );
        assert!(matches!(plan.predicate, Some(Expr::Or(_, _))));
        assert!(plan_select(&database, "SELECT age FROM Products").is_err());
        assert!(plan_select(&database, "SELECT * FROM Products FOR UPDATE").is_err());
        assert!(plan_select(&database, "SELECT COUNT(*) FROM Products").is_err());
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
            let error = plan_select(&database, &format!("SELECT * FROM Items WHERE {predicate}"))
                .unwrap_err();
            assert!(error.message.contains("budget"), "{}", error.message);
        }
        assert!(
            plan_select(
                &database,
                "SELECT * FROM Items WHERE NOT (id = 1 OR id BETWEEN 2 AND 3)"
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
            "SELECT Items.id FROM dbo.Items WHERE Items.id = 1 ORDER BY Items.label;",
            "SELECT i.id FROM Items AS i WHERE i.id = 1 ORDER BY i.label;",
            "SELECT i.id FROM Items i WHERE i.id = 1 ORDER BY i.label;",
            "SELECT [picked source].id FROM Items [picked source] WHERE [picked source].id = 1 ORDER BY [picked source].label;",
            "SELECT id FROM Items AS i WHERE id = 1 ORDER BY label;",
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
            "SELECT wrong.id FROM Items;",
            "SELECT id FROM Items WHERE wrong.id = 1;",
            "SELECT id FROM Items ORDER BY wrong.id;",
            "SELECT Items.id FROM Items AS i;",
            "SELECT id FROM Items AS i WHERE Items.id = 1;",
            "SELECT id FROM Items AS i ORDER BY Items.id;",
            "SELECT other.id FROM Items AS i;",
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
}
