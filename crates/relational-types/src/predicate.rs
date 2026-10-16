//! Shared bounded typed predicate grammar; binding policy is explicit per caller.
use crate::{
    Error, Value,
    lexer::{Parser, TokenKind},
    literal_for_type,
    names::{Rules, Scope},
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
pub(crate) fn parse(
    parser: &mut Parser<'_>,
    scope: &Scope<'_>,
    source_now: Option<&str>,
) -> Result<Expr, Error> {
    parse_or(parser, scope, source_now, &mut 0)
}
fn parse_or(
    parser: &mut Parser<'_>,
    scope: &Scope<'_>,
    source_now: Option<&str>,
    budget: &mut usize,
) -> Result<Expr, Error> {
    let mut expr = parse_and(parser, scope, source_now, budget)?;
    while parser.eat_word("OR") {
        use_budget(budget)?;
        expr = Expr::Or(
            Box::new(expr),
            Box::new(parse_and(parser, scope, source_now, budget)?),
        );
    }
    Ok(expr)
}
fn parse_and(
    parser: &mut Parser<'_>,
    scope: &Scope<'_>,
    source_now: Option<&str>,
    budget: &mut usize,
) -> Result<Expr, Error> {
    let mut expr = parse_atom(parser, scope, source_now, budget)?;
    while parser.eat_word("AND") {
        use_budget(budget)?;
        expr = Expr::And(
            Box::new(expr),
            Box::new(parse_atom(parser, scope, source_now, budget)?),
        );
    }
    Ok(expr)
}
fn parse_atom(
    parser: &mut Parser<'_>,
    scope: &Scope<'_>,
    source_now: Option<&str>,
    budget: &mut usize,
) -> Result<Expr, Error> {
    use_budget(budget)?;
    if parser.eat_word("NOT") {
        return Ok(Expr::Not(Box::new(parse_atom(
            parser, scope, source_now, budget,
        )?)));
    }
    if parser.eat_symbol('(') {
        let expr = parse_or(parser, scope, source_now, budget)?;
        parser.expect_symbol(')')?;
        return Ok(expr);
    }
    let column = scope.column(parser)?;
    if parser.eat_word("IS") {
        let negated = parser.eat_word("NOT");
        parser.expect_word("NULL")?;
        return Ok(Expr::IsNull { column, negated });
    }
    let negated = parser.eat_word("NOT");
    if parser.eat_word("BETWEEN") {
        let lower = typed_literal(parser, scope, source_now, column)?;
        parser.expect_word("AND")?;
        let upper = typed_literal(parser, scope, source_now, column)?;
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
            value: typed_literal(parser, scope, source_now, column)?,
        };
        while parser.eat_symbol(',') {
            use_budget(budget)?;
            expr = Expr::Or(
                Box::new(expr),
                Box::new(Expr::Compare {
                    column,
                    op: CompareOp::Eq,
                    value: typed_literal(parser, scope, source_now, column)?,
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
        value: typed_literal(parser, scope, source_now, column)?,
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
    scope: &Scope<'_>,
    source_now: Option<&str>,
    column: usize,
) -> Result<Value, Error> {
    let schema = scope.schema;
    let literal = if scope.rules == Rules::SqlServerDump && parser.eat_word("GETDATE") {
        parser.expect_symbol('(')?;
        parser.expect_symbol(')')?;
        TokenKind::String(
            source_now
                .ok_or_else(|| Error::new("missing import validation time"))?
                .to_owned(),
        )
    } else {
        parser.literal()?
    };
    // A comparison does not store the literal in this column. Its typmod must
    // neither reject a longer string nor pad/truncate the predicate operand.
    if matches!(
        schema.columns[column].data_type,
        crate::DataType::Text { .. }
    ) && let TokenKind::String(text) = &literal
    {
        return Ok(Value::Text(text.clone()));
    }
    let value = literal_for_type(&schema.columns[column].data_type, &literal)?;
    if !matches!(value, Value::Null) {
        crate::validate_value(&schema.columns[column], &value)?;
    }
    Ok(value)
}
