use crate::{
    Column, Comparison, Error, MAX_SQL_BYTES, Predicate, Projection, QueryPlan, RowValues,
};

/// Parses the supported fixed-schema grammar, consuming the entire input.
/// No SQL clause is silently discarded or evaluated in plaintext as a fallback.
pub fn parse_sql(sql: &str) -> Result<QueryPlan, Error> {
    if sql.len() > MAX_SQL_BYTES {
        return Err(Error::InvalidInput("SQL exceeds 4096 bytes".into()));
    }
    let tokens = tokenize(sql)?;
    let mut parser = Parser { tokens, index: 0 };
    let plan = if parser.take("SELECT") {
        parser.select()?
    } else if parser.take("INSERT") {
        parser.expect("INTO")?;
        parser.expect("RECORDS")?;
        if parser.take("(") {
            for token in ["AGE", ",", "AMOUNT", ")"] {
                parser.expect(token)?;
            }
        }
        parser.expect("VALUES")?;
        parser.expect("(")?;
        let age = parser.number("age must be in 0..=255")?;
        parser.expect(",")?;
        let amount = parser.number("amount must be in 0..=65535")?;
        parser.expect(")")?;
        QueryPlan::Insert {
            row: RowValues { age, amount },
        }
    } else if parser.take("UPDATE") {
        for token in ["RECORDS", "SET", "AMOUNT", "=", "AMOUNT", "+"] {
            parser.expect(token)?;
        }
        let delta = parser.number::<u16>("delta must be in 0..=65535")?;
        QueryPlan::AddAmount {
            predicate: parser.predicate()?,
            delta,
        }
    } else {
        return Err(unsupported("expected SELECT, INSERT or UPDATE"));
    };
    parser.take(";");
    if parser.index != parser.tokens.len() {
        return Err(unsupported("extra clauses or multiple statements"));
    }
    Ok(plan)
}

// A deliberately small lexical grammar; unsupported punctuation, comments, quoted
// identifiers, expressions and aliases fail explicitly rather than being ignored.
fn tokenize(sql: &str) -> Result<Vec<String>, Error> {
    let bytes = sql.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_whitespace() {
            index += 1;
        } else if byte.is_ascii_alphanumeric() || byte == b'_' {
            let start = index;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            tokens.push(sql[start..index].to_ascii_uppercase());
        } else if matches!(byte, b'<' | b'>') {
            let length = if bytes.get(index + 1) == Some(&b'=') {
                2
            } else {
                1
            };
            tokens.push(sql[index..index + length].into());
            index += length;
        } else if b"(),*+=;".contains(&byte) {
            tokens.push((byte as char).to_string());
            index += 1;
        } else {
            return Err(unsupported("unsupported character or operator"));
        }
    }
    Ok(tokens)
}

struct Parser {
    tokens: Vec<String>,
    index: usize,
}

impl Parser {
    fn select(&mut self) -> Result<QueryPlan, Error> {
        if self.take("COUNT") {
            for token in ["(", "*", ")"] {
                self.expect(token)?;
            }
            let both = self.take(",");
            if both {
                self.sum_expression()?;
            }
            self.expect_from_records()?;
            let predicate = self.predicate()?;
            return Ok(if both {
                QueryPlan::Aggregate { predicate }
            } else {
                QueryPlan::Count { predicate }
            });
        }
        if self.tokens.get(self.index).map(String::as_str) == Some("SUM") {
            self.sum_expression()?;
            self.expect_from_records()?;
            return Ok(QueryPlan::Sum {
                predicate: self.predicate()?,
            });
        }
        let projection = if self.take("*") {
            Projection::AgeAmount
        } else {
            let first = self.column()?;
            let second = if self.take(",") {
                Some(self.column()?)
            } else {
                None
            };
            match (first, second) {
                (Column::Age, None) => Projection::Age,
                (Column::Amount, None) => Projection::Amount,
                (Column::Age, Some(Column::Amount)) => Projection::AgeAmount,
                (Column::Amount, Some(Column::Age)) => Projection::AmountAge,
                _ => return Err(unsupported("duplicate projection column")),
            }
        };
        self.expect_from_records()?;
        let predicate = self.predicate()?;
        let limit = if self.take("LIMIT") {
            let value =
                self.number::<usize>("LIMIT must be a non-negative integer fitting usize")?;
            Some(value)
        } else {
            None
        };
        Ok(QueryPlan::Select {
            predicate,
            projection,
            limit,
        })
    }
    fn column(&mut self) -> Result<Column, Error> {
        if self.take("AGE") {
            Ok(Column::Age)
        } else {
            self.expect("AMOUNT")?;
            Ok(Column::Amount)
        }
    }
    fn sum_expression(&mut self) -> Result<(), Error> {
        for token in ["SUM", "(", "AMOUNT", ")"] {
            self.expect(token)?;
        }
        Ok(())
    }
    fn expect_from_records(&mut self) -> Result<(), Error> {
        self.expect("FROM")?;
        self.expect("RECORDS")
    }
    fn take(&mut self, token: &str) -> bool {
        if self.tokens.get(self.index).map(String::as_str) == Some(token) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, token: &str) -> Result<(), Error> {
        if self.take(token) {
            Ok(())
        } else {
            Err(unsupported(&format!("expected {token}")))
        }
    }

    fn number<T: std::str::FromStr>(&mut self, message: &str) -> Result<T, Error> {
        let token = self
            .tokens
            .get(self.index)
            .ok_or_else(|| unsupported(message))?;
        if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(unsupported(message));
        }
        let value = token.parse().map_err(|_| unsupported(message))?;
        self.index += 1;
        Ok(value)
    }

    fn predicate(&mut self) -> Result<Predicate, Error> {
        if !self.take("WHERE") {
            return Ok(Predicate::default());
        }
        self.expect("AGE")?;
        if self.take("BETWEEN") {
            let threshold = self.number("age must be in 0..=255")?;
            self.expect("AND")?;
            return Ok(Predicate {
                comparison: Comparison::Between {
                    upper: self.number("age must be in 0..=255")?,
                },
                threshold,
            });
        }
        let comparison = if self.take(">=") {
            Comparison::AtLeast
        } else if self.take("<=") {
            Comparison::AtMost
        } else if self.take("<") {
            Comparison::LessThan
        } else if self.take(">") {
            Comparison::GreaterThan
        } else {
            self.expect("=")?;
            Comparison::Equal
        };
        Ok(Predicate {
            comparison,
            threshold: self.number("age must be in 0..=255")?,
        })
    }
}

fn unsupported(reason: &str) -> Error {
    Error::UnsupportedSql(format!(
        "{reason}. Supported: SELECT *, age, amount, COUNT(*), SUM(amount), or COUNT(*), SUM(amount) FROM records; INSERT INTO records (age, amount) VALUES (A, N); UPDATE records SET amount = amount + N. Optional read/update WHERE age =, <, <=, >, >= N or age BETWEEN lower AND upper. Row SELECT allows a non-negative LIMIT; execution resource budgets are checked by the executor."
    ))
}
