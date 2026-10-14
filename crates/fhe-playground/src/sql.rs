#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Comparison {
    Equal,
    AtLeast,
}

use crate::LabError;

pub const MAX_SQL_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Predicate {
    pub comparison: Comparison,
    pub threshold: u8,
}

impl Default for Predicate {
    fn default() -> Self {
        Self {
            comparison: Comparison::AtLeast,
            threshold: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryPlan {
    Aggregate { predicate: Predicate },
    AddAmount { predicate: Predicate, delta: u16 },
}

pub struct Preset {
    pub name: &'static str,
    pub sql: &'static str,
}

pub const PRESETS: &[Preset] = &[
    Preset {
        name: "All rows",
        sql: "SELECT COUNT(*), SUM(amount)\nFROM records;",
    },
    Preset {
        name: "Adults",
        sql: "SELECT COUNT(*), SUM(amount)\nFROM records\nWHERE age >= 18;",
    },
    Preset {
        name: "Age 18",
        sql: "SELECT COUNT(*), SUM(amount)\nFROM records\nWHERE age = 18;",
    },
    Preset {
        name: "No matches",
        sql: "SELECT COUNT(*), SUM(amount)\nFROM records\nWHERE age = 255;",
    },
    Preset {
        name: "Add 5",
        sql: "UPDATE records\nSET amount = amount + 5\nWHERE age >= 18;",
    },
    Preset {
        name: "Overflow test",
        sql: "UPDATE records\nSET amount = amount + 65535\nWHERE age >= 18;",
    },
];

/// Parses only the documented laboratory grammar, consuming the entire input.
/// No SQL clause is silently discarded or evaluated in plaintext as a fallback.
pub fn parse_sql(sql: &str) -> Result<QueryPlan, LabError> {
    if sql.len() > MAX_SQL_BYTES {
        return Err(LabError::InvalidInput("SQL exceeds 4096 bytes".into()));
    }
    let tokens = tokenize(sql)?;
    let mut parser = Parser { tokens, index: 0 };
    let plan = if parser.take("SELECT") {
        for token in [
            "COUNT", "(", "*", ")", ",", "SUM", "(", "AMOUNT", ")", "FROM", "RECORDS",
        ] {
            parser.expect(token)?;
        }
        QueryPlan::Aggregate {
            predicate: parser.predicate()?,
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
        return Err(unsupported("expected SELECT or UPDATE"));
    };
    parser.take(";");
    if parser.index != parser.tokens.len() {
        return Err(unsupported("extra clauses or multiple statements"));
    }
    Ok(plan)
}

// A deliberately small lexical grammar; unsupported punctuation, comments, quoted
// identifiers, expressions and aliases fail explicitly rather than being ignored.
fn tokenize(sql: &str) -> Result<Vec<String>, LabError> {
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
        } else if byte == b'>' && bytes.get(index + 1) == Some(&b'=') {
            tokens.push(">=".into());
            index += 2;
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
    fn take(&mut self, token: &str) -> bool {
        if self.tokens.get(self.index).map(String::as_str) == Some(token) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, token: &str) -> Result<(), LabError> {
        if self.take(token) {
            Ok(())
        } else {
            Err(unsupported(&format!("expected {token}")))
        }
    }

    fn number<T: std::str::FromStr>(&mut self, message: &str) -> Result<T, LabError> {
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

    fn predicate(&mut self) -> Result<Predicate, LabError> {
        if !self.take("WHERE") {
            return Ok(Predicate::default());
        }
        self.expect("AGE")?;
        let comparison = if self.take(">=") {
            Comparison::AtLeast
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

fn unsupported(reason: &str) -> LabError {
    LabError::UnsupportedSql(format!(
        "{reason}. Supported: SELECT COUNT(*), SUM(amount) FROM records or UPDATE records SET amount = amount + N; optional WHERE age = N / age >= N."
    ))
}
