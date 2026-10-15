//! Bounded client-side script planning. Every read/write is still executed and
//! proved by Session; this module never evaluates data or constructs query answers.
use crate::{Error, Session, VerifiedResult};
use sql_plan::QueryPlan;
use std::fmt;
use version_journal::HeadRef;

pub const MAX_SCRIPT_BYTES: usize = 64 * 1024;
/// Multi-row INSERTs count once per row: every row requires its actual proof.
pub const MAX_SCRIPT_STATEMENTS: usize = 256;

#[derive(Clone, Debug)]
pub enum SqlStatement {
    /// The only supported schema is records(age: u8, amount: u16), both NOT NULL.
    CreateTable {
        if_not_exists: bool,
    },
    Query {
        sql: String,
        plan: QueryPlan,
    },
}

#[derive(Clone, Debug)]
pub struct SqlScript {
    statements: Vec<SqlStatement>,
    source_statements: Vec<usize>,
}

#[derive(Debug)]
pub enum StatementResult {
    /// DDL creates the actual empty encrypted Session and its journal, or leaves
    /// an existing table untouched. This is not a claimed computation proof.
    Created {
        created: bool,
        version: HeadRef,
    },
    Executed(VerifiedResult),
}

#[derive(Debug)]
pub struct StatementOutcome {
    /// One-based source statement number; multi-row INSERT outcomes share it.
    pub statement: usize,
    pub result: StatementResult,
}

#[derive(Debug)]
pub struct ScriptResult {
    pub statements: Vec<StatementOutcome>,
}

/// Scripts are sequential, not transactions. Successfully completed operations
/// remain committed on a later runtime failure. Pending mutations retain Session's
/// exact identity and must be resolved without replaying earlier statements.
#[derive(Debug)]
pub struct ScriptError {
    pub failed_statement: usize,
    pub completed: Vec<StatementOutcome>,
    pub source: Error,
}

impl fmt::Display for ScriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Statement {}: {}", self.failed_statement, self.source)?;
        if self.completed.is_empty() {
            f.write_str(". No statement completed")
        } else {
            write!(
                f,
                ". {} preceding operation(s) completed and were not rolled back; this script is not a transaction",
                self.completed.len()
            )
        }
    }
}
impl std::error::Error for ScriptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl SqlScript {
    /// Fully validate all syntax and proof-supported operations before network I/O.
    /// Ordinary comments are accepted; executable/nested comments, strings,
    /// unsupported schema/types, transactions and locking clauses reject explicitly.
    pub fn parse(source: &str) -> Result<Self, ScriptError> {
        if source.len() > MAX_SCRIPT_BYTES {
            return Err(invalid(1, "SQL script exceeds the 64 KiB execution limit"));
        }
        let token_statements = tokenize(source)?;
        let mut script = Self {
            statements: Vec::new(),
            source_statements: Vec::new(),
        };
        for (index, tokens) in token_statements.into_iter().enumerate() {
            let statement = index + 1;
            let operations = prepare_statement(tokens, statement)?;
            if script.statements.len() + operations.len() > MAX_SCRIPT_STATEMENTS {
                return Err(invalid(
                    statement,
                    "SQL script exceeds 256 operations after expanding multi-row INSERTs",
                ));
            }
            script
                .source_statements
                .extend(std::iter::repeat_n(statement, operations.len()));
            script.statements.extend(operations);
        }
        if script.statements.is_empty() {
            return Err(invalid(1, "SQL script is empty"));
        }
        Ok(script)
    }

    pub fn statements(&self) -> &[SqlStatement] {
        &self.statements
    }

    pub fn statement_count(&self) -> usize {
        self.statements.len()
    }

    pub fn inserted_rows(&self) -> usize {
        self.statements
            .iter()
            .filter(|statement| {
                matches!(
                    statement,
                    SqlStatement::Query {
                        plan: QueryPlan::Insert { .. },
                        ..
                    }
                )
            })
            .count()
    }

    pub fn has_create(&self) -> bool {
        self.statements
            .iter()
            .any(|statement| matches!(statement, SqlStatement::CreateTable { .. }))
    }

    /// Validate table existence across the entire script before executing anything.
    /// The callback owns process/profile selection and must create an empty Session
    /// on actual peers. It runs at most once and only for an absent table.
    /// Session remains owned by the caller even when a later operation fails.
    pub fn execute(
        &self,
        session: &mut Option<Session>,
        create_empty: impl FnOnce() -> Result<Session, Error>,
    ) -> Result<ScriptResult, ScriptError> {
        self.check_table_lifecycle(session.is_some())?;
        let mut create_empty = Some(create_empty);
        let mut completed = Vec::new();
        for (statement, source) in self.statements.iter().zip(&self.source_statements) {
            let result = match statement {
                SqlStatement::CreateTable { .. } => {
                    let created = session.is_none();
                    if created {
                        let bootstrap = create_empty.take().ok_or_else(|| ScriptError {
                            failed_statement: *source,
                            completed: std::mem::take(&mut completed),
                            source: Error::InvalidInput("Missing empty database creator".into()),
                        })?;
                        match bootstrap() {
                            Ok(database) => *session = Some(database),
                            Err(error) => {
                                return Err(ScriptError {
                                    failed_statement: *source,
                                    completed,
                                    source: error,
                                });
                            }
                        }
                    }
                    Ok(StatementResult::Created {
                        created,
                        version: session.as_ref().expect("table lifecycle checked").version(),
                    })
                }
                SqlStatement::Query { sql, .. } => session
                    .as_mut()
                    .expect("table lifecycle checked")
                    .execute(sql)
                    .map(StatementResult::Executed),
            };
            match result {
                Ok(result) => completed.push(StatementOutcome {
                    statement: *source,
                    result,
                }),
                Err(source_error) => {
                    return Err(ScriptError {
                        failed_statement: *source,
                        completed,
                        source: source_error,
                    });
                }
            }
        }
        Ok(ScriptResult {
            statements: completed,
        })
    }

    fn check_table_lifecycle(&self, mut exists: bool) -> Result<(), ScriptError> {
        for (statement, source) in self.statements.iter().zip(&self.source_statements) {
            match statement {
                SqlStatement::CreateTable { if_not_exists } => {
                    if exists && !if_not_exists {
                        return Err(invalid(
                            *source,
                            "Table records already exists; use CREATE TABLE IF NOT EXISTS to preserve it",
                        ));
                    }
                    exists = true;
                }
                SqlStatement::Query { .. } if !exists => {
                    return Err(invalid(
                        *source,
                        "No database/table exists; run CREATE TABLE IF NOT EXISTS records (age TINYINT UNSIGNED NOT NULL, amount SMALLINT UNSIGNED NOT NULL) first",
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

fn invalid(statement: usize, message: impl Into<String>) -> ScriptError {
    ScriptError {
        failed_statement: statement,
        completed: Vec::new(),
        source: Error::InvalidInput(message.into()),
    }
}

fn prepare_statement(tokens: Vec<String>, number: usize) -> Result<Vec<SqlStatement>, ScriptError> {
    if tokens.first().is_some_and(|token| token == "CREATE") {
        let mut expected = vec!["CREATE", "TABLE"];
        let if_not_exists = tokens.get(2).is_some_and(|token| token == "IF");
        if if_not_exists {
            expected.extend(["IF", "NOT", "EXISTS"]);
        }
        expected.extend([
            "RECORDS", "(", "AGE", "TINYINT", "UNSIGNED", "NOT", "NULL", ",", "AMOUNT", "SMALLINT",
            "UNSIGNED", "NOT", "NULL", ")",
        ]);
        if tokens != expected {
            return Err(invalid(
                number,
                "Supported DDL is CREATE TABLE [IF NOT EXISTS] records (age TINYINT UNSIGNED NOT NULL, amount SMALLINT UNSIGNED NOT NULL); other tables, types, nullable columns and constraints are not implemented",
            ));
        }
        return Ok(vec![SqlStatement::CreateTable { if_not_exists }]);
    }
    if tokens.windows(2).any(|pair| pair == ["FOR", "UPDATE"]) {
        return Err(invalid(
            number,
            "SELECT FOR UPDATE requires transactions and row locking, which are not implemented; the locking clause cannot be ignored",
        ));
    }
    if tokens.first().is_some_and(|token| token == "INSERT") {
        // Expand only the literal VALUES grammar. Each generated single-row SQL
        // is validated by sql-plan and then executes through its actual FHE proof.
        if let Some(values) = tokens.iter().position(|token| token == "VALUES") {
            let prefix = &tokens[..=values];
            let mut cursor = values + 1;
            let mut operations = Vec::new();
            loop {
                let start = cursor;
                if tokens.get(cursor).map(String::as_str) != Some("(") {
                    return Err(invalid(
                        number,
                        "INSERT VALUES expects a literal (age, amount) tuple",
                    ));
                }
                cursor += 1;
                while cursor < tokens.len() && tokens[cursor] != ")" {
                    cursor += 1;
                }
                if cursor == tokens.len() {
                    return Err(invalid(number, "INSERT VALUES tuple is not closed"));
                }
                cursor += 1;
                let sql = prefix
                    .iter()
                    .chain(&tokens[start..cursor])
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(" ");
                operations.push(prepare_query(sql, number)?);
                if operations.len() > MAX_SCRIPT_STATEMENTS {
                    return Err(invalid(
                        number,
                        "INSERT exceeds the 256-operation script limit",
                    ));
                }
                if cursor == tokens.len() {
                    return Ok(operations);
                }
                if tokens[cursor] != "," {
                    return Err(invalid(
                        number,
                        "Extra clauses after INSERT VALUES are unsupported",
                    ));
                }
                cursor += 1;
            }
        }
    }
    Ok(vec![prepare_query(tokens.join(" "), number)?])
}

fn prepare_query(sql: String, number: usize) -> Result<SqlStatement, ScriptError> {
    let plan = sql_plan::parse_sql(&sql).map_err(|source| ScriptError {
        failed_statement: number,
        completed: Vec::new(),
        source: source.into(),
    })?;
    if matches!(
        plan,
        QueryPlan::Aggregate { .. } | QueryPlan::Count { .. } | QueryPlan::Sum { .. }
    ) {
        return Err(invalid(
            number,
            "COUNT/SUM computation proofs are not implemented",
        ));
    }
    Ok(SqlStatement::Query { sql, plan })
}

fn tokenize(source: &str) -> Result<Vec<Vec<String>>, ScriptError> {
    let source = source.trim_start_matches('\u{feff}');
    let bytes = source.as_bytes();
    let mut cursor = 0;
    let mut statement = Vec::new();
    let mut statements = Vec::new();
    while cursor < bytes.len() {
        let rest = &source[cursor..];
        let number = statements.len() + 1;
        if bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        } else if rest.starts_with("--") {
            cursor += rest.find('\n').unwrap_or(rest.len());
        } else if let Some(comment) = rest.strip_prefix("/*") {
            let end = comment
                .find("*/")
                .ok_or_else(|| invalid(number, "Unterminated SQL comment"))?;
            if comment[..end].contains("/*")
                || comment.starts_with('!')
                || comment.starts_with("M!")
                || comment.starts_with("m!")
            {
                return Err(invalid(
                    number,
                    "Nested or executable SQL comments are unsupported",
                ));
            }
            cursor += end + 4;
        } else if bytes[cursor] == b';' {
            if !statement.is_empty() {
                statements.push(std::mem::take(&mut statement));
                if statements.len() > MAX_SCRIPT_STATEMENTS {
                    return Err(invalid(number, "SQL script exceeds 256 source statements"));
                }
            }
            cursor += 1;
        } else if bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'_' {
            let start = cursor;
            while cursor < bytes.len()
                && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'_')
            {
                cursor += 1;
            }
            statement.push(source[start..cursor].to_ascii_uppercase());
        } else if b"(),*+=<>".contains(&bytes[cursor]) {
            let start = cursor;
            cursor += 1;
            if matches!(bytes[start], b'<' | b'>') && bytes.get(cursor) == Some(&b'=') {
                cursor += 1;
            }
            statement.push(source[start..cursor].to_string());
        } else {
            return Err(invalid(
                number,
                "Unsupported SQL character, quoted value or operator; no input is silently discarded",
            ));
        }
    }
    if !statement.is_empty() {
        statements.push(statement);
    }
    Ok(statements)
}

#[cfg(test)]
mod tests {
    use super::*;
    const CREATE: &str = "CREATE TABLE IF NOT EXISTS records (age TINYINT UNSIGNED NOT NULL, amount SMALLINT UNSIGNED NOT NULL)";

    #[test]
    fn bootstrap_script_preserves_create_and_proved_select_as_distinct_operations() {
        let script = SqlScript::parse(&format!("{CREATE}; SELECT * FROM records;")).unwrap();
        assert!(script.has_create());
        assert_eq!(script.statement_count(), 2);
        assert!(matches!(
            script.statements()[0],
            SqlStatement::CreateTable {
                if_not_exists: true
            }
        ));
        assert!(matches!(
            script.statements()[1],
            SqlStatement::Query {
                plan: QueryPlan::Select { .. },
                ..
            }
        ));
        assert!(script.check_table_lifecycle(false).is_ok());
        assert!(script.check_table_lifecycle(true).is_ok());
    }

    #[test]
    fn comments_and_multi_row_insert_preserve_every_literal_and_source_statement() {
        let script = SqlScript::parse(&format!("-- client input\n{CREATE}; /* two rows */ INSERT INTO records(age,amount) VALUES(18,20),(42,30); SELECT amount FROM records;")).unwrap();
        assert_eq!(script.inserted_rows(), 2);
        assert_eq!(script.statement_count(), 4);
        assert_eq!(script.source_statements, [1, 2, 2, 3]);
        let values: Vec<_> = script
            .statements()
            .iter()
            .filter_map(|statement| match statement {
                SqlStatement::Query {
                    plan: QueryPlan::Insert { row },
                    ..
                } => Some((row.age, row.amount)),
                _ => None,
            })
            .collect();
        assert_eq!(values, [(18, 20), (42, 30)]);
    }

    #[test]
    fn unsupported_later_statement_rejects_the_entire_plan_before_creation() {
        for unsupported in [
            "SELECT COUNT(*) FROM records",
            "SELECT * FROM records FOR UPDATE",
            "DELETE FROM records",
            "CREATE TABLE customers (id INT)",
            "INSERT INTO records VALUES (18,20),(256,30)",
        ] {
            let error = SqlScript::parse(&format!(
                "{CREATE}; INSERT INTO records VALUES(18,20); {unsupported};"
            ))
            .unwrap_err();
            assert_eq!(error.failed_statement, 3, "{unsupported}");
            assert!(error.completed.is_empty());
        }
    }

    #[test]
    fn missing_table_and_duplicate_create_never_call_the_creator() {
        for source in [
            "SELECT * FROM records".to_string(),
            format!("{CREATE}; {}", CREATE.replace("IF NOT EXISTS ", "")),
        ] {
            let mut session = None;
            let script = SqlScript::parse(&source).unwrap();
            let error = script
                .execute(&mut session, || panic!("No I/O during lifecycle rejection"))
                .unwrap_err();
            assert!(session.is_none());
            assert!(error.completed.is_empty());
        }
    }

    #[test]
    fn failed_creation_keeps_the_workspace_empty_and_reports_the_actual_error() {
        let script = SqlScript::parse(&format!("{CREATE}; SELECT * FROM records")).unwrap();
        let mut session = None;
        let error = script
            .execute(&mut session, || {
                Err(Error::InvalidInput(
                    "No authenticated peers are connected".into(),
                ))
            })
            .unwrap_err();
        assert_eq!(error.failed_statement, 1);
        assert!(error.completed.is_empty());
        assert!(error.to_string().contains("No authenticated peers"));
        assert!(session.is_none());
    }

    #[test]
    fn script_limits_and_unsupported_comment_forms_reject_before_execution() {
        for source in [
            " ".repeat(MAX_SCRIPT_BYTES + 1),
            "SELECT * FROM records;".repeat(MAX_SCRIPT_STATEMENTS + 1),
            "/* unterminated".into(),
            "/*! SELECT * FROM records */".into(),
            "/* outer /* inner */ */".into(),
            "SELECT * FROM records WHERE age = '18'".into(),
        ] {
            assert!(SqlScript::parse(&source).is_err());
        }
    }
}
