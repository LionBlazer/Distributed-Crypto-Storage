//! Bounded script preflight. Data statements reject before execution; only the
//! existing empty CREATE provisioning is admitted. No data is evaluated here.
use crate::{Error, Session, VerifiedResult};
use sql_plan::QueryPlan;
use std::fmt;
use version_journal::HeadRef;

pub const MAX_SCRIPT_BYTES: usize = 64 * 1024;
pub const MAX_SCRIPT_STATEMENTS: usize = 256;
/// Bound literal input independently of statement count and backend capacity.
pub const MAX_SCRIPT_INSERTED_ROWS: usize = 256;

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
    /// One-based source statement number; one INSERT batch produces one outcome.
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
    /// Fully validate syntax and capability availability before network I/O.
    /// Each INSERT remains one statement; at most 256 literal rows may be supplied
    /// across all INSERT batches, independently of the 256-statement limit.
    /// Ordinary comments are accepted; executable/nested comments, strings,
    /// unsupported schema/types, transactions and locking clauses reject explicitly.
    pub fn parse(source: &str) -> Result<Self, ScriptError> {
        if source.len() > MAX_SCRIPT_BYTES {
            return Err(invalid(1, "SQL script exceeds the 64 KiB execution limit"));
        }
        let token_statements = tokenize(source)?;
        let mut script = Self {
            statements: Vec::new(),
        };
        let mut inserted_rows = 0;
        for (index, tokens) in token_statements.into_iter().enumerate() {
            let statement = index + 1;
            if statement > MAX_SCRIPT_STATEMENTS {
                return Err(invalid(
                    statement,
                    "SQL script exceeds 256 source statements",
                ));
            }
            let operation = prepare_statement(tokens, statement)?;
            if let SqlStatement::Query {
                plan: QueryPlan::Insert { rows },
                ..
            } = &operation
            {
                inserted_rows += rows.len();
                if inserted_rows > MAX_SCRIPT_INSERTED_ROWS {
                    return Err(invalid(
                        statement,
                        "SQL script exceeds the 256 inserted-row input limit",
                    ));
                }
            }
            script.statements.push(operation);
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
            .map(|statement| match statement {
                SqlStatement::Query {
                    plan: QueryPlan::Insert { rows },
                    ..
                } => rows.len(),
                _ => 0,
            })
            .sum()
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
        for (index, statement) in self.statements.iter().enumerate() {
            let source = index + 1;
            let result = match statement {
                SqlStatement::CreateTable { .. } => {
                    let created = session.is_none();
                    if created {
                        let bootstrap = create_empty.take().ok_or_else(|| ScriptError {
                            failed_statement: source,
                            completed: std::mem::take(&mut completed),
                            source: Error::InvalidInput("Missing empty database creator".into()),
                        })?;
                        match bootstrap() {
                            Ok(database) => *session = Some(database),
                            Err(error) => {
                                return Err(ScriptError {
                                    failed_statement: source,
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
                    statement: source,
                    result,
                }),
                Err(source_error) => {
                    return Err(ScriptError {
                        failed_statement: source,
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
        for (index, statement) in self.statements.iter().enumerate() {
            let source = index + 1;
            match statement {
                SqlStatement::CreateTable { if_not_exists } => {
                    if exists && !if_not_exists {
                        return Err(invalid(
                            source,
                            "Table records already exists; use CREATE TABLE IF NOT EXISTS to preserve it",
                        ));
                    }
                    exists = true;
                }
                SqlStatement::Query { .. } if !exists => {
                    return Err(invalid(
                        source,
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

fn prepare_statement(tokens: Vec<String>, number: usize) -> Result<SqlStatement, ScriptError> {
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
        return Ok(SqlStatement::CreateTable { if_not_exists });
    }
    // Keep lexical boundaries without inflating punctuation-heavy batches beyond
    // sql-plan's statement-byte limit. Separated comparison symbols must not turn
    // malformed `< =` or `> =` into a supported compound operator.
    let mut sql = String::new();
    let mut previous: Option<&str> = None;
    let word = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    for token in &tokens {
        if previous.is_some_and(|previous| {
            (previous.bytes().next_back().is_some_and(word)
                && token.bytes().next().is_some_and(word))
                || (matches!(previous, "<" | ">" | "!") && matches!(token.as_str(), "=" | ">"))
        }) {
            sql.push(' ');
        }
        sql.push_str(token);
        previous = Some(token);
    }
    prepare_query(sql, number)
}

fn prepare_query(sql: String, number: usize) -> Result<SqlStatement, ScriptError> {
    let plan = sql_plan::parse_sql(&sql).map_err(|source| ScriptError {
        failed_statement: number,
        completed: Vec::new(),
        source: source.into(),
    })?;
    // Reject unavailable complete SQL proofs before any earlier statement can
    // create a database, store rows or resume a mutation.
    crate::require_sql_capability(&plan).map_err(|source| ScriptError {
        failed_statement: number,
        completed: Vec::new(),
        source,
    })?;
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
        } else if b"(),*+=<>!-".contains(&bytes[cursor]) {
            let start = cursor;
            cursor += 1;
            if (matches!(bytes[start], b'<' | b'>' | b'!') && bytes.get(cursor) == Some(&b'='))
                || (bytes[start] == b'<' && bytes.get(cursor) == Some(&b'>'))
            {
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
    fn unavailable_sql_rejects_the_whole_script_before_any_creation() {
        for sql in [
            "SELECT * FROM records",
            "SELECT amount FROM records LIMIT 0",
            "SELECT COUNT(*) FROM records",
            "SELECT SUM(amount) FROM records WHERE FALSE",
            "UPDATE records SET amount=amount+0 WHERE TRUE",
            "INSERT INTO records VALUES (18,20)",
        ] {
            let error = SqlScript::parse(&format!("{CREATE}; {sql}")).unwrap_err();
            assert_eq!(error.failed_statement, 2, "{sql}");
            assert!(error.completed.is_empty());
            assert!(
                error
                    .to_string()
                    .contains("encrypted SQL execution is unavailable"),
                "{error}"
            );
        }
        let error = SqlScript::parse(&format!(
            "{CREATE}; INSERT INTO records VALUES(18,20); SELECT * FROM records"
        ))
        .unwrap_err();
        assert_eq!(error.failed_statement, 2);
        assert!(error.completed.is_empty());
    }

    #[test]
    fn lexical_comments_literals_and_compound_tokens_remain_parser_inputs() {
        let tokens = tokenize("\u{feff}-- public fixture\nINSERT INTO records VALUES(18,20),(255,65535); /* ordinary */ SELECT * FROM records WHERE age<>-1 AND age!=+42").unwrap();
        assert_eq!(tokens.len(), 2);
        assert!(tokens[1].iter().any(|token| token == "<>"));
        assert!(tokens[1].iter().any(|token| token == "!="));
        let error = prepare_query("INSERT INTO records VALUES(18,20)".into(), 1).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("encrypted SQL execution is unavailable")
        );
    }

    #[test]
    fn literal_and_statement_limits_are_checked_at_their_owning_parser_boundary() {
        let tuples = std::iter::repeat_n("(255,65535)", MAX_SCRIPT_INSERTED_ROWS)
            .collect::<Vec<_>>()
            .join(",");
        let source = format!("INSERT INTO records VALUES {tuples}");
        assert!(source.len() < sql_plan::MAX_SQL_BYTES);
        let QueryPlan::Insert { rows } = sql_plan::parse_sql(&source).unwrap() else {
            panic!("INSERT syntax expected")
        };
        assert_eq!(rows.len(), MAX_SCRIPT_INSERTED_ROWS);
        assert_eq!(
            rows[255],
            sql_plan::RowValues {
                age: 255,
                amount: 65535
            }
        );
        let ddl = format!("{CREATE};").repeat(MAX_SCRIPT_STATEMENTS);
        assert_eq!(
            SqlScript::parse(&ddl).unwrap().statement_count(),
            MAX_SCRIPT_STATEMENTS
        );
        let error = SqlScript::parse(&format!("{ddl}{CREATE}")).unwrap_err();
        assert_eq!(error.failed_statement, MAX_SCRIPT_STATEMENTS + 1);
        assert!(error.completed.is_empty());
    }

    #[test]
    fn duplicate_create_rejects_before_the_creator_and_failed_creation_leaves_no_session() {
        let script = SqlScript::parse(&format!(
            "{CREATE}; {}",
            CREATE.replace("IF NOT EXISTS ", "")
        ))
        .unwrap();
        let mut session = None;
        let error = script
            .execute(&mut session, || panic!("No I/O for an invalid lifecycle"))
            .unwrap_err();
        assert_eq!(error.failed_statement, 2);
        assert!(error.completed.is_empty());
        assert!(session.is_none());
        let script = SqlScript::parse(CREATE).unwrap();
        let error = script
            .execute(&mut session, || {
                Err(Error::InvalidInput(
                    "No authenticated peers are connected".into(),
                ))
            })
            .unwrap_err();
        assert_eq!(error.failed_statement, 1);
        assert!(error.to_string().contains("No authenticated peers"));
        assert!(session.is_none());
    }

    #[test]
    fn unsupported_lexical_forms_and_oversized_scripts_reject_before_execution() {
        for source in [
            " ".repeat(MAX_SCRIPT_BYTES + 1),
            "/* unterminated".into(),
            "/*! SELECT * FROM records */".into(),
            "/* outer /* inner */ */".into(),
            "SELECT * FROM records WHERE age='18'".into(),
            "INSERT INTO records VALUES(18,20),(256,30)".into(),
            "SELECT * FROM records WHERE age < =18".into(),
        ] {
            assert!(SqlScript::parse(&source).is_err(), "{source}");
        }
    }
}

#[cfg(test)]
mod locking_plan_tests {
    use super::*;
    #[test]
    fn all_lock_strengths_reject_the_entire_script_before_creation_or_prior_statement_execution() {
        for strength in ["KEY SHARE", "SHARE", "NO KEY UPDATE", "UPDATE"] {
            for option in ["", "NOWAIT", "SKIP LOCKED"] {
                let script = format!(
                    "CREATE TABLE records (age TINYINT UNSIGNED NOT NULL, amount SMALLINT UNSIGNED NOT NULL); SELECT amount FROM records FOR {strength} {option}"
                );
                let error = SqlScript::parse(&script).unwrap_err();
                assert_eq!(error.failed_statement, 2);
                assert!(error.completed.is_empty());
                assert!(
                    matches!(error.source,Error::InvalidInput(ref text) if text.contains("composite source/ownership/FHE proof"))
                );
            }
        }
    }
}
