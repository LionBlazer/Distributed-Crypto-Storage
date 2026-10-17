//! Bounded client-side script planning. Every read/write is still executed and
//! proved by Session; this module never evaluates data or constructs query answers.
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
    /// Fully validate all syntax and proof-supported operations before network I/O.
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
    // Reject every strength/policy before the script can create or store anything.
    crate::reject_locking_plan(&plan).map_err(|source| ScriptError {
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
        assert_eq!(script.statement_count(), 3);
        let SqlStatement::Query { sql, plan } = &script.statements()[1] else {
            panic!("one INSERT statement expected");
        };
        assert_eq!(
            plan,
            &QueryPlan::Insert {
                rows: vec![
                    sql_plan::RowValues {
                        age: 18,
                        amount: 20
                    },
                    sql_plan::RowValues {
                        age: 42,
                        amount: 30
                    },
                ],
            }
        );
        assert_eq!(sql_plan::parse_sql(sql).unwrap(), *plan);
        assert!(matches!(
            script.statements()[2],
            SqlStatement::Query {
                plan: QueryPlan::Select { .. },
                ..
            }
        ));
    }

    #[test]
    fn pagination_preserves_nulls_and_window_order_and_rejects_a_later_duplicate_before_execution()
    {
        let script = SqlScript::parse("SELECT amount FROM records OFFSET NULL LIMIT ALL; SELECT age FROM records OFFSET 2 LIMIT 3").unwrap();
        let SqlStatement::Query { sql, plan } = &script.statements()[1] else {
            panic!("row-window query expected");
        };
        assert!(
            matches!(plan, QueryPlan::Select { window, .. } if *window == sql_plan::RowWindow { offset: 2, limit: Some(3) })
        );
        assert_eq!(sql_plan::parse_sql(sql).unwrap(), *plan);
        let error = SqlScript::parse(
            "UPDATE records SET amount=amount+1; SELECT * FROM records OFFSET NULL OFFSET 1",
        )
        .unwrap_err();
        assert_eq!(error.failed_statement, 2);
        assert!(error.completed.is_empty());
    }

    #[test]
    fn malformed_later_tuple_rejects_the_whole_script_before_creation() {
        for tuple in ["(256,30)", "(42,65536)", "(42)", "(42,30", "", "SELECT"] {
            let error = SqlScript::parse(&format!(
                "{CREATE}; INSERT INTO records VALUES(18,20),{tuple}; SELECT * FROM records"
            ))
            .unwrap_err();

            assert_eq!(error.failed_statement, 2, "{tuple}");
            assert!(error.completed.is_empty(), "{tuple}");
        }
    }

    #[test]
    fn inserted_row_budget_counts_all_batches_independently_of_statement_count() {
        let half_batch = std::iter::repeat_n("(18,20)", MAX_SCRIPT_INSERTED_ROWS / 2)
            .collect::<Vec<_>>()
            .join(",");
        let source = format!(
            "INSERT INTO records VALUES {half_batch}; INSERT INTO records VALUES {half_batch}"
        );
        let script = SqlScript::parse(&source).unwrap();

        assert_eq!(script.statement_count(), 2);
        assert_eq!(script.inserted_rows(), MAX_SCRIPT_INSERTED_ROWS);

        let error =
            SqlScript::parse(&format!("{source}; INSERT INTO records VALUES (1,1)")).unwrap_err();
        assert_eq!(error.failed_statement, 3);
        assert!(error.completed.is_empty());
        assert!(error.to_string().contains("inserted-row input limit"));

        let oversized_batch = std::iter::repeat_n("(1,1)", MAX_SCRIPT_INSERTED_ROWS + 1)
            .collect::<Vec<_>>()
            .join(",");
        let error =
            SqlScript::parse(&format!("INSERT INTO records VALUES {oversized_batch}")).unwrap_err();
        assert_eq!(error.failed_statement, 1);
        assert!(error.completed.is_empty());
        assert!(error.to_string().contains("inserted-row input limit"));
    }

    #[test]
    fn maximum_literal_batch_fits_the_statement_byte_limit_without_token_space_inflation() {
        let tuples = std::iter::repeat_n("(255,65535)", MAX_SCRIPT_INSERTED_ROWS)
            .collect::<Vec<_>>()
            .join(",");
        let source = format!("INSERT INTO records VALUES {tuples}");
        assert!(source.len() < sql_plan::MAX_SQL_BYTES);

        let script = SqlScript::parse(&source).unwrap();

        assert_eq!(script.statement_count(), 1);
        assert_eq!(script.inserted_rows(), MAX_SCRIPT_INSERTED_ROWS);
        let SqlStatement::Query { plan, .. } = &script.statements()[0] else {
            panic!("one INSERT batch expected");
        };
        assert_eq!(
            plan,
            &QueryPlan::Insert {
                rows: vec![
                    sql_plan::RowValues {
                        age: 255,
                        amount: 65535
                    };
                    MAX_SCRIPT_INSERTED_ROWS
                ],
            },
        );
    }

    #[test]
    fn statement_budget_counts_source_statements_including_an_unterminated_last_one() {
        let source = "SELECT * FROM records;".repeat(MAX_SCRIPT_STATEMENTS);
        let script = SqlScript::parse(&source).unwrap();
        assert_eq!(script.statement_count(), MAX_SCRIPT_STATEMENTS);
        assert_eq!(script.inserted_rows(), 0);

        let error = SqlScript::parse(&format!("{source}SELECT * FROM records")).unwrap_err();
        assert_eq!(error.failed_statement, MAX_SCRIPT_STATEMENTS + 1);
        assert!(error.completed.is_empty());
    }

    #[test]
    fn aggregate_statements_are_planned_without_a_plaintext_fallback() {
        let script = SqlScript::parse("SELECT COUNT(*) FROM records; SELECT SUM(amount) FROM records; SELECT COUNT(*), SUM(amount) FROM records WHERE age >= 18;").unwrap();
        assert_eq!(script.statements().len(), 3);
        assert!(matches!(
            script.statements()[0],
            SqlStatement::Query {
                plan: QueryPlan::Count { .. },
                ..
            }
        ));
        assert!(matches!(
            script.statements()[1],
            SqlStatement::Query {
                plan: QueryPlan::Sum { .. },
                ..
            }
        ));
        assert!(matches!(
            script.statements()[2],
            SqlStatement::Query {
                plan: QueryPlan::Aggregate { .. },
                ..
            }
        ));
    }

    #[test]
    fn unsupported_later_statement_rejects_the_entire_plan_before_creation() {
        for unsupported in [
            "SELECT AVG(amount) FROM records",
            "SELECT * FROM records FOR UPDATE",
            "SELECT * FROM records WHERE age < = 18",
            "SELECT * FROM records WHERE age > = 18",
            "SELECT * FROM records WHERE age < > 18",
            "SELECT * FROM records WHERE age ! = 18",
            "SELECT * FROM records WHERE age IN(7,NULL) OR amount=1",
            "DELETE FROM records",
            "CREATE TABLE customers (id INT)",
            "INSERT INTO records VALUES (18,20),(256,30)",
            "INSERT INTO records VALUES (18,20),(2 55,30)",
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
    fn boolean_script_preserves_signed_bounds_null_semantics_and_compound_tokens() {
        let script = SqlScript::parse("SELECT * FROM records WHERE age<>-1 AND NOT(age IN(7,NULL)) OR age!=+42; UPDATE records SET amount=amount+0 WHERE NOT(age BETWEEN NULL AND 10);").unwrap();
        assert_eq!(script.statement_count(), 2);
        for statement in script.statements() {
            let SqlStatement::Query { sql, plan } = statement else {
                panic!("query expected")
            };
            assert_eq!(sql_plan::parse_sql(sql).unwrap(), *plan);
        }
    }

    #[test]
    fn missing_table_and_duplicate_create_never_call_the_creator() {
        for (source, failed_statement) in [
            ("SELECT * FROM records".to_string(), 1),
            (
                format!(
                    "{CREATE}; INSERT INTO records VALUES (18,20),(42,30); {}",
                    CREATE.replace("IF NOT EXISTS ", "")
                ),
                3,
            ),
        ] {
            let mut session = None;
            let script = SqlScript::parse(&source).unwrap();
            let error = script
                .execute(&mut session, || panic!("No I/O during lifecycle rejection"))
                .unwrap_err();
            assert!(session.is_none());
            assert!(error.completed.is_empty());
            assert_eq!(error.failed_statement, failed_statement);
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
