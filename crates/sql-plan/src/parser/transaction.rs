//! Syntax only, following PG18 TransactionStmt/TransactionStmtLegacy and its
//! ordered transaction_mode_list. The tokenizer and query parser are shared.
use super::Parser;
use crate::{
    Deferrability, Error, IsolationLevel, StatementPlan, TransactionAccess, TransactionChain,
    TransactionMode,
};

impl Parser {
    pub(super) fn statement(&mut self) -> Result<StatementPlan, Error> {
        if self.take("BEGIN") {
            self.transaction_keyword();
            Ok(StatementPlan::Begin {
                modes: self.transaction_modes()?,
            })
        } else if self.take("START") {
            self.expect("TRANSACTION")?;
            Ok(StatementPlan::Begin {
                modes: self.transaction_modes()?,
            })
        } else if self.take("COMMIT") || self.take("END") {
            self.transaction_keyword();
            Ok(StatementPlan::Commit {
                chain: self.transaction_chain()?,
            })
        } else if self.take("ROLLBACK") || self.take("ABORT") {
            self.transaction_keyword();
            Ok(StatementPlan::Rollback {
                chain: self.transaction_chain()?,
            })
        } else {
            self.query().map(StatementPlan::Query)
        }
    }

    fn transaction_keyword(&mut self) {
        if !self.take("WORK") {
            self.take("TRANSACTION");
        }
    }

    fn transaction_modes(&mut self) -> Result<Vec<TransactionMode>, Error> {
        let mut modes = Vec::new();
        if !self.starts_transaction_mode() {
            return Ok(modes);
        }
        loop {
            modes.push(self.transaction_mode()?);
            // PG permits commas or adjacency, but never a trailing/double comma.
            if self.take(",") {
                continue;
            }
            if !self.starts_transaction_mode() {
                break;
            }
        }
        Ok(modes)
    }

    fn starts_transaction_mode(&self) -> bool {
        matches!(
            self.tokens.get(self.index).map(String::as_str),
            Some("ISOLATION" | "READ" | "DEFERRABLE" | "NOT")
        )
    }

    fn transaction_mode(&mut self) -> Result<TransactionMode, Error> {
        if self.take("ISOLATION") {
            self.expect("LEVEL")?;
            let isolation = if self.take("SERIALIZABLE") {
                IsolationLevel::Serializable
            } else if self.take("REPEATABLE") {
                self.expect("READ")?;
                IsolationLevel::RepeatableRead
            } else if self.take("READ") {
                if self.take("COMMITTED") {
                    IsolationLevel::ReadCommitted
                } else {
                    self.expect("UNCOMMITTED")?;
                    IsolationLevel::ReadUncommitted
                }
            } else {
                return Err(transaction_error("expected a PostgreSQL isolation level"));
            };
            Ok(TransactionMode::Isolation(isolation))
        } else if self.take("READ") {
            let access = if self.take("ONLY") {
                TransactionAccess::ReadOnly
            } else {
                self.expect("WRITE")?;
                TransactionAccess::ReadWrite
            };
            Ok(TransactionMode::Access(access))
        } else if self.take("DEFERRABLE") {
            Ok(TransactionMode::Deferrability(Deferrability::Deferrable))
        } else if self.take("NOT") {
            self.expect("DEFERRABLE")?;
            Ok(TransactionMode::Deferrability(Deferrability::NotDeferrable))
        } else {
            Err(transaction_error("expected a transaction mode after comma"))
        }
    }

    fn transaction_chain(&mut self) -> Result<TransactionChain, Error> {
        if !self.take("AND") {
            return Ok(TransactionChain::Unspecified);
        }
        let no = self.take("NO");
        self.expect("CHAIN")?;
        Ok(if no {
            TransactionChain::NoChain
        } else {
            TransactionChain::Chain
        })
    }
}

fn transaction_error(reason: &str) -> Error {
    Error::UnsupportedSql(reason.into())
}
