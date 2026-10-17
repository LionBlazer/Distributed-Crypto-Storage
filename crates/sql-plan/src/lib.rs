//! Backend-independent SQL plans for the currently supported encrypted schema.
//! Parsing never reads rows, evaluates a query or applies a storage policy.
#![forbid(unsafe_code)]

mod error;
mod parser;
mod plan;

pub use error::Error;
pub use parser::parse_sql;
pub use plan::{
    Column, LockStrength, LockWait, LockingClause, MAX_SQL_BYTES, Predicate, Projection, QueryPlan,
    RowValues, RowWindow,
};
