//! Small, local experiments with encrypted relational operations.
//!
//! Outputs are explicitly unverified: this crate does not implement query proofs.

#![forbid(unsafe_code)]

mod client;
mod error;
mod evaluator;
mod image;
mod table;

pub use client::Owner;
pub use error::{Error, Result};
pub use evaluator::{Evaluator, UnverifiedAggregate, UnverifiedUpdate};
pub use table::{AgePredicate, AmountDelta, Comparison, EncryptedTable, MAX_ROWS, PlainRow};
