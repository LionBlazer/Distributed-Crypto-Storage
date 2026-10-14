use tfhe::prelude::*;
use tfhe::{FheBool, FheUint32, ServerKey, with_server_key_as_context};

use crate::error::crypto_error;
use crate::table::KeyDomain;
use crate::{AgePredicate, AmountDelta, Comparison, EncryptedTable, Error, Result};

/// Owns only evaluation material. Clone shares the underlying server key allocation.
#[derive(Clone)]
pub struct Evaluator {
    pub(crate) server_key: ServerKey,
    pub(crate) domain: KeyDomain,
}

pub struct UnverifiedAggregate {
    pub(crate) domain: KeyDomain,
    pub(crate) count: FheUint32,
    pub(crate) sum: FheUint32,
}

pub struct UnverifiedUpdate {
    pub(crate) domain: KeyDomain,
    pub(crate) rejected: FheBool,
}

impl Evaluator {
    /// Full scan returning encrypted count and sum with an encrypted age predicate.
    /// An empty result returns (0, 0); SQL NULL semantics are not implemented.
    pub fn aggregate(
        &self,
        table: &EncryptedTable,
        predicate: &AgePredicate,
    ) -> Result<UnverifiedAggregate> {
        self.check_domain(table.domain)?;
        self.check_domain(predicate.domain)?;
        Ok(self.in_context(|| {
            let zero = FheUint32::encrypt_trivial(0_u32);
            let mut count = zero.clone();
            let mut sum = zero.clone();
            for row in &table.rows {
                let matches = match predicate.comparison {
                    Comparison::Equal => row.age.eq(&predicate.threshold),
                    Comparison::AtLeast => row.age.ge(&predicate.threshold),
                };
                count += FheUint32::if_then_else(&matches, 1_u32, 0_u32);
                let amount: FheUint32 = row.amount.clone().cast_into();
                sum += matches.if_then_else(&amount, &zero);
            }
            UnverifiedAggregate {
                domain: self.domain,
                count,
                sum,
            }
        }))
    }

    /// Adds an encrypted delta to matching rows. If any matching u16 would overflow,
    /// an encrypted condition preserves every original amount; no plaintext branching occurs.
    pub fn add_amount(
        &self,
        table: &mut EncryptedTable,
        predicate: &AgePredicate,
        delta: &AmountDelta,
    ) -> Result<UnverifiedUpdate> {
        self.check_domain(table.domain)?;
        self.check_domain(predicate.domain)?;
        self.check_domain(delta.domain)?;
        Ok(self.in_context(|| {
            let mut rejected = FheBool::encrypt_trivial(false);
            let candidates: Vec<_> = table
                .rows
                .iter()
                .map(|row| {
                    let matches = match predicate.comparison {
                        Comparison::Equal => row.age.eq(&predicate.threshold),
                        Comparison::AtLeast => row.age.ge(&predicate.threshold),
                    };
                    let candidate = &row.amount + &delta.value;
                    rejected |= &matches & candidate.lt(&row.amount);
                    (matches, candidate)
                })
                .collect();
            let permitted = !&rejected;
            let amounts: Vec<_> = table
                .rows
                .iter()
                .zip(candidates)
                .map(|(row, (matches, candidate))| {
                    let apply = matches & &permitted;
                    apply.if_then_else(&candidate, &row.amount)
                })
                .collect();
            for (row, amount) in table.rows.iter_mut().zip(amounts) {
                row.amount = amount;
            }
            UnverifiedUpdate {
                domain: self.domain,
                rejected,
            }
        }))
    }

    /// Serialized public evaluation-key size, not its RAM footprint.
    pub fn evaluation_key_serialized_bytes(&self) -> Result<u64> {
        tfhe::safe_serialization::safe_serialized_size(&self.server_key).map_err(crypto_error)
    }

    pub(crate) fn in_context<T>(&self, operation: impl FnOnce() -> T) -> T {
        with_server_key_as_context(self.server_key.clone(), operation)
    }

    pub(crate) fn check_domain(&self, domain: KeyDomain) -> Result<()> {
        if self.domain != domain {
            return Err(Error::DifferentKeyDomain);
        }
        Ok(())
    }
}
