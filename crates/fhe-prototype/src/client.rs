use tfhe::prelude::*;
use tfhe::shortint::parameters::{
    COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use tfhe::{ClientKey, ConfigBuilder, FheUint8, FheUint16, generate_keys};

use crate::error::crypto_error;
use crate::table::{EncryptedRow, KeyDomain};
use crate::{
    AgePredicate, AmountDelta, Comparison, EncryptedTable, Error, Evaluator, MAX_ROWS, PlainRow,
    Result, UnverifiedAggregate, UnverifiedUpdate,
};

/// Owns the secret decryption key. It is neither serializable nor printable.
pub struct Owner {
    key: ClientKey,
    domain: KeyDomain,
}

impl Owner {
    pub fn generate() -> Result<(Self, Evaluator)> {
        let config =
            ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
                .enable_compression(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
                .build();
        let mut domain = [0; 16];
        getrandom::getrandom(&mut domain).map_err(crypto_error)?;
        let (key, server_key) = generate_keys(config);
        let domain = KeyDomain(domain);
        Ok((Self { key, domain }, Evaluator { server_key, domain }))
    }

    pub fn encrypt_table(&self, rows: &[PlainRow]) -> Result<EncryptedTable> {
        if rows.len() > MAX_ROWS {
            return Err(Error::TooManyRows {
                count: rows.len(),
                limit: MAX_ROWS,
            });
        }
        let rows = rows
            .iter()
            .map(|row| {
                Ok(EncryptedRow {
                    age: FheUint8::try_encrypt(row.age, &self.key).map_err(crypto_error)?,
                    amount: FheUint16::try_encrypt(row.amount, &self.key).map_err(crypto_error)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(EncryptedTable {
            domain: self.domain,
            rows,
        })
    }

    pub fn encrypt_predicate(&self, comparison: Comparison, threshold: u8) -> Result<AgePredicate> {
        Ok(AgePredicate {
            domain: self.domain,
            comparison,
            threshold: FheUint8::try_encrypt(threshold, &self.key).map_err(crypto_error)?,
        })
    }

    pub fn encrypt_delta(&self, value: u16) -> Result<AmountDelta> {
        Ok(AmountDelta {
            domain: self.domain,
            value: FheUint16::try_encrypt(value, &self.key).map_err(crypto_error)?,
        })
    }

    /// Only for locally trusted experiments. No query proof is checked here.
    pub fn decrypt_aggregate_for_experiment(
        &self,
        aggregate: &UnverifiedAggregate,
    ) -> Result<(u32, u32)> {
        self.check_domain(aggregate.domain)?;
        Ok((
            aggregate.count.decrypt(&self.key),
            aggregate.sum.decrypt(&self.key),
        ))
    }

    /// True means at least one matching row would overflow and all amounts were retained.
    /// Only for locally trusted experiments; this does not verify an update proof.
    pub fn decrypt_update_rejection_for_experiment(
        &self,
        update: &UnverifiedUpdate,
    ) -> Result<bool> {
        self.check_domain(update.domain)?;
        Ok(update.rejected.decrypt(&self.key))
    }

    fn check_domain(&self, domain: KeyDomain) -> Result<()> {
        if self.domain != domain {
            return Err(Error::DifferentKeyDomain);
        }
        Ok(())
    }
}
