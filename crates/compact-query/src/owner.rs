use crate::wire::{CountCipher, EncryptedPredicate, MaskedRow, Request, SumCipher};
use crate::{
    AgeRange, Aggregate, AppliedUpdate, Error, Evaluator, MAX_ROWS, Operation, Owner, PlainRow,
    PreparedQuery, ROW_BYTES, Result, Selection, Stages, Table, UnverifiedOutput, check_schema,
    index, ms, random_id,
};
use compact_store::{Commitment, Limits, LookupResponse};
use std::collections::BTreeMap;
use tfhe::prelude::*;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use tfhe::{ConfigBuilder, FheUint8, FheUint16, generate_keys};
use zeroize::Zeroizing;

impl Owner {
    pub fn generate(database: [u8; 16]) -> Result<(Self, Evaluator)> {
        let store = compact_store::Owner::generate(database)?;
        let domain = random_id()?;
        let (key, server_key) = generate_keys(
            ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
                .build(),
        );
        Ok((
            Self { store, key, domain },
            Evaluator {
                server_key,
                domain,
                row_workers: 1,
            },
        ))
    }
    /// Independent trusted table handles share this owner's keys and no global head.
    pub fn seal(&self, rows: &[PlainRow], rows_per_page: u32, limits: Limits) -> Result<Table> {
        crate::storage::seal(&self.store, rows, rows_per_page, limits)
    }
    /// Seals one partition of an existing logical table, consuming its fresh row-ID allocation.
    pub fn seal_partition(
        &self,
        table_id: &crate::TableId,
        rows: &[PlainRow],
        ids: crate::RowIds,
        rows_per_page: u32,
        limits: Limits,
    ) -> Result<Table> {
        crate::storage::seal_partition(&self.store, table_id, rows, ids, rows_per_page, limits)
    }
    /// Authenticated private metadata at this exact table/head pair; no SQL proof or lock grant.
    pub fn row_references(&self, table: &Table, ordinals: &[u64]) -> Result<crate::RowReferences> {
        crate::index::references(&self.store, table, ordinals, &mut 0)
    }
    /// In-memory restart with the same live key authority. The expected heads must
    /// come independently of the encoded peer data. This is not durable key recovery.
    pub fn restore_table_for_experiment(
        &self,
        data: &[u8],
        index_bytes: &[u8],
        table_id: &crate::TableId,
        expected_data: &Commitment,
        expected_index: &Commitment,
        limits: Limits,
    ) -> Result<Table> {
        crate::storage::restore(
            &self.store,
            data,
            index_bytes,
            table_id,
            expected_data,
            expected_index,
            limits,
        )
    }
    pub fn prepare(
        &self,
        table: &Table,
        selection: Selection,
        predicate: AgeRange,
        operation: Operation,
        budget: usize,
        limits: Limits,
    ) -> Result<PreparedQuery> {
        predicate.validate()?;
        check_schema(table.commitment())?;
        let start = std::time::Instant::now();
        let mut index_response_bytes = 0;
        let ordinals = match selection {
            Selection::IndexedAgeRange(range) => {
                range.validate()?;
                // A candidate range must contain the full predicate, or completeness
                // would silently depend on an application-side assumption.
                if range.lower > predicate.lower || range.upper < predicate.upper {
                    return Err(Error::InvalidRange);
                }
                index::select(
                    &self.store,
                    &table.index,
                    &table.read_heads(),
                    crate::AgeSet256::try_from(range)?,
                    index::MaterializationBudget::rows(budget),
                    &mut index_response_bytes,
                )?
            }
            Selection::FullScan => {
                index::check_binding_counted(
                    &self.store,
                    &table.index,
                    &table.read_heads(),
                    &mut index_response_bytes,
                )?;
                let count = table.commitment().layout().row_count as usize;
                if count > budget || count > MAX_ROWS {
                    return Err(Error::SelectionBudget {
                        selected: count,
                        budget: budget.min(MAX_ROWS),
                    });
                }
                (0..count as u64).collect()
            }
        };
        let mut stages = Stages {
            owner_index_lookup_proof_decrypt_ms: ms(start),
            owner_index_response_bytes: index_response_bytes,
            ..Stages::default()
        };
        let start = std::time::Instant::now();
        let mut rows = Vec::with_capacity(ordinals.len());
        let layout = table.commitment().layout();
        let mut page_index = u64::MAX;
        let mut page = None;
        for ordinal in ordinals {
            let address = layout.address_of(ordinal)?;
            if page_index != address.page_index {
                let encoded = table.data.lookup(address.page_index, limits)?.encode();
                stages.owner_data_response_bytes += encoded.len();
                page = Some(LookupResponse::decode(&encoded, limits)?.verify(
                    table.commitment(),
                    address.page_index,
                    limits,
                )?);
                page_index = address.page_index;
            }
            let pad = self.store.derive_keystream_range(
                page.as_ref().unwrap(),
                address.byte_offset..address.byte_offset + ROW_BYTES as usize,
            )?;
            rows.push(MaskedRow {
                ordinal,
                age: FheUint8::encrypt(pad.as_bytes()[0], &self.key),
                amount: FheUint16::encrypt(
                    u16::from_le_bytes(pad.as_bytes()[1..3].try_into().unwrap()),
                    &self.key,
                ),
            });
        }
        let encrypted_predicate = if predicate.lower == predicate.upper {
            EncryptedPredicate::Equal(FheUint8::encrypt(predicate.lower, &self.key))
        } else if predicate.upper == u8::MAX {
            EncryptedPredicate::AtLeast(FheUint8::encrypt(predicate.lower, &self.key))
        } else if predicate.lower == 0 {
            EncryptedPredicate::AtMost(FheUint8::encrypt(predicate.upper, &self.key))
        } else {
            EncryptedPredicate::Range {
                lower: FheUint8::encrypt(predicate.lower, &self.key),
                upper: FheUint8::encrypt(predicate.upper, &self.key),
            }
        };
        let request = Request {
            domain: self.domain,
            id: random_id()?,
            head: table.commitment().encode().to_vec(),
            rows,
            predicate: encrypted_predicate,
            delta: match operation {
                Operation::CountSum => None,
                Operation::AddAmount(delta) => Some(FheUint16::encrypt(delta, &self.key)),
            },
        };
        stages.owner_data_authenticate_mask_encrypt_ms = ms(start);
        Ok(PreparedQuery {
            request,
            index_head: table.index_commitment().clone(),
            predicate,
            operation,
            stages,
        })
    }
    /// Decryption plus metadata/freshness checks only. No query proof is checked.
    pub fn decrypt_aggregate_for_experiment(
        &self,
        table: &Table,
        query: &PreparedQuery,
        output: &UnverifiedOutput,
    ) -> Result<Aggregate> {
        self.check_output(table, query, output)?;
        Ok(self.decrypt_output_aggregate(output))
    }
    /// Locally recomputes the selected plaintext update at the owner and compares
    /// every decrypted FHE result. Then stages both images before committing either.
    /// This intentionally does not satisfy succinct single-peer query verification.
    pub fn apply_update_for_experiment(
        &self,
        table: &mut Table,
        query: &PreparedQuery,
        output: &UnverifiedOutput,
        limits: Limits,
    ) -> Result<AppliedUpdate> {
        self.check_output(table, query, output)?;
        let Operation::AddAmount(delta) = query.operation else {
            return Err(Error::InvalidOutput);
        };
        if output.rows.len() != query.request.rows.len() {
            return Err(Error::InvalidOutput);
        }
        let rejected: bool = output
            .rejected
            .as_ref()
            .ok_or(Error::InvalidOutput)?
            .decrypt(&self.key);
        let old = table.commitment().clone();
        let layout = old.layout();
        let mut pages: BTreeMap<u64, Zeroizing<Vec<u8>>> = BTreeMap::new();
        let mut expected_rejected = false;
        let mut count = 0u32;
        let mut sum = 0u32;
        for row in &query.request.rows {
            let address = layout.address_of(row.ordinal)?;
            if let std::collections::btree_map::Entry::Vacant(entry) =
                pages.entry(address.page_index)
            {
                let verified = table.data.lookup(address.page_index, limits)?.verify(
                    &old,
                    address.page_index,
                    limits,
                )?;
                entry.insert(Zeroizing::new(
                    self.store.decrypt(&verified)?.as_bytes().to_vec(),
                ));
            }
            let bytes = &pages[&address.page_index];
            let age = bytes[address.byte_offset];
            let amount = u16::from_le_bytes(
                bytes[address.byte_offset + 1..address.byte_offset + 3]
                    .try_into()
                    .unwrap(),
            );
            if query.predicate.contains(age) {
                count += 1;
                sum += u32::from(amount);
                expected_rejected |= amount.checked_add(delta).is_none();
            }
        }
        let actual = self.decrypt_output_aggregate(output);
        if rejected != expected_rejected || actual.count != count || actual.sum != sum {
            return Err(Error::InvalidOutput);
        }
        let mut changed_rows = 0;
        for (input, updated) in query.request.rows.iter().zip(&output.rows) {
            if input.ordinal != updated.ordinal {
                return Err(Error::InvalidOutput);
            }
            let address = layout.address_of(input.ordinal)?;
            let bytes = pages.get_mut(&address.page_index).unwrap();
            let amount = u16::from_le_bytes(
                bytes[address.byte_offset + 1..address.byte_offset + 3]
                    .try_into()
                    .unwrap(),
            );
            let matched = query.predicate.contains(bytes[address.byte_offset]);
            let expected = if matched && !rejected {
                amount.checked_add(delta).ok_or(Error::InvalidOutput)?
            } else {
                amount
            };
            let actual: u16 = updated.amount.decrypt(&self.key);
            if actual != expected {
                return Err(Error::InvalidOutput);
            }
            if actual != amount {
                changed_rows += 1;
            }
            bytes[address.byte_offset + 1..address.byte_offset + 3]
                .copy_from_slice(&actual.to_le_bytes());
        }
        if changed_rows == 0 {
            return Ok(AppliedUpdate {
                rejected,
                changed_rows,
            });
        }
        let staged = crate::storage::replace_amount_pages(
            &self.store,
            table,
            &old,
            table.index_commitment(),
            &pages,
            limits,
        )?;
        *table = staged;
        Ok(AppliedUpdate {
            rejected,
            changed_rows,
        })
    }
    pub fn decrypt_row_for_experiment(
        &self,
        table: &Table,
        ordinal: u64,
        limits: Limits,
    ) -> Result<PlainRow> {
        crate::storage::row(&self.store, table, ordinal, limits)
    }
    pub fn secret_key_serialized_bytes(&self) -> Result<u64> {
        bincode::serialized_size(&self.key).map_err(|e| Error::Codec(e.to_string()))
    }
    fn decrypt_output_aggregate(&self, output: &UnverifiedOutput) -> Aggregate {
        let count = match &output.count {
            CountCipher::Single(bit) => {
                let matched: bool = bit.decrypt(&self.key);
                u32::from(matched)
            }
            CountCipher::Multiple(value) => value.decrypt(&self.key),
        };
        let sum = match &output.sum {
            SumCipher::Single(value) => value.decrypt(&self.key),
            SumCipher::Multiple(value) => value.decrypt(&self.key),
        };
        Aggregate { count, sum }
    }
    fn check_output(
        &self,
        table: &Table,
        query: &PreparedQuery,
        output: &UnverifiedOutput,
    ) -> Result<()> {
        if query.request.domain != self.domain || output.domain != self.domain {
            return Err(Error::WrongDomain);
        }
        if query.request.id != output.id {
            return Err(Error::WrongQuery);
        }
        if query.request.head != table.commitment().encode()
            || output.head != query.request.head
            || &query.index_head != table.index_commitment()
        {
            return Err(Error::WrongVersion);
        }
        let single = query.request.rows.len() == 1;
        if matches!(output.count, CountCipher::Single(_)) != single
            || matches!(output.sum, SumCipher::Single(_)) != single
        {
            return Err(Error::InvalidOutput);
        }
        if output.rejected.is_some() != matches!(query.operation, Operation::AddAmount(_))
            || (query.operation == Operation::CountSum && !output.rows.is_empty())
        {
            return Err(Error::InvalidOutput);
        }
        Ok(())
    }
}
