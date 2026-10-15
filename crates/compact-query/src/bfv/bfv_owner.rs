use super::*;
use crate::{MAX_ROWS, ROW_BYTES, check_schema, index, random_id, storage};
use bfv_core::{Geometry, QueryContext, UnverifiedUpdateOutcome};

impl Owner {
    pub fn generate(database: [u8; 16]) -> Result<(Self, Evaluator)> {
        let store = compact_store::Owner::generate(database)?;
        let (key, setup) = bfv_core::Owner::generate(Geometry::Rows256)?;
        let peer = bfv_core::PeerEvaluator::from_public_setup(&setup)?;
        Ok((
            Self { store, key },
            Evaluator {
                peer: Arc::new(peer),
                setup: Arc::new(setup),
            },
        ))
    }
    pub fn seal(&self, rows: &[PlainRow], rows_per_page: u32, limits: Limits) -> Result<Table> {
        storage::seal(&self.store, rows, rows_per_page, limits)
    }
    /// Same live authority only: this does not restore either secret key.
    pub fn restore_table_for_experiment(
        &self,
        data: &[u8],
        index: &[u8],
        expected_data: &Commitment,
        expected_index: &Commitment,
        limits: Limits,
    ) -> Result<Table> {
        storage::restore(
            &self.store,
            data,
            index,
            expected_data,
            expected_index,
            limits,
        )
    }
    pub fn decrypt_row_for_experiment(
        &self,
        table: &Table,
        ordinal: u64,
        limits: Limits,
    ) -> Result<PlainRow> {
        storage::row(&self.store, table, ordinal, limits)
    }
    pub fn profile(&self) -> ParameterProfile {
        self.key.profile()
    }
    pub fn secret_key_serialized_bytes(&self) -> usize {
        self.key.secret_key_serialized_bytes()
    }

    // This private constructor establishes exact selection under this owner's index-build contract.
    // Neither arbitrary SelectedField vectors nor coarse/full-scan candidates can call these APIs.
    fn select_exact(
        &self,
        table: &Table,
        predicate: AgeRange,
        budget: usize,
        limits: Limits,
    ) -> Result<ExactSelection> {
        predicate.validate()?;
        check_schema(table.commitment())?;
        let ordinals = index::select(
            &self.store,
            &table.index,
            table.commitment(),
            predicate,
            budget.min(MAX_ROWS),
            &mut 0,
        )?;
        // Capacity is known before any plaintext fields exist; never grow/copy their allocation.
        let fields = Vec::with_capacity(ordinals.len());
        let mut selection = ExactSelection {
            data_head: table.commitment().clone(),
            index_head: table.index_commitment().clone(),
            ordinals,
            fields,
            pages: BTreeMap::new(),
        };
        let layout = table.commitment().layout();
        for ordinal in &selection.ordinals {
            let address = layout.address_of(*ordinal)?;
            if let std::collections::btree_map::Entry::Vacant(entry) =
                selection.pages.entry(address.page_index)
            {
                let wire = table.data.lookup(address.page_index, limits)?.encode();
                let verified = compact_store::LookupResponse::decode(&wire, limits)?.verify(
                    table.commitment(),
                    address.page_index,
                    limits,
                )?;
                entry.insert(Zeroizing::new(
                    self.store.decrypt(&verified)?.as_bytes().to_vec(),
                ));
            }
            let bytes = &selection.pages[&address.page_index]
                [address.byte_offset..address.byte_offset + ROW_BYTES as usize];
            // Reject the complete selection on mismatch; never filter a faulty exact posting.
            if !predicate.contains(bytes[0]) {
                return Err(Error::InvalidIndex);
            }
            selection.fields.push(bfv_core::SelectedField {
                age: bytes[0],
                amount: u16::from_le_bytes([bytes[1], bytes[2]]),
                active: true,
            });
        }
        current(table, &selection)?;
        Ok(selection)
    }
    pub fn prepare_exact_aggregate_for_experiment(
        &self,
        table: &Table,
        predicate: AgeRange,
        budget: usize,
        limits: Limits,
    ) -> Result<PreparedAggregate> {
        let selection = self.select_exact(table, predicate, budget, limits)?;
        let context = QueryContext::new(
            random_id()?,
            selection.data_head.encode(),
            selection.index_head.encode(),
        );
        let prepared = self
            .key
            .prepare_exact_index_aggregate_for_experiment(context, &selection.fields)?;
        Ok(PreparedAggregate {
            request: prepared.request,
            pending: prepared.pending,
            selection,
        })
    }
    /// Metadata/current-head checks only. The result remains explicitly UnverifiedAggregate.
    pub fn complete_exact_aggregate_unverified_for_experiment(
        &self,
        table: &Table,
        prepared: PreparedAggregate,
        output: &[u8],
    ) -> Result<UnverifiedAggregate> {
        current(table, &prepared.selection)?;
        Ok(self
            .key
            .decrypt_exact_index_unverified_for_experiment(prepared.pending, output)?)
    }
    pub fn prepare_exact_update_for_experiment(
        &self,
        table: &Table,
        predicate: AgeRange,
        delta: u16,
        budget: usize,
        limits: Limits,
    ) -> Result<PreparedUpdate> {
        let selection = self.select_exact(table, predicate, budget, limits)?;
        let context = QueryContext::new(
            random_id()?,
            selection.data_head.encode(),
            selection.index_head.encode(),
        );
        let prepared =
            self.key
                .prepare_indexed_update_for_experiment(context, &selection.fields, delta)?;
        Ok(PreparedUpdate {
            request: prepared.request,
            pending: prepared.pending,
            selection,
            delta,
        })
    }
    /// Owner-local arithmetic recomputation AFTER actual peer evaluation is required before staging.
    /// This is not a succinct computation proof, and does not establish disk crash durability.
    pub fn apply_exact_update_checked_for_experiment(
        &self,
        table: &mut Table,
        prepared: PreparedUpdate,
        output: &[u8],
        limits: Limits,
    ) -> Result<AppliedUpdate> {
        current(table, &prepared.selection)?;
        let PreparedUpdate {
            pending,
            mut selection,
            delta,
            ..
        } = prepared;
        let outcome = self
            .key
            .decrypt_indexed_update_unverified_for_experiment(pending, output)?;
        // No owner answer calculation occurs in prepare; these checks run only after completion.
        let overflow = selection
            .fields
            .iter()
            .any(|field| field.amount.checked_add(delta).is_none());
        let rows = match outcome {
            UnverifiedUpdateOutcome::Overflow {
                proof: ProofStatus::Unavailable,
            } if overflow => {
                return Ok(AppliedUpdate {
                    rejected: true,
                    changed_rows: 0,
                });
            }
            UnverifiedUpdateOutcome::Values(values) if !overflow => {
                if values.proof != ProofStatus::Unavailable
                    || values.rows.len() != selection.fields.len()
                {
                    return Err(Error::InvalidOutput);
                }
                values.rows
            }
            _ => return Err(Error::InvalidOutput),
        };
        // Validate ALL slots before changing even an owner temporary page buffer.
        for (slot, (field, row)) in selection.fields.iter().zip(&rows).enumerate() {
            let value = field
                .amount
                .checked_add(delta)
                .ok_or(Error::InvalidOutput)?;
            if row.slot != slot
                || row.amount != value
                || row.low_limb_sum != (field.amount & 255) + (delta & 255)
                || row.high_limb_sum != (field.amount >> 8) + (delta >> 8)
            {
                return Err(Error::InvalidOutput);
            }
        }
        let changed_rows = rows
            .iter()
            .zip(&selection.fields)
            .filter(|(row, field)| row.amount != field.amount)
            .count();
        if changed_rows == 0 {
            return Ok(AppliedUpdate {
                rejected: false,
                changed_rows: 0,
            });
        }
        current(table, &selection)?;
        for row in rows {
            let address = table
                .commitment()
                .layout()
                .address_of(selection.ordinals[row.slot])?;
            let bytes = selection
                .pages
                .get_mut(&address.page_index)
                .ok_or(Error::InvalidOutput)?;
            bytes[address.byte_offset + 1..address.byte_offset + 3]
                .copy_from_slice(&row.amount.to_le_bytes());
        }
        let staged = storage::replace_amount_pages(
            &self.store,
            table,
            &selection.data_head,
            &selection.index_head,
            &selection.pages,
            limits,
        )?;
        current(table, &selection)?;
        *table = staged;
        Ok(AppliedUpdate {
            rejected: false,
            changed_rows,
        })
    }
}
