use super::*;
use crate::{MAX_ROWS, ROW_BYTES, check_schema, index, random_id, storage};
use bfv_core::{Geometry, QueryContext, UnverifiedUpdateOutcome};

impl Owner {
    pub fn generate(database: [u8; 16]) -> Result<(Self, Evaluator)> {
        let store = compact_store::Owner::generate(database)?;
        let (key, setup) = bfv_core::Owner::generate(Geometry::Rows256)?;
        let peer = bfv_core::PeerEvaluator::from_public_setup(&setup)?;
        let linear = bfv_core::PublicUpdateEvaluator::from_parameters(&setup.update_parameters()?)?;
        Ok((
            Self { store, key, linear },
            Evaluator {
                peer: Arc::new(peer),
                setup: Arc::new(setup),
            },
        ))
    }
    pub fn seal(&self, rows: &[PlainRow], rows_per_page: u32, limits: Limits) -> Result<Table> {
        storage::seal(&self.store, rows, rows_per_page, limits)
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
    /// Same live authority only: this does not restore either secret key.
    pub fn restore_table_for_experiment(
        &self,
        data: &[u8],
        index: &[u8],
        table_id: &crate::TableId,
        expected_data: &Commitment,
        expected_index: &Commitment,
        limits: Limits,
    ) -> Result<Table> {
        storage::restore(
            &self.store,
            data,
            index,
            table_id,
            expected_data,
            expected_index,
            limits,
        )
    }
    /// Full canonical image/root and owner header checks, without allocating Table packets.
    /// Same expected heads, TableId and live owner as restore; no SQL or freshness proof.
    pub fn validate_table_images_for_experiment(
        &self,
        data: &[u8],
        index: &[u8],
        table_id: &crate::TableId,
        expected_data: &Commitment,
        expected_index: &Commitment,
        limits: Limits,
    ) -> Result<()> {
        storage::validate(
            &self.store,
            data,
            index,
            table_id,
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
    /// Authenticate every original row of the bounded target shard; input preparation
    /// encrypts originals and the incoming batch separately, never a preassembled answer.
    pub fn prepare_insert_for_experiment(
        &self,
        table: &Table,
        incoming: &[PlainRow],
        ids: crate::RowIds,
        budget: usize,
        limits: Limits,
    ) -> Result<PreparedInsert> {
        if ids.len() != incoming.len() {
            return Err(Error::InvalidIndex);
        }
        let total = table
            .commitment()
            .layout()
            .row_count
            .checked_add(incoming.len() as u64);
        if incoming.is_empty() || total.is_none_or(|total| total > MAX_ROWS.min(budget) as u64) {
            return Err(Error::InvalidInsertSize {
                existing: table.commitment().layout().row_count,
                incoming: incoming.len(),
                maximum: MAX_ROWS.min(budget),
            });
        }
        let selection = self.select_exact(
            table,
            AgeRange {
                lower: 0,
                upper: 255,
            },
            index::MaterializationBudget::rows(budget),
            limits,
        )?;
        let context = QueryContext::new(
            random_id()?,
            selection.data_head.encode(),
            selection.index_head.encode(),
        );
        let fields = Zeroizing::new(
            incoming
                .iter()
                .map(|row| bfv_core::SelectedField {
                    age: row.age,
                    amount: row.amount,
                    active: true,
                })
                .collect::<Vec<_>>(),
        );
        let prepared =
            self.key
                .prepare_indexed_insert_for_experiment(context, &selection.fields, &fields)?;
        let incoming = Zeroizing::new(
            incoming
                .iter()
                .map(|row| {
                    let [low, high] = row.amount.to_le_bytes();
                    [row.age, low, high]
                })
                .collect(),
        );
        Ok(PreparedInsert {
            request: prepared.request,
            pending: prepared.pending,
            selection,
            incoming,
            ids,
        })
    }
    /// All decoded rows must match authenticated originals and the authorized insertion
    /// before any page/index staging. This local check is NOT a succinct query proof.
    pub fn apply_insert_checked_for_experiment(
        &self,
        table: &mut Table,
        prepared: PreparedInsert,
        output: &[u8],
        limits: Limits,
    ) -> Result<()> {
        current(table, &prepared.selection)?;
        let answer = self
            .key
            .decrypt_indexed_insert_unverified_for_experiment(prepared.pending, output)?;
        let count = prepared.selection.fields.len();
        if answer.proof != ProofStatus::Unavailable
            || answer.rows.len() != count + prepared.incoming.len()
        {
            return Err(Error::InvalidOutput);
        }
        for (slot, row) in answer.rows.iter().enumerate() {
            let (age, amount) = if slot < count {
                (
                    prepared.selection.fields[slot].age,
                    prepared.selection.fields[slot].amount,
                )
            } else {
                let incoming = prepared.incoming[slot - count];
                (incoming[0], u16::from_le_bytes([incoming[1], incoming[2]]))
            };
            if row.slot != slot || row.age != age || row.amount != amount {
                return Err(Error::InvalidOutput);
            }
        }
        let rows: Vec<_> = answer
            .rows
            .into_iter()
            .map(|row| PlainRow {
                age: row.age,
                amount: row.amount,
            })
            .collect();
        let staged = storage::grow_checked(
            &self.store,
            table,
            &prepared.selection.data_head,
            &prepared.selection.index_head,
            &prepared.ids,
            &rows,
            limits,
        )?;
        current(table, &prepared.selection)?;
        *table = staged;
        Ok(())
    }

    /// Authenticate the complete indexed selection and encrypt ORIGINAL row fields
    /// and a projection/active mask. No plaintext projected result is produced.
    pub fn prepare_exact_select_for_experiment(
        &self,
        table: &Table,
        predicate: AgeRange,
        projection: RowProjection,
        budget: usize,
        limits: Limits,
    ) -> Result<PreparedSelect> {
        let selection = self.select_exact(
            table,
            predicate,
            index::MaterializationBudget::rows(budget),
            limits,
        )?;
        let context = QueryContext::new(
            random_id()?,
            selection.data_head.encode(),
            selection.index_head.encode(),
        );
        let prepared = self.key.prepare_indexed_select_for_experiment(
            context,
            &selection.fields,
            projection,
        )?;
        Ok(PreparedSelect {
            request: prepared.request,
            pending: prepared.pending,
            selection: SelectState::from_selection(table.read_heads(), selection),
        })
    }
    /// Recheck both current heads and consume encrypted peer output. Returned fields
    /// come ONLY from final BFV decoding, never from retained authenticated inputs.
    pub fn complete_exact_select_unverified_for_experiment(
        &self,
        table: &Table,
        prepared: PreparedSelect,
        output: &[u8],
    ) -> Result<UnverifiedSelectedRows> {
        self.complete_select_for_heads(&table.read_heads(), prepared, output)
    }
    pub(super) fn complete_select_for_heads(
        &self,
        heads: &crate::ReadHeads,
        prepared: PreparedSelect,
        output: &[u8],
    ) -> Result<UnverifiedSelectedRows> {
        current_select(heads, &prepared.selection)?;
        let answer = self
            .key
            .decrypt_indexed_select_unverified_for_experiment(prepared.pending, output)?;
        if answer.rows.len() != prepared.selection.ordinals.len() {
            return Err(Error::InvalidOutput);
        }
        let mut rows = Vec::with_capacity(answer.rows.len());
        for (expected, row) in answer.rows.into_iter().enumerate() {
            if row.slot != expected {
                return Err(Error::InvalidOutput);
            }
            rows.push(SelectedRow {
                ordinal: prepared.selection.ordinals[expected],
                age: row.age,
                amount: row.amount,
            });
        }
        Ok(UnverifiedSelectedRows {
            rows,
            proof: answer.proof,
        })
    }

    // This private constructor establishes exact selection under this owner's index-build contract.
    // Neither arbitrary SelectedField vectors nor coarse/full-scan candidates can call these APIs.
    pub(super) fn select_exact(
        &self,
        table: &Table,
        predicate: AgeRange,
        budget: index::MaterializationBudget,
        limits: Limits,
    ) -> Result<ExactSelection> {
        self.select_exact_read(
            &table.read_view(),
            AgeSet256::try_from(predicate)?,
            budget,
            limits,
        )
    }
    pub(super) fn select_exact_read(
        &self,
        source: &crate::ReadView<'_>,
        predicate: AgeSet256,
        budget: index::MaterializationBudget,
        limits: Limits,
    ) -> Result<ExactSelection> {
        let heads = source.heads();
        check_schema(heads.data())?;
        let ordinals = index::select(&self.store, source.index, heads, predicate, budget, &mut 0)?;
        // Capacity is known before any plaintext fields exist; never grow/copy their allocation.
        let fields = Vec::with_capacity(ordinals.len());
        let mut selection = ExactSelection {
            data_head: heads.data().clone(),
            index_head: heads.index().clone(),
            ordinals,
            fields,
            pages: BTreeMap::new(),
        };
        let layout = heads.data().layout();
        for ordinal in &selection.ordinals {
            let address = layout.address_of(*ordinal)?;
            if let std::collections::btree_map::Entry::Vacant(entry) =
                selection.pages.entry(address.page_index)
            {
                let verified = crate::read::checked_page(
                    source.data,
                    heads.data(),
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
        if source.data.commitment() != heads.data() || source.index.commitment() != heads.index() {
            return Err(Error::WrongVersion);
        }
        Ok(selection)
    }
    /// Validates every matching posting and original row, retaining only the ordered
    /// prefix. Discarded plaintext validates the index; returned cells still require FHE.
    pub(super) fn select_limited_read(
        &self,
        source: &crate::ReadView<'_>,
        predicate: AgeSet256,
        limit: usize,
        budget: index::MaterializationBudget,
        limits: Limits,
    ) -> Result<ExactSelection> {
        let heads = source.heads();
        check_schema(heads.data())?;
        let candidates =
            index::select_candidates(&self.store, source.index, heads, predicate, limit, budget)?;
        let mut selection = ExactSelection {
            data_head: heads.data().clone(),
            index_head: heads.index().clone(),
            ordinals: Vec::with_capacity(candidates.retained),
            fields: Vec::with_capacity(candidates.retained),
            pages: BTreeMap::new(),
        };
        let mut current_page: Option<(u64, compact_store::PlainPage)> = None;
        for ordinal in candidates.ordinals() {
            let address = heads.data().layout().address_of(ordinal)?;
            if current_page.as_ref().map(|(page, _)| *page) != Some(address.page_index) {
                let verified = crate::read::checked_page(
                    source.data,
                    heads.data(),
                    address.page_index,
                    limits,
                )?;
                current_page = Some((address.page_index, self.store.decrypt(&verified)?));
            }
            let bytes = &current_page.as_ref().unwrap().1.as_bytes()
                [address.byte_offset..address.byte_offset + ROW_BYTES as usize];
            if !predicate.contains(bytes[0]) {
                return Err(Error::InvalidIndex);
            }
            if selection.fields.len() < candidates.retained {
                selection.ordinals.push(ordinal);
                selection.fields.push(bfv_core::SelectedField {
                    age: bytes[0],
                    amount: u16::from_le_bytes([bytes[1], bytes[2]]),
                    active: true,
                });
            }
        }
        if source.data.commitment() != heads.data() || source.index.commitment() != heads.index() {
            return Err(Error::WrongVersion);
        }
        Ok(selection)
    }
    pub fn prepare_exact_aggregate_for_experiment(
        &self,
        table: &Table,
        predicate: AgeRange,
        budget: usize,
        limits: Limits,
    ) -> Result<PreparedAggregate> {
        let selection = self.select_exact(
            table,
            predicate,
            index::MaterializationBudget::rows(budget),
            limits,
        )?;
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
        let selection = self.select_exact(
            table,
            predicate,
            index::MaterializationBudget::rows(budget),
            limits,
        )?;
        let context = QueryContext::new(
            random_id()?,
            selection.data_head.encode(),
            selection.index_head.encode(),
        );
        let prepared =
            self.key
                .prepare_indexed_update_for_experiment(context, &selection.fields, delta)?;
        Ok(PreparedUpdate {
            heads: table.read_heads(),
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
        current_update(&table.read_heads(), &prepared)?;
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
