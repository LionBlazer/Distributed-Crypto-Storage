//! Designated-client composition of complete authenticated selection and real FHE proofs.
//! Agreement/freshness and publication belong to the network client, not this module.
use super::*;
use crate::{MAX_ROWS, check_schema, index, random_id, storage};
use bfv_core::{QueryContext, UnverifiedUpdateOutcome};

pub struct VerifiedSelection {
    rows: Vec<SelectedRow>,
    evidence: bfv_query_proof::CheckedOperation,
}
impl VerifiedSelection {
    pub fn rows(&self) -> &[SelectedRow] {
        &self.rows
    }
    pub fn into_rows(self) -> Vec<SelectedRow> {
        self.rows
    }
    pub fn evidence(&self) -> &bfv_query_proof::CheckedOperation {
        &self.evidence
    }
}

/// Staged owner-finalized ciphertext only. No state is published by this value.
pub struct VerifiedUpdate {
    table: Option<Table>,
    changed_rows: usize,
    evidence: bfv_query_proof::CheckedOperation,
}
impl VerifiedUpdate {
    pub fn overflowed(&self) -> bool {
        self.table.is_none()
    }
    pub fn changed_rows(&self) -> usize {
        self.changed_rows
    }
    pub fn into_table(self) -> Option<Table> {
        self.table
    }
    pub fn evidence(&self) -> &bfv_query_proof::CheckedOperation {
        &self.evidence
    }
}

fn proof_error(error: bfv_query_proof::Error) -> Error {
    Error::ComputationProof(error.to_string())
}

fn require_checked_statement(
    evidence: &bfv_query_proof::CheckedOperation,
    input: &[u8],
    output: &[u8],
) -> Result<()> {
    if evidence.matches_statement(input, output) {
        Ok(())
    } else {
        Err(Error::ComputationProof(
            "Checked arithmetic evidence does not match the exact pending request and result"
                .into(),
        ))
    }
}

impl Owner {
    pub(super) fn proof_selection(
        &self,
        table: &Table,
        predicate: Option<AgeRange>,
        budget: usize,
        limits: Limits,
    ) -> Result<ExactSelection> {
        match predicate {
            Some(range) => self.select_exact(table, range, budget, limits),
            // None is the SQL planner's schema-proven constant-false predicate.
            // It examines no stored field and is not a substitute for filtering data.
            None => {
                check_schema(table.commitment())?;
                index::check_binding(&self.store, &table.index, table.commitment())?;
                Ok(ExactSelection {
                    data_head: table.commitment().clone(),
                    index_head: table.index_commitment().clone(),
                    ordinals: vec![],
                    fields: vec![],
                    pages: BTreeMap::new(),
                })
            }
        }
    }

    /// Complete owner-built index authentication precedes encryption of original rows.
    /// The public projection mask covers every slot; it never contains private match bits.
    pub fn prepare_provable_select(
        &self,
        table: &Table,
        predicate: Option<AgeRange>,
        projection: RowProjection,
        budget: usize,
        limits: Limits,
    ) -> Result<PreparedSelect> {
        let selection = self.proof_selection(table, predicate, budget.min(MAX_ROWS), limits)?;
        let context = QueryContext::new(
            random_id()?,
            selection.data_head.encode(),
            selection.index_head.encode(),
        );
        let prepared =
            self.key
                .prepare_exact_select_for_experiment(context, &selection.fields, projection)?;
        Ok(PreparedSelect {
            request: prepared.request,
            pending: prepared.pending,
            selection,
        })
    }

    pub fn prepare_provable_update(
        &self,
        table: &Table,
        predicate: Option<AgeRange>,
        delta: u16,
        budget: usize,
        limits: Limits,
    ) -> Result<PreparedUpdate> {
        let selection = self.proof_selection(table, predicate, budget.min(MAX_ROWS), limits)?;
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

    /// Checks one candidate response without consuming the authenticated pending
    /// selection, so another real executor may be tried after an invalid proof.
    pub fn check_select_proof(
        &self,
        table: &Table,
        prepared: &PreparedSelect,
        output: &[u8],
        proof: &[u8],
    ) -> Result<bfv_query_proof::CheckedOperation> {
        current(table, &prepared.selection)?;
        let input = self.linear.select_circuit_request(prepared.request())?;
        bfv_query_proof::verify(&input, output, proof).map_err(proof_error)
    }

    pub fn check_update_proof(
        &self,
        table: &Table,
        prepared: &PreparedUpdate,
        output: &[u8],
        proof: &[u8],
    ) -> Result<bfv_query_proof::CheckedOperation> {
        current(table, &prepared.selection)?;
        let input = self.linear.circuit_request(prepared.request())?;
        bfv_query_proof::verify(&input, output, proof).map_err(proof_error)
    }

    pub fn check_insert_proof(
        &self,
        table: &Table,
        prepared: &PreparedInsert,
        output: &[u8],
        proof: &[u8],
    ) -> Result<bfv_query_proof::CheckedOperation> {
        current(table, &prepared.selection)?;
        let input = self.linear.insert_circuit_request(prepared.request())?;
        bfv_query_proof::verify(&input, output, proof).map_err(proof_error)
    }

    /// Verifies exactly once, then consumes the same checked statement.
    pub fn complete_proved_select(
        &self,
        table: &Table,
        prepared: PreparedSelect,
        output: &[u8],
        proof: &[u8],
    ) -> Result<VerifiedSelection> {
        let evidence = self.check_select_proof(table, &prepared, output, proof)?;
        self.complete_checked_select(table, prepared, output, evidence)
    }

    /// Rechecks current heads and exact evidence binding before restoration and
    /// decryption. A marker from another pending request cannot finish this one.
    pub fn complete_checked_select(
        &self,
        table: &Table,
        prepared: PreparedSelect,
        output: &[u8],
        evidence: bfv_query_proof::CheckedOperation,
    ) -> Result<VerifiedSelection> {
        current(table, &prepared.selection)?;
        let input = self.linear.select_circuit_request(prepared.request())?;
        require_checked_statement(&evidence, &input, output)?;
        let response = self
            .linear
            .restore_select_circuit_output(prepared.request(), output)?;
        let answer =
            self.complete_exact_select_unverified_for_experiment(table, prepared, &response)?;
        Ok(VerifiedSelection {
            rows: answer.rows,
            evidence,
        })
    }

    /// Genuine proof verification, decryption and bounded writeback; no sum recomputation.
    /// The caller must verify ALL shards before publishing any staged head.
    pub fn stage_proved_update(
        &self,
        table: &Table,
        prepared: PreparedUpdate,
        output: &[u8],
        proof: &[u8],
        limits: Limits,
    ) -> Result<VerifiedUpdate> {
        let evidence = self.check_update_proof(table, &prepared, output, proof)?;
        self.stage_checked_update(table, prepared, output, evidence, limits)
    }

    /// Consumes evidence only after checking its exact input/output identity.
    pub fn stage_checked_update(
        &self,
        table: &Table,
        prepared: PreparedUpdate,
        output: &[u8],
        evidence: bfv_query_proof::CheckedOperation,
        limits: Limits,
    ) -> Result<VerifiedUpdate> {
        current(table, &prepared.selection)?;
        let input = self.linear.circuit_request(prepared.request())?;
        require_checked_statement(&evidence, &input, output)?;
        let response = self
            .linear
            .restore_circuit_output(prepared.request(), output)?;
        let PreparedUpdate {
            pending,
            mut selection,
            ..
        } = prepared;
        let rows = match self
            .key
            .decrypt_indexed_update_unverified_for_experiment(pending, &response)?
        {
            UnverifiedUpdateOutcome::Overflow { .. } => {
                return Ok(VerifiedUpdate {
                    table: None,
                    changed_rows: 0,
                    evidence,
                });
            }
            UnverifiedUpdateOutcome::Values(values) => values.rows,
        };
        if rows.len() != selection.ordinals.len()
            || rows.iter().enumerate().any(|(slot, row)| row.slot != slot)
        {
            return Err(Error::InvalidOutput);
        }
        let changed_rows = rows
            .iter()
            .zip(&selection.fields)
            .filter(|(row, original)| row.amount != original.amount)
            .count();
        if changed_rows == 0 {
            return Ok(VerifiedUpdate {
                table: Some(Table {
                    data: table.data.clone(),
                    index: table.index.clone(),
                }),
                changed_rows,
                evidence,
            });
        }
        for row in rows {
            let address = table
                .commitment()
                .layout()
                .address_of(selection.ordinals[row.slot])?;
            let page = selection
                .pages
                .get_mut(&address.page_index)
                .ok_or(Error::InvalidOutput)?;
            page[address.byte_offset + 1..address.byte_offset + 3]
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
        Ok(VerifiedUpdate {
            table: Some(staged),
            changed_rows,
            evidence,
        })
    }

    /// The append proof covers both separately encrypted operands and every output slot.
    pub fn stage_proved_insert(
        &self,
        table: &Table,
        prepared: PreparedInsert,
        output: &[u8],
        proof: &[u8],
        limits: Limits,
    ) -> Result<Table> {
        let evidence = self.check_insert_proof(table, &prepared, output, proof)?;
        self.stage_checked_insert(table, prepared, output, evidence, limits)
    }

    pub fn stage_checked_insert(
        &self,
        table: &Table,
        prepared: PreparedInsert,
        output: &[u8],
        evidence: bfv_query_proof::CheckedOperation,
        limits: Limits,
    ) -> Result<Table> {
        current(table, &prepared.selection)?;
        let input = self.linear.insert_circuit_request(prepared.request())?;
        require_checked_statement(&evidence, &input, output)?;
        let response = self
            .linear
            .restore_insert_circuit_output(prepared.request(), output)?;
        let answer = self
            .key
            .decrypt_indexed_insert_unverified_for_experiment(prepared.pending, &response)?;
        if answer.rows.len() != prepared.selection.ordinals.len() + prepared.incoming.len()
            || answer
                .rows
                .iter()
                .enumerate()
                .any(|(slot, row)| slot != row.slot)
        {
            return Err(Error::InvalidOutput);
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
            prepared.incoming.len(),
            &rows,
            limits,
        )?;
        current(table, &prepared.selection)?;
        Ok(staged)
    }
}
