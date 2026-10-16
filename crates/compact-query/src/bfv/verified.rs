//! Designated-client composition of complete authenticated selection and real FHE proofs.
//! Agreement/freshness and publication belong to the network client, not this module.
use super::*;
use crate::{check_schema, index, random_id, storage};
use bfv_core::QueryContext;

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

pub(super) fn proof_error(error: bfv_query_proof::Error) -> Error {
    Error::ComputationProof(error.to_string())
}

pub(super) fn require_checked_statement(
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
    pub(super) fn proof_selection_read(
        &self,
        source: &crate::ReadView<'_>,
        predicate: Option<AgeRange>,
        budget: index::MaterializationBudget,
        limits: Limits,
    ) -> Result<ExactSelection> {
        let heads = source.heads();
        match predicate {
            Some(range) => self.select_exact_read(source, range, budget, limits),
            // None is the SQL planner's schema-proven constant-false predicate.
            // It examines no stored field and is not a substitute for filtering data.
            None => {
                check_schema(heads.data())?;
                index::check_binding(&self.store, source.index, heads)?;
                Ok(ExactSelection {
                    data_head: heads.data().clone(),
                    index_head: heads.index().clone(),
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
        self.prepare_provable_select_from_source(
            &table.read_view(),
            predicate,
            projection,
            budget,
            limits,
        )
    }
    /// Same canonical complete parser for full snapshots and immutable read views.
    /// Source plaintext is erased immediately after fresh encrypted preparation.
    pub fn prepare_provable_select_from_source(
        &self,
        source: &crate::ReadView<'_>,
        predicate: Option<AgeRange>,
        projection: RowProjection,
        budget: usize,
        limits: Limits,
    ) -> Result<PreparedSelect> {
        let selection = self.proof_selection_read(
            source,
            predicate,
            index::MaterializationBudget::rows(budget),
            limits,
        )?;
        self.prepare_selected(source, selection, projection)
    }

    /// Validates the complete matching source in O(matches), plus a bounded bitmap
    /// scan of O(table rows / 64), then encrypts only its first `limit` rows in ordinal
    /// order. There is no early stop in source validation.
    /// The retained prefix must fit both the caller budget and the 256-row FHE geometry;
    /// a larger explicit limit is never silently clamped. Network privacy is source-owned.
    pub fn prepare_provable_select_limited_from_source(
        &self,
        source: &crate::ReadView<'_>,
        predicate: Option<AgeRange>,
        projection: RowProjection,
        limit: usize,
        budget: usize,
        limits: Limits,
    ) -> Result<PreparedSelect> {
        let budget = index::MaterializationBudget::rows(budget);
        let selection = match predicate {
            Some(range) => self.select_limited_read(source, range, limit, budget, limits)?,
            None => self.proof_selection_read(source, None, budget, limits)?,
        };
        self.prepare_selected(source, selection, projection)
    }

    fn prepare_selected(
        &self,
        source: &crate::ReadView<'_>,
        selection: ExactSelection,
        projection: RowProjection,
    ) -> Result<PreparedSelect> {
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
            selection: SelectState::from_selection(source.heads().clone(), selection),
        })
    }

    /// Checks one candidate response without consuming the authenticated pending
    /// selection, so another real executor may be tried after an invalid proof.
    pub fn check_select_proof(
        &self,
        heads: &crate::ReadHeads,
        prepared: &PreparedSelect,
        output: &[u8],
        proof: &[u8],
    ) -> Result<bfv_query_proof::CheckedOperation> {
        current_select(heads, &prepared.selection)?;
        let input = self.linear.select_circuit_request(prepared.request())?;
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
        let heads = table.read_heads();
        let evidence = self.check_select_proof(&heads, &prepared, output, proof)?;
        self.complete_checked_select(&heads, prepared, output, evidence)
    }

    /// Rechecks current heads and exact evidence binding before restoration and
    /// decryption. A marker from another pending request cannot finish this one.
    pub fn complete_checked_select(
        &self,
        heads: &crate::ReadHeads,
        prepared: PreparedSelect,
        output: &[u8],
        evidence: bfv_query_proof::CheckedOperation,
    ) -> Result<VerifiedSelection> {
        current_select(heads, &prepared.selection)?;
        let input = self.linear.select_circuit_request(prepared.request())?;
        require_checked_statement(&evidence, &input, output)?;
        let response = self
            .linear
            .restore_select_circuit_output(prepared.request(), output)?;
        let answer = self.complete_select_for_heads(heads, prepared, &response)?;
        Ok(VerifiedSelection {
            rows: answer.rows,
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
            &prepared.ids,
            &rows,
            limits,
        )?;
        current(table, &prepared.selection)?;
        Ok(staged)
    }
}
