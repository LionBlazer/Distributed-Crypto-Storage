//! Whole-head-bound genuine UPDATE decoding shared by full and static sources.
use super::verified::{proof_error, require_checked_statement};
use super::*;
use crate::{ReadHeads, ReadView, UpdateView, index, random_id, storage};
use compact_store::{EncryptedSnapshot, LookupResponse};

/// Staged owner-finalized ciphertext only. No state is published by this value.
pub struct VerifiedUpdate {
    table: Option<Table>,
    matched_rows: usize,
    changed_rows: usize,
    data_pages: Vec<u64>,
    index_pages: Vec<u64>,
    evidence: bfv_query_proof::CheckedOperation,
}
impl VerifiedUpdate {
    pub fn overflowed(&self) -> bool {
        self.table.is_none()
    }
    pub fn changed_rows(&self) -> usize {
        self.changed_rows
    }
    /// Complete authenticated selection size, including unchanged values.
    /// An overflowing stage is still rejected as a whole by its caller.
    pub fn matched_rows(&self) -> usize {
        self.matched_rows
    }
    /// Exact encrypted data pages reissued by this checked stage. Addresses
    /// alone provide no authorization, membership, or computation evidence.
    pub fn replaced_data_pages(&self) -> &[u64] {
        &self.data_pages
    }
    /// Exact encrypted index pages reissued by this checked stage.
    pub fn replaced_index_pages(&self) -> &[u64] {
        &self.index_pages
    }
    pub fn into_table(self) -> Option<Table> {
        self.table
    }
    pub fn evidence(&self) -> &bfv_query_proof::CheckedOperation {
        &self.evidence
    }
}

/// Immutable same-geometry proposal. The index remains a real page proof, never
/// a partial snapshot/Table. This value grants no publication or freshness.
pub struct UpdatePatch {
    data: EncryptedSnapshot,
    heads: ReadHeads,
    header: LookupResponse,
    data_pages: Vec<u64>,
}
impl UpdatePatch {
    pub fn data(&self) -> &EncryptedSnapshot {
        &self.data
    }
    pub fn heads(&self) -> &ReadHeads {
        &self.heads
    }
    pub fn index_replacement(&self) -> (u64, &LookupResponse) {
        (0, &self.header)
    }
    pub fn replaced_data_pages(&self) -> &[u64] {
        &self.data_pages
    }
}
/// Verified BFV completion and optional changed ciphertext proposal. Overflow and
/// no-change retain distinct status, without reissuing either encrypted image.
pub struct VerifiedPartialUpdate {
    patch: Option<UpdatePatch>,
    overflowed: bool,
    matched_rows: usize,
    changed_rows: usize,
    evidence: bfv_query_proof::CheckedOperation,
}
impl VerifiedPartialUpdate {
    pub fn overflowed(&self) -> bool {
        self.overflowed
    }
    pub fn matched_rows(&self) -> usize {
        self.matched_rows
    }
    pub fn changed_rows(&self) -> usize {
        self.changed_rows
    }
    pub fn patch(&self) -> Option<&UpdatePatch> {
        self.patch.as_ref()
    }
    pub fn into_patch(self) -> Option<UpdatePatch> {
        self.patch
    }
    pub fn evidence(&self) -> &bfv_query_proof::CheckedOperation {
        &self.evidence
    }
}
struct DecodedUpdate {
    selection: ExactSelection,
    overflowed: bool,
    changed_rows: usize,
    evidence: bfv_query_proof::CheckedOperation,
}
impl Owner {
    pub fn prepare_provable_update(
        &self,
        table: &Table,
        predicate: Option<AgeRange>,
        delta: u16,
        budget: usize,
        limits: Limits,
    ) -> Result<PreparedUpdate> {
        self.prepare_provable_update_from_source(
            &table.read_view(),
            predicate,
            delta,
            budget,
            limits,
        )
    }
    /// The caller supplies independently authorized ReadHeads; parsing a peer's
    /// heads alone grants no provenance, publication or agreed freshness.
    /// Authenticates every complete posting and candidate age before encrypting
    /// original fields with the unchanged bounded BFV UPDATE contract.
    pub fn prepare_provable_update_from_source(
        &self,
        source: &ReadView<'_>,
        predicate: Option<AgeRange>,
        delta: u16,
        budget: usize,
        limits: Limits,
    ) -> Result<PreparedUpdate> {
        let selection = self.proof_selection_read(
            source,
            predicate,
            index::MaterializationBudget::rows(budget),
            limits,
        )?;
        let context = bfv_core::QueryContext::new(
            random_id()?,
            selection.data_head.encode(),
            selection.index_head.encode(),
        );
        let prepared =
            self.key
                .prepare_indexed_update_for_experiment(context, &selection.fields, delta)?;
        Ok(PreparedUpdate {
            heads: source.heads().clone(),
            request: prepared.request,
            pending: prepared.pending,
            selection,
            delta,
        })
    }
    pub fn check_update_proof(
        &self,
        table: &Table,
        prepared: &PreparedUpdate,
        output: &[u8],
        proof: &[u8],
    ) -> Result<bfv_query_proof::CheckedOperation> {
        self.check_update_proof_from_source(&table.read_heads(), prepared, output, proof)
    }
    pub fn check_update_proof_from_source(
        &self,
        heads: &ReadHeads,
        prepared: &PreparedUpdate,
        output: &[u8],
        proof: &[u8],
    ) -> Result<bfv_query_proof::CheckedOperation> {
        current_update(heads, prepared)?;
        let input = self.linear.circuit_request(prepared.request())?;
        bfv_query_proof::verify(&input, output, proof).map_err(proof_error)
    }
    /// Genuine proof verification, decryption and bounded writeback. The caller
    /// verifies ALL shards and agreed freshness before publishing any proposal.
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
    pub fn stage_checked_update(
        &self,
        table: &Table,
        prepared: PreparedUpdate,
        output: &[u8],
        evidence: bfv_query_proof::CheckedOperation,
        limits: Limits,
    ) -> Result<VerifiedUpdate> {
        let decoded =
            self.decode_checked_update(&table.read_heads(), prepared, output, evidence)?;
        let matched_rows = decoded.selection.ordinals.len();
        let changed = decoded.changed_rows != 0;
        let staged = if decoded.overflowed {
            None
        } else if !changed {
            Some(Table {
                table_id: table.table_id,
                data: table.data.clone(),
                index: table.index.clone(),
            })
        } else {
            Some(storage::replace_amount_pages(
                &self.store,
                table,
                &decoded.selection.data_head,
                &decoded.selection.index_head,
                &decoded.selection.pages,
                limits,
            )?)
        };
        current(table, &decoded.selection)?;
        Ok(VerifiedUpdate {
            table: staged,
            matched_rows,
            changed_rows: decoded.changed_rows,
            data_pages: if changed {
                decoded.selection.pages.keys().copied().collect()
            } else {
                vec![]
            },
            index_pages: if changed { vec![0] } else { vec![] },
            evidence: decoded.evidence,
        })
    }
    /// Stages real decoded peer output against full data and an authenticated
    /// index prefix/path. Neither the old source nor any published state changes.
    pub fn stage_checked_update_from_source(
        &self,
        source: UpdateView<'_>,
        prepared: PreparedUpdate,
        output: &[u8],
        evidence: bfv_query_proof::CheckedOperation,
        limits: Limits,
    ) -> Result<VerifiedPartialUpdate> {
        let decoded =
            self.decode_checked_update(source.read.heads(), prepared, output, evidence)?;
        let matched_rows = decoded.selection.ordinals.len();
        let patch = if decoded.overflowed || decoded.changed_rows == 0 {
            None
        } else {
            let data = storage::replace_data_pages(
                &self.store,
                source.data,
                &decoded.selection.data_head,
                &decoded.selection.pages,
                limits,
            )?;
            let (index_head, header) = index::rebound_from_path(
                &self.store,
                source.read.index,
                source.read.heads(),
                data.commitment(),
                source.header,
            )?;
            let heads = ReadHeads::new(
                *source.read.heads().table_id(),
                data.commitment(),
                &index_head,
                limits,
            )?;
            Some(UpdatePatch {
                data,
                heads,
                header,
                data_pages: decoded.selection.pages.keys().copied().collect(),
            })
        };
        Ok(VerifiedPartialUpdate {
            patch,
            overflowed: decoded.overflowed,
            matched_rows,
            changed_rows: decoded.changed_rows,
            evidence: decoded.evidence,
        })
    }
    fn decode_checked_update(
        &self,
        heads: &ReadHeads,
        prepared: PreparedUpdate,
        output: &[u8],
        evidence: bfv_query_proof::CheckedOperation,
    ) -> Result<DecodedUpdate> {
        current_update(heads, &prepared)?;
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
            bfv_core::UnverifiedUpdateOutcome::Overflow { .. } => {
                return Ok(DecodedUpdate {
                    selection,
                    overflowed: true,
                    changed_rows: 0,
                    evidence,
                });
            }
            bfv_core::UnverifiedUpdateOutcome::Values(values) => values.rows,
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
        if changed_rows != 0 {
            for row in rows {
                let address = heads
                    .data()
                    .layout()
                    .address_of(selection.ordinals[row.slot])?;
                let page = selection
                    .pages
                    .get_mut(&address.page_index)
                    .ok_or(Error::InvalidOutput)?;
                page[address.byte_offset + 1..address.byte_offset + 3]
                    .copy_from_slice(&row.amount.to_le_bytes());
            }
        }
        Ok(DecodedUpdate {
            selection,
            overflowed: false,
            changed_rows,
            evidence,
        })
    }
}

#[cfg(test)]
mod tests;
