//! Explicit owner-online exact-index BFV operations. No FullScan/coarse shortcut exists here.
//! Input authentication and owner-local UPDATE checking do not prove malicious peer arithmetic.
use crate::{AgeRange, AppliedUpdate, Error, PlainRow, Result, Table};
use bfv_query_core as bfv_core;
use compact_store::{Commitment, Limits};
use std::{collections::BTreeMap, sync::Arc};
use zeroize::{Zeroize, Zeroizing};
mod aggregate;
mod bfv_evaluator;
mod bfv_owner;
mod update;
mod verified;
pub use aggregate::{PreparedProvableAggregate, VerifiedAggregate};
pub use update::{UpdatePatch, VerifiedPartialUpdate, VerifiedUpdate};
pub use verified::VerifiedSelection;

pub use bfv_core::{
    EvaluationStats, IndexedUpdateStats, POLYNOMIAL_AGGREGATE_CAPACITY, ParameterProfile,
    ProofStatus, PublicSetupBytes, RowProjection, UnverifiedAggregate,
};

/// Owns compact AEAD authority and the only BFV secret. No Clone, Debug or secret export.
pub struct Owner {
    store: compact_store::Owner,
    key: bfv_core::Owner,
    linear: bfv_core::PublicUpdateEvaluator,
}
/// Cheap clones share only public material. A peer never receives this module's Owner.
#[derive(Clone)]
pub struct Evaluator {
    peer: Arc<bfv_core::PeerEvaluator>,
    setup: Arc<bfv_core::PublicSetup>,
}
struct ExactSelection {
    data_head: Commitment,
    index_head: Commitment,
    ordinals: Vec<u64>,
    fields: Vec<bfv_core::SelectedField>,
    pages: BTreeMap<u64, Zeroizing<Vec<u8>>>,
}
impl Drop for ExactSelection {
    fn drop(&mut self) {
        self.ordinals.zeroize();
        self.fields.zeroize();
    }
}
pub struct PreparedAggregate {
    request: Vec<u8>,
    pending: bfv_core::PendingIndexedAggregate,
    selection: ExactSelection,
}
struct SelectState {
    heads: crate::ReadHeads,
    ordinals: Vec<u64>,
}
impl SelectState {
    fn from_selection(heads: crate::ReadHeads, mut selection: ExactSelection) -> Self {
        let ordinals = std::mem::take(&mut selection.ordinals);
        // Input fields and decrypted pages are zeroized before any network wait.
        drop(selection);
        Self { heads, ordinals }
    }
}
impl Drop for SelectState {
    fn drop(&mut self) {
        self.ordinals.zeroize();
    }
}
fn current_select(heads: &crate::ReadHeads, state: &SelectState) -> Result<()> {
    if heads != &state.heads {
        return Err(Error::WrongVersion);
    }
    Ok(())
}
/// One-use storage/head-bound encrypted SELECT operation; retains no source plaintext.
pub struct PreparedSelect {
    request: Vec<u8>,
    pending: bfv_core::PendingIndexedSelect,
    selection: SelectState,
}
/// One-use checked append state; only ciphertext request crosses to the evaluator.
pub struct PreparedInsert {
    request: Vec<u8>,
    pending: bfv_core::PendingIndexedInsert,
    selection: ExactSelection,
    incoming: Zeroizing<Vec<[u8; 3]>>,
    ids: crate::RowIds,
}
impl PreparedInsert {
    pub fn request(&self) -> &[u8] {
        &self.request
    }
}
impl PreparedSelect {
    pub fn request(&self) -> &[u8] {
        &self.request
    }
    pub fn selected_rows(&self) -> usize {
        self.selection.ordinals.len()
    }
}
/// Owner's final BFV-decoded plaintext. Caller owns its lifecycle; no query proof exists.
#[derive(Debug, PartialEq, Eq)]
pub struct SelectedRow {
    pub ordinal: u64,
    pub age: Option<u8>,
    pub amount: Option<u16>,
}
#[derive(Debug, PartialEq, Eq)]
pub struct UnverifiedSelectedRows {
    pub rows: Vec<SelectedRow>,
    pub proof: ProofStatus,
}
impl PreparedAggregate {
    pub fn request(&self) -> &[u8] {
        &self.request
    }
    pub fn selected_rows(&self) -> usize {
        self.selection.ordinals.len()
    }
}
/// One-use owner completion state, with no Clone or wire codec.
/// ```compile_fail
/// use compact_query::bfv::PreparedUpdate;
/// fn cannot_reuse(token: PreparedUpdate) { let moved = token; drop(token); drop(moved); }
/// ```
pub struct PreparedUpdate {
    heads: crate::ReadHeads,
    request: Vec<u8>,
    pending: bfv_core::PendingIndexedUpdate,
    selection: ExactSelection,
    delta: u16,
}
impl PreparedUpdate {
    pub fn request(&self) -> &[u8] {
        &self.request
    }
    pub fn selected_rows(&self) -> usize {
        self.selection.ordinals.len()
    }
}
fn current_update(heads: &crate::ReadHeads, prepared: &PreparedUpdate) -> Result<()> {
    if heads != &prepared.heads
        || heads.data() != &prepared.selection.data_head
        || heads.index() != &prepared.selection.index_head
    {
        return Err(Error::WrongVersion);
    }
    Ok(())
}
fn current(table: &Table, selection: &ExactSelection) -> Result<()> {
    if table.commitment() != &selection.data_head
        || table.index_commitment() != &selection.index_head
    {
        return Err(Error::WrongVersion);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
