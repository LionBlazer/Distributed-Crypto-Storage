//! Explicit owner-online exact-index BFV operations. No FullScan/coarse shortcut exists here.
//! Input authentication and owner-local UPDATE checking do not prove malicious peer arithmetic.
use crate::{AgeRange, AppliedUpdate, Error, PlainRow, Result, Table};
use bfv_query_core as bfv_core;
use compact_store::{Commitment, Limits};
use std::{collections::BTreeMap, sync::Arc};
use zeroize::{Zeroize, Zeroizing};
mod bfv_evaluator;
mod bfv_owner;
mod verified;
pub use verified::{VerifiedSelection, VerifiedUpdate};

pub use bfv_core::{
    EvaluationStats, IndexedUpdateStats, ParameterProfile, ProofStatus, PublicSetupBytes,
    RowProjection, UnverifiedAggregate,
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
        for field in &mut self.fields {
            field.age.zeroize();
            field.amount.zeroize();
            field.active.zeroize();
        }
    }
}
pub struct PreparedAggregate {
    request: Vec<u8>,
    pending: bfv_core::PendingIndexedAggregate,
    selection: ExactSelection,
}
/// One-use storage/head-bound encrypted SELECT operation.
pub struct PreparedSelect {
    request: Vec<u8>,
    pending: bfv_core::PendingIndexedSelect,
    selection: ExactSelection,
}
/// One-use checked append state; only ciphertext request crosses to the evaluator.
pub struct PreparedInsert {
    request: Vec<u8>,
    pending: bfv_core::PendingIndexedInsert,
    selection: ExactSelection,
    incoming: Zeroizing<[u8; 3]>,
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
