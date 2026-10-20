//! Acquire continuation in the SAME exclusive phase owner. No persisted proof receipts.
use super::super::{
    EncryptedJointRecovery, JointRecoveryIdentity, JointRecoveryInputs, JointRecoveryKey,
    RecoverableJointLockingPreparation,
};
use super::*;
use crate::private_predicate::{
    BfvContext, EncryptedSourceState, SourceStateAuthority, SourceStateIdentity,
};
use bfv_product_evidence::CatalogId;
use bfv_query_core::{
    BfvKeyAnchor, EncryptedOwnerState, Owner, OwnerStateAuthority, OwnerStateIdentity, PublicSetup,
};
use registry200_finality::joint::AcquireExpectation;
use registry200_joint::AcquireExpected;
use zeroize::Zeroize;
#[path = "acquire_inventory.rs"]
mod inventory;
#[path = "acquire_run.rs"]
mod run;
use inventory::{Inventory, PublicInputs};

/// Independently retained ORIGINAL backups. These remain external and bounded
/// by their existing record parsers; in particular Ready is NOT a WAL payload.
/// Wrapping authorities must not be automatically stored beside this Vault.
/// No decoded peer claim is an acceptable replacement for `anchor` or `key`.
pub struct OwnerVaultAcquireMaterial<'a> {
    pub setup: &'a PublicSetup,
    pub anchor: &'a BfvKeyAnchor,
    pub key: &'a bfv_key_transform::Statement,
    pub owner_identity: &'a OwnerStateIdentity,
    pub owner_authority: &'a OwnerStateAuthority,
    pub owner_record: &'a EncryptedOwnerState,
    pub anchor_record: &'a EncryptedOwnerState,
    pub ready_record: &'a EncryptedOwnerState,
    pub source_identity: &'a SourceStateIdentity,
    pub source_authority: &'a SourceStateAuthority,
    pub source_record: &'a EncryptedSourceState,
    pub recovery_identity: &'a JointRecoveryIdentity,
    pub recovery_key: &'a JointRecoveryKey,
}
impl OwnerVaultAcquireMaterial<'_> {
    fn require_binding(&self, binding: &JointBinding) -> VaultResult<()> {
        let descriptor = binding.application_descriptor();
        let spec = descriptor.source_spec().map_err(owner_error)?;
        let reconstructed = Descriptor::checked(
            ApplicationDescriptor::from_application(&spec).map_err(owner_error)?,
            descriptor.source_object(),
            self.setup,
            self.anchor,
            self.key,
        )
        .map_err(owner_error)?;
        if reconstructed.encode() != descriptor.encode()
            || self.owner_identity.scope != *self.anchor.scope()
        {
            return Err(OwnerVaultError::Pins);
        }
        Ok(())
    }
    fn fingerprint(&self, binding: &JointBinding) -> VaultResult<[u8; 32]> {
        self.require_binding(binding)?;
        Ok(hash(&[
            b"DCS/owner-vault/Acquire-original-backups/v2",
            &binding.id(),
            &self.owner_identity.record_id,
            &self.recovery_identity.record,
            self.owner_record.as_bytes(),
            self.anchor_record.as_bytes(),
            self.ready_record.as_bytes(),
            self.source_record.as_bytes(),
        ]))
    }
    fn source(&self, fetched: FetchedSource<'_>) -> VaultResult<SourceOwner> {
        SourceOwner::restore_private_state(
            self.source_identity,
            fetched,
            self.source_authority,
            self.source_record,
        )
        .map_err(Into::into)
    }
    fn owner(&self) -> VaultResult<Owner> {
        Owner::restore_private_state(
            self.setup,
            self.owner_identity,
            self.owner_authority,
            self.owner_record,
        )
        .map_err(owner_error)
    }
}

/// Public original work, available only after ComputePrepared fsync and its
/// complete terminal reservation. It carries no pending private BFV object.
pub struct OwnerVaultAcquireWork {
    cursor: OwnerVaultCursor,
    invocation: [u8; 32],
    object: [u8; 32],
    public: PublicInputs,
}
impl OwnerVaultAcquireWork {
    pub fn cursor(&self) -> OwnerVaultCursor {
        self.cursor
    }
    pub fn invocation_id(&self) -> [u8; 32] {
        self.invocation
    }
    pub fn object(&self) -> [u8; 32] {
        self.object
    }
    pub fn provenance(&self) -> &bfv_mul_relin_proof::Provenance {
        &self.public.provenance
    }
    pub fn encrypted_request(&self) -> &[u8] {
        &self.public.request
    }
    pub fn proofs(&self) -> VaultResult<bfv_mul_relin_proof::InputEvidence<'_>> {
        self.public.evidence()
    }
    /// Move public inputs into the existing shared recorder. This does not move
    /// the saved private bank or lose the Vault's original retry identities.
    pub fn into_parts(self) -> (bfv_mul_relin_proof::Provenance, Vec<u8>, [Vec<u8>; 15]) {
        (
            self.public.provenance,
            self.public.request,
            self.public.frames,
        )
    }
}
/// WAIT/NOWAIT is not an empty successful query and does not create a pending
/// Vault operation. It remains a conflict result from the actual private model.
pub enum OwnerVaultAcquirePreparation {
    Prepared(Box<OwnerVaultAcquireWork>),
    NonAdmitted(Box<super::super::super::NonAdmittedJointLocking>),
}
/// Original invocation result AFTER bank CAS/fsync. It is historical, including
/// on recovery. No new invocation or current lease can be inferred from it.
pub struct OwnerVaultAcquireCompletion {
    cursor: OwnerVaultCursor,
    invocation: [u8; 32],
    recovered: bool,
    rows: Vec<CompletedJointRow>,
}
impl OwnerVaultAcquireCompletion {
    pub fn cursor(&self) -> OwnerVaultCursor {
        self.cursor
    }
    pub fn invocation_id(&self) -> [u8; 32] {
        self.invocation
    }
    pub fn is_recovered_invocation(&self) -> bool {
        self.recovered
    }
    pub fn rows(&self) -> &[CompletedJointRow] {
        &self.rows
    }
}
impl Drop for OwnerVaultAcquireCompletion {
    fn drop(&mut self) {
        for row in &mut self.rows {
            row.ordinal.zeroize();
            row.row_id.zeroize();
            row.age.zeroize();
            row.amount.zeroize();
        }
    }
}

pub(in crate::private_predicate::source::locking::joint::vault) struct AcquireState {
    material: [u8; 32],
    before_stamp: [u8; 32],
    before_idle: Zeroizing<[u8; IDLE_BYTES]>,
    request: Vec<u8>,
    roots: [[u8; 32]; 2],
    capsule: EncryptedJointRecovery,
    inventory: Inventory,
    catalog: Option<CatalogId>,
}
pub(in crate::private_predicate::source::locking::joint::vault) const MAX_ACQUIRE_STATE: usize =
    8192;
impl AcquireState {
    #[cfg(test)]
    pub(super) fn last_input(&self) -> protocol_storage::BlobId {
        self.inventory.0[17]
    }
    pub fn encode(&self) -> VaultResult<Zeroizing<Vec<u8>>> {
        let mut out = Zeroizing::new(Vec::with_capacity(MAX_ACQUIRE_STATE));
        out.extend_from_slice(b"DCSOVA02");
        out.extend_from_slice(&self.material);
        out.extend_from_slice(&self.before_stamp);
        out.extend_from_slice(self.before_idle.as_ref());
        out.extend_from_slice(&(self.request.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.request);
        out.extend_from_slice(&self.roots[0]);
        out.extend_from_slice(&self.roots[1]);
        out.extend_from_slice(self.capsule.as_bytes());
        self.inventory.encode(&mut out);
        match self.catalog {
            None => out.extend_from_slice(&[0; 40]),
            Some(id) => {
                out.extend_from_slice(id.blob_id().sha256());
                out.extend_from_slice(&id.blob_id().bytes().to_le_bytes());
            }
        }
        if out.len() > MAX_ACQUIRE_STATE {
            return Err(OwnerVaultError::ResourceLimit);
        }
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> VaultResult<Self> {
        if bytes.len() > MAX_ACQUIRE_STATE {
            return Err(OwnerVaultError::ResourceLimit);
        }
        let mut r = super::super::durable_wal::Reader::new(bytes);
        if r.take(8)? != b"DCSOVA02" {
            return Err(OwnerVaultError::Encoding);
        }
        let material = r.array()?;
        let before_stamp = r.array()?;
        let before_idle = Zeroizing::new(r.array()?);
        let request = r.blob(registry200_joint::REQUEST_BYTES)?.to_vec();
        let outer = JointRequest::decode(&request).map_err(owner_error)?;
        if outer.lane() != Lane::Acquire {
            return Err(OwnerVaultError::Encoding);
        }
        let roots = [r.array()?, r.array()?];
        let capsule =
            EncryptedJointRecovery::from_bytes(r.take(super::super::JOINT_RECOVERY_BYTES)?)?;
        let inventory = Inventory::decode(r.take(inventory::INVENTORY_BYTES)?)?;
        let digest: [u8; 32] = r.array()?;
        let length = r.u64()?;
        let catalog = if length == 0 && digest == [0; 32] {
            None
        } else {
            Some(
                CatalogId::from_blob(protocol_storage::BlobId::new(digest, length)?)
                    .map_err(owner_error)?,
            )
        };
        r.end()?;
        Ok(Self {
            material,
            before_stamp,
            before_idle,
            request,
            roots,
            capsule,
            inventory,
            catalog,
        })
    }
    pub fn copy(&self) -> VaultResult<Self> {
        Self::decode(&self.encode()?)
    }
    fn load(
        &self,
        ingress: &JointEvidenceIngress,
        binding: &JointBinding,
        material: &OwnerVaultAcquireMaterial<'_>,
    ) -> VaultResult<PublicInputs> {
        // Independent complete setup/anchor/Key33 and original backup identity
        // precede even the public claim's SDK parsing, not merely private restore.
        if material.fingerprint(binding)? != self.material {
            return Err(OwnerVaultError::Pins);
        }
        self.inventory.load(ingress, material.setup, self.roots)
    }
    fn expectation(
        &self,
        public: &PublicInputs,
        binding: &JointBinding,
        before: &control::JointControlParent,
    ) -> VaultResult<AcquireExpectation> {
        let request = JointRequest::decode(&self.request).map_err(owner_error)?;
        let app = JointApplication::new(
            binding.application_descriptor().clone(),
            binding.journal_genesis(),
        )
        .map_err(owner_error)?;
        let inputs = AcquireExpected::new(
            &app,
            &request,
            &public.provenance,
            &public.request,
            self.catalog.ok_or(OwnerVaultError::Phase)?,
        )
        .map_err(owner_error)?;
        AcquireExpectation::new(
            binding,
            before.verified_parent(),
            before.current_context(),
            inputs,
        )
        .map_err(Into::into)
    }
}

// A helper returns no Ready/anchor borrow or private factory callback. Every
// original is authenticated and both private roots plus all Key33 are reopened.
fn restore(
    saved: &AcquireState,
    binding: &JointBinding,
    before: &control::JointControlParent,
    fetched: FetchedSource<'_>,
    material: &OwnerVaultAcquireMaterial<'_>,
    public: &PublicInputs,
) -> VaultResult<(
    Owner,
    bfv_query_core::PreparedPrivateCoefficientPredicate,
    JointLockingCandidates,
)> {
    if material.fingerprint(binding)? != saved.material
        || stamp(binding, before.verified_parent(), before.current_context())? != saved.before_stamp
    {
        return Err(OwnerVaultError::Pins);
    }
    let source = material.source(again(&fetched))?;
    drop(state::restore_idle(
        saved.before_idle.as_ref(),
        &source,
        fetched,
        before,
    )?);
    let owner = material.owner()?;
    let recovered = {
        let anchor = owner
            .restore_key_anchor(
                material.setup,
                material.anchor,
                material.owner_identity,
                material.owner_authority,
                material.anchor_record,
            )
            .map_err(owner_error)?;
        let epoch = anchor
            .restore_ready_epoch(
                material.setup,
                material.key,
                material.owner_identity,
                material.owner_authority,
                material.ready_record,
            )
            .map_err(owner_error)?;
        let bfv = BfvContext {
            owner: &owner,
            setup: material.setup,
            anchor: material.anchor,
        };
        let parent = JointLockingParent::from_verified(
            before.verified_parent(),
            binding,
            BfvContext {
                owner: &owner,
                setup: material.setup,
                anchor: material.anchor,
            },
            &epoch,
        )?;
        let request = JointRequest::decode(&saved.request).map_err(owner_error)?;
        saved.capsule.restore_compute_prepared(
            material.recovery_identity,
            material.recovery_key,
            bfv,
            &epoch,
            &parent,
            JointRecoveryInputs {
                request: &request,
                provenance: &public.provenance,
                encrypted_request: &public.request,
                proofs: public.evidence()?,
                lifecycle: &public.lifecycle,
                link: &public.link,
            },
        )?
    };
    let (pending, candidates) = recovered.into_parts();
    Ok((owner, pending, candidates))
}
fn owner_error(e: impl core::fmt::Display) -> OwnerVaultError {
    OwnerVaultError::Owner(cryptography(e))
}

impl OwnerVault {
    pub(super) fn acquire_records_remaining(&self) -> VaultResult<u64> {
        let saved = self.saved.acquire.as_ref().ok_or(OwnerVaultError::Phase)?;
        match self.saved.phase {
            OwnerVaultPhase::AcquireComputePrepared => {
                Ok(if saved.catalog.is_some() { 2 } else { 3 })
            }
            OwnerVaultPhase::BodyPrepared | OwnerVaultPhase::SubmittedUnknown => Ok(1),
            _ => Err(OwnerVaultError::Phase),
        }
    }
    pub(super) fn replay_pending_acquire(
        &mut self,
        entry: &OwnerVaultReplay<'_>,
        fetched: FetchedSource<'_>,
        material: &OwnerVaultAcquireMaterial<'_>,
    ) -> VaultResult<()> {
        let saved = self.saved.acquire.as_ref().ok_or(OwnerVaultError::Phase)?;
        let before = self
            .pending_parent
            .as_ref()
            .ok_or(OwnerVaultError::Encoding)?;
        let public = saved.load(&self.ingress, &self.pins.binding, material)?;
        let (owner, pending, candidates) = restore(
            saved,
            &self.pins.binding,
            before,
            fetched,
            material,
            &public,
        )?;
        let expected = saved.expectation(&public, &self.pins.binding, before)?;
        drop(public);
        let operation = self
            .history
            .apply_acquire(entry.checkpoint, entry.block, &expected)?;
        let completed = candidates.complete_acquire(&owner, pending, operation)?;
        drop(owner);
        let (rows, opening) = completed.into_opening();
        drop(OwnerVaultAcquireCompletion {
            cursor: OwnerVaultCursor {
                generation: self.saved.generation,
                pending: self.saved.pending,
                digest: self.wal.digest,
            },
            invocation: self.saved.pending,
            recovered: true,
            rows,
        });
        drop(opening);
        Ok(())
    }
    /// NEW invocation: fresh query blind/nonce/ID are generated after this call
    /// begins. Its QC can linearize this invocation; it is never a permanent lease.
    /// Hold the actual caller-owned ProofGate, not a depot mutex, over native work.
    pub fn prepare_acquire(
        &mut self,
        cas: OwnerVaultCursor,
        fetched: FetchedSource<'_>,
        material: &OwnerVaultAcquireMaterial<'_>,
        sql: &str,
        transaction: u64,
        principal: u8,
    ) -> VaultResult<OwnerVaultAcquirePreparation> {
        self.require_cas(cas)?;
        if self.saved.phase != OwnerVaultPhase::Idle || self.draft.is_some() {
            return Err(OwnerVaultError::Phase);
        }
        // Four bounded records: Compute, completed catalog, Body, Completed.
        // All future record slots and bytes are reserved BEFORE native compute
        // or any original request escapes. Failure here publishes nothing.
        self.wal
            .require_capacity(4, 4 * OWNER_VAULT_MAX_RECORD_BYTES as u64)?;
        let lease = if self.saved.managed.is_some() {
            self.terminal.take().ok_or(OwnerVaultError::Poisoned)?
        } else {
            self.wal
                .budget
                .reserve(4 * OWNER_VAULT_MAX_RECORD_BYTES as u64)?
        };
        let fingerprint = material.fingerprint(&self.pins.binding)?;
        let before = parent(&self.history, &self.pins.binding)?;
        if current_stamp(&self.history, &self.pins.binding)? != self.saved.stamp {
            return Err(OwnerVaultError::RecoveryRequired);
        }
        let mut blind = Zeroizing::new([0; 32]);
        let mut nonce = [0; 32];
        let mut query_id = [0; 16];
        let mut invocation = [0; 32];
        if let Some(call) = &self.managed_draft {
            invocation = call.invocation;
        }
        getrandom::getrandom(blind.as_mut()).map_err(owner_error)?;
        getrandom::getrandom(&mut nonce).map_err(owner_error)?;
        getrandom::getrandom(&mut query_id).map_err(owner_error)?;
        if self.managed_draft.is_none() {
            getrandom::getrandom(&mut invocation).map_err(owner_error)?;
        }
        if invocation == [0; 32] {
            return Err(OwnerVaultError::Pins);
        }
        let compiled =
            CompiledLockingSelect::compile(sql, blind, nonce, query_id).map_err(owner_error)?;
        let source = material.source(again(&fetched))?;
        let opening =
            state::restore_idle(self.saved.idle.as_ref(), &source, again(&fetched), &before)?;
        let owner = material.owner()?;
        let prepared = {
            let anchor = owner
                .restore_key_anchor(
                    material.setup,
                    material.anchor,
                    material.owner_identity,
                    material.owner_authority,
                    material.anchor_record,
                )
                .map_err(owner_error)?;
            let mut epoch = anchor
                .restore_ready_epoch(
                    material.setup,
                    material.key,
                    material.owner_identity,
                    material.owner_authority,
                    material.ready_record,
                )
                .map_err(owner_error)?;
            source.prepare_joint_locking_owned_recoverable(
                BfvContext {
                    owner: &owner,
                    setup: material.setup,
                    anchor: material.anchor,
                },
                &mut epoch,
                fetched,
                &compiled,
                opening.for_acquire(&before, transaction, principal)?,
                control::JointOwnedRecovery::new(
                    &before,
                    material.recovery_identity,
                    material.recovery_key,
                ),
            )?
        };
        let RecoverableJointLockingPreparation::Prepared(prepared) = prepared else {
            let RecoverableJointLockingPreparation::NonAdmitted(conflict) = prepared else {
                unreachable!()
            };
            return Ok(OwnerVaultAcquirePreparation::NonAdmitted(conflict));
        };
        let (prepared, capsule) = prepared.into_parts();
        let (inputs, life, link, request, candidates) = prepared.into_parts();
        let inventory = Inventory::retain(
            &self.ingress,
            inputs.provenance(),
            inputs.request(),
            &inputs.proofs().as_input_evidence(),
            life.as_bytes(),
            link.as_bytes(),
        )?;
        let roots = [
            registry200_proof::source::statement::encode_digest(life.statement().next),
            registry200_proof::source::statement::encode_digest(life.statement().result),
        ];
        let saved = Snapshot {
            managed: self.managed_next(OwnerVaultPhase::AcquireComputePrepared, None)?,
            phase: OwnerVaultPhase::AcquireComputePrepared,
            generation: self.saved.generation,
            pending: invocation,
            stamp: self.saved.stamp,
            idle: Zeroizing::new(*self.saved.idle),
            candidate: None,
            block: None,
            checkpoint: None,
            outcome: None,
            acquire: Some(AcquireState {
                material: fingerprint,
                before_stamp: self.saved.stamp,
                before_idle: Zeroizing::new(*self.saved.idle),
                request: request.encode().map_err(owner_error)?,
                roots,
                capsule,
                inventory,
                catalog: None,
            }),
        };
        self.require_managed_acquire(&saved, &candidates)?;
        // Drop both original private completion banks and original BFV pending.
        // Subsequent attempts use ONLY the exact authenticated restore path.
        drop(candidates);
        drop(inputs);
        drop(life);
        drop(link);
        drop(owner);
        let remaining = self.wal.append(&saved, lease)?;
        self.terminal = Some(remaining);
        self.pending_parent = Some(before);
        self.saved = saved;
        self.managed_draft = None;
        self.acquire_recovered = false;
        let public = self.saved.acquire.as_ref().unwrap().load(
            &self.ingress,
            &self.pins.binding,
            material,
        )?;
        Ok(OwnerVaultAcquirePreparation::Prepared(Box::new(
            OwnerVaultAcquireWork {
                cursor: self.cursor()?,
                invocation,
                object: self.pins.binding.application_descriptor().source_object(),
                public,
            },
        )))
    }

    /// Reconstruct the ORIGINAL public request and authenticate original private
    /// backups/pending before returning it. No fresh nonce/encryption/proving.
    pub fn acquire_work(
        &self,
        cas: OwnerVaultCursor,
        fetched: FetchedSource<'_>,
        material: &OwnerVaultAcquireMaterial<'_>,
    ) -> VaultResult<OwnerVaultAcquireWork> {
        self.require_cas(cas)?;
        if self.saved.phase != OwnerVaultPhase::AcquireComputePrepared {
            return Err(OwnerVaultError::Phase);
        }
        let saved = self.saved.acquire.as_ref().ok_or(OwnerVaultError::Phase)?;
        let before = self
            .pending_parent
            .as_ref()
            .ok_or(OwnerVaultError::Encoding)?;
        let public = saved.load(&self.ingress, &self.pins.binding, material)?;
        drop(restore(
            saved,
            &self.pins.binding,
            before,
            fetched,
            material,
            &public,
        )?);
        Ok(OwnerVaultAcquireWork {
            cursor: self.cursor()?,
            invocation: self.saved.pending,
            object: self.pins.binding.application_descriptor().source_object(),
            public,
        })
    }

    /// The recorder must have reached its real 118/END/EOF boundary. This method
    /// independently replays input16/output118 and the private Link before saving
    /// the untrusted catalog identity. There is no serialized verified flag.
    pub fn save_acquire_catalog(
        &mut self,
        cas: OwnerVaultCursor,
        catalog: CatalogId,
        fetched: FetchedSource<'_>,
        material: &OwnerVaultAcquireMaterial<'_>,
    ) -> VaultResult<OwnerVaultDraft> {
        self.require_cas(cas)?;
        if self.saved.phase != OwnerVaultPhase::AcquireComputePrepared {
            return Err(OwnerVaultError::Phase);
        }
        let old = self
            .saved
            .acquire
            .as_ref()
            .ok_or(OwnerVaultError::Encoding)?;
        if old.catalog.is_some() {
            return Err(OwnerVaultError::Phase);
        }
        let public = old.load(&self.ingress, &self.pins.binding, material)?;
        drop(restore(
            old,
            &self.pins.binding,
            self.pending_parent
                .as_ref()
                .ok_or(OwnerVaultError::Encoding)?,
            fetched,
            material,
            &public,
        )?);
        let (provenance, request) = public.into_product_inputs();
        drop(
            self.ingress
                .recording_store()
                .replay(
                    catalog,
                    self.pins.binding.application_descriptor().source_object(),
                    provenance,
                    &request,
                )
                .map_err(owner_error)?,
        );
        drop(request);
        let mut next = self.compute_snapshot()?;
        next.acquire.as_mut().unwrap().catalog = Some(catalog);
        self.append_acquire(next)?;
        self.acquire_draft(self.cursor()?)
    }
    /// Public signing inputs only; immutable original outer intent and roots.
    pub fn acquire_draft(&self, cas: OwnerVaultCursor) -> VaultResult<OwnerVaultDraft> {
        self.require_cas(cas)?;
        if self.saved.phase != OwnerVaultPhase::AcquireComputePrepared {
            return Err(OwnerVaultError::Phase);
        }
        let saved = self.saved.acquire.as_ref().ok_or(OwnerVaultError::Phase)?;
        let manifest = Manifest::acquire(
            saved.roots[0],
            saved.roots[1],
            saved.catalog.ok_or(OwnerVaultError::Phase)?,
            saved.inventory.0[18],
            saved.inventory.0[19],
        )
        .map_err(owner_error)?;
        Ok(OwnerVaultDraft {
            pending: self.saved.pending,
            request: saved.request.clone(),
            manifest: manifest.encode(),
            parent: self
                .pending_parent
                .as_ref()
                .ok_or(OwnerVaultError::Encoding)?
                .verified_parent()
                .clone(),
        })
    }
    /// Actual own Header/Body and all fixed proofs are verified read-only BEFORE
    /// exact-byte BodyPrepared fsync. Caller cannot choose a verifier or receipt.
    pub fn seal_acquire_body(
        &mut self,
        cas: OwnerVaultCursor,
        block: CandidateBlock,
        fetched: FetchedSource<'_>,
        material: &OwnerVaultAcquireMaterial<'_>,
    ) -> VaultResult<OwnerVaultCursor> {
        self.require_cas(cas)?;
        if self.saved.phase != OwnerVaultPhase::AcquireComputePrepared
            || block.body().len() > OWNER_VAULT_MAX_BODY_BYTES
        {
            return Err(OwnerVaultError::Phase);
        }
        let saved = self
            .saved
            .acquire
            .as_ref()
            .ok_or(OwnerVaultError::Encoding)?;
        let public = saved.load(&self.ingress, &self.pins.binding, material)?;
        let before = self
            .pending_parent
            .as_ref()
            .ok_or(OwnerVaultError::Encoding)?;
        drop(restore(
            saved,
            &self.pins.binding,
            before,
            fetched,
            material,
            &public,
        )?);
        let expected = saved.expectation(&public, &self.pins.binding, before)?;
        drop(public);
        self.history.check_acquire_candidate(&block, &expected)?;
        let mut next = self.compute_snapshot()?;
        next.phase = OwnerVaultPhase::BodyPrepared;
        next.block = Some(block);
        self.append_acquire(next)?;
        self.cursor()
    }

    pub fn complete_acquire(
        &mut self,
        cas: OwnerVaultCursor,
        fetched: FetchedSource<'_>,
        material: &OwnerVaultAcquireMaterial<'_>,
        checkpoint: &JointCheckpoint,
    ) -> VaultResult<OwnerVaultAcquireCompletion> {
        self.require_cas(cas)?;
        if !self.is_pending() || self.saved.acquire.is_none() {
            return Err(OwnerVaultError::Phase);
        }
        let saved = self.saved.acquire.as_ref().unwrap();
        let before = self
            .pending_parent
            .as_ref()
            .ok_or(OwnerVaultError::Encoding)?;
        let public = saved.load(&self.ingress, &self.pins.binding, material)?;
        let (owner, pending, candidates) = restore(
            saved,
            &self.pins.binding,
            before,
            again(&fetched),
            material,
            &public,
        )?;
        self.require_managed_acquire(&self.saved, &candidates)?;
        let expected = saved.expectation(&public, &self.pins.binding, before)?;
        drop(public);
        let block = self.saved.block.as_ref().ok_or(OwnerVaultError::Encoding)?;
        let old_context = self.history.context()?.id();
        let operation = match self.history.apply_acquire(checkpoint, block, &expected) {
            Ok(op) => op,
            Err(e) => {
                if self
                    .history
                    .context()
                    .map(|c| c.id() != old_context)
                    .unwrap_or(true)
                {
                    self.poison_after_advance();
                }
                return Err(e.into());
            }
        };
        let result = (|| -> VaultResult<(Snapshot, OwnerVaultAcquireCompletion)> {
            let completed = candidates.complete_acquire(&owner, pending, operation)?;
            drop(owner);
            let (rows, opening) = completed.into_opening();
            let result = OwnerVaultAcquireCompletion {
                cursor: cas,
                invocation: self.saved.pending,
                recovered: self.acquire_recovered,
                rows,
            };
            let after = parent(&self.history, &self.pins.binding)?;
            state::require_idle_parent(&opening, &after)?;
            let idle = state::encode_idle(&opening)?;
            Ok((
                Snapshot {
                    managed: self.managed_next(OwnerVaultPhase::Completed, None)?,
                    phase: OwnerVaultPhase::Completed,
                    generation: self
                        .saved
                        .generation
                        .checked_add(1)
                        .ok_or(OwnerVaultError::ResourceLimit)?,
                    pending: self.saved.pending,
                    stamp: current_stamp(&self.history, &self.pins.binding)?,
                    idle,
                    candidate: None,
                    block: Some(
                        CandidateBlock::new(block.header().clone(), block.body().to_vec())
                            .map_err(OwnerVaultError::Finality)?,
                    ),
                    checkpoint: Some(JointCheckpoint::decode(&checkpoint.encode())?),
                    outcome: None,
                    acquire: Some(saved.copy()?),
                },
                result,
            ))
        })();
        let (next, mut result) = match result {
            Ok(r) => r,
            Err(e) => {
                self.poison_after_advance();
                return Err(e);
            }
        };
        if next.managed.is_some() {
            let checked_bank = (|| -> VaultResult<()> {
                let source = material.source(again(&fetched))?;
                let after = parent(&self.history, &self.pins.binding)?;
                self.require_managed_bank(&next, &source, fetched, &after)
            })();
            if let Err(error) = checked_bank {
                self.poison_after_advance();
                return Err(error);
            }
        }
        if let Err(e) = self.append_acquire(next) {
            self.poison_after_advance();
            return Err(e);
        }
        self.pending_parent = None;
        result.cursor = self.cursor()?;
        Ok(result)
    }
    /// Redelivery only of the ORIGINAL recovered invocation, never a new query.
    /// This cache was reconstructed by actual full replay/decrypt during open;
    /// plaintext rows are not read from an authenticated phase record.
    pub fn take_recovered_acquire(
        &mut self,
        cas: OwnerVaultCursor,
    ) -> VaultResult<OwnerVaultAcquireCompletion> {
        self.require_cas(cas)?;
        if self.saved.phase != OwnerVaultPhase::Completed || self.saved.acquire.is_none() {
            return Err(OwnerVaultError::Phase);
        }
        let mut result = self.acquire_result.take().ok_or(OwnerVaultError::Phase)?;
        result.cursor = self.cursor()?;
        Ok(result)
    }
    fn compute_snapshot(&self) -> VaultResult<Snapshot> {
        Ok(Snapshot {
            managed: self.managed_next(OwnerVaultPhase::AcquireComputePrepared, None)?,
            phase: OwnerVaultPhase::AcquireComputePrepared,
            generation: self.saved.generation,
            pending: self.saved.pending,
            stamp: self.saved.stamp,
            idle: Zeroizing::new(*self.saved.idle),
            candidate: None,
            block: None,
            checkpoint: None,
            outcome: None,
            acquire: Some(
                self.saved
                    .acquire
                    .as_ref()
                    .ok_or(OwnerVaultError::Phase)?
                    .copy()?,
            ),
        })
    }
    fn append_acquire(&mut self, next: Snapshot) -> VaultResult<()> {
        let lease = self.terminal.as_mut().ok_or(OwnerVaultError::Poisoned)?;
        // Preserve the reservation on errors before an append: an attempted
        // phase write cannot silently lose the already promised terminal budget.
        match self.wal.append_reserved(&next, lease) {
            Ok(()) => {
                if next.phase == OwnerVaultPhase::Completed && next.managed.is_none() {
                    self.terminal = None;
                }
                self.saved = next;
                Ok(())
            }
            Err(e) => {
                self.poison_after_advance();
                Err(e)
            }
        }
    }
}
