//! Original private objects for ONE fresh, exclusively borrowed driver execution.
//! No object here is serialized, published, cloned or restored as proof authority.
use super::*;
use bfv_mul_relin_proof::Provenance;
use peer_runtime::{CheckedPrivateProduct, RecordedPrivateProduct};
use registry200_proof::predicate_acquire;
use sha2::Sha512;

pub(in crate::private_predicate::source::locking::joint::vault) enum Preparation {
    Prepared(Box<OwnerVaultAcquireWork>, Box<Original>),
    NonAdmitted(Box<super::super::super::super::NonAdmittedJointLocking>),
}

pub(in crate::private_predicate::source::locking::joint::vault) struct Original {
    owner: Owner,
    pending: bfv_query_core::PreparedPrivateCoefficientPredicate,
    candidates: JointLockingCandidates,
    cursor: OwnerVaultCursor,
    // Independent public expectation, never a proof-success marker.
    expected: Option<AcquireExpectation>,
}
impl Original {
    pub(super) fn new(
        owner: Owner,
        pending: bfv_query_core::PreparedPrivateCoefficientPredicate,
        candidates: JointLockingCandidates,
        cursor: OwnerVaultCursor,
    ) -> Box<Self> {
        Box::new(Self {
            owner,
            pending,
            candidates,
            cursor,
            expected: None,
        })
    }
    fn require(&self, vault: &OwnerVault) -> VaultResult<()> {
        vault.require_cas(self.cursor)?; // includes shared poison and WAL position
        let saved = vault.saved.acquire.as_ref().ok_or(OwnerVaultError::Phase)?;
        if self.candidates._binding.id() != vault.pins.binding.id()
            || self.candidates._outer_request != saved.request
            || self.pending.request != self.candidates._staged.encrypted_request
            || current_stamp(&vault.history, &vault.pins.binding)? != saved.before_stamp
            || stamp(
                &vault.pins.binding,
                &self.candidates._parent,
                vault.history.context()?,
            )? != saved.before_stamp
        {
            return Err(OwnerVaultError::Pins);
        }
        Ok(())
    }
    pub(in crate::private_predicate::source::locking::joint::vault) fn require_work(
        &self,
        vault: &OwnerVault,
        work: &OwnerVaultAcquireWork,
    ) -> VaultResult<()> {
        self.require(vault)?;
        if vault.saved.phase != OwnerVaultPhase::AcquireComputePrepared
            || work.cursor != self.cursor
            || work.invocation != self.cursor.pending
            || work.object != vault.pins.binding.application_descriptor().source_object()
            || work.public.request != self.pending.request
            || work.public.provenance.encode_claim().map_err(owner_error)?
                != self.candidates._staged.provenance
        {
            return Err(OwnerVaultError::Pins);
        }
        // The FHE recorder checks input16/output118, not this SQL-control join.
        // Use the ORIGINAL full Cmd48/Cmd160/Result144 expectation and genuine
        // Source/query/Lifecycle/Link proof bytes, before moving inputs to RPC.
        predicate_acquire::verify(
            &self.candidates._staged._association,
            &predicate_acquire::Prerequisites {
                query: &work.public.frames[2],
                lifecycle: &work.public.lifecycle,
            },
            &work.public.link,
        )
        .map_err(owner_error)?;
        Ok(())
    }
    pub(in crate::private_predicate::source::locking::joint::vault) fn save_recorded(
        &mut self,
        vault: &mut OwnerVault,
        recorded: RecordedPrivateProduct,
        material: &OwnerVaultAcquireMaterial<'_>,
    ) -> VaultResult<OwnerVaultDraft> {
        self.require(vault)?;
        let saved = vault.saved.acquire.as_ref().ok_or(OwnerVaultError::Phase)?;
        if vault.saved.phase != OwnerVaultPhase::AcquireComputePrepared
            || saved.catalog.is_some()
            || material.fingerprint(&vault.pins.binding)? != saved.material
        {
            return Err(OwnerVaultError::Phase);
        }
        let (checked, catalog) = recorded.into_parts();
        require_retained(vault, saved, catalog, &checked)?;
        // Decode only bounded public claim metadata. There is no second input
        // proof collection, Ready/Owner restore or output118 replay here.
        let bytes = vault
            .ingress
            .read_public_blob(
                saved.inventory.0[0],
                bfv_mul_relin_proof::MAX_PROVENANCE_CLAIM_BYTES,
            )
            .map_err(owner_error)?;
        let provenance =
            Provenance::decode_claim(material.setup.clone(), &bytes).map_err(owner_error)?;
        if bytes != self.candidates._staged.provenance {
            return Err(OwnerVaultError::Pins);
        }
        let app = JointApplication::new(
            vault.pins.binding.application_descriptor().clone(),
            vault.pins.binding.journal_genesis(),
        )
        .map_err(owner_error)?;
        let request = JointRequest::decode(&saved.request).map_err(owner_error)?;
        let inputs =
            AcquireExpected::new(&app, &request, &provenance, &self.pending.request, catalog)
                .map_err(owner_error)?;
        let before = vault
            .pending_parent
            .as_ref()
            .ok_or(OwnerVaultError::Encoding)?;
        let expected = AcquireExpectation::new(
            &vault.pins.binding,
            before.verified_parent(),
            before.current_context(),
            inputs,
        )?;
        drop(provenance);
        drop(bytes);
        drop(checked);
        let mut next = vault.compute_snapshot()?;
        next.acquire.as_mut().unwrap().catalog = Some(catalog);
        vault.append_acquire(next)?; // SAME reserved writer/fsync/poison ordering
        self.cursor = vault.cursor()?;
        self.expected = Some(expected);
        vault.acquire_draft(self.cursor)
    }
    pub(in crate::private_predicate::source::locking::joint::vault) fn seal(
        &mut self,
        vault: &mut OwnerVault,
        block: CandidateBlock,
    ) -> VaultResult<()> {
        self.require(vault)?;
        if vault.saved.phase != OwnerVaultPhase::AcquireComputePrepared
            || block.body().len() > OWNER_VAULT_MAX_BODY_BYTES
        {
            return Err(OwnerVaultError::Phase);
        }
        let expected = self.expected.as_ref().ok_or(OwnerVaultError::Phase)?;
        // Intentionally unchanged full fresh application verification before
        // Body fsync. A checked stream is NOT supplied to this verifier.
        vault.history.check_acquire_candidate(&block, expected)?;
        let mut next = vault.compute_snapshot()?;
        next.phase = OwnerVaultPhase::BodyPrepared;
        next.block = Some(block);
        vault.append_acquire(next)?;
        self.cursor = vault.cursor()?;
        Ok(())
    }
    pub(in crate::private_predicate::source::locking::joint::vault) fn complete(
        self,
        vault: &mut OwnerVault,
        fetched: FetchedSource<'_>,
        material: &OwnerVaultAcquireMaterial<'_>,
        checkpoint: &JointCheckpoint,
    ) -> VaultResult<OwnerVaultAcquireCompletion> {
        self.require(vault)?;
        if !vault.is_pending() {
            return Err(OwnerVaultError::Phase);
        }
        vault.require_pending_checkpoint(checkpoint)?;
        vault.require_managed_acquire(&vault.saved, &self.candidates)?;
        let Self {
            owner,
            pending,
            candidates,
            cursor,
            expected,
        } = self;
        // The common tail STILL obtains actual fresh apply_acquire/QC/lineage,
        // performs private Result/Root checks and writes Completed BEFORE reply.
        vault.complete_acquire_original(
            cursor,
            fetched,
            material,
            checkpoint,
            (owner, pending, candidates),
            &expected.ok_or(OwnerVaultError::Phase)?,
        )
    }
}

fn require_retained(
    vault: &OwnerVault,
    saved: &AcquireState,
    id: CatalogId,
    checked: &CheckedPrivateProduct,
) -> VaultResult<()> {
    let catalog = require_inventory(vault, saved, id)?;
    let response = checked.encrypted_response();
    let response_id =
        protocol_storage::BlobId::new(Sha256::digest(response).into(), response.len() as u64)?;
    if catalog.graph_identity() != checked.product().identity() || catalog.response() != response_id
    {
        return Err(OwnerVaultError::Pins);
    }
    Ok(())
}

// A metadata/availability check only. The returned claim remains UNTRUSTED and
// cannot construct any checked product or admission result. Separating it lets
// malformed-catalog rejection be tested without fabricating a CheckedProduct.
pub(in crate::private_predicate::source::locking::joint::vault) fn require_inventory(
    vault: &OwnerVault,
    saved: &AcquireState,
    id: CatalogId,
) -> VaultResult<bfv_product_evidence::CatalogClaim> {
    vault.live()?;
    let catalog = vault.ingress.catalog_claim(id).map_err(owner_error)?;
    let setup = vault.pins.binding.setup_claim();
    if catalog.setup_parts() != setup.parts() || catalog.setup_bytes() != setup.bytes() {
        return Err(OwnerVaultError::Pins);
    }
    let mut sha256 = Sha256::new();
    let mut sha512 = Sha512::new();
    let mut setup_bytes = 0u64;
    for reference in catalog.references() {
        let ordinal = usize::from(reference.ordinal());
        let input = match reference.role() {
            2 => Some(0),
            3 => Some(1),
            5 => Some(2),
            6 => Some(3),
            7 => Some(4 + ordinal),
            8 => Some(6 + ordinal),
            9 => Some(16 + ordinal),
            _ => None,
        };
        if input.is_some_and(|i| saved.inventory.0.get(i).copied() != Some(reference.blob_id())) {
            return Err(OwnerVaultError::Pins);
        }
        // Fresh local identity/extent/hash/EOF checks on EVERY retained premise,
        // one bounded buffer at a time. These are availability checks, not proof
        // substitutes; the caller separately consumes the actual checked stream.
        let bytes = vault
            .ingress
            .read_public_blob(reference.blob_id(), reference.byte_cap())
            .map_err(owner_error)?;
        if reference.role() == 1 {
            setup_bytes = setup_bytes
                .checked_add(bytes.len() as u64)
                .ok_or(OwnerVaultError::ResourceLimit)?;
            sha256.update(&bytes);
            sha512.update(&bytes);
        }
    }
    let descriptor = vault.pins.binding.application_descriptor();
    if setup_bytes != setup.bytes()
        || <[u8; 32]>::from(sha256.finalize()) != descriptor.full_setup_id()
        || <[u8; 64]>::from(sha512.finalize()) != descriptor.full_setup_digest()
    {
        return Err(OwnerVaultError::Pins);
    }
    for (id, cap) in [
        (
            saved.inventory.0[18],
            registry200_proof::wire::frame::MAX_CHILD_BYTES,
        ),
        (saved.inventory.0[19], predicate_acquire::wire::MAX_FRAME),
    ] {
        drop(
            vault
                .ingress
                .read_public_blob(id, cap)
                .map_err(owner_error)?,
        );
    }
    Ok(catalog)
}
