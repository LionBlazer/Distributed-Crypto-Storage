use crate::{
    CatalogClaim, CatalogId, Error, ProductStore, Result, SharedProductStore,
    access::StoreAccess,
    catalog::{CLAIMS, RECORDS},
    record::ScopedRecordedProduct,
    storage,
};
use bfv_mul_relin_proof::{
    CheckedProduct, Expected, INPUT_FRAMES, InputEvidence, PROOF_RECORDS, Provenance, Verifier,
};
use bfv_relinearization_key_source::PreparedKey;
use registry200_proof::{coefficient_encoding::wire, source::statement::encode_digest};

/// Private common storage. Its only producers are actual native stream finish
/// and actual cold verifier finish; byte association alone cannot construct it.
pub(crate) struct CompletedMath {
    pub(crate) product: CheckedProduct,
    pub(crate) response: Vec<u8>,
}

/// Complete actual mathematical verification, from either fresh cold replay or
/// the consumed SAME-execute native recording plus full byte association. This retains no input proof buffer,
/// verifier backend, private opening, application receipt or agreed-head token.
/// ```compile_fail
/// fn forge(value: bfv_product_evidence::ReplayedProduct)
///     -> bfv_product_evidence::ReplayedProduct {
///     bfv_product_evidence::ReplayedProduct { math: value.math }
/// }
/// ```
pub struct ReplayedProduct {
    math: CompletedMath,
}
impl ReplayedProduct {
    pub fn product(&self) -> &CheckedProduct {
        &self.math.product
    }
    pub fn encrypted_response(&self) -> &[u8] {
        &self.math.response
    }
    pub fn into_parts(self) -> (CheckedProduct, Vec<u8>) {
        (self.math.product, self.math.response)
    }
}
impl ProductStore {
    /// Reopen/hash every referenced original blob and genuinely replay ALL
    /// proofs. `provenance` and `request` are the caller's independent local pins,
    /// never labels promoted from this catalog or a prior QC. The original full
    /// setup and all Key33/Source/query/heads/packet/CT claims remain bound.
    pub fn replay(
        &mut self,
        id: CatalogId,
        object: [u8; 32],
        provenance: Provenance,
        request: &[u8],
    ) -> Result<ReplayedProduct> {
        replay_in(
            &mut StoreAccess::Exclusive(self),
            id,
            object,
            provenance,
            request,
        )
    }
}
impl SharedProductStore {
    /// Consume genuine same-scope native mathematics, then reread ALL original
    /// bytes under the unchanged role caps. This is not another native pass.
    /// It grants no current head, SQL, signer, floor or consensus authority.
    pub fn consume_scoped_recording(
        &self,
        recorded: ScopedRecordedProduct<'_>,
        id: CatalogId,
        object: [u8; 32],
        provenance: Provenance,
        request: &[u8],
    ) -> Result<ReplayedProduct> {
        require_recording_origin(self, id, &recorded.store, recorded.id)?;
        let mut access = StoreAccess::Shared(self.clone());
        let catalog = access.catalog_claim(id)?;
        if catalog.encode()? != recorded.catalog.encode()?
            || catalog.binding != storage::binding(object, &provenance, request)?
            || catalog.graph != recorded.math.product.identity()
        {
            return Err(Error::Association);
        }
        access.check_setup(&catalog.setup, catalog.setup_len, &provenance)?;
        for (part, reference) in catalog.references().skip(catalog.setup.len()).enumerate() {
            let bytes = access.read(reference.blob_id(), reference.byte_cap())?;
            match part {
                0 if bytes != provenance.encode_claim()? => return Err(Error::Association),
                1 if bytes != request => return Err(Error::Association),
                2 if bytes != recorded.math.response => return Err(Error::Association),
                _ => {}
            }
        }
        if storage::require_response(&provenance, request, &recorded.math.response)?
            != recorded.math.product.output_ciphertext()
        {
            return Err(Error::Association);
        }
        Ok(ReplayedProduct {
            math: recorded.math,
        })
    }
    /// Perform the SAME fresh original proof replay. Only each bounded blob
    /// read/hash/EOF holds the store lock; all SDK/proof work runs after it is
    /// released. The process owner must hold its one actual native resource gate.
    pub fn replay(
        &self,
        id: CatalogId,
        object: [u8; 32],
        provenance: Provenance,
        request: &[u8],
    ) -> Result<ReplayedProduct> {
        replay_in(
            &mut StoreAccess::Shared(self.clone()),
            id,
            object,
            provenance,
            request,
        )
    }
}
fn replay_in(
    store: &mut StoreAccess<'_>,
    id: CatalogId,
    object: [u8; 32],
    provenance: Provenance,
    request: &[u8],
) -> Result<ReplayedProduct> {
    let catalog = store.catalog_claim(id)?;
    if catalog.binding != storage::binding(object, &provenance, request)? {
        return Err(Error::Association);
    }
    store.check_setup(&catalog.setup, catalog.setup_len, &provenance)?;
    let claim = store.read(
        catalog.parts[0],
        bfv_mul_relin_proof::MAX_PROVENANCE_CLAIM_BYTES,
    )?;
    if claim != provenance.encode_claim()? {
        return Err(Error::Association);
    }
    drop(claim);
    if store.read(
        catalog.parts[1],
        bfv_query_core::MAX_PRIVATE_COEFFICIENT_REQUEST_BYTES,
    )? != request
    {
        return Err(Error::Association);
    }
    let response = store.read(
        catalog.parts[2],
        bfv_query_core::MAX_PRIVATE_COEFFICIENT_RESPONSE_BYTES,
    )?;
    let output = storage::require_response(&provenance, request, &response)?;
    let expected = Expected::new(provenance, output)?;
    let key = PreparedKey::from_original(
        expected.provenance().setup(),
        expected.provenance().anchor().full_setup_id(),
    )
    .map_err(|_| Error::Association)?;
    let mut verifier = Verifier::new(&expected, &key);
    {
        let claims = store.read(catalog.parts[CLAIMS], bfv_mul_relin_proof::MAX_CLAIMS_BYTES)?;
        verifier.accept_claims(&claims)?;
    }
    {
        // The original input verifier borrows a complete bounded input
        // collection. Pair assembly reuses ONE stored Source but preserves
        // the exact old DCSCEP01 wire and verifies Source twice as before.
        let frames = input_frames(store, &catalog, expected.provenance())?;
        let evidence = InputEvidence::from_frames(frames.each_ref().map(Vec::as_slice))?;
        verifier.verify_inputs(&evidence)?;
    } // All input proof bytes are dropped before any output record is read.
    for ordinal in 0..PROOF_RECORDS {
        let record = store.read(
            catalog.parts[RECORDS + ordinal],
            bfv_mul_relin_proof::RECORD_HEADER + bfv_mul_relin_proof::MAX_PROOF_BYTES,
        )?;
        verifier.accept(&record)?;
    }
    let product = verifier.finish()?;
    if product.identity() != catalog.graph {
        return Err(Error::Association);
    }
    Ok(ReplayedProduct {
        math: CompletedMath { product, response },
    })
}
fn input_frames(
    store: &mut StoreAccess<'_>,
    c: &CatalogClaim,
    p: &Provenance,
) -> Result<[Vec<u8>; INPUT_FRAMES]> {
    let mut frames: [Vec<u8>; INPUT_FRAMES] = core::array::from_fn(|_| Vec::new());
    frames[0] = store.read(
        c.parts[3],
        bfv_mul_relin_proof::input_frame_limit(0).unwrap(),
    )?;
    {
        let source = store.read(c.parts[4], wire::MAX_SOURCE)?;
        for (operand, statement) in p.encodings().iter().enumerate() {
            let child = store.read(c.parts[5 + operand], wire::MAX_CHILD)?;
            frames[1 + operand] = wire::join(
                &statement.expected,
                encode_digest(statement.encoded),
                &source,
                &child,
            )
            .map_err(|_| Error::Association)?;
        }
    }
    for (ordinal, frame) in frames.iter_mut().enumerate().skip(3) {
        // Catalog's Basis/Formation order is exactly the existing input
        // collection, after replacing its two pairs by Source+two children.
        *frame = store.read(
            c.parts[ordinal + 4],
            bfv_mul_relin_proof::input_frame_limit(ordinal).unwrap(),
        )?;
    }
    Ok(frames)
}

// Ordinary identity guard only. Success cannot construct any checked product.
pub(crate) fn require_recording_origin(
    store: &SharedProductStore,
    id: CatalogId,
    original: &SharedProductStore,
    original_id: CatalogId,
) -> Result<()> {
    if !std::sync::Arc::ptr_eq(&store.inner, &original.inner) || id != original_id {
        Err(Error::Association)
    } else {
        Ok(())
    }
}
