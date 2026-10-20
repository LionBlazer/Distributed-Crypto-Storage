use crate::{
    CatalogClaim, CatalogId, Error, ProductStore, Result, SharedProductStore,
    access::StoreAccess,
    catalog::{CLAIMS, INPUT_START, MAX_SETUP_BYTES, PARTS, RECORDS},
    storage,
};
use bfv_mul_relin_proof::{CheckedProduct, Expected, InputEvidence, Verifier};
use bfv_relinearization_key_source::PreparedKey;
use protocol_storage::{BlobId, MAX_BLOB_BYTES};
use registry200_proof::coefficient_encoding::wire::BorrowedFrame;
use std::io::Read;

/// All original mathematical checks succeeded, then an immutable catalog was
/// published. The catalog remains an untrusted identity on subsequent use.
pub struct RecordedProduct {
    product: CheckedProduct,
    catalog: CatalogId,
}
impl RecordedProduct {
    pub fn product(&self) -> &CheckedProduct {
        &self.product
    }
    pub fn catalog(&self) -> CatalogId {
        self.catalog
    }
    pub fn into_parts(self) -> (CheckedProduct, CatalogId) {
        (self.product, self.catalog)
    }
}

/// Opaque completed verification after actual END/EOF. The transport owner can
/// recheck cancellation/deadline before `publish`. Dropping it publishes no
/// catalog and releases no already retained file charge.
pub struct CompletedRecording<'a> {
    store: StoreAccess<'a>,
    product: CheckedProduct,
    catalog: CatalogClaim,
}
impl CompletedRecording<'_> {
    pub fn publish(mut self) -> Result<RecordedProduct> {
        let id = CatalogId::from_blob(self.store.put(&self.catalog.encode()?)?)?;
        Ok(RecordedProduct {
            product: self.product,
            catalog: id,
        })
    }
}

/// A concrete recorder around the existing actual input16/output118 verifier.
/// No proof-success callback, decoded-proof cache or prefix receipt exists.
/// Errors are terminal for this recorder; already published public blobs remain
/// accounted, and no completed catalog is published by cancellation or Drop.
pub struct RecordingVerifier<'a> {
    verifier: Verifier<'a>,
    expected: &'a Expected,
    store: StoreAccess<'a>,
    setup: Vec<BlobId>,
    setup_len: u64,
    parts: [Option<BlobId>; PARTS],
    binding: [u8; 64],
    failed: bool,
}
impl<'a> RecordingVerifier<'a> {
    pub fn new(
        store: &'a mut ProductStore,
        expected: &'a Expected,
        key: &'a PreparedKey,
        object: [u8; 32],
        request: &[u8],
        response: &[u8],
    ) -> Result<Self> {
        Self::new_in(
            StoreAccess::Exclusive(store),
            expected,
            key,
            object,
            request,
            response,
        )
    }
    /// Record into the SAME already-open shared store. The recorder owns only
    /// a handle clone: no mutex guard is retained through verification, network
    /// I/O, cancellation checks or END/EOF. Publication still requires finish.
    pub fn new_shared(
        store: SharedProductStore,
        expected: &'a Expected,
        key: &'a PreparedKey,
        object: [u8; 32],
        request: &[u8],
        response: &[u8],
    ) -> Result<Self> {
        Self::new_in(
            StoreAccess::Shared(store),
            expected,
            key,
            object,
            request,
            response,
        )
    }
    fn new_in(
        mut store: StoreAccess<'a>,
        expected: &'a Expected,
        key: &'a PreparedKey,
        object: [u8; 32],
        request: &[u8],
        response: &[u8],
    ) -> Result<Self> {
        let p = expected.provenance();
        let binding = storage::binding(object, p, request)?;
        if storage::require_response(p, request, response)? != expected.output_ciphertext() {
            return Err(Error::Association);
        }
        if key.keyset_id() != p.anchor().full_setup_id()
            || key.original_setup_digest() != p.original_setup_digest()
        {
            return Err(Error::Association);
        }
        let original = p.setup().to_bytes().map_err(|_| Error::Association)?;
        if original.is_empty() || original.len() > MAX_SETUP_BYTES {
            return Err(Error::ResourceLimit);
        }
        let setup_len = original.len() as u64;
        let mut setup = Vec::with_capacity(2);
        for chunk in original.chunks(MAX_BLOB_BYTES as usize) {
            setup.push(store.put(chunk)?);
        }
        drop(original);
        let mut parts = [None; PARTS];
        parts[0] = Some(store.put(&p.encode_claim()?)?);
        parts[1] = Some(store.put(request)?);
        parts[2] = Some(store.put(response)?);
        Ok(Self {
            verifier: Verifier::new(expected, key),
            expected,
            store,
            setup,
            setup_len,
            parts,
            binding,
            failed: false,
        })
    }
    fn live(&self) -> Result<()> {
        if self.failed {
            Err(Error::Poisoned)
        } else {
            Ok(())
        }
    }
    pub fn accept_claims(&mut self, bytes: &[u8]) -> Result<()> {
        self.live()?;
        let result = self.claims_inner(bytes);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn claims_inner(&mut self, bytes: &[u8]) -> Result<()> {
        self.verifier.accept_claims(bytes)?;
        self.parts[CLAIMS] = Some(self.store.put(bytes)?);
        Ok(())
    }
    pub fn verify_inputs(&mut self, evidence: &InputEvidence<'_>) -> Result<()> {
        self.live()?;
        let result = self.inputs_inner(evidence);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn inputs_inner(&mut self, evidence: &InputEvidence<'_>) -> Result<()> {
        self.verifier.verify_inputs(evidence)?; // Actual Key/Source/Encoding/Basis/Formation first.
        let p = self.expected.provenance();
        let a = BorrowedFrame::parse(&p.encodings()[0].expected, evidence.encodings[0])
            .map_err(|_| Error::Association)?;
        let b = BorrowedFrame::parse(&p.encodings()[1].expected, evidence.encodings[1])
            .map_err(|_| Error::Association)?;
        if a.source() != b.source() {
            return Err(Error::Association);
        }
        self.parts[INPUT_START] = Some(self.store.put(evidence.key)?);
        self.parts[4] = Some(self.store.put(a.source())?);
        self.parts[5] = Some(self.store.put(a.child())?);
        self.parts[6] = Some(self.store.put(b.child())?);
        for (i, bytes) in evidence.bases.iter().flatten().enumerate() {
            self.parts[7 + i] = Some(self.store.put(bytes)?);
        }
        for (i, bytes) in evidence.formations.iter().enumerate() {
            self.parts[17 + i] = Some(self.store.put(bytes)?);
        }
        Ok(())
    }
    pub fn accept(&mut self, bytes: &[u8]) -> Result<()> {
        self.live()?;
        let ordinal = self.verifier.progress();
        let result = (|| {
            self.verifier.accept(bytes)?;
            self.parts[RECORDS + ordinal] = Some(self.store.put(bytes)?);
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub fn progress(&self) -> usize {
        self.verifier.progress()
    }
    pub fn cancel(mut self) {
        self.verifier.cancel();
        self.failed = true;
    }

    /// The transport owner must have obtained this terminal payload from its
    /// actual bound END/ordinal parser. This method checks empty END and reads
    /// actual EOF itself BEFORE verifier.finish. Publication is a separate
    /// consuming step so the transport owner can check cancellation afterward.
    /// No persisted EOF/verified bit is trusted by a subsequent reader.
    pub fn finish(self, terminal: &[u8], stream: &mut impl Read) -> Result<CompletedRecording<'a>> {
        self.live()?;
        require_end(terminal, stream)?;
        let product = self.verifier.finish()?;
        let parts = self
            .parts
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or(Error::Incomplete)?
            .try_into()
            .map_err(|_| Error::Incomplete)?;
        let catalog = CatalogClaim {
            setup_len: self.setup_len,
            setup: self.setup,
            parts,
            binding: self.binding,
            graph: product.identity(),
        };
        Ok(CompletedRecording {
            store: self.store,
            product,
            catalog,
        })
    }
}

pub(crate) fn require_end(terminal: &[u8], stream: &mut impl Read) -> Result<()> {
    if !terminal.is_empty() {
        return Err(Error::Encoding);
    }
    let mut trailing = [0];
    if stream.read(&mut trailing)? != 0 {
        return Err(Error::Encoding);
    }
    Ok(())
}
