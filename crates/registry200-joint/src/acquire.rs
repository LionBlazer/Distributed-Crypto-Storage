//! Independently pinned public inputs and the result of one actual Acquire replay.
//! Neither type establishes a current network head or an SQL capability.
use crate::{Application, Error, Lane, Manifest, Request, Result};
use bfv_mul_relin_proof::{CheckedProduct, Provenance};
use bfv_product_evidence::{CatalogId, ReplayedProduct};

/// Caller-owned public claims, never a proof receipt. Construct these from the
/// original owner-produced inputs and locally recorded catalog before admission.
pub struct AcquireExpected {
    application: [u8; 32],
    request: Vec<u8>,
    provenance: Vec<u8>,
    encrypted_request: Vec<u8>,
    catalog: CatalogId,
}
impl AcquireExpected {
    pub fn new(
        application: &Application,
        request: &Request,
        provenance: &Provenance,
        encrypted_request: &[u8],
        catalog: CatalogId,
    ) -> Result<Self> {
        request.require_application(application)?;
        if request.lane() != Lane::Acquire {
            return Err(Error::Domain);
        }
        application.descriptor().require_provenance(provenance)?;
        let source = request.inner().source(application.source_spec())?;
        for encoding in provenance.encodings() {
            let actual = encoding.expected.source_claim();
            if actual.values() != source.values()
                || actual.heads != source.heads
                || actual.packets != source.packets
                || actual.request != request.inner().query
            {
                return Err(Error::Domain);
            }
        }
        if encrypted_request.len() > bfv_query_core::MAX_PRIVATE_COEFFICIENT_REQUEST_BYTES {
            return Err(Error::ResourceLimit);
        }
        let input = provenance
            .setup()
            .private_coefficient_request(encrypted_request)
            .map_err(|_| Error::Domain)?;
        if input.query() != request.inner().query
            || input.context().data_head() != source.heads[0]
            || input.context().index_head() != source.heads[1]
            || input.ciphertexts() != provenance.ciphertexts().each_ref().map(Vec::as_slice)
        {
            return Err(Error::Domain);
        }
        Ok(Self {
            application: application.id(),
            request: request.encode()?,
            provenance: provenance.encode_claim().map_err(|_| Error::Domain)?,
            encrypted_request: encrypted_request.to_vec(),
            catalog,
        })
    }
    pub fn application_id(&self) -> [u8; 32] {
        self.application
    }
    pub fn request_bytes(&self) -> &[u8] {
        &self.request
    }
    pub fn provenance_claim(&self) -> &[u8] {
        &self.provenance
    }
    pub fn encrypted_request(&self) -> &[u8] {
        &self.encrypted_request
    }
    pub fn catalog(&self) -> CatalogId {
        self.catalog
    }
    pub(crate) fn require_manifest(&self, r: &Request, m: &Manifest) -> Result<()> {
        if r.lane() != Lane::Acquire
            || m.lane() != Lane::Acquire
            || r.encode()? != self.request
            || CatalogId::from_blob(m.reference(0)?)? != self.catalog
        {
            return Err(Error::Domain);
        }
        Ok(())
    }
    pub(crate) fn require_inputs(&self, provenance: &[u8], request: &[u8]) -> Result<()> {
        if provenance != self.provenance || request != self.encrypted_request {
            return Err(Error::Domain);
        }
        Ok(())
    }
}

/// The actual fresh input16/output118 replay, released only after the SAME
/// Source/Lifecycle/PredicateAcquire check succeeds. Historical mathematics only;
/// the finality owner must separately bind the exact signed Body and quorum.
pub struct CheckedAcquire {
    pub(crate) request: Vec<u8>,
    pub(crate) provenance: Vec<u8>,
    pub(crate) encrypted_request: Vec<u8>,
    pub(crate) manifest: Manifest,
    pub(crate) catalog: CatalogId,
    pub(crate) replayed: ReplayedProduct,
}
impl CheckedAcquire {
    pub fn request_bytes(&self) -> &[u8] {
        &self.request
    }
    pub fn provenance_claim(&self) -> &[u8] {
        &self.provenance
    }
    pub fn encrypted_request(&self) -> &[u8] {
        &self.encrypted_request
    }
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn catalog(&self) -> CatalogId {
        self.catalog
    }
    pub fn product(&self) -> &CheckedProduct {
        self.replayed.product()
    }
    pub fn encrypted_response(&self) -> &[u8] {
        self.replayed.encrypted_response()
    }
}
