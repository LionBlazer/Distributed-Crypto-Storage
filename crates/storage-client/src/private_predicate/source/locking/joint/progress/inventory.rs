//! Fixed public content references. Catalog labels are never proof authority.
use super::*;
use crate::private_predicate::InputProofFrames;
use bfv_mul_relin_proof::Provenance;
use bfv_product_evidence::{CatalogClaim, CatalogId};
use protocol_storage::BlobId;
use registry200_joint::progress::{Lane, ProgressEvidenceIngress, Request};
use registry200_proof::{
    coefficient_encoding::wire as enc, registry_progress as core, source::statement::encode_digest,
};
use sha2::Sha512;

pub(super) const REFERENCES: usize = 19;
pub(super) const INVENTORY_BYTES: usize = REFERENCES * 40;
// Claim, encrypted request, Key, Source, Enc0, Enc1, ordered Basis0[5],
// Basis1[5], Formation0, Formation1, actual new Core Control815/Predicate896.
#[derive(Clone, Copy)]
pub(super) struct Inventory {
    pub refs: [Option<BlobId>; REFERENCES],
}
impl Inventory {
    pub fn predicate(
        ingress: &ProgressEvidenceIngress,
        provenance: &Provenance,
        request: &[u8],
        frames: &InputProofFrames,
        source: &[u8],
        core_proof: &[u8],
    ) -> Result<Self> {
        let pairs = [
            enc::BorrowedFrame::parse(&provenance.encodings()[0].expected, &frames.encodings[0])
                .map_err(crypto)?,
            enc::BorrowedFrame::parse(&provenance.encodings()[1].expected, &frames.encodings[1])
                .map_err(crypto)?,
        ];
        if pairs.iter().any(|p| p.source() != source) {
            return Err(Error::Pins);
        }
        let claim = provenance.encode_claim().map_err(crypto)?;
        let mut bytes = [b"".as_slice(); REFERENCES];
        bytes[0] = &claim;
        bytes[1] = request;
        bytes[2] = &frames.key;
        bytes[3] = source;
        bytes[4] = pairs[0].child();
        bytes[5] = pairs[1].child();
        bytes[6..11].copy_from_slice(&frames.bases[0].each_ref().map(Vec::as_slice));
        bytes[11..16].copy_from_slice(&frames.bases[1].each_ref().map(Vec::as_slice));
        bytes[16..18].copy_from_slice(&frames.formations.each_ref().map(Vec::as_slice));
        bytes[18] = core_proof;
        let mut refs = [None; REFERENCES];
        for (i, part) in bytes.into_iter().enumerate() {
            if part.is_empty() || part.len() > cap(i) {
                return Err(Error::ResourceLimit);
            }
            refs[i] = Some(ingress.retain_public_blob(part).map_err(crypto)?);
        }
        Ok(Self { refs })
    }
    pub fn control(
        ingress: &ProgressEvidenceIngress,
        source: &[u8],
        core_proof: &[u8],
    ) -> Result<Self> {
        let mut refs = [None; REFERENCES];
        for (i, bytes) in [(3, source), (18, core_proof)] {
            if bytes.is_empty() || bytes.len() > cap(i) {
                return Err(Error::ResourceLimit);
            }
            refs[i] = Some(ingress.retain_public_blob(bytes).map_err(crypto)?);
        }
        Ok(Self { refs })
    }
    pub fn id(&self, i: usize) -> Result<BlobId> {
        self.refs.get(i).and_then(|r| *r).ok_or(Error::Encoding)
    }
    pub fn encode(&self) -> [u8; INVENTORY_BYTES] {
        let mut out = [0; INVENTORY_BYTES];
        for (i, id) in self.refs.iter().enumerate() {
            if let Some(id) = id {
                out[40 * i..40 * i + 32].copy_from_slice(id.sha256());
                out[40 * i + 32..40 * i + 40].copy_from_slice(&id.bytes().to_le_bytes());
            }
        }
        out
    }
    pub fn decode(bytes: &[u8], lane: Lane) -> Result<Self> {
        if bytes.len() != INVENTORY_BYTES {
            return Err(Error::Encoding);
        }
        let mut refs = [None; REFERENCES];
        for (i, part) in bytes.as_chunks::<40>().0.iter().enumerate() {
            let needed = lane == Lane::Predicate || i == 3 || i == 18;
            if *part == [0; 40] {
                if needed {
                    return Err(Error::Encoding);
                }
                continue;
            }
            if !needed {
                return Err(Error::Encoding);
            }
            let len = u64::from_le_bytes(part[32..40].try_into().unwrap());
            let id = BlobId::new(part[..32].try_into().unwrap(), len).map_err(storage)?;
            if len > cap(i) as u64 {
                return Err(Error::ResourceLimit);
            }
            refs[i] = Some(id);
        }
        Ok(Self { refs })
    }
    pub fn read(&self, ingress: &ProgressEvidenceIngress, i: usize) -> Result<Vec<u8>> {
        ingress
            .read_public_blob(self.id(i)?, cap(i))
            .map_err(crypto)
    }
    pub fn load(
        &self,
        ingress: &ProgressEvidenceIngress,
        pins: &Pins,
        material: &Material<'_>,
        outer: &Request,
    ) -> Result<PublicInputs> {
        material.require(pins)?;
        if outer.lane() != Lane::Predicate {
            return Err(Error::Phase);
        }
        let claim = self.read(ingress, 0)?;
        let provenance =
            Provenance::decode_claim(material.setup.clone(), &claim).map_err(crypto)?;
        let source = outer
            .inner()
            .source(app(&pins.binding)?.source_spec())
            .map_err(crypto)?;
        if provenance.anchor().encode_claim().map_err(crypto)?
            != material.anchor.encode_claim().map_err(crypto)?
            || provenance.original_setup_digest()
                != pins.binding.application_descriptor().full_setup_digest()
            || provenance.query() != outer.inner().query
        {
            return Err(Error::Pins);
        }
        for encoding in provenance.encodings() {
            if encoding.expected.bfv().full_setup()
                != pins.binding.application_descriptor().full_setup_id()
                || encoding.expected.bfv().key().public_values() != material.key.public_values()
                || encoding.expected.source_claim().values() != source.values()
                || encoding.expected.source_claim().heads != source.heads
                || encoding.expected.source_claim().packets != source.packets
            {
                return Err(Error::Pins);
            }
        }
        let request = self.read(ingress, 1)?;
        let parsed = material
            .setup
            .private_coefficient_request(&request)
            .map_err(crypto)?;
        if parsed.query() != outer.inner().query
            || parsed.ciphertexts() != provenance.ciphertexts().each_ref().map(Vec::as_slice)
        {
            return Err(Error::Pins);
        }
        let source_bytes = self.read(ingress, 3)?;
        let mut frames: Vec<Vec<u8>> = Vec::with_capacity(15);
        frames.push(self.read(ingress, 2)?);
        for i in 0..2 {
            frames.push(
                enc::join(
                    &provenance.encodings()[i].expected,
                    encode_digest(provenance.encodings()[i].encoded),
                    &source_bytes,
                    &self.read(ingress, 4 + i)?,
                )
                .map_err(crypto)?,
            );
        }
        for i in 6..18 {
            frames.push(self.read(ingress, i)?);
        }
        Ok(PublicInputs {
            provenance,
            request,
            frames: frames.try_into().map_err(|_| Error::Encoding)?,
        })
    }
    // Exact retained identities and local availability only. Actual checked
    // product or fresh replay remains mandatory; this cannot mint evidence.
    pub fn require_catalog(
        &self,
        ingress: &ProgressEvidenceIngress,
        pins: &Pins,
        id: CatalogId,
    ) -> Result<CatalogClaim> {
        let catalog = ingress.catalog_claim(id).map_err(crypto)?;
        let setup = pins.binding.setup_claim();
        if catalog.setup_parts() != setup.parts() || catalog.setup_bytes() != setup.bytes() {
            return Err(Error::Pins);
        }
        let mut h256 = Sha256::new();
        let mut h512 = Sha512::new();
        let mut length = 0u64;
        for r in catalog.references() {
            let ordinal = usize::from(r.ordinal());
            let input = match r.role() {
                2 => Some(0),
                3 => Some(1),
                5 => Some(2),
                6 => Some(3),
                7 => Some(4 + ordinal),
                8 => Some(6 + ordinal),
                9 => Some(16 + ordinal),
                _ => None,
            };
            if input.is_some_and(|i| self.refs.get(i).copied().flatten() != Some(r.blob_id())) {
                return Err(Error::Pins);
            }
            let bytes = ingress
                .read_public_blob(r.blob_id(), r.byte_cap())
                .map_err(crypto)?;
            if r.role() == 1 {
                length = length
                    .checked_add(bytes.len() as u64)
                    .ok_or(Error::ResourceLimit)?;
                h256.update(&bytes);
                h512.update(&bytes);
            }
        }
        let d = pins.binding.application_descriptor();
        if length != setup.bytes()
            || <[u8; 32]>::from(h256.finalize()) != d.full_setup_id()
            || <[u8; 64]>::from(h512.finalize()) != d.full_setup_digest()
        {
            return Err(Error::Pins);
        }
        drop(self.read(ingress, 18)?);
        Ok(catalog)
    }
}
pub(super) struct PublicInputs {
    pub provenance: Provenance,
    pub request: Vec<u8>,
    pub frames: [Vec<u8>; 15],
}
fn cap(i: usize) -> usize {
    match i {
        0 => bfv_mul_relin_proof::MAX_PROVENANCE_CLAIM_BYTES,
        1 => bfv_query_core::MAX_PRIVATE_COEFFICIENT_REQUEST_BYTES,
        2 => bfv_mul_relin_proof::input_frame_limit(0).unwrap(),
        3 => enc::MAX_SOURCE,
        4 | 5 => enc::MAX_CHILD,
        6..=15 => bfv_mul_relin_proof::input_frame_limit(3).unwrap(),
        16 | 17 => bfv_mul_relin_proof::input_frame_limit(13).unwrap(),
        18 => core::bootstrap::MAX_FRAME,
        _ => 0,
    }
}
