//! Fixed PUBLIC references only. No proof-success bit or private opening lives here.
use super::*;
use bfv_mul_relin_proof::{InputEvidence, Provenance};
use protocol_storage::BlobId;
use registry200_proof::{
    coefficient_encoding::wire as ew, source::statement::encode_digest, wire::frame,
};

pub(super) const REFERENCES: usize = 20;
pub(super) const INVENTORY_BYTES: usize = REFERENCES * 40;
// Claim, encrypted request, Key, Source, Enc0, Enc1, Basis0[5], Basis1[5],
// Formation0, Formation1, Lifecycle child, PredicateAcquire Link.
pub(super) struct Inventory(pub [BlobId; REFERENCES]);
impl Inventory {
    pub fn retain(
        ingress: &JointEvidenceIngress,
        provenance: &Provenance,
        request: &[u8],
        proofs: &InputEvidence<'_>,
        lifecycle: &[u8],
        link: &[u8],
    ) -> VaultResult<Self> {
        let pairs = [
            ew::BorrowedFrame::parse(&provenance.encodings()[0].expected, proofs.encodings[0])
                .map_err(owner_error)?,
            ew::BorrowedFrame::parse(&provenance.encodings()[1].expected, proofs.encodings[1])
                .map_err(owner_error)?,
        ];
        let life = frame::Frame::parse(frame::Role::Transition, lifecycle).map_err(owner_error)?;
        if pairs[0].source() != pairs[1].source() || pairs[0].source() != life.source {
            return Err(OwnerVaultError::Pins);
        }
        let claim = provenance.encode_claim().map_err(owner_error)?;
        let mut bytes = [b"".as_slice(); REFERENCES];
        bytes[0] = &claim;
        bytes[1] = request;
        bytes[2] = proofs.key;
        bytes[3] = pairs[0].source();
        bytes[4] = pairs[0].child();
        bytes[5] = pairs[1].child();
        bytes[6..11].copy_from_slice(&proofs.bases[0]);
        bytes[11..16].copy_from_slice(&proofs.bases[1]);
        bytes[16..18].copy_from_slice(&proofs.formations);
        bytes[18] = life.child;
        bytes[19] = link;
        let mut ids = Vec::with_capacity(REFERENCES);
        for (i, bytes) in bytes.iter().enumerate() {
            if bytes.is_empty() || bytes.len() > cap(i) {
                return Err(OwnerVaultError::ResourceLimit);
            }
            ids.push(ingress.retain_public_blob(bytes).map_err(owner_error)?);
        }
        Ok(Self(ids.try_into().map_err(|_| OwnerVaultError::Encoding)?))
    }
    pub fn encode(&self, out: &mut Vec<u8>) {
        for id in self.0 {
            out.extend_from_slice(id.sha256());
            out.extend_from_slice(&id.bytes().to_le_bytes());
        }
    }
    pub fn decode(bytes: &[u8]) -> VaultResult<Self> {
        if bytes.len() != INVENTORY_BYTES {
            return Err(OwnerVaultError::Encoding);
        }
        let mut ids = Vec::with_capacity(REFERENCES);
        for (i, b) in bytes.as_chunks::<40>().0.iter().enumerate() {
            let id = BlobId::new(
                b[..32].try_into().unwrap(),
                u64::from_le_bytes(b[32..].try_into().unwrap()),
            )?;
            if id.bytes() > cap(i) as u64 {
                return Err(OwnerVaultError::ResourceLimit);
            }
            ids.push(id);
        }
        Ok(Self(ids.try_into().map_err(|_| OwnerVaultError::Encoding)?))
    }
    pub fn load(
        &self,
        ingress: &JointEvidenceIngress,
        setup: &bfv_query_core::PublicSetup,
        roots: [[u8; 32]; 2],
    ) -> VaultResult<PublicInputs> {
        let store = ingress.recording_store();
        let mut blobs = Vec::with_capacity(REFERENCES);
        for (i, id) in self.0.iter().enumerate() {
            blobs.push(store.read_public_blob(*id, cap(i)).map_err(owner_error)?);
        }
        let provenance = Provenance::decode_claim(setup.clone(), &blobs[0]).map_err(owner_error)?;
        drop(core::mem::take(&mut blobs[0]));
        let encodings = core::array::from_fn::<_, 2, _>(|i| {
            ew::join(
                &provenance.encodings()[i].expected,
                encode_digest(provenance.encodings()[i].encoded),
                &blobs[3],
                &blobs[4 + i],
            )
        });
        let [enc0, enc1] = encodings;
        let encodings = [enc0.map_err(owner_error)?, enc1.map_err(owner_error)?];
        let lifecycle = frame::join(frame::Role::Transition, &roots, &blobs[3], &blobs[18])
            .map_err(owner_error)?;
        // All joins have finished borrowing Source/children. Free their original
        // buffers before retaining the reconstructed pairs for any native check.
        for i in [3, 4, 5, 18] {
            drop(core::mem::take(&mut blobs[i]));
        }
        let mut frames = Vec::with_capacity(15);
        frames.push(core::mem::take(&mut blobs[2]));
        frames.extend(encodings);
        frames.extend((6..18).map(|i| core::mem::take(&mut blobs[i])));
        let request = core::mem::take(&mut blobs[1]);
        let link = core::mem::take(&mut blobs[19]);
        drop(blobs);
        Ok(PublicInputs {
            provenance,
            request,
            frames: frames.try_into().map_err(|_| OwnerVaultError::Encoding)?,
            lifecycle,
            link,
        })
    }
}
pub(super) struct PublicInputs {
    pub provenance: Provenance,
    pub request: Vec<u8>,
    pub frames: [Vec<u8>; 15],
    pub lifecycle: Vec<u8>,
    pub link: Vec<u8>,
}
impl PublicInputs {
    pub fn evidence(&self) -> VaultResult<InputEvidence<'_>> {
        InputEvidence::from_frames(self.frames.each_ref().map(Vec::as_slice)).map_err(owner_error)
    }
    pub fn into_product_inputs(self) -> (Provenance, Vec<u8>) {
        let Self {
            provenance,
            request,
            frames,
            lifecycle,
            link,
        } = self;
        drop(frames);
        drop(lifecycle);
        drop(link);
        (provenance, request)
    }
}
fn cap(i: usize) -> usize {
    match i {
        0 => bfv_mul_relin_proof::MAX_PROVENANCE_CLAIM_BYTES,
        1 => bfv_query_core::MAX_PRIVATE_COEFFICIENT_REQUEST_BYTES,
        2 => bfv_mul_relin_proof::input_frame_limit(0).unwrap(),
        3 => ew::MAX_SOURCE,
        4 | 5 => ew::MAX_CHILD,
        6..=15 => bfv_mul_relin_proof::input_frame_limit(3).unwrap(),
        16 | 17 => bfv_mul_relin_proof::input_frame_limit(13).unwrap(),
        18 => frame::MAX_CHILD_BYTES,
        19 => registry200_proof::predicate_acquire::wire::MAX_FRAME,
        _ => 0,
    }
}
