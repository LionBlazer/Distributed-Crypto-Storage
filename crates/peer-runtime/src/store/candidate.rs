//! Request-local custody admission. Factories own all cryptographic validation;
//! persistence receives immutable canonical bytes, never an unchecked Bundle.
use super::{error, object_info, validate};
use crate::{Bundle, ObjectInfo, RemoteError, delta::ReconstructedDelta, wire::encode};

pub(super) struct Candidate {
    bytes: Vec<u8>,
    data_head: [u8; 112],
    index_head: [u8; 112],
    info: ObjectInfo,
}
impl Candidate {
    pub(super) fn full(bundle: Bundle) -> Result<Self, RemoteError> {
        // Preserve the full-frame bound before raw images are decoded/allocated.
        let bytes = encode(&bundle).map_err(error)?;
        let info = validate(&bundle, bytes.len() as u64)?;
        Ok(Self {
            bytes,
            data_head: bundle
                .data_head
                .as_slice()
                .try_into()
                .map_err(|_| RemoteError::Integrity)?,
            index_head: bundle
                .index_head
                .as_slice()
                .try_into()
                .map_err(|_| RemoteError::Integrity)?,
            info,
        })
    }

    pub(super) fn from_reconstructed(
        reconstructed: ReconstructedDelta,
    ) -> Result<Self, RemoteError> {
        let (object, expected_data, expected_index, data, index) = reconstructed.into_images();
        if data.commitment() != &expected_data || index.commitment() != &expected_index {
            return Err(RemoteError::Integrity);
        }
        // Every unchanged packet comes from the fully audited physical base;
        // every replaced packet and the complete resulting roots are checked.
        // Canonical encoding preserves that entire authenticated image.
        let bundle = Bundle {
            data_head: expected_data.encode().to_vec(),
            index_head: expected_index.encode().to_vec(),
            data: data.encode(),
            index: index.encode(),
        };
        drop((data, index));
        // This ID is the existing four big-endian-length-prefixed parts hash,
        // NOT the hash of bincode disk bytes. Check it exactly once.
        if bundle.id() != object {
            return Err(RemoteError::Integrity);
        }
        let bytes = encode(&bundle).map_err(error)?;
        let info = object_info(&bundle, bytes.len() as u64, object, &expected_data)?;
        Ok(Self {
            bytes,
            data_head: expected_data.encode(),
            index_head: expected_index.encode(),
            info,
        })
    }
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(super) fn heads(&self) -> (&[u8; 112], &[u8; 112]) {
        (&self.data_head, &self.index_head)
    }
    pub(super) fn info(&self) -> &ObjectInfo {
        &self.info
    }
}
