//! Request-local custody admission. Factories own all cryptographic validation;
//! persistence receives immutable canonical bytes, never an unchecked RawBundle.
use super::object_info;
use crate::{
    CheckedObject, ObjectInfo, RawBundle, RemoteError, delta::ReconstructedDelta, objects,
};

pub(super) struct Candidate {
    bytes: Vec<u8>,
    data_head: [u8; 112],
    index_head: [u8; 112],
    info: ObjectInfo,
}
impl Candidate {
    pub(super) fn full(bundle: RawBundle) -> Result<Self, RemoteError> {
        Self::checked(CheckedObject::audit(bundle)?)
    }
    pub(super) fn checked(checked: CheckedObject) -> Result<Self, RemoteError> {
        let (version, bundle, _, _) = checked.into_parts();
        let bytes = objects::encode_disk(&bundle)?;
        let info = object_info(
            &bundle,
            bytes.len() as u64,
            *version.object(),
            version.data_head(),
        )?;
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
        let (version, data, index) = reconstructed.into_images();
        let object = *version.object();
        let expected_data = version.data_head().clone();
        let expected_index = version.index_head().clone();
        if data.commitment() != &expected_data || index.commitment() != &expected_index {
            return Err(RemoteError::Integrity);
        }
        // Every unchanged packet comes from the fully audited physical base;
        // every replaced packet and the complete resulting roots are checked.
        // Canonical encoding preserves that entire authenticated image.
        let bundle = RawBundle::from_images(version.nonce(), &data, &index)?;
        drop((data, index));
        if bundle.target_version()?.object() != &object {
            return Err(RemoteError::Integrity);
        }
        let bytes = objects::encode_disk(&bundle)?;
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
