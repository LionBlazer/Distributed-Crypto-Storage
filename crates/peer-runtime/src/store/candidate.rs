//! Request-local custody admission. Factories own all cryptographic validation;
//! persistence receives an immutable checked object, never an unchecked RawBundle.
use super::object_info;
use crate::{
    CheckedObject, ObjectInfo, RawBundle, RemoteError, delta::ReconstructedDelta, objects,
};

pub(super) struct Candidate {
    raw: RawBundle,
    data_head: [u8; 112],
    index_head: [u8; 112],
    info: ObjectInfo,
}
impl Candidate {
    pub(super) fn full(bundle: RawBundle) -> Result<Self, RemoteError> {
        Self::checked(CheckedObject::audit(bundle)?)
    }
    pub(super) fn checked(checked: CheckedObject) -> Result<Self, RemoteError> {
        let (version, bundle) = checked.into_raw_with_version();
        let stored = objects::disk_encoded_len(&bundle)? as u64;
        let info = object_info(&bundle, stored, *version.object(), version.data_head())?;
        let data_head = bundle
            .data_head
            .as_slice()
            .try_into()
            .map_err(|_| RemoteError::Integrity)?;
        let index_head = bundle
            .index_head
            .as_slice()
            .try_into()
            .map_err(|_| RemoteError::Integrity)?;
        Ok(Self {
            raw: bundle,
            data_head,
            index_head,
            info,
        })
    }

    pub(super) fn from_reconstructed(
        reconstructed: ReconstructedDelta,
    ) -> Result<Self, RemoteError> {
        let (version, data, index) = reconstructed.into_verified_images();
        let object = *version.object();
        let expected_data = version.data_head().clone();
        let expected_index = version.index_head().clone();
        if data.commitment() != &expected_data || index.commitment() != &expected_index {
            return Err(RemoteError::Integrity);
        }
        // The consumed canonical buffers already contain the exact target
        // manifests, unchanged audited packets and verified replacements. Moving
        // them preserves that lineage without packet materialization or encoding.
        let bundle = RawBundle {
            version: 2,
            nonce: version.nonce(),
            data_head: expected_data.encode().to_vec(),
            index_head: expected_index.encode().to_vec(),
            data: data.into_bytes(),
            index: index.into_bytes(),
        };
        if bundle.target_version()?.object() != &object {
            return Err(RemoteError::Integrity);
        }
        let stored = objects::disk_encoded_len(&bundle)? as u64;
        let info = object_info(&bundle, stored, object, &expected_data)?;
        Ok(Self {
            raw: bundle,
            data_head: expected_data.encode(),
            index_head: expected_index.encode(),
            info,
        })
    }
    // Only the factories above can produce this immutable, fully checked payload.
    // Repeating codec preflight cannot change it or skip any custody validation.
    pub(super) fn write_to(&self, output: &mut impl std::io::Write) -> std::io::Result<()> {
        objects::write_disk(&self.raw, output)
    }
    pub(super) fn heads(&self) -> (&[u8; 112], &[u8; 112]) {
        (&self.data_head, &self.index_head)
    }
    pub(super) fn info(&self) -> &ObjectInfo {
        &self.info
    }
}
