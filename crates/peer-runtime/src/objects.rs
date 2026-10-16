//! Randomized object binding and complete custody admission; no SQL policy.
use crate::{RemoteError, store::custody_limits};
use compact_store::{Commitment, EncryptedSnapshot, OwnedVerifiedSnapshotBytes};
use peer_transport::MAX_FRAME_BYTES;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const OBJECT_PROFILE_ID: [u8; 32] = *b"DCS-SALTED-HEAD-OBJECT-PROFILE02";
const DOMAIN: &[u8] = b"dcs/peer-runtime/salted-head-object/v2";
pub(crate) const DISK_MAGIC: &[u8; 8] = b"DCSOBJ02";
pub(crate) const DISK_HEADER_BYTES: usize = 40;
mod slice;
pub(crate) use slice::decode as decode_slice;

/// Untrusted wire envelope. Parsing/version metadata never establishes custody.
/// Nonce is public to object recipients, but must not enter Status or journals.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RawBundle {
    pub version: u16,
    pub nonce: [u8; 32],
    #[serde(serialize_with = "crate::bytes::serialize")]
    pub data_head: Vec<u8>,
    #[serde(serialize_with = "crate::bytes::serialize")]
    pub index_head: Vec<u8>,
    #[serde(serialize_with = "crate::bytes::serialize")]
    pub data: Vec<u8>,
    #[serde(serialize_with = "crate::bytes::serialize")]
    pub index: Vec<u8>,
}
impl std::fmt::Debug for RawBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawBundle")
            .field("version", &self.version)
            .field("data_bytes", &self.data.len())
            .field("index_bytes", &self.index.len())
            .finish_non_exhaustive()
    }
}
impl RawBundle {
    /// Fresh owner staging from already authenticated immutable images. One call
    /// per object, before any Store; cloning/copying preserves the exact nonce.
    pub fn from_snapshots(
        data: &EncryptedSnapshot,
        index: &EncryptedSnapshot,
    ) -> Result<Self, RemoteError> {
        Self::stage_with_random(data, index, |nonce| {
            getrandom::getrandom(nonce).map_err(|_| ())
        })
    }
    fn stage_with_random(
        data: &EncryptedSnapshot,
        index: &EncryptedSnapshot,
        random: impl FnOnce(&mut [u8; 32]) -> Result<(), ()>,
    ) -> Result<Self, RemoteError> {
        let mut nonce = [0; 32];
        random(&mut nonce).map_err(|()| RemoteError::Integrity)?;
        Self::from_images(nonce, data, index)
    }
    pub(crate) fn from_images(
        nonce: [u8; 32],
        data: &EncryptedSnapshot,
        index: &EncryptedSnapshot,
    ) -> Result<Self, RemoteError> {
        TargetVersion::new(nonce, data.commitment().clone(), index.commitment().clone())?;
        check_size([112, 112, data.encoded_len(), index.encoded_len()])?;
        let bundle = Self {
            version: 2,
            nonce,
            data_head: data.commitment().encode().to_vec(),
            index_head: index.commitment().encode().to_vec(),
            data: data.encode(),
            index: index.encode(),
        };
        bundle.check_frame()?;
        Ok(bundle)
    }
    /// Structural binding ONLY; this does not check either encrypted image.
    pub fn target_version(&self) -> Result<TargetVersion, RemoteError> {
        if self.version != 2 {
            return Err(RemoteError::Integrity);
        }
        let data = Commitment::decode(&self.data_head, custody_limits())
            .map_err(|_| RemoteError::Integrity)?;
        let index = Commitment::decode(&self.index_head, custody_limits())
            .map_err(|_| RemoteError::Integrity)?;
        TargetVersion::new(self.nonce, data, index)
    }
    pub(crate) fn check_frame(&self) -> Result<(), RemoteError> {
        check_size([
            self.data_head.len(),
            self.index_head.len(),
            self.data.len(),
            self.index.len(),
        ])
    }
}
fn check_size(lengths: [usize; 4]) -> Result<(), RemoteError> {
    let size = lengths
        .into_iter()
        .try_fold(2usize + 32 + 4 * 8 + DISK_HEADER_BYTES, |size, len| {
            size.checked_add(len)
        })
        .ok_or(RemoteError::ResourceLimit)?;
    if size > MAX_FRAME_BYTES {
        return Err(RemoteError::ResourceLimit);
    }
    Ok(())
}
/// Immutable nonce/head binding and object address. Not a custody, authorization,
/// completeness, freshness or AEAD proof. Full admission must still audit bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct TargetVersion {
    pub(crate) nonce: [u8; 32],
    pub(crate) data: Commitment,
    pub(crate) index: Commitment,
    pub(crate) object: [u8; 32],
}
impl TargetVersion {
    pub fn new(nonce: [u8; 32], data: Commitment, index: Commitment) -> Result<Self, RemoteError> {
        data.layout()
            .validate(custody_limits())
            .map_err(|_| RemoteError::Integrity)?;
        index
            .layout()
            .validate(custody_limits())
            .map_err(|_| RemoteError::Integrity)?;
        let mut h = Sha256::new();
        h.update(DOMAIN);
        h.update(nonce);
        h.update(data.encode());
        h.update(index.encode());
        Ok(Self {
            nonce,
            data,
            index,
            object: h.finalize().into(),
        })
    }
    pub fn object(&self) -> &[u8; 32] {
        &self.object
    }
    pub fn data_head(&self) -> &Commitment {
        &self.data
    }
    pub fn index_head(&self) -> &Commitment {
        &self.index
    }
    pub(crate) fn nonce(&self) -> [u8; 32] {
        self.nonce
    }
}
/// Complete request-local checked custody. No Clone/Deserialize/mutable payload.
/// This capability is never cached across physical reads or RPCs.
pub struct CheckedObject {
    version: TargetVersion,
    envelope: ObjectEnvelope,
    data: OwnedVerifiedSnapshotBytes,
    index: OwnedVerifiedSnapshotBytes,
}
// Original wire metadata moves with the fully audited canonical image buffers.
// It is never reconstructed from an independently supplied target or new nonce.
struct ObjectEnvelope {
    version: u16,
    nonce: [u8; 32],
    data_head: Vec<u8>,
    index_head: Vec<u8>,
}
impl CheckedObject {
    pub fn audit(raw: RawBundle) -> Result<Self, RemoteError> {
        raw.check_frame()?;
        let version = raw.target_version()?;
        let RawBundle {
            version: format,
            nonce,
            data_head,
            index_head,
            data,
            index,
        } = raw;
        let data = OwnedVerifiedSnapshotBytes::decode_for_head(
            data,
            version.data_head(),
            custody_limits(),
        )
        .map_err(|_| RemoteError::Integrity)?;
        let index = OwnedVerifiedSnapshotBytes::decode_for_head(
            index,
            version.index_head(),
            custody_limits(),
        )
        .map_err(|_| RemoteError::Integrity)?;
        Ok(Self {
            version,
            envelope: ObjectEnvelope {
                version: format,
                nonce,
                data_head,
                index_head,
            },
            data,
            index,
        })
    }
    pub fn version(&self) -> &TargetVersion {
        &self.version
    }
    pub fn into_raw(self) -> RawBundle {
        self.into_raw_with_version().1
    }
    pub(crate) fn into_raw_with_version(self) -> (TargetVersion, RawBundle) {
        let ObjectEnvelope {
            version,
            nonce,
            data_head,
            index_head,
        } = self.envelope;
        let raw = RawBundle {
            version,
            nonce,
            data_head,
            index_head,
            data: self.data.into_bytes(),
            index: self.index.into_bytes(),
        };
        (self.version, raw)
    }
    pub(crate) fn into_verified_images(
        self,
    ) -> (
        TargetVersion,
        OwnedVerifiedSnapshotBytes,
        OwnedVerifiedSnapshotBytes,
    ) {
        (self.version, self.data, self.index)
    }
}
pub(crate) fn encode_disk(raw: &RawBundle) -> Result<Vec<u8>, RemoteError> {
    raw.check_frame()?;
    let mut bytes = Vec::with_capacity(DISK_HEADER_BYTES + raw.data.len() + raw.index.len() + 290);
    bytes.extend_from_slice(DISK_MAGIC);
    bytes.extend_from_slice(&OBJECT_PROFILE_ID);
    crate::wire::encode_into(raw, &mut bytes).map_err(|_| RemoteError::ResourceLimit)?;
    Ok(bytes)
}
pub(crate) fn decode_disk(bytes: &[u8]) -> std::io::Result<RawBundle> {
    check_disk_header(bytes)?;
    crate::wire::check_frame_size(bytes)?;
    decode_slice(&bytes[DISK_HEADER_BYTES..])
}
pub(crate) fn check_disk_header(bytes: &[u8]) -> std::io::Result<()> {
    if bytes.get(..8) != Some(DISK_MAGIC.as_slice())
        || bytes.get(8..40) != Some(OBJECT_PROFILE_ID.as_slice())
    {
        return Err(std::io::Error::other("Unsupported object namespace"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn images() -> (EncryptedSnapshot, EncryptedSnapshot) {
        let owner = compact_store::Owner::generate([93; 16]).unwrap();
        let image = owner
            .seal(
                compact_store::Layout {
                    schema: [94; 16],
                    row_width: 1,
                    rows_per_page: 3,
                    row_count: 7,
                },
                &[1; 7],
                compact_store::Limits::default(),
            )
            .unwrap();
        (image.clone(), image)
    }
    #[test]
    fn binding_only_metadata_never_authenticates_same_head_payload_tampering() {
        let (data, index) = images();
        let raw = RawBundle::from_snapshots(&data, &index).unwrap();
        let id = *raw.target_version().unwrap().object();
        for field in 0..2 {
            let mut bad = raw.clone();
            let bytes = if field == 0 {
                &mut bad.data
            } else {
                &mut bad.index
            };
            *bytes.last_mut().unwrap() ^= 1;
            assert_eq!(bad.target_version().unwrap().object(), &id);
            assert!(CheckedObject::audit(bad).is_err());
        }
        assert_eq!(CheckedObject::audit(raw.clone()).unwrap().into_raw(), raw);
    }
    #[test]
    fn checked_raw_round_trip_moves_all_original_buffers_and_binding_metadata() {
        let (data, index) = images();
        let mut raw = RawBundle::from_snapshots(&data, &index).unwrap();
        for bytes in [
            &mut raw.data_head,
            &mut raw.index_head,
            &mut raw.data,
            &mut raw.index,
        ] {
            bytes.reserve_exact(71);
        }
        let expected = raw.clone();
        let buffers = [&raw.data_head, &raw.index_head, &raw.data, &raw.index]
            .map(|bytes| (bytes.as_ptr(), bytes.capacity()));
        let expected_version = raw.target_version().unwrap();

        let checked = CheckedObject::audit(raw).unwrap();
        assert!(checked.version() == &expected_version);
        let returned = checked.into_raw();

        assert_eq!(returned, expected);
        for (bytes, (pointer, capacity)) in [
            &returned.data_head,
            &returned.index_head,
            &returned.data,
            &returned.index,
        ]
        .into_iter()
        .zip(buffers)
        {
            assert_eq!(bytes.as_ptr(), pointer);
            assert_eq!(bytes.capacity(), capacity);
        }
    }
    #[test]
    fn fresh_owner_staging_randomizes_ids_and_entropy_failure_returns_no_object() {
        let (data, index) = images();
        let one = RawBundle::from_snapshots(&data, &index).unwrap();
        let two = RawBundle::from_snapshots(&data, &index).unwrap();
        assert_ne!(one.nonce, two.nonce);
        assert_ne!(
            one.target_version().unwrap().object(),
            two.target_version().unwrap().object()
        );
        assert_eq!(one.data, two.data);
        assert!(RawBundle::stage_with_random(&data, &index, |_| Err(())).is_err());
        assert!(!format!("{one:?}").contains("nonce"));
    }
}

#[cfg(test)]
mod serialization_tests;
