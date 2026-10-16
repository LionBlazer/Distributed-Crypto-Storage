//! Private bounded-slice parsing and request-local full-image audits.
use super::{BorrowedCheckedImages, RawBundle, TargetVersion};
use crate::{RemoteError, wire};
use compact_store::VerifiedSnapshotBytes;
use serde::Deserialize;
use std::{io, ops::Range};

/// A bounded, request-bound RawBundle reply in its original immutable frame.
/// This is untrusted ciphertext, not checked custody or a query/freshness proof.
/// Image borrows stay valid only while this non-cloneable frame is retained.
///
/// ```compile_fail
/// fn duplicate(frame: peer_runtime::ReceivedVersionBytes) {
///     let _ = frame.clone();
/// }
/// ```
/// ```compile_fail
/// fn escape(frame: peer_runtime::ReceivedVersionBytes) -> &'static [u8] {
///     frame.encoded_images().0
/// }
/// ```
pub struct ReceivedVersionBytes {
    frame: Vec<u8>,
    version: u16,
    nonce: [u8; 32],
    fields: [Range<usize>; 4],
}
impl ReceivedVersionBytes {
    /// Structural object binding only; both full images still require the
    /// owner's independent canonical, AEAD, TableId and agreed-head checks.
    pub fn target_version(&self) -> Result<TargetVersion, RemoteError> {
        super::target_version(
            self.version,
            self.nonce,
            &self.frame[self.fields[0].clone()],
            &self.frame[self.fields[1].clone()],
        )
    }
    pub fn encoded_images(&self) -> (&[u8], &[u8]) {
        (
            &self.frame[self.fields[2].clone()],
            &self.frame[self.fields[3].clone()],
        )
    }
}
impl std::fmt::Debug for ReceivedVersionBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceivedVersionBytes")
            .field("frame_bytes", &self.frame.len())
            .finish_non_exhaustive()
    }
}

// Deserialize borrows every payload directly from one immutable input. The
// ordinary public RawBundle Deserialize implementation remains unchanged.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBundleSlice<'a> {
    version: u16,
    nonce: [u8; 32],
    #[serde(borrow)]
    data_head: &'a [u8],
    #[serde(borrow)]
    index_head: &'a [u8],
    #[serde(borrow)]
    data: &'a [u8],
    #[serde(borrow)]
    index: &'a [u8],
}
impl<'a> RawBundleSlice<'a> {
    fn parse(bytes: &'a [u8]) -> io::Result<Self> {
        // Only slice decode may call this path. SliceReader checks each announced
        // length against remaining bytes before lending a payload; reject_trailing
        // checks the end before any owned payload is allocated.
        crate::wire::decode(bytes)
    }
    fn into_owned(self) -> RawBundle {
        RawBundle {
            version: self.version,
            nonce: self.nonce,
            data_head: self.data_head.to_vec(),
            index_head: self.index_head.to_vec(),
            data: self.data.to_vec(),
            index: self.index.to_vec(),
        }
    }
    fn checked_version(&self) -> Result<TargetVersion, RemoteError> {
        super::check_size([
            self.data_head.len(),
            self.index_head.len(),
            self.data.len(),
            self.index.len(),
        ])?;
        super::target_version(self.version, self.nonce, self.data_head, self.index_head)
    }
}
pub(crate) fn decode(bytes: &[u8]) -> io::Result<RawBundle> {
    Ok(RawBundleSlice::parse(bytes)?.into_owned())
}

// Compute admission needs the complete physical audit, but retains neither image.
// Lend the same fully parsed fields directly to the canonical snapshot auditor.
pub(super) fn audit_version(bytes: &[u8]) -> Result<TargetVersion, RemoteError> {
    let raw = RawBundleSlice::parse(bytes).map_err(crate::store::error)?;
    let version = raw.checked_version()?;
    let workers = super::audit_workers();
    for (bytes, head) in [
        (raw.data, version.data_head()),
        (raw.index, version.index_head()),
    ] {
        VerifiedSnapshotBytes::decode_for_head_with_workers(
            bytes,
            head,
            super::custody_limits(),
            workers,
        )
        .map_err(|_| RemoteError::Integrity)?;
    }
    Ok(version)
}

// Both complete images are audited before a caller may compare the object ID
// or construct a reply. This retains their checked trees, not payload Vecs.
pub(super) fn audit_images(bytes: &[u8]) -> Result<BorrowedCheckedImages<'_>, RemoteError> {
    let raw = RawBundleSlice::parse(bytes).map_err(crate::store::error)?;
    let version = raw.checked_version()?;
    let workers = super::audit_workers();
    let data = VerifiedSnapshotBytes::decode_for_head_with_workers(
        raw.data,
        version.data_head(),
        super::custody_limits(),
        workers,
    )
    .map_err(|_| RemoteError::Integrity)?;
    let index = VerifiedSnapshotBytes::decode_for_head_with_workers(
        raw.index,
        version.index_head(),
        super::custody_limits(),
        workers,
    )
    .map_err(|_| RemoteError::Integrity)?;
    Ok(BorrowedCheckedImages {
        version,
        data,
        index,
    })
}

pub(crate) fn receive_version(
    frame: Vec<u8>,
    expected_id: u64,
) -> io::Result<Option<ReceivedVersionBytes>> {
    wire::check_frame_size(&frame)?;
    wire::check_version(&frame)?;
    if frame.get(10..18) != Some([0u8, 0, 0, 0, 3, 0, 0, 0].as_slice()) {
        let response = wire::decode_response(&frame)?;
        wire::check_response_binding(response.version, response.id, expected_id)?;
        // A known unexpected success remains an RPC success, without changing
        // trace or endpoint-negative-cache policy. Remote errors stay errors.
        return response.result.map(|_| None).map_err(io::Error::other);
    }
    let (version, id, _, _): (u16, u64, u32, u32) = wire::decode(&frame[..18])?;
    let (inner_version, nonce, fields) = {
        let raw = RawBundleSlice::parse(&frame[18..])?;
        // Derive locations from the SAME completely parsed borrowed fields.
        // No second length decoder, payload copy or self-reference is retained.
        let mut cursor = 18usize + 34;
        let mut fields = [const { 0..0 }; 4];
        for (range, bytes) in
            fields
                .iter_mut()
                .zip([raw.data_head, raw.index_head, raw.data, raw.index])
        {
            let start = cursor.checked_add(8).ok_or_else(invalid_ranges)?;
            cursor = start.checked_add(bytes.len()).ok_or_else(invalid_ranges)?;
            if !frame
                .get(start..cursor)
                .is_some_and(|field| field.as_ptr() == bytes.as_ptr())
            {
                return Err(invalid_ranges());
            }
            *range = start..cursor;
        }
        if cursor != frame.len() {
            return Err(invalid_ranges());
        }
        (raw.version, raw.nonce, fields)
    };
    wire::check_response_binding(version, id, expected_id)?;
    Ok(Some(ReceivedVersionBytes {
        frame,
        version: inner_version,
        nonce,
        fields,
    }))
}
fn invalid_ranges() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "Invalid raw reply field ranges")
}

#[cfg(test)]
mod received_tests;
#[cfg(test)]
mod tests;
