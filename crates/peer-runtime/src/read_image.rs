//! Static public-geometry custody: one full data image and an index prefix.
use crate::{PageError, bytes::deserialize_frame, pages::lookup_bytes, store::custody_limits};
use compact_store::{
    Commitment, EncryptedSnapshot, Limits, LookupResponse, OwnedVerifiedSnapshotBytes,
    VerifiedPage, VerifiedPagePath,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

pub const MAX_READ_IMAGE_PREFIX_PAGES: u32 = 512;
pub const MAX_READ_IMAGE_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const HEADER_BYTES: usize = 270;
const ENVELOPE_BYTES: usize = 26;
const MAX_BODY_BYTES: usize = MAX_READ_IMAGE_RESPONSE_BYTES - ENVELOPE_BYTES;
const REQUEST_MAGIC: &[u8; 8] = b"DCSRIMQ2";
const RESPONSE_MAGIC: &[u8; 8] = b"DCSRIMR2";
const VERSION: u16 = 2;
type Result<T> = std::result::Result<T, PageError>;

/// Exact immutable image request. Prefix length is public; SQL consumers must
/// derive it only from public layout, never from a predicate or selected rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadImageRequest {
    object: [u8; 32],
    data_head: Commitment,
    index_head: Commitment,
    prefix_pages: u32,
}
impl ReadImageRequest {
    pub fn new(
        object: [u8; 32],
        data_head: &Commitment,
        index_head: &Commitment,
        prefix_pages: u32,
    ) -> Result<Self> {
        data_head.layout().validate(custody_limits())?;
        index_head.layout().validate(custody_limits())?;
        if prefix_pages > MAX_READ_IMAGE_PREFIX_PAGES
            || prefix_pages as usize > index_head.layout().page_count()?
        {
            return Err(PageError::ResourceLimit);
        }
        let request = Self {
            object,
            data_head: data_head.clone(),
            index_head: index_head.clone(),
            prefix_pages,
        };
        if request.encoded_response_bytes()? > MAX_READ_IMAGE_RESPONSE_BYTES {
            return Err(PageError::ResourceLimit);
        }
        Ok(request)
    }
    pub fn object(&self) -> &[u8; 32] {
        &self.object
    }
    pub fn data_head(&self) -> &Commitment {
        &self.data_head
    }
    pub fn index_head(&self) -> &Commitment {
        &self.index_head
    }
    pub fn prefix_pages(&self) -> u32 {
        self.prefix_pages
    }
    /// Exact successful encoded response length for this authenticated geometry.
    pub fn encoded_response_bytes(&self) -> Result<usize> {
        let mut bytes =
            ENVELOPE_BYTES + HEADER_BYTES + 32 + 4 + self.data_head.layout().encoded_len()?;
        for page in 0..u64::from(self.prefix_pages) {
            bytes = bytes
                .checked_add(4 + lookup_bytes(&self.index_head, page)?)
                .ok_or(PageError::ResourceLimit)?;
        }
        Ok(bytes)
    }
    fn encode(&self, magic: &[u8; 8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_BYTES);
        bytes.extend_from_slice(magic);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.object);
        bytes.extend_from_slice(&self.data_head.encode());
        bytes.extend_from_slice(&self.index_head.encode());
        bytes.extend_from_slice(&self.prefix_pages.to_le_bytes());
        bytes
    }
    fn decode(bytes: &[u8], magic: &[u8; 8]) -> Result<Self> {
        if bytes.len() < HEADER_BYTES
            || &bytes[..8] != magic
            || bytes[8..10] != VERSION.to_le_bytes()
        {
            return Err(PageError::InvalidFormat);
        }
        Self::new(
            bytes[10..42].try_into().unwrap(),
            &Commitment::decode(&bytes[42..154], custody_limits())?,
            &Commitment::decode(&bytes[154..266], custody_limits())?,
            u32::from_le_bytes(bytes[266..270].try_into().unwrap()),
        )
    }
}

/// Immutable ciphertext view, not a partial EncryptedSnapshot/Table or SQL answer.
/// Its complete data and prefix membership are authenticated against the encoded
/// heads. Call verify with independently trusted heads/request before using it.
pub struct ReadImage {
    request: ReadImageRequest,
    nonce: [u8; 32],
    data: EncryptedSnapshot,
    index: Vec<LookupResponse>,
}
impl ReadImage {
    pub(crate) fn from_images(
        request: ReadImageRequest,
        nonce: [u8; 32],
        data: OwnedVerifiedSnapshotBytes,
        index: &OwnedVerifiedSnapshotBytes,
    ) -> Result<Self> {
        check_object(&request, nonce)?;
        if data.commitment() != request.data_head() || index.commitment() != request.index_head() {
            return Err(PageError::BindingMismatch);
        }
        let pages = (0..u64::from(request.prefix_pages))
            .map(|page| {
                index
                    .lookup(page, custody_limits())
                    .map_err(PageError::from)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            request,
            nonce,
            data: data.into_snapshot(),
            index: pages,
        })
    }
    pub fn verify(&self, expected: &ReadImageRequest) -> Result<()> {
        check_object(expected, self.nonce)?;
        if &self.request != expected
            || self.data.commitment() != expected.data_head()
            || self.index.len() != expected.prefix_pages as usize
        {
            return Err(PageError::BindingMismatch);
        }
        for (page, response) in self.index.iter().enumerate() {
            response.verify(expected.index_head(), page as u64, custody_limits())?;
        }
        Ok(())
    }
    pub fn data(&self) -> &EncryptedSnapshot {
        &self.data
    }
    pub fn index_head(&self) -> &Commitment {
        self.request.index_head()
    }
    /// Rechecks membership for an independently requested address; consumers must
    /// also compare the returned commitment with their separately trusted head.
    pub fn index_page(&self, page: u64, limits: Limits) -> Result<VerifiedPage> {
        let response = usize::try_from(page)
            .ok()
            .and_then(|page| self.index.get(page))
            .ok_or(PageError::Page(compact_store::Error::InvalidPage))?;
        Ok(response.verify(self.request.index_head(), page, limits)?)
    }
    /// Authenticated immutable rewrite path for an already returned prefix page.
    /// The caller independently supplies its trusted head to the owner reissue API.
    /// This grants no complete custody, SQL authorization or freshness.
    pub fn index_page_for_reissue(&self, page: u64) -> Result<VerifiedPagePath> {
        let response = usize::try_from(page)
            .ok()
            .and_then(|page| self.index.get(page))
            .ok_or(PageError::Page(compact_store::Error::InvalidPage))?;
        Ok(response.verify_for_reissue(self.request.index_head(), page, custody_limits())?)
    }
    fn encode(&self) -> Vec<u8> {
        let mut bytes = self.request.encode(RESPONSE_MAGIC);
        bytes.reserve(
            self.request
                .encoded_response_bytes()
                .expect("validated read geometry")
                - ENVELOPE_BYTES
                - HEADER_BYTES,
        );
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&(self.data.encoded_len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.data.encode());
        for page in &self.index {
            bytes.extend_from_slice(&(page.encoded_len() as u32).to_le_bytes());
            bytes.extend_from_slice(&page.encode());
        }
        bytes
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_BODY_BYTES {
            return Err(PageError::ResourceLimit);
        }
        let request = ReadImageRequest::decode(bytes, RESPONSE_MAGIC)?;
        if bytes.len() + ENVELOPE_BYTES != request.encoded_response_bytes()? {
            return Err(PageError::InvalidFormat);
        }
        let mut offset = HEADER_BYTES;
        let nonce = take(bytes, &mut offset, 32)?.try_into().unwrap();
        check_object(&request, nonce)?;
        let length = u32::from_le_bytes(take(bytes, &mut offset, 4)?.try_into().unwrap()) as usize;
        if length != request.data_head.layout().encoded_len()? {
            return Err(PageError::InvalidFormat);
        }
        let data = EncryptedSnapshot::decode_for_head(
            take(bytes, &mut offset, length)?,
            request.data_head(),
            custody_limits(),
        )?;
        let mut index = Vec::with_capacity(request.prefix_pages as usize);
        for page in 0..u64::from(request.prefix_pages) {
            let length =
                u32::from_le_bytes(take(bytes, &mut offset, 4)?.try_into().unwrap()) as usize;
            if length != lookup_bytes(request.index_head(), page)? {
                return Err(PageError::InvalidFormat);
            }
            let response =
                LookupResponse::decode(take(bytes, &mut offset, length)?, custody_limits())?;
            response.verify(request.index_head(), page, custody_limits())?;
            index.push(response);
        }
        if offset != bytes.len() {
            return Err(PageError::InvalidFormat);
        }
        Ok(Self {
            request,
            nonce,
            data,
            index,
        })
    }
}
fn check_object(request: &ReadImageRequest, nonce: [u8; 32]) -> Result<()> {
    let version =
        crate::TargetVersion::new(nonce, request.data_head.clone(), request.index_head.clone())
            .map_err(|_| PageError::BindingMismatch)?;
    if version.object() != request.object() {
        return Err(PageError::BindingMismatch);
    }
    Ok(())
}
fn take<'a>(bytes: &'a [u8], offset: &mut usize, length: usize) -> Result<&'a [u8]> {
    let end = offset.checked_add(length).ok_or(PageError::ResourceLimit)?;
    let slice = bytes.get(*offset..end).ok_or(PageError::InvalidFormat)?;
    *offset = end;
    Ok(slice)
}
impl Serialize for ReadImageRequest {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.encode(REQUEST_MAGIC))
    }
}
impl<'de> Deserialize<'de> for ReadImageRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let bytes = deserialize_frame(deserializer, HEADER_BYTES)?;
        if bytes.len() != HEADER_BYTES {
            return Err(de::Error::custom("Invalid read request length"));
        }
        Self::decode(&bytes, REQUEST_MAGIC).map_err(de::Error::custom)
    }
}
impl Serialize for ReadImage {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.encode())
    }
}
impl<'de> Deserialize<'de> for ReadImage {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        Self::decode(&deserialize_frame(deserializer, MAX_BODY_BYTES)?).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{self, Response, WireResponse};
    use compact_store::{Layout, Owner};
    fn fixture() -> (
        Owner,
        EncryptedSnapshot,
        EncryptedSnapshot,
        ReadImageRequest,
    ) {
        let owner = Owner::generate([76; 16]).unwrap();
        let layout = Layout {
            schema: [77; 16],
            row_width: 1,
            rows_per_page: 8,
            row_count: 24,
        };
        let data = owner
            .seal(layout, &(0..24).collect::<Vec<_>>(), custody_limits())
            .unwrap();
        let index = owner
            .seal(
                Layout {
                    schema: [78; 16],
                    ..layout
                },
                &[91; 24],
                custody_limits(),
            )
            .unwrap();
        let request = ReadImageRequest::new(
            *crate::TargetVersion::new(
                [31; 32],
                data.commitment().clone(),
                index.commitment().clone(),
            )
            .unwrap()
            .object(),
            data.commitment(),
            index.commitment(),
            2,
        )
        .unwrap();
        (owner, data, index, request)
    }
    fn image(
        data: &EncryptedSnapshot,
        index: &EncryptedSnapshot,
        request: &ReadImageRequest,
    ) -> ReadImage {
        ReadImage::from_images(request.clone(), [31; 32], audited(data), &audited(index)).unwrap()
    }
    fn audited(image: &EncryptedSnapshot) -> OwnedVerifiedSnapshotBytes {
        OwnedVerifiedSnapshotBytes::decode_for_head(
            image.encode(),
            image.commitment(),
            custody_limits(),
        )
        .unwrap()
    }
    #[test]
    fn immutable_read_image_authenticates_complete_data_and_the_exact_index_prefix() {
        let (owner, data, index, request) = fixture();
        let bytes = wire::encode(&WireResponse {
            version: 2,
            id: 7,
            result: Ok(Response::ReadImage(image(&data, &index, &request))),
        })
        .unwrap();
        assert_eq!(bytes.len(), request.encoded_response_bytes().unwrap());
        let response =
            wire::decode_custody_response(&bytes, MAX_READ_IMAGE_RESPONSE_BYTES, 13).unwrap();
        let Response::ReadImage(actual) = response.result.unwrap() else {
            panic!("read image expected")
        };
        actual.verify(&request).unwrap();
        assert_eq!(actual.data().encode(), data.encode());
        for page in 0..2 {
            assert_eq!(
                owner
                    .decrypt(&actual.index_page(page, custody_limits()).unwrap())
                    .unwrap()
                    .as_bytes(),
                &[91; 8]
            );
        }
        assert!(actual.index_page(2, custody_limits()).is_err());
        for page in 0..2 {
            let path = actual.index_page_for_reissue(page).unwrap();
            assert_eq!(path.commitment(), request.index_head());
            assert_eq!(path.page_index(), page);
            let (next, rewritten) = owner
                .reissue_page(path, request.index_head(), &[92; 8], custody_limits())
                .unwrap();
            let checked = rewritten.verify(&next, page, custody_limits()).unwrap();
            assert_eq!(owner.decrypt(&checked).unwrap().as_bytes(), &[92; 8]);
        }
        assert!(actual.index_page_for_reissue(2).is_err());
        let data_page = actual
            .data()
            .lookup(2, custody_limits())
            .unwrap()
            .verify(request.data_head(), 2, custody_limits())
            .unwrap();
        assert_eq!(
            owner.decrypt(&data_page).unwrap().as_bytes(),
            &[16, 17, 18, 19, 20, 21, 22, 23]
        );
        let encoded_request = wire::encode(&request).unwrap();
        let decoded_request: ReadImageRequest = wire::decode(&encoded_request).unwrap();
        assert_eq!(decoded_request, request);
    }
    #[test]
    fn nonce_tamper_rejects_and_rebound_nonce_never_matches_the_original_request() {
        let (_, data, index, request) = fixture();
        let mut encoded = image(&data, &index, &request).encode();
        encoded[HEADER_BYTES] ^= 1;
        assert!(ReadImage::decode(&encoded).is_err());
        let nonce: [u8; 32] = encoded[HEADER_BYTES..HEADER_BYTES + 32].try_into().unwrap();
        let rebound = crate::TargetVersion::new(
            nonce,
            request.data_head().clone(),
            request.index_head().clone(),
        )
        .unwrap();
        encoded[10..42].copy_from_slice(rebound.object());
        let valid_other_object = ReadImage::decode(&encoded).unwrap();
        assert!(valid_other_object.verify(&request).is_err());
        let different = ReadImageRequest::new(
            *rebound.object(),
            request.data_head(),
            request.index_head(),
            request.prefix_pages(),
        )
        .unwrap();
        valid_other_object.verify(&different).unwrap();
    }
    #[test]
    fn actual_custody_limits_bound_million_row_geometry_before_image_allocation() {
        let (_, data, index, _) = fixture();
        let mut data_head = data.commitment().encode();
        data_head[64..68].copy_from_slice(&3u32.to_le_bytes());
        data_head[68..72].copy_from_slice(&256u32.to_le_bytes());
        data_head[72..80].copy_from_slice(&1_000_000u64.to_le_bytes());
        let data_head = Commitment::decode(&data_head, Limits::default()).unwrap();
        let mut index_head = index.commitment().encode();
        index_head[68..72].copy_from_slice(&4096u32.to_le_bytes());
        index_head[72..80].copy_from_slice(&34_017_824u64.to_le_bytes());
        let index_head = Commitment::decode(&index_head, custody_limits()).unwrap();
        let request = ReadImageRequest::new([9; 32], &data_head, &index_head, 493).unwrap();
        assert_eq!(data_head.layout().encoded_len().unwrap(), 3_187_648);
        assert_eq!(index_head.layout().page_count().unwrap(), 8306);
        assert_eq!(request.encoded_response_bytes().unwrap(), 5_461_696);
        assert!(ReadImageRequest::new([9; 32], &data_head, &index_head, 512).is_ok());
        assert!(matches!(
            ReadImageRequest::new([9; 32], &data_head, &index_head, 513),
            Err(PageError::ResourceLimit)
        ));
        let mut excessive = data_head.encode();
        excessive[64..68].copy_from_slice(&1u32.to_le_bytes());
        excessive[68..72].copy_from_slice(&65536u32.to_le_bytes());
        excessive[72..80].copy_from_slice(&(32u64 * 1024 * 1024).to_le_bytes());
        let excessive = Commitment::decode(&excessive, custody_limits()).unwrap();
        assert!(matches!(
            ReadImageRequest::new([9; 32], &excessive, &index_head, 1),
            Err(PageError::ResourceLimit)
        ));
    }
    #[test]
    fn read_image_codec_rejects_unknown_versions_counts_lengths_truncation_and_tamper() {
        let (_, data, index, request) = fixture();
        let original = image(&data, &index, &request).encode();
        for offset in [
            0,
            8,
            42 + 80,
            154 + 80,
            HEADER_BYTES + 32 + 4 + 112 + 32,
            original.len() - 1,
        ] {
            let mut changed = original.clone();
            changed[offset] ^= 1;
            assert!(
                ReadImage::decode(&changed).is_err(),
                "tamper offset {offset}"
            );
        }
        for prefix in [1u32, 3, 513, u32::MAX] {
            let mut changed = original.clone();
            changed[266..270].copy_from_slice(&prefix.to_le_bytes());
            assert!(ReadImage::decode(&changed).is_err());
        }
        for length in [0, HEADER_BYTES - 1, HEADER_BYTES, original.len() - 1] {
            assert!(ReadImage::decode(&original[..length]).is_err());
        }
        let mut changed = original.clone();
        changed.push(0);
        assert!(ReadImage::decode(&changed).is_err());
        let mut changed = original.clone();
        changed[HEADER_BYTES + 32..HEADER_BYTES + 36].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(ReadImage::decode(&changed).is_err());
        let first_lookup = HEADER_BYTES + 32 + 4 + data.encoded_len() + 4;
        let second_lookup =
            first_lookup + index.lookup(0, custody_limits()).unwrap().encoded_len() + 4;
        let mut duplicate = original.clone();
        let first = original[first_lookup..second_lookup - 4].to_vec();
        duplicate[second_lookup..].copy_from_slice(&first);
        assert!(ReadImage::decode(&duplicate).is_err());
        let hostile = u64::MAX.to_le_bytes();
        assert!(wire::decode::<ReadImageRequest>(&hostile).is_err());
        assert!(wire::decode::<ReadImage>(&hostile).is_err());
    }
    #[test]
    fn read_image_request_binding_rejects_other_objects_heads_and_prefixes() {
        let (_, data, index, request) = fixture();
        let actual = image(&data, &index, &request);
        let wrong_object =
            ReadImageRequest::new([8; 32], request.data_head(), request.index_head(), 2).unwrap();
        assert!(actual.verify(&wrong_object).is_err());
        let wrong_prefix = ReadImageRequest::new(
            *request.object(),
            request.data_head(),
            request.index_head(),
            1,
        )
        .unwrap();
        assert!(actual.verify(&wrong_prefix).is_err());
        let wrong_heads =
            ReadImageRequest::new([9; 32], request.index_head(), request.data_head(), 2).unwrap();
        assert!(actual.verify(&wrong_heads).is_err());
        assert!(
            ReadImage::from_images(wrong_heads, [31; 32], audited(&data), &audited(&index))
                .is_err()
        );
        let data_only = ReadImageRequest::new(
            *request.object(),
            request.data_head(),
            request.index_head(),
            0,
        )
        .unwrap();
        let actual = image(&data, &index, &data_only);
        actual.verify(&data_only).unwrap();
        assert!(actual.index_page(0, custody_limits()).is_err());
    }
}
