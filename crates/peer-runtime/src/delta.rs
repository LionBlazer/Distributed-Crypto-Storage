//! Fixed public-geometry padded ciphertext replacement; never SQL acceptance.
use crate::{
    Bundle, PageAddress, PageError, PageImage, pages::lookup_bytes, store::custody_limits,
};
use compact_store::{Commitment, EncryptedSnapshot, LookupResponse, VerifiedPage};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

pub const MAX_STORE_DELTA_PAGES: usize = 257;
/// Entire encoded WireRequest, excluding the transport prefix and TLS.
pub const MAX_STORE_DELTA_REQUEST_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_STORE_DELTA_RESPONSE_BYTES: usize = 64 * 1024;
const HEADER_BYTES: usize = 524;
const REQUEST_ENVELOPE_BYTES: usize = 22;
const FULL_STORE_ENVELOPE_BYTES: usize = 270;
const MAX_BODY_BYTES: usize = MAX_STORE_DELTA_REQUEST_BYTES - REQUEST_ENVELOPE_BYTES;
const MAGIC: &[u8; 8] = b"DCSDLTA1";
const VERSION: u16 = 1;
type Result<T> = std::result::Result<T, PageError>;

/// Advisory transport geometry only. Recipient classification belongs to the
/// caller's previously committed placement, never to a failed RPC or dirty set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreDeltaPlan {
    padded_bytes: Option<usize>,
    full_bytes: usize,
}
impl StoreDeltaPlan {
    pub fn for_heads(data: &Commitment, index: &Commitment) -> Result<Self> {
        for head in [data, index] {
            head.layout().validate(custody_limits())?;
        }
        let full = data
            .layout()
            .encoded_len()?
            .checked_add(index.layout().encoded_len()?)
            .and_then(|size| size.checked_add(FULL_STORE_ENVELOPE_BYTES))
            .ok_or(PageError::ResourceLimit)?;
        if full > peer_transport::MAX_FRAME_BYTES {
            return Err(PageError::ResourceLimit);
        }
        // At most four public groups: full pages and the last page of each image.
        // Taking the largest groups avoids any scan of actual changed addresses.
        let mut groups = Vec::with_capacity(4);
        for head in [data, index] {
            let count = head.layout().page_count()?;
            if count == 0 {
                continue;
            }
            if count > 1 {
                groups.push((13 + lookup_bytes(head, 0)?, count - 1));
            }
            groups.push((13 + lookup_bytes(head, (count - 1) as u64)?, 1));
        }
        groups.sort_unstable_by_key(|group| std::cmp::Reverse(group.0));
        let mut remaining = MAX_STORE_DELTA_PAGES;
        let mut padded = HEADER_BYTES + REQUEST_ENVELOPE_BYTES;
        for (size, count) in groups {
            let take = remaining.min(count);
            padded = padded
                .checked_add(size.checked_mul(take).ok_or(PageError::ResourceLimit)?)
                .ok_or(PageError::ResourceLimit)?;
            remaining -= take;
        }
        if padded < full && padded <= MAX_STORE_DELTA_REQUEST_BYTES {
            Ok(Self {
                padded_bytes: Some(padded),
                full_bytes: full,
            })
        } else {
            Ok(Self {
                padded_bytes: None,
                full_bytes: full,
            })
        }
    }
    /// Some only when the fixed worst-case delta is smaller than full storage.
    pub fn padded_request_bytes(self) -> Option<usize> {
        self.padded_bytes
    }
    pub fn full_request_bytes(self) -> usize {
        self.full_bytes
    }
}
#[derive(Clone)]
struct ObjectVersion {
    object: [u8; 32],
    data: Commitment,
    index: Commitment,
}
impl ObjectVersion {
    fn head(&self, image: PageImage) -> &Commitment {
        match image {
            PageImage::Data => &self.data,
            PageImage::Index => &self.index,
        }
    }
}

#[derive(Clone)]
struct VersionBinding {
    base: ObjectVersion,
    next: ObjectVersion,
}
/// Untrusted encrypted delta with a canonical zero-padded length. Parsing does
/// not establish source custody, target membership, authorization or freshness.
#[derive(Clone)]
pub struct StoreDeltaRequest {
    binding: Box<VersionBinding>,
    pages: Vec<(PageAddress, LookupResponse)>,
    request_bytes: usize,
}
pub(crate) struct VerifiedReplacementPages {
    data: Vec<VerifiedPage>,
    index: Vec<VerifiedPage>,
}
impl StoreDeltaRequest {
    pub fn new(
        base_object: [u8; 32],
        old_data: &Commitment,
        old_index: &Commitment,
        next: &Bundle,
        pages: &[(PageAddress, LookupResponse)],
    ) -> Result<Self> {
        if pages.is_empty() || pages.len() > MAX_STORE_DELTA_PAGES {
            return Err(PageError::ResourceLimit);
        }
        let data = Commitment::decode(&next.data_head, custody_limits())?;
        let index = Commitment::decode(&next.index_head, custody_limits())?;
        check_transition(old_data, &data)?;
        check_transition(old_index, &index)?;
        if next.data.len() != data.layout().encoded_len()?
            || next.index.len() != index.layout().encoded_len()?
        {
            return Err(PageError::InvalidFormat);
        }
        Self::checked(
            ObjectVersion {
                object: base_object,
                data: old_data.clone(),
                index: old_index.clone(),
            },
            ObjectVersion {
                object: next.id(),
                data,
                index,
            },
            pages.to_vec(),
        )
    }
    fn checked(
        base: ObjectVersion,
        next: ObjectVersion,
        pages: Vec<(PageAddress, LookupResponse)>,
    ) -> Result<Self> {
        let Some(request_bytes) =
            StoreDeltaPlan::for_heads(&base.data, &base.index)?.padded_request_bytes()
        else {
            return Err(PageError::InvalidFormat);
        };
        check_transition(&base.data, &next.data)?;
        check_transition(&base.index, &next.index)?;
        if base.object == next.object || (base.data == next.data && base.index == next.index) {
            return Err(PageError::BindingMismatch);
        }
        if pages.is_empty() || pages.len() > MAX_STORE_DELTA_PAGES {
            return Err(PageError::ResourceLimit);
        }
        let mut used = HEADER_BYTES + REQUEST_ENVELOPE_BYTES;
        let mut previous = None;
        for (address, page) in &pages {
            if previous.is_some_and(|old| old >= *address) {
                return Err(PageError::DuplicateAddress);
            }
            previous = Some(*address);
            if base.head(address.image) == next.head(address.image) {
                return Err(PageError::BindingMismatch);
            }
            let exact = lookup_bytes(next.head(address.image), address.index)?;
            if page.encoded_len() != exact {
                return Err(PageError::InvalidFormat);
            }
            used = used
                .checked_add(13 + exact)
                .ok_or(PageError::ResourceLimit)?;
        }
        if used > request_bytes {
            return Err(PageError::ResourceLimit);
        }
        Ok(Self {
            binding: Box::new(VersionBinding { base, next }),
            pages,
            request_bytes,
        })
    }
    pub fn base_object(&self) -> &[u8; 32] {
        &self.binding.base.object
    }
    pub fn object(&self) -> &[u8; 32] {
        &self.binding.next.object
    }
    pub fn request_bytes(&self) -> usize {
        self.request_bytes
    }
    pub(crate) fn old_heads(&self) -> (&Commitment, &Commitment) {
        (&self.binding.base.data, &self.binding.base.index)
    }
    pub(crate) fn new_heads(&self) -> (&Commitment, &Commitment) {
        (&self.binding.next.data, &self.binding.next.index)
    }
    pub(crate) fn verify_pages(&self) -> Result<VerifiedReplacementPages> {
        let mut data_pages: Vec<VerifiedPage> = Vec::new();
        let mut index_pages: Vec<VerifiedPage> = Vec::new();
        for (address, page) in &self.pages {
            let verified = page.verify(
                self.binding.next.head(address.image),
                address.index,
                custody_limits(),
            )?;
            match address.image {
                PageImage::Data => data_pages.push(verified),
                PageImage::Index => index_pages.push(verified),
            }
        }
        Ok(VerifiedReplacementPages {
            data: data_pages,
            index: index_pages,
        })
    }
    pub(crate) fn reconstruct(
        self,
        data: EncryptedSnapshot,
        index: EncryptedSnapshot,
        verified: VerifiedReplacementPages,
    ) -> Result<Bundle> {
        let data = data.apply_verified_replacements(
            &self.binding.base.data,
            &self.binding.next.data,
            verified.data,
            custody_limits(),
        )?;
        let index = index.apply_verified_replacements(
            &self.binding.base.index,
            &self.binding.next.index,
            verified.index,
            custody_limits(),
        )?;
        let bundle = Bundle {
            data_head: self.binding.next.data.encode().to_vec(),
            index_head: self.binding.next.index.encode().to_vec(),
            data: data.encode(),
            index: index.encode(),
        };
        if bundle.id() != self.binding.next.object {
            return Err(PageError::BindingMismatch);
        }
        Ok(bundle)
    }
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.request_bytes - REQUEST_ENVELOPE_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.binding.base.object);
        bytes.extend_from_slice(&self.binding.next.object);
        for head in [
            &self.binding.base.data,
            &self.binding.base.index,
            &self.binding.next.data,
            &self.binding.next.index,
        ] {
            bytes.extend_from_slice(&head.encode());
        }
        bytes.extend_from_slice(&(self.pages.len() as u16).to_le_bytes());
        for (address, page) in &self.pages {
            bytes.push(match address.image {
                PageImage::Data => 0,
                PageImage::Index => 1,
            });
            bytes.extend_from_slice(&address.index.to_le_bytes());
            bytes.extend_from_slice(&(page.encoded_len() as u32).to_le_bytes());
            bytes.extend_from_slice(&page.encode());
        }
        bytes.resize(self.request_bytes - REQUEST_ENVELOPE_BYTES, 0);
        bytes
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_BODY_BYTES {
            return Err(PageError::ResourceLimit);
        }
        if bytes.len() < HEADER_BYTES
            || &bytes[..8] != MAGIC
            || bytes[8..10] != VERSION.to_le_bytes()
        {
            return Err(PageError::InvalidFormat);
        }
        let head = |start| {
            Commitment::decode(&bytes[start..start + 112], custody_limits())
                .map_err(PageError::from)
        };
        let base = ObjectVersion {
            object: bytes[10..42].try_into().unwrap(),
            data: head(74)?,
            index: head(186)?,
        };
        let next = ObjectVersion {
            object: bytes[42..74].try_into().unwrap(),
            data: head(298)?,
            index: head(410)?,
        };
        let Some(request_bytes) =
            StoreDeltaPlan::for_heads(&base.data, &base.index)?.padded_request_bytes()
        else {
            return Err(PageError::InvalidFormat);
        };
        if bytes.len() != request_bytes - REQUEST_ENVELOPE_BYTES {
            return Err(PageError::InvalidFormat);
        }
        check_transition(&base.data, &next.data)?;
        check_transition(&base.index, &next.index)?;
        let count = u16::from_le_bytes(bytes[522..524].try_into().unwrap()) as usize;
        if count == 0 || count > MAX_STORE_DELTA_PAGES {
            return Err(PageError::ResourceLimit);
        }
        let mut pages = Vec::with_capacity(count);
        let mut offset = HEADER_BYTES;
        for _ in 0..count {
            let header = take(bytes, &mut offset, 13)?;
            let image = match header[0] {
                0 => PageImage::Data,
                1 => PageImage::Index,
                _ => return Err(PageError::InvalidFormat),
            };
            let address = PageAddress {
                image,
                index: u64::from_le_bytes(header[1..9].try_into().unwrap()),
            };
            let length = u32::from_le_bytes(header[9..13].try_into().unwrap()) as usize;
            if length != lookup_bytes(next.head(image), address.index)? {
                return Err(PageError::InvalidFormat);
            }
            pages.push((
                address,
                LookupResponse::decode(take(bytes, &mut offset, length)?, custody_limits())?,
            ));
        }
        if bytes[offset..].iter().any(|byte| *byte != 0) {
            return Err(PageError::InvalidFormat);
        }
        Self::checked(base, next, pages)
    }
}
fn check_transition(old: &Commitment, next: &Commitment) -> Result<()> {
    next.layout().validate(custody_limits())?;
    if old.database() != next.database()
        || old.key_domain() != next.key_domain()
        || old.layout() != next.layout()
        || (old != next && old.revision().checked_add(1) != Some(next.revision()))
    {
        return Err(PageError::BindingMismatch);
    }
    Ok(())
}
fn take<'a>(bytes: &'a [u8], offset: &mut usize, count: usize) -> Result<&'a [u8]> {
    let end = offset.checked_add(count).ok_or(PageError::ResourceLimit)?;
    let value = bytes.get(*offset..end).ok_or(PageError::InvalidFormat)?;
    *offset = end;
    Ok(value)
}
impl Serialize for StoreDeltaRequest {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.encode())
    }
}
impl<'de> Deserialize<'de> for StoreDeltaRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        Self::decode(&crate::bytes::deserialize_frame(
            deserializer,
            MAX_BODY_BYTES,
        )?)
        .map_err(de::Error::custom)
    }
}
#[cfg(test)]
mod tests;
