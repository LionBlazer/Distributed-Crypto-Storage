//! Bounded, exact-head ciphertext page custody. Membership is not SQL acceptance.
use crate::store::custody_limits;
use compact_store::{Commitment, EncryptedSnapshot, LookupResponse, VerifiedPage};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::{collections::BTreeSet, fmt};

pub const MAX_PAGE_BATCH_ADDRESSES: usize = 64;
/// Complete encoded runtime response, excluding the transport's frame prefix/TLS.
pub const MAX_PAGE_BATCH_RESPONSE_BYTES: usize = 1024 * 1024;
const HEADER_BYTES: usize = 8 + 2 + 32 + 112 + 112 + 2;
// Fixed-width WireResponse(version, id, Ok, Pages, byte-vector length).
const RESPONSE_ENVELOPE_BYTES: usize = 2 + 8 + 4 + 4 + 8;
const MAX_REPLY_BODY: usize = MAX_PAGE_BATCH_RESPONSE_BYTES - RESPONSE_ENVELOPE_BYTES;
const MAX_REQUEST_BODY: usize = HEADER_BYTES + MAX_PAGE_BATCH_ADDRESSES * 9;
const REQUEST_MAGIC: &[u8; 8] = b"DCSPAGQ1";
const RESPONSE_MAGIC: &[u8; 8] = b"DCSPAGR1";
const VERSION: u16 = 1;

type Result<T> = std::result::Result<T, PageError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageError {
    InvalidFormat,
    ResourceLimit,
    DuplicateAddress,
    BindingMismatch,
    Page(compact_store::Error),
}
impl fmt::Display for PageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for PageError {}
impl From<compact_store::Error> for PageError {
    fn from(value: compact_store::Error) -> Self {
        Self::Page(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PageImage {
    Data,
    Index,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PageAddress {
    pub image: PageImage,
    pub index: u64,
}

/// Immutable request bound to independently trusted heads and explicit addresses.
/// It does not establish that the chosen heads are current or authorized.
#[derive(Clone, Debug)]
pub struct PageBatchRequest {
    object: [u8; 32],
    data_head: Commitment,
    index_head: Commitment,
    addresses: Vec<PageAddress>,
}
impl PageBatchRequest {
    pub fn new(
        object: [u8; 32],
        data_head: &Commitment,
        index_head: &Commitment,
        addresses: &[PageAddress],
    ) -> Result<Self> {
        check_count(addresses.len())?;
        let mut unique = BTreeSet::new();
        let mut reply_bytes = HEADER_BYTES;
        data_head.layout().validate(custody_limits())?;
        index_head.layout().validate(custody_limits())?;
        for address in addresses {
            if !unique.insert(*address) {
                return Err(PageError::DuplicateAddress);
            }
            let head = match address.image {
                PageImage::Data => data_head,
                PageImage::Index => index_head,
            };
            reply_bytes = reply_bytes
                .checked_add(13 + lookup_bytes(head, address.index)?)
                .ok_or(PageError::ResourceLimit)?;
            if reply_bytes > MAX_REPLY_BODY {
                return Err(PageError::ResourceLimit);
            }
        }
        Ok(Self {
            object,
            data_head: data_head.clone(),
            index_head: index_head.clone(),
            addresses: addresses.to_vec(),
        })
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
    pub fn addresses(&self) -> &[PageAddress] {
        &self.addresses
    }
    fn head(&self, image: PageImage) -> &Commitment {
        match image {
            PageImage::Data => &self.data_head,
            PageImage::Index => &self.index_head,
        }
    }
    fn encode(&self) -> Vec<u8> {
        let mut bytes = encode_header(REQUEST_MAGIC, self);
        for address in &self.addresses {
            encode_address(&mut bytes, *address);
        }
        bytes
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_REQUEST_BODY {
            return Err(PageError::ResourceLimit);
        }
        let (object, data, index, count) = decode_header(bytes, REQUEST_MAGIC)?;
        if bytes.len() != HEADER_BYTES + count * 9 {
            return Err(PageError::InvalidFormat);
        }
        let mut addresses = Vec::with_capacity(count);
        for chunk in bytes[HEADER_BYTES..].as_chunks::<9>().0 {
            addresses.push(decode_address(chunk)?);
        }
        Self::new(object, &data, &index, &addresses)
    }
}

/// Untrusted encrypted page response. Call `verify` with the original request.
/// Successful verification proves exact Merkle membership, not AEAD validity,
/// complete SQL selection, a computation proof, or consensus freshness.
pub struct PageBatch {
    request: PageBatchRequest,
    pages: Vec<LookupResponse>,
}
impl PageBatch {
    pub(crate) fn from_snapshots(
        request: PageBatchRequest,
        data: &EncryptedSnapshot,
        index: &EncryptedSnapshot,
    ) -> Result<Self> {
        if data.commitment() != request.data_head() || index.commitment() != request.index_head() {
            return Err(PageError::BindingMismatch);
        }
        let pages = request
            .addresses
            .iter()
            .map(|address| {
                match address.image {
                    PageImage::Data => data,
                    PageImage::Index => index,
                }
                .lookup(address.index, custody_limits())
                .map_err(PageError::from)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { request, pages })
    }
    pub fn verify(&self, expected: &PageBatchRequest) -> Result<Vec<(PageAddress, VerifiedPage)>> {
        if self.request.object != expected.object
            || self.request.data_head != expected.data_head
            || self.request.index_head != expected.index_head
            || self.request.addresses != expected.addresses
            || self.pages.len() != expected.addresses.len()
        {
            return Err(PageError::BindingMismatch);
        }
        expected
            .addresses
            .iter()
            .zip(&self.pages)
            .map(|(address, page)| {
                Ok((
                    *address,
                    page.verify(
                        expected.head(address.image),
                        address.index,
                        custody_limits(),
                    )?,
                ))
            })
            .collect()
    }
    fn encode(&self) -> Vec<u8> {
        let mut bytes = encode_header(RESPONSE_MAGIC, &self.request);
        for (address, page) in self.request.addresses.iter().zip(&self.pages) {
            encode_address(&mut bytes, *address);
            bytes.extend_from_slice(&(page.encoded_len() as u32).to_le_bytes());
            bytes.extend_from_slice(&page.encode());
        }
        bytes
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_REPLY_BODY {
            return Err(PageError::ResourceLimit);
        }
        let (object, data, index, count) = decode_header(bytes, RESPONSE_MAGIC)?;
        // Each entry needs an address, length and minimally sized LookupResponse.
        if bytes.len() < HEADER_BYTES + count * (13 + 16 + compact_store::PAGE_OVERHEAD) {
            return Err(PageError::InvalidFormat);
        }
        let mut offset = HEADER_BYTES;
        let mut addresses = Vec::with_capacity(count);
        let mut pages = Vec::with_capacity(count);
        for _ in 0..count {
            let header = take(bytes, &mut offset, 13)?;
            let address = decode_address(&header[..9])?;
            let length = u32::from_le_bytes(header[9..].try_into().unwrap()) as usize;
            let head = match address.image {
                PageImage::Data => &data,
                PageImage::Index => &index,
            };
            // Validate exact address-dependent proof geometry before page allocation.
            if length != lookup_bytes(head, address.index)? {
                return Err(PageError::InvalidFormat);
            }
            let page = LookupResponse::decode(take(bytes, &mut offset, length)?, custody_limits())?;
            addresses.push(address);
            pages.push(page);
        }
        if offset != bytes.len() {
            return Err(PageError::InvalidFormat);
        }
        let request = PageBatchRequest::new(object, &data, &index, &addresses)?;
        Ok(Self { request, pages })
    }
}

fn lookup_bytes(head: &Commitment, index: u64) -> Result<usize> {
    let layout = head.layout();
    let mut pages = layout.page_count()?;
    if index >= pages as u64 {
        return Err(PageError::Page(compact_store::Error::InvalidPage));
    }
    let first = index
        .checked_mul(u64::from(layout.rows_per_page))
        .ok_or(PageError::ResourceLimit)?;
    let rows = (layout.row_count - first).min(u64::from(layout.rows_per_page));
    let plaintext = usize::try_from(rows * u64::from(layout.row_width))
        .map_err(|_| PageError::ResourceLimit)?;
    let mut height = 0;
    while pages > 1 {
        pages = pages.div_ceil(2);
        height += 1;
    }
    Ok(16 + compact_store::PAGE_OVERHEAD + plaintext + height * 32)
}
fn check_count(count: usize) -> Result<()> {
    if count == 0 {
        Err(PageError::InvalidFormat)
    } else if count > MAX_PAGE_BATCH_ADDRESSES {
        Err(PageError::ResourceLimit)
    } else {
        Ok(())
    }
}
fn encode_header(magic: &[u8; 8], request: &PageBatchRequest) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_BYTES);
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&VERSION.to_le_bytes());
    bytes.extend_from_slice(&request.object);
    bytes.extend_from_slice(&request.data_head.encode());
    bytes.extend_from_slice(&request.index_head.encode());
    bytes.extend_from_slice(&(request.addresses.len() as u16).to_le_bytes());
    bytes
}
fn decode_header(
    bytes: &[u8],
    magic: &[u8; 8],
) -> Result<([u8; 32], Commitment, Commitment, usize)> {
    if bytes.len() < HEADER_BYTES || &bytes[..8] != magic || bytes[8..10] != VERSION.to_le_bytes() {
        return Err(PageError::InvalidFormat);
    }
    let count = u16::from_le_bytes(bytes[266..268].try_into().unwrap()) as usize;
    check_count(count)?;
    Ok((
        bytes[10..42].try_into().unwrap(),
        Commitment::decode(&bytes[42..154], custody_limits())?,
        Commitment::decode(&bytes[154..266], custody_limits())?,
        count,
    ))
}
fn encode_address(bytes: &mut Vec<u8>, address: PageAddress) {
    bytes.push(match address.image {
        PageImage::Data => 0,
        PageImage::Index => 1,
    });
    bytes.extend_from_slice(&address.index.to_le_bytes());
}
fn decode_address(bytes: &[u8]) -> Result<PageAddress> {
    Ok(PageAddress {
        image: match bytes[0] {
            0 => PageImage::Data,
            1 => PageImage::Index,
            _ => return Err(PageError::InvalidFormat),
        },
        index: u64::from_le_bytes(bytes[1..9].try_into().unwrap()),
    })
}
fn take<'a>(bytes: &'a [u8], offset: &mut usize, length: usize) -> Result<&'a [u8]> {
    let end = offset.checked_add(length).ok_or(PageError::ResourceLimit)?;
    let slice = bytes.get(*offset..end).ok_or(PageError::InvalidFormat)?;
    *offset = end;
    Ok(slice)
}

// A sequence visitor sees bincode's announced length BEFORE allocation. Using
// deserialize_bytes here would let bincode allocate an unchecked byte vector first.
fn deserialize_frame<'de, D: Deserializer<'de>>(
    deserializer: D,
    maximum: usize,
) -> std::result::Result<Vec<u8>, D::Error> {
    struct Frame(usize);
    impl<'de> de::Visitor<'de> for Frame {
        type Value = Vec<u8>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded page RPC byte sequence")
        }
        fn visit_seq<A: de::SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let length = sequence
                .size_hint()
                .ok_or_else(|| de::Error::custom("Missing page frame length"))?;
            if length > self.0 {
                return Err(de::Error::custom("Page frame exceeds limit"));
            }
            let mut bytes = Vec::with_capacity(length);
            while let Some(byte) = sequence.next_element::<u8>()? {
                if bytes.len() == length {
                    return Err(de::Error::custom("Page frame length mismatch"));
                }
                bytes.push(byte);
            }
            if bytes.len() != length {
                return Err(de::Error::custom("Truncated page frame"));
            }
            Ok(bytes)
        }
    }
    deserializer.deserialize_seq(Frame(maximum))
}
impl Serialize for PageBatchRequest {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.encode())
    }
}
impl<'de> Deserialize<'de> for PageBatchRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        Self::decode(&deserialize_frame(deserializer, MAX_REQUEST_BODY)?).map_err(de::Error::custom)
    }
}
impl Serialize for PageBatch {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.encode())
    }
}
impl<'de> Deserialize<'de> for PageBatch {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        Self::decode(&deserialize_frame(deserializer, MAX_REPLY_BODY)?).map_err(de::Error::custom)
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
        PageBatchRequest,
    ) {
        let owner = Owner::generate([41; 16]).unwrap();
        let layout = Layout {
            schema: [3; 16],
            row_width: 1,
            rows_per_page: 8,
            row_count: 18,
        };
        let data = owner
            .seal(layout, &(0..18).collect::<Vec<_>>(), custody_limits())
            .unwrap();
        let index = owner
            .seal(
                Layout {
                    schema: [4; 16],
                    ..layout
                },
                &[91; 18],
                custody_limits(),
            )
            .unwrap();
        let request = PageBatchRequest::new(
            [7; 32],
            data.commitment(),
            index.commitment(),
            &[
                PageAddress {
                    image: PageImage::Index,
                    index: 2,
                },
                PageAddress {
                    image: PageImage::Data,
                    index: 0,
                },
            ],
        )
        .unwrap();
        (owner, data, index, request)
    }
    fn response(
        data: &EncryptedSnapshot,
        index: &EncryptedSnapshot,
        request: &PageBatchRequest,
    ) -> PageBatch {
        PageBatch::from_snapshots(request.clone(), data, index).unwrap()
    }
    #[test]
    fn exact_ordered_pages_round_trip_and_decrypt_only_at_the_owner() {
        let (owner, data, index, request) = fixture();
        let encoded_request = wire::encode(&request).unwrap();
        let decoded_request: PageBatchRequest = wire::decode(&encoded_request).unwrap();
        assert_eq!(decoded_request.addresses(), request.addresses());
        let batch = response(&data, &index, &request);
        let body_length = batch.encode().len();
        let bytes = wire::encode(&WireResponse {
            version: 1,
            id: 4,
            result: Ok(Response::Pages(batch)),
        })
        .unwrap();
        assert_eq!(bytes.len(), body_length + RESPONSE_ENVELOPE_BYTES);
        assert!(bytes.len() <= MAX_PAGE_BATCH_RESPONSE_BYTES);

        let wire: WireResponse = wire::decode_page_response(&bytes).unwrap();
        let Response::Pages(batch) = wire.result.unwrap() else {
            panic!("page response expected")
        };
        let pages = batch.verify(&request).unwrap();

        assert_eq!(
            pages
                .iter()
                .map(|(address, _)| *address)
                .collect::<Vec<_>>(),
            request.addresses()
        );
        assert_eq!(owner.decrypt(&pages[0].1).unwrap().as_bytes(), &[91; 2]);
        assert_eq!(
            owner.decrypt(&pages[1].1).unwrap().as_bytes(),
            &[0, 1, 2, 3, 4, 5, 6, 7]
        );
    }
    #[test]
    fn page_response_envelope_rejects_other_rpc_tags_and_unbounded_error_lengths() {
        let (_, data, index, request) = fixture();
        let bytes = wire::encode(&WireResponse {
            version: 1,
            id: 2,
            result: Ok(Response::Pages(response(&data, &index, &request))),
        })
        .unwrap();
        let mut substituted = bytes.clone();
        // Bundle has arbitrary-sized vectors; it is forbidden before decoding it.
        substituted[14..18].copy_from_slice(&3u32.to_le_bytes());
        substituted[18..26].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(wire::decode_page_response(&substituted).is_err());
        for error in [
            crate::RemoteError::NotFound,
            crate::RemoteError::Io("read failed".into()),
        ] {
            let encoded = wire::encode(&WireResponse {
                version: 1,
                id: 2,
                result: Err(error),
            })
            .unwrap();
            assert!(
                wire::decode_page_response(&encoded)
                    .unwrap()
                    .result
                    .is_err()
            );
        }
        let mut oversized_error = wire::encode(&WireResponse {
            version: 1,
            id: 2,
            result: Err(crate::RemoteError::Io(String::new())),
        })
        .unwrap();
        oversized_error[18..26].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(wire::decode_page_response(&oversized_error).is_err());
    }
    #[test]
    fn request_rejects_empty_duplicate_unknown_and_out_of_range_addresses() {
        let (_, data, index, request) = fixture();
        let make = |addresses: &[PageAddress]| {
            PageBatchRequest::new([7; 32], data.commitment(), index.commitment(), addresses)
        };
        assert!(matches!(make(&[]), Err(PageError::InvalidFormat)));
        assert!(matches!(
            make(&[request.addresses[0]; 2]),
            Err(PageError::DuplicateAddress)
        ));
        assert!(matches!(
            make(&[request.addresses[0]; 65]),
            Err(PageError::ResourceLimit)
        ));
        assert!(
            make(&[PageAddress {
                image: PageImage::Data,
                index: 3
            }])
            .is_err()
        );
        assert!(
            make(&[PageAddress {
                image: PageImage::Data,
                index: u64::MAX
            }])
            .is_err()
        );
        let mut bytes = request.encode();
        bytes[HEADER_BYTES] = 2;
        assert!(PageBatchRequest::decode(&bytes).is_err());
    }
    #[test]
    fn requested_geometry_bounds_the_complete_response_before_any_page_lookup() {
        let owner = Owner::generate([42; 16]).unwrap();
        let image = owner
            .seal(
                Layout {
                    schema: [3; 16],
                    row_width: 1,
                    rows_per_page: 65536,
                    row_count: 16 * 65536,
                },
                &vec![1; 16 * 65536],
                custody_limits(),
            )
            .unwrap();
        let addresses = (0..16)
            .map(|index| PageAddress {
                image: PageImage::Data,
                index,
            })
            .collect::<Vec<_>>();
        let valid = PageBatchRequest::new(
            [7; 32],
            image.commitment(),
            image.commitment(),
            &addresses[..15],
        )
        .unwrap();
        let batch = response(&image, &image, &valid);
        let wire = wire::encode(&WireResponse {
            version: 1,
            id: 1,
            result: Ok(Response::Pages(batch)),
        })
        .unwrap();
        assert!(wire.len() < MAX_PAGE_BATCH_RESPONSE_BYTES);
        assert!(matches!(
            PageBatchRequest::new([7; 32], image.commitment(), image.commitment(), &addresses),
            Err(PageError::ResourceLimit)
        ));
        let tiny = owner
            .seal(
                Layout {
                    schema: [4; 16],
                    row_width: 1,
                    rows_per_page: 1,
                    row_count: 64,
                },
                &[1; 64],
                custody_limits(),
            )
            .unwrap();
        let addresses = (0..64)
            .map(|index| PageAddress {
                image: PageImage::Index,
                index,
            })
            .collect::<Vec<_>>();
        assert!(
            PageBatchRequest::new([7; 32], tiny.commitment(), tiny.commitment(), &addresses)
                .is_ok()
        );
    }
    #[test]
    fn unknown_versions_counts_lengths_and_truncation_fail_closed() {
        let (_, data, index, request) = fixture();
        for original in [request.encode(), response(&data, &index, &request).encode()] {
            let is_request = original.starts_with(REQUEST_MAGIC);
            let rejects = |bytes: &[u8]| {
                if is_request {
                    PageBatchRequest::decode(bytes).is_err()
                } else {
                    PageBatch::decode(bytes).is_err()
                }
            };
            for offset in [0, 8] {
                let mut changed = original.clone();
                changed[offset] ^= 1;
                assert!(rejects(&changed));
            }
            for count in [0u16, 1, 3, 65, u16::MAX] {
                let mut changed = original.clone();
                changed[266..268].copy_from_slice(&count.to_le_bytes());
                assert!(rejects(&changed));
            }
            for length in [0, 7, HEADER_BYTES - 1, HEADER_BYTES, original.len() - 1] {
                assert!(rejects(&original[..length]));
            }
            let mut trailing = original.clone();
            trailing.push(0);
            assert!(rejects(&trailing));
        }
        let mut reply = response(&data, &index, &request).encode();
        reply[HEADER_BYTES + 9..HEADER_BYTES + 13].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(PageBatch::decode(&reply).is_err());
        // These announce a huge nested byte sequence without supplying its bytes.
        let hostile = u64::MAX.to_le_bytes();
        assert!(wire::decode::<PageBatchRequest>(&hostile).is_err());
        assert!(wire::decode::<PageBatch>(&hostile).is_err());
        let mut oversize = vec![0; MAX_REPLY_BODY + 1];
        oversize[..8].copy_from_slice(RESPONSE_MAGIC);
        assert!(PageBatch::decode(&oversize).is_err());
    }
    #[test]
    fn response_must_match_both_heads_object_kind_and_every_requested_address() {
        let (_, data, index, request) = fixture();
        let encoded = response(&data, &index, &request).encode();
        for offset in [10, 42 + 80, 154 + 80, HEADER_BYTES] {
            let mut changed = encoded.clone();
            changed[offset] ^= 1;
            let changed = PageBatch::decode(&changed).unwrap();
            assert!(
                changed.verify(&request).is_err(),
                "changed field at {offset}"
            );
        }
        let mut wrong_address = encoded.clone();
        wrong_address[HEADER_BYTES + 1..HEADER_BYTES + 9].copy_from_slice(&1u64.to_le_bytes());
        // The shorter final page cannot be relabeled as a full page.
        assert!(PageBatch::decode(&wrong_address).is_err());
        let mut reordered = response(&data, &index, &request);
        reordered.request.addresses.swap(0, 1);
        reordered.pages.swap(0, 1);
        assert!(reordered.verify(&request).is_err());
        let mut missing = response(&data, &index, &request);
        missing.pages.pop();
        assert!(missing.verify(&request).is_err());
        let mut extra = response(&data, &index, &request);
        extra.pages.push(data.lookup(1, custody_limits()).unwrap());
        assert!(extra.verify(&request).is_err());
        let mut duplicate = response(&data, &index, &request);
        duplicate.request.addresses[1] = duplicate.request.addresses[0];
        duplicate.pages[1] = duplicate.pages[0].clone();
        assert!(matches!(
            PageBatch::decode(&duplicate.encode()),
            Err(PageError::DuplicateAddress)
        ));
        let mut unknown_kind = encoded.clone();
        unknown_kind[HEADER_BYTES] = 2;
        assert!(PageBatch::decode(&unknown_kind).is_err());
        assert!(PageBatch::from_snapshots(request, &index, &data).is_err());
    }
    #[test]
    fn valid_framing_cannot_hide_tampered_ciphertext_membership_or_embedded_address() {
        let (_, data, index, request) = fixture();
        let encoded = response(&data, &index, &request).encode();
        let lookup_start = HEADER_BYTES + 13;
        // Lookup's embedded index, encrypted payload, and a Merkle sibling.
        for offset in [lookup_start, lookup_start + 16 + 32, lookup_start + 16 + 50] {
            let mut changed = encoded.clone();
            changed[offset] ^= 1;
            let batch = PageBatch::decode(&changed).unwrap();
            assert!(
                batch.verify(&request).is_err(),
                "tampered lookup at {offset}"
            );
        }
    }
}
