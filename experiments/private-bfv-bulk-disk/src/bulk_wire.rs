//! Bounded PUBLIC whole-snapshot framing. No age/predicate/count/page-address field exists.
use std::fmt;
pub(crate) const HEADER_BYTES: usize = 270;
pub(crate) const MAX_IMAGE_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_RESPONSE_BYTES: usize = HEADER_BYTES + 2 * MAX_IMAGE_BYTES;
const REQUEST_MAGIC: &[u8; 8] = b"CBULKQ01";
const RESPONSE_MAGIC: &[u8; 8] = b"CBULKR01";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WireError {
    Shape,
    Version,
    Limit,
    Binding,
}
impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bulk frame rejected {self:?}")
    }
}
impl std::error::Error for WireError {}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Header {
    pub table_id: u32,
    pub request_id: [u8; 16],
    pub data_head: [u8; 112],
    pub index_head: [u8; 112],
    pub data_len: usize,
    pub index_len: usize,
}
impl Header {
    pub fn response_len(&self) -> Result<usize, WireError> {
        if !(112..=MAX_IMAGE_BYTES).contains(&self.data_len)
            || !(112..=MAX_IMAGE_BYTES).contains(&self.index_len)
        {
            return Err(WireError::Limit);
        }
        HEADER_BYTES
            .checked_add(self.data_len)
            .and_then(|n| n.checked_add(self.index_len))
            .filter(|n| *n <= MAX_RESPONSE_BYTES)
            .ok_or(WireError::Limit)
    }
    fn encode(&self, magic: &[u8; 8]) -> Result<Vec<u8>, WireError> {
        self.response_len()?;
        let mut wire = Vec::with_capacity(HEADER_BYTES);
        wire.extend_from_slice(magic);
        wire.extend_from_slice(&1u16.to_le_bytes());
        wire.extend_from_slice(&self.table_id.to_le_bytes());
        wire.extend_from_slice(&self.request_id);
        wire.extend_from_slice(&self.data_head);
        wire.extend_from_slice(&self.index_head);
        wire.extend_from_slice(&(self.data_len as u64).to_le_bytes());
        wire.extend_from_slice(&(self.index_len as u64).to_le_bytes());
        debug_assert_eq!(wire.len(), HEADER_BYTES);
        Ok(wire)
    }
    pub fn request(&self) -> Result<Vec<u8>, WireError> {
        self.encode(REQUEST_MAGIC)
    }
    pub fn response_header(&self) -> Result<Vec<u8>, WireError> {
        self.encode(RESPONSE_MAGIC)
    }
    fn parse(wire: &[u8], magic: &[u8; 8]) -> Result<Self, WireError> {
        if wire.len() < HEADER_BYTES || &wire[..8] != magic {
            return Err(WireError::Shape);
        }
        if wire[8..10] != 1u16.to_le_bytes() {
            return Err(WireError::Version);
        }
        let value = Self {
            table_id: u32::from_le_bytes(wire[10..14].try_into().map_err(|_| WireError::Shape)?),
            request_id: wire[14..30].try_into().map_err(|_| WireError::Shape)?,
            data_head: wire[30..142].try_into().map_err(|_| WireError::Shape)?,
            index_head: wire[142..254].try_into().map_err(|_| WireError::Shape)?,
            data_len: usize::try_from(u64::from_le_bytes(
                wire[254..262].try_into().map_err(|_| WireError::Shape)?,
            ))
            .map_err(|_| WireError::Limit)?,
            index_len: usize::try_from(u64::from_le_bytes(
                wire[262..270].try_into().map_err(|_| WireError::Shape)?,
            ))
            .map_err(|_| WireError::Limit)?,
        };
        value.response_len()?;
        Ok(value)
    }
    pub fn parse_request(wire: &[u8]) -> Result<Self, WireError> {
        if wire.len() != HEADER_BYTES {
            return Err(WireError::Shape);
        }
        Self::parse(wire, REQUEST_MAGIC)
    }
    /// Exact total/length/binding checks precede allocation or cryptographic snapshot decode.
    pub fn split_response<'a>(&self, wire: &'a [u8]) -> Result<(&'a [u8], &'a [u8]), WireError> {
        if wire.len() > MAX_RESPONSE_BYTES {
            return Err(WireError::Limit);
        }
        let actual = Self::parse(wire, RESPONSE_MAGIC)?;
        if &actual != self {
            return Err(WireError::Binding);
        }
        if wire.len() != self.response_len()? {
            return Err(WireError::Shape);
        }
        let boundary = HEADER_BYTES
            .checked_add(self.data_len)
            .ok_or(WireError::Limit)?;
        Ok((&wire[HEADER_BYTES..boundary], &wire[boundary..]))
    }
}
