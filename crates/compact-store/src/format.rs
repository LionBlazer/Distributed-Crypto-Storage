use sha2::{Digest, Sha256};

pub const MANIFEST_BYTES: usize = 112;
pub const PAGE_OVERHEAD: usize = 48;
pub(crate) const MAGIC: &[u8; 8] = b"CSTORE01";

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    ResourceLimit,
    InvalidFormat,
    InvalidProof,
    WrongVersion,
    WrongOwner,
    InvalidPage,
    Authentication,
    Randomness,
    RevisionExhausted,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

/// Application-selected fixed-width schema. Bytes are packed without padding.
/// Schema identity and geometry are authenticated, but their meaning is external.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub schema: [u8; 16],
    pub row_width: u32,
    pub rows_per_page: u32,
    pub row_count: u64,
}

/// Hard caps checked before decoding allocates page or proof storage.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_rows: u64,
    pub max_pages: u32,
    pub max_page_plaintext_bytes: usize,
    pub max_image_bytes: usize,
    pub max_response_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_rows: 1_000_000,
            max_pages: 65_536,
            max_page_plaintext_bytes: 65_536,
            max_image_bytes: 64 * 1024 * 1024,
            max_response_bytes: 68 * 1024,
        }
    }
}

impl Layout {
    pub fn logical_bytes(&self) -> Result<usize> {
        usize::try_from(
            self.row_count
                .checked_mul(u64::from(self.row_width))
                .ok_or(Error::ResourceLimit)?,
        )
        .map_err(|_| Error::ResourceLimit)
    }

    pub fn page_count(&self) -> Result<usize> {
        if self.row_width == 0 || self.rows_per_page == 0 {
            return Err(Error::InvalidFormat);
        }
        usize::try_from(self.row_count.div_ceil(u64::from(self.rows_per_page)))
            .map_err(|_| Error::ResourceLimit)
    }

    pub fn encoded_len(&self) -> Result<usize> {
        self.logical_bytes()?
            .checked_add(
                self.page_count()?
                    .checked_mul(PAGE_OVERHEAD)
                    .ok_or(Error::ResourceLimit)?,
            )
            .and_then(|n| n.checked_add(MANIFEST_BYTES))
            .ok_or(Error::ResourceLimit)
    }

    pub fn validate(&self, limits: Limits) -> Result<()> {
        let page_capacity = u64::from(self.row_width) * u64::from(self.rows_per_page);
        if self.row_width == 0 || self.rows_per_page == 0 {
            return Err(Error::InvalidFormat);
        }
        if self.row_count > limits.max_rows
            || page_capacity > limits.max_page_plaintext_bytes as u64
            || page_capacity > (u32::MAX as usize - PAGE_OVERHEAD) as u64
            || self.page_count()? > limits.max_pages as usize
            || self.encoded_len()? > limits.max_image_bytes
        {
            return Err(Error::ResourceLimit);
        }
        Ok(())
    }

    pub(crate) fn page_plaintext_len(&self, index: u64) -> Result<usize> {
        if index >= self.page_count()? as u64 {
            return Err(Error::InvalidPage);
        }
        let first = index
            .checked_mul(u64::from(self.rows_per_page))
            .ok_or(Error::ResourceLimit)?;
        let rows = (self.row_count - first).min(u64::from(self.rows_per_page));
        usize::try_from(rows * u64::from(self.row_width)).map_err(|_| Error::ResourceLimit)
    }

    pub fn address_of(&self, row_index: u64) -> Result<RowAddress> {
        if self.row_width == 0 || self.rows_per_page == 0 || row_index >= self.row_count {
            return Err(Error::InvalidPage);
        }
        Ok(RowAddress {
            page_index: row_index / u64::from(self.rows_per_page),
            byte_offset: usize::try_from(
                (row_index % u64::from(self.rows_per_page)) * u64::from(self.row_width),
            )
            .map_err(|_| Error::ResourceLimit)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RowAddress {
    pub page_index: u64,
    pub byte_offset: usize,
}

/// A trusted read head only when obtained from an independently authenticated
/// source. Parsing a peer-supplied commitment does not establish its freshness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment {
    pub(crate) database: [u8; 16],
    pub(crate) domain: [u8; 16],
    pub(crate) layout: Layout,
    pub(crate) revision: u64,
    pub(crate) root: [u8; 32],
}

impl Commitment {
    pub fn database(&self) -> [u8; 16] {
        self.database
    }
    pub fn key_domain(&self) -> [u8; 16] {
        self.domain
    }
    pub fn layout(&self) -> Layout {
        self.layout
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    pub fn encode(&self) -> [u8; MANIFEST_BYTES] {
        let mut bytes = [0; MANIFEST_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..24].copy_from_slice(&self.database);
        bytes[24..40].copy_from_slice(&self.domain);
        bytes[40..56].copy_from_slice(&self.layout.schema);
        bytes[56..64].copy_from_slice(&self.revision.to_le_bytes());
        bytes[64..68].copy_from_slice(&self.layout.row_width.to_le_bytes());
        bytes[68..72].copy_from_slice(&self.layout.rows_per_page.to_le_bytes());
        bytes[72..80].copy_from_slice(&self.layout.row_count.to_le_bytes());
        bytes[80..112].copy_from_slice(&self.root);
        bytes
    }

    pub fn decode(bytes: &[u8], limits: Limits) -> Result<Self> {
        if bytes.len() != MANIFEST_BYTES || &bytes[..8] != MAGIC {
            return Err(Error::InvalidFormat);
        }
        let value = Self {
            database: bytes[8..24].try_into().unwrap(),
            domain: bytes[24..40].try_into().unwrap(),
            layout: Layout {
                schema: bytes[40..56].try_into().unwrap(),
                row_width: u32::from_le_bytes(bytes[64..68].try_into().unwrap()),
                rows_per_page: u32::from_le_bytes(bytes[68..72].try_into().unwrap()),
                row_count: u64::from_le_bytes(bytes[72..80].try_into().unwrap()),
            },
            revision: u64::from_le_bytes(bytes[56..64].try_into().unwrap()),
            root: bytes[80..112].try_into().unwrap(),
        };
        value.layout.validate(limits)?;
        Ok(value)
    }

    pub(crate) fn with_tree_root(&self, tree_root: [u8; 32]) -> [u8; 32] {
        hash(&[
            b"compact-store/snapshot/v1",
            &self.encode()[..80],
            &tree_root,
        ])
    }

    /// Associated data binds encryption domain, database, schema, complete
    /// row geometry, exact address and page revision. Global snapshot revision is
    /// bound by the outer commitment so unchanged pages survive a new snapshot.
    pub(crate) fn aad(&self, index: u64, page_revision: u64) -> Vec<u8> {
        let mut bytes = b"compact-store/page-aead/v1".to_vec();
        let manifest = self.encode();
        bytes.extend_from_slice(&manifest[8..56]);
        bytes.extend_from_slice(&manifest[64..80]);
        bytes.extend_from_slice(&index.to_le_bytes());
        bytes.extend_from_slice(&page_revision.to_le_bytes());
        bytes
    }
}

pub(crate) fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

pub(crate) fn leaf(index: usize, packet: &[u8]) -> [u8; 32] {
    hash(&[
        b"compact-store/leaf/v1",
        &(index as u64).to_le_bytes(),
        &(packet.len() as u64).to_le_bytes(),
        packet,
    ])
}

pub(crate) fn parent(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    hash(&[b"compact-store/node/v1", left, right])
}

pub(crate) fn proof_height(mut pages: usize) -> usize {
    let mut height = 0;
    while pages > 1 {
        pages = pages.div_ceil(2);
        height += 1;
    }
    height
}
