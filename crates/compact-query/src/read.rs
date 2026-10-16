//! Immutable owner read contracts, independent of custody transport and storage.
use crate::{Commitment, Error, Result, Table, TableId, check_schema, index};
use compact_store::{EncryptedSnapshot, Limits, VerifiedPage};

/// Encrypted pages authenticated against an exact independently supplied head.
/// Core consumers recheck both commitment and address before owner AEAD decryption.
pub trait PageSource {
    fn commitment(&self) -> &Commitment;
    fn lookup(&self, page: u64, limits: Limits) -> Result<VerifiedPage>;
}
impl PageSource for EncryptedSnapshot {
    fn commitment(&self) -> &Commitment {
        self.commitment()
    }
    fn lookup(&self, page: u64, limits: Limits) -> Result<VerifiedPage> {
        Ok(self
            .lookup(page, limits)?
            .verify(self.commitment(), page, limits)?)
    }
}

/// Caller-selected authorized read heads and logical table. Parsing does not
/// establish consensus freshness; the network caller must independently do so.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadHeads {
    table: TableId,
    data: Commitment,
    index: Commitment,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadRequirements {
    pub data_image_bytes: usize,
    pub index_prefix_pages: u32,
}
impl ReadHeads {
    pub fn new(
        table: TableId,
        data: &Commitment,
        index: &Commitment,
        limits: Limits,
    ) -> Result<Self> {
        data.layout().validate(limits)?;
        check_schema(data)?;
        index.layout().validate(crate::index::index_limits())?;
        crate::index::check_geometry(index, data.layout().row_count)?;
        Ok(Self {
            table,
            data: data.clone(),
            index: index.clone(),
        })
    }
    pub fn table_id(&self) -> &TableId {
        &self.table
    }
    pub fn data(&self) -> &Commitment {
        &self.data
    }
    pub fn index(&self) -> &Commitment {
        &self.index
    }
    /// Same footprint for all predicates, projections, limits and empty results.
    /// Includes the complete public padded posting capacity, not selected buckets.
    pub fn read_requirements(&self) -> Result<ReadRequirements> {
        let prefix = index::identity_offset(self.data.layout().row_count)?;
        Ok(ReadRequirements {
            data_image_bytes: self.data.layout().encoded_len()?,
            index_prefix_pages: u32::try_from(prefix.div_ceil(index::INDEX_PAGE_BYTES))
                .map_err(|_| Error::WireLimit)?,
        })
    }
}

/// Borrows real immutable sources without pretending an index prefix is a Table.
#[cfg(feature = "bfv-experiment")]
pub struct ReadView<'a> {
    heads: ReadHeads,
    pub(crate) data: &'a dyn PageSource,
    pub(crate) index: &'a dyn PageSource,
}
#[cfg(feature = "bfv-experiment")]
impl<'a> ReadView<'a> {
    pub fn new(
        heads: ReadHeads,
        data: &'a dyn PageSource,
        index: &'a dyn PageSource,
    ) -> Result<Self> {
        if data.commitment() != heads.data() || index.commitment() != heads.index() {
            return Err(Error::WrongVersion);
        }
        Ok(Self { heads, data, index })
    }
    pub fn heads(&self) -> &ReadHeads {
        &self.heads
    }
}
impl Table {
    pub fn read_heads(&self) -> ReadHeads {
        ReadHeads {
            table: self.table_id,
            data: self.commitment().clone(),
            index: self.index_commitment().clone(),
        }
    }
    #[cfg(feature = "bfv-experiment")]
    pub fn read_view(&self) -> ReadView<'_> {
        ReadView {
            heads: self.read_heads(),
            data: &self.data,
            index: &self.index,
        }
    }
}
pub(crate) fn checked_page(
    source: &dyn PageSource,
    expected: &Commitment,
    page: u64,
    limits: Limits,
) -> Result<VerifiedPage> {
    if source.commitment() != expected {
        return Err(Error::WrongVersion);
    }
    let checked = source.lookup(page, limits)?;
    if checked.commitment() != expected || checked.page_index() != page {
        return Err(Error::WrongVersion);
    }
    Ok(checked)
}

#[cfg(test)]
mod tests;
