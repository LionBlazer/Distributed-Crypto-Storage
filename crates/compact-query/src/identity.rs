//! Owner-private logical identities. Random allocation is not authentication or lock authority.
use crate::{Error, MAX_TABLE_ROWS, Result};
use compact_store::Commitment;
use zeroize::{Zeroize, Zeroizing};

pub(crate) const ID_BYTES: usize = 32;

/// Stable logical table identity, unrelated to database keys, physical shards or heads.
/// Bytes belong to the owner; peers receive this value only inside the encrypted index.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TableId([u8; ID_BYTES]);
impl TableId {
    pub fn generate() -> Result<Self> {
        let mut bytes = [0; ID_BYTES];
        getrandom::getrandom(&mut bytes).map_err(|_| Error::Randomness)?;
        Self::from_bytes(bytes).map_err(|_| Error::Randomness)
    }
    /// Parses owner-held metadata; this alone authenticates neither a table nor its version.
    pub fn from_bytes(bytes: [u8; ID_BYTES]) -> Result<Self> {
        if bytes == [0; ID_BYTES] {
            return Err(Error::InvalidIndex);
        }
        Ok(Self(bytes))
    }
    pub fn as_bytes(&self) -> &[u8; ID_BYTES] {
        &self.0
    }
}
impl std::fmt::Debug for TableId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TableId(<private>)")
    }
}

/// Random owner-private row identity. Copying this metadata confers no proof or lock authority.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RowId([u8; ID_BYTES]);
impl RowId {
    pub fn as_bytes(&self) -> &[u8; ID_BYTES] {
        &self.0
    }
    pub(crate) fn parse(bytes: [u8; ID_BYTES]) -> Result<Self> {
        if bytes == [0; ID_BYTES] {
            return Err(Error::InvalidIndex);
        }
        Ok(Self(bytes))
    }
}
impl Zeroize for RowId {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl std::fmt::Debug for RowId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RowId(<private>)")
    }
}

/// Fresh non-Clone allocation consumed by a partition seal or INSERT preparation.
/// Uniqueness is checked within this allocation; across allocations it relies on 256-bit CSPRNG.
pub struct RowIds {
    ids: Zeroizing<Vec<RowId>>,
}
impl RowIds {
    pub fn generate(count: usize) -> Result<Self> {
        Self::generate_with(count, |bytes| {
            getrandom::getrandom(bytes).map_err(|_| Error::Randomness)
        })
    }
    fn generate_with(count: usize, mut fill: impl FnMut(&mut [u8]) -> Result<()>) -> Result<Self> {
        if count > MAX_TABLE_ROWS {
            return Err(Error::SelectionBudget {
                selected: count,
                budget: MAX_TABLE_ROWS,
            });
        }
        let mut ids = Zeroizing::new(Vec::with_capacity(count));
        // Bounded entropy scratch avoids one OS RNG call per row or another 32 MB image.
        let mut entropy = Zeroizing::new([[0_u8; ID_BYTES]; 256]);
        for start in (0..count).step_by(entropy.len()) {
            let take = (count - start).min(entropy.len());
            fill(entropy[..take].as_flattened_mut())?;
            for bytes in &entropy[..take] {
                ids.push(RowId::parse(*bytes).map_err(|_| Error::Randomness)?);
            }
        }
        Self::checked(ids).map_err(|_| Error::Randomness)
    }
    pub fn len(&self) -> usize {
        self.ids.len()
    }
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }
    /// Assigns every original position once, preserving its order within its partition.
    /// Consumes the allocation; no mutable mapping or unchecked construction is exposed.
    pub fn partition(mut self, assignments: &[usize], partitions: usize) -> Result<Vec<Self>> {
        if partitions == 0
            || partitions > MAX_TABLE_ROWS
            || assignments.len() != self.len()
            || assignments.iter().any(|slot| *slot >= partitions)
        {
            return Err(Error::InvalidIndex);
        }
        let mut counts = vec![0; partitions];
        for slot in assignments {
            counts[*slot] += 1;
        }
        let mut result: Vec<_> = counts
            .into_iter()
            .map(|count| Self {
                ids: Zeroizing::new(Vec::with_capacity(count)),
            })
            .collect();
        for (id, slot) in self.ids.iter_mut().zip(assignments) {
            result[*slot].ids.push(*id);
            id.zeroize();
        }
        Ok(result)
    }
    pub(crate) fn as_slice(&self) -> &[RowId] {
        &self.ids
    }
    pub(crate) fn checked(ids: Zeroizing<Vec<RowId>>) -> Result<Self> {
        if ids.len() > MAX_TABLE_ROWS {
            return Err(Error::InvalidIndex);
        }
        let mut sorted = Zeroizing::new(ids.to_vec());
        sorted.sort_unstable();
        if sorted.iter().any(|id| id.0 == [0; ID_BYTES])
            || sorted.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(Error::InvalidIndex);
        }
        Ok(Self { ids })
    }
}

/// One authenticated position in an owner-issued head-bound reference set.
#[derive(Debug, PartialEq, Eq)]
pub struct RowReference {
    pub(crate) ordinal: u64,
    pub(crate) id: RowId,
}
impl RowReference {
    pub fn ordinal(&self) -> u64 {
        self.ordinal
    }
    pub fn row_id(&self) -> &RowId {
        &self.id
    }
}
impl Zeroize for RowReference {
    fn zeroize(&mut self) {
        self.ordinal.zeroize();
        self.id.zeroize();
    }
}
/// Owner-authenticated private mapping at an exact data/index pair. This is metadata,
/// not a public computation/completeness proof, freshness certificate or SQL lock grant.
pub struct RowReferences {
    pub(crate) table: TableId,
    pub(crate) data: Commitment,
    pub(crate) index: Commitment,
    pub(crate) rows: Zeroizing<Vec<RowReference>>,
}
impl RowReferences {
    pub fn table_id(&self) -> &TableId {
        &self.table
    }
    pub fn data_head(&self) -> &Commitment {
        &self.data
    }
    pub fn index_head(&self) -> &Commitment {
        &self.index
    }
    pub fn rows(&self) -> &[RowReference] {
        &self.rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_is_consumed_into_ordered_partitions_without_reassigning_ids() {
        let mut next = 1_u64;
        let ids = RowIds::generate_with(5, |bytes| {
            for row in bytes.as_chunks_mut::<ID_BYTES>().0 {
                row.fill(0);
                row[..8].copy_from_slice(&next.to_le_bytes());
                next += 1;
            }
            Ok(())
        })
        .unwrap();
        let expected = ids.as_slice().to_vec();

        let parts = ids.partition(&[0, 1, 0, 1, 0], 3).unwrap();

        assert_eq!(
            parts[0].as_slice(),
            &[expected[0], expected[2], expected[4]]
        );
        assert_eq!(parts[1].as_slice(), &[expected[1], expected[3]]);
        assert!(parts[2].is_empty());
    }

    #[test]
    fn entropy_failure_zero_collision_and_invalid_partition_fail_closed() {
        assert!(matches!(
            RowIds::generate_with(2, |_| Err(Error::Randomness)),
            Err(Error::Randomness)
        ));
        assert!(matches!(
            RowIds::generate_with(1, |_| Ok(())),
            Err(Error::Randomness)
        ));
        assert!(matches!(
            RowIds::generate_with(2, |bytes| {
                bytes.fill(1);
                Ok(())
            }),
            Err(Error::Randomness)
        ));
        assert!(matches!(
            RowIds::generate(2).unwrap().partition(&[0, 2], 2),
            Err(Error::InvalidIndex)
        ));
        assert!(matches!(
            RowIds::generate(2).unwrap().partition(&[0], 2),
            Err(Error::InvalidIndex)
        ));
        assert!(matches!(
            RowIds::generate(MAX_TABLE_ROWS + 1),
            Err(Error::SelectionBudget { .. })
        ));
        assert!(TableId::from_bytes([0; ID_BYTES]).is_err());
    }
}
