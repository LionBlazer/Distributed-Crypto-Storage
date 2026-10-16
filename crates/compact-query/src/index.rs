use crate::identity::ID_BYTES;
use crate::{
    AgeRange, Error, INDEX_HEADER_BYTES, INDEX_SCHEMA, MAX_TABLE_ROWS, PlainRow, Result, RowId,
    RowIds, RowReference, RowReferences, Table, TableId,
};
use compact_store::{
    Commitment, EncryptedSnapshot, Layout, Limits, LookupResponse, MANIFEST_BYTES,
};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

const AGE_BUCKETS: usize = 256;
const INDEX_PAGE_BYTES: usize = 4096;
const TABLE_ID_START: usize = MANIFEST_BYTES;
const COUNTS_START: usize = TABLE_ID_START + ID_BYTES;
const OFFSETS_START: usize = COUNTS_START + AGE_BUCKETS * 4;
const _: () = assert!(INDEX_HEADER_BYTES == OFFSETS_START + (AGE_BUCKETS + 1) * 4);

pub(crate) fn index_limits() -> Limits {
    let bytes = index_bytes(MAX_TABLE_ROWS as u64).expect("fixed bounded index geometry");
    Limits {
        max_rows: bytes as u64,
        max_pages: bytes.div_ceil(INDEX_PAGE_BYTES) as u32,
        max_page_plaintext_bytes: INDEX_PAGE_BYTES,
        max_image_bytes: MANIFEST_BYTES
            + bytes
            + compact_store::PAGE_OVERHEAD * bytes.div_ceil(INDEX_PAGE_BYTES),
        ..Limits::default()
    }
}

fn identity_offset(rows: u64) -> Result<usize> {
    Ok((INDEX_HEADER_BYTES + posting_capacity(rows)?).next_multiple_of(ID_BYTES))
}
fn index_bytes(rows: u64) -> Result<usize> {
    identity_offset(rows)?
        .checked_add(ID_BYTES * rows as usize)
        .ok_or(Error::InvalidIndex)
}
/// Parses this version's bounded byte-oriented index geometry, without establishing
/// ownership, the private table identity or freshness of either supplied head.
pub(crate) fn decode_head(bytes: &[u8], data_rows: u64) -> Result<Commitment> {
    let head = Commitment::decode(bytes, index_limits())?;
    check_geometry(&head, data_rows)?;
    Ok(head)
}
fn check_geometry(head: &Commitment, rows: u64) -> Result<()> {
    let layout = head.layout();
    if layout.schema != INDEX_SCHEMA
        || layout.row_width != 1
        || layout.rows_per_page != INDEX_PAGE_BYTES as u32
        || layout.row_count != index_bytes(rows)? as u64
    {
        return Err(Error::InvalidIndex);
    }
    Ok(())
}

/// Fixed per-table-size capacity: one byte per posting plus upper bounds on
/// second/third groups from the sum of the per-age gaps. No value reaches 2^21.
fn posting_capacity(rows: u64) -> Result<usize> {
    if rows > MAX_TABLE_ROWS as u64 {
        return Err(Error::InvalidIndex);
    }
    if rows == 0 {
        return Ok(0);
    }
    let gap_sum_bound = (rows - 1)
        .checked_mul(AGE_BUCKETS as u64)
        .ok_or(Error::InvalidIndex)?;
    let bytes = rows
        .checked_add(rows.min(gap_sum_bound / 128))
        .and_then(|sum| sum.checked_add(rows.min(gap_sum_bound / 16384)))
        .ok_or(Error::InvalidIndex)?;
    usize::try_from(bytes).map_err(|_| Error::InvalidIndex)
}

/// Parsed authenticated header. The decrypted page buffer is zeroized on drop;
/// copied counts/offsets are ordinary owner-side metadata.
/// Counts permit preflight without visiting the selected posting pages.
pub(crate) struct IndexHeader {
    counts: [u32; AGE_BUCKETS],
    offsets: [u32; AGE_BUCKETS + 1],
    first_page: compact_store::PlainPage,
    table_id: TableId,
}

pub(crate) fn build(
    owner: &compact_store::Owner,
    rows: &[PlainRow],
    head: &Commitment,
    table_id: &TableId,
    ids: &RowIds,
) -> Result<EncryptedSnapshot> {
    let bytes = build_plaintext(rows, head, table_id, ids.as_slice())?;
    Ok(owner.seal(
        Layout {
            schema: INDEX_SCHEMA,
            row_width: 1,
            rows_per_page: INDEX_PAGE_BYTES as u32,
            row_count: bytes.len() as u64,
        },
        &bytes,
        index_limits(),
    )?)
}
#[cfg(feature = "bfv-experiment")]
pub(crate) fn grow(
    owner: &compact_store::Owner,
    rows: &[PlainRow],
    head: &Commitment,
    table: &Table,
    incoming: &RowIds,
) -> Result<EncryptedSnapshot> {
    let old_count = table.commitment().layout().row_count;
    if old_count > crate::MAX_ROWS as u64 || old_count as usize + incoming.len() != rows.len() {
        return Err(Error::InvalidIndex);
    }
    let ordinals: Vec<_> = (0..old_count).collect();
    let original = references(owner, table, &ordinals, &mut 0)?;
    let mut ids = Zeroizing::new(Vec::with_capacity(rows.len()));
    ids.extend(original.rows().iter().map(|row| *row.row_id()));
    ids.extend_from_slice(incoming.as_slice());
    let ids = RowIds::checked(ids)?;
    let bytes = build_plaintext(rows, head, table.table_id(), ids.as_slice())?;
    Ok(owner.grow_from_checked_plaintext(
        &table.index,
        table.index_commitment(),
        bytes.len() as u64,
        &bytes,
        index_limits(),
    )?)
}
fn build_plaintext(
    rows: &[PlainRow],
    head: &Commitment,
    table_id: &TableId,
    ids: &[RowId],
) -> Result<Zeroizing<Vec<u8>>> {
    if rows.len() > MAX_TABLE_ROWS
        || rows.len() as u64 != head.layout().row_count
        || ids.len() != rows.len()
    {
        return Err(Error::InvalidIndex);
    }
    let mut postings = Zeroizing::new(
        (0..AGE_BUCKETS)
            .map(|_| Vec::<u32>::new())
            .collect::<Vec<_>>(),
    );
    for (ordinal, row) in rows.iter().enumerate() {
        postings[row.age as usize].push(ordinal as u32);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(index_bytes(rows.len() as u64)?));
    bytes.resize(INDEX_HEADER_BYTES, 0);
    bytes[..MANIFEST_BYTES].copy_from_slice(&head.encode());
    bytes[TABLE_ID_START..COUNTS_START].copy_from_slice(table_id.as_bytes());
    let mut offsets = [0_u32; AGE_BUCKETS + 1];
    for (age, list) in postings.iter().enumerate() {
        let count_start = COUNTS_START + age * 4;
        bytes[count_start..count_start + 4].copy_from_slice(&(list.len() as u32).to_le_bytes());
        let mut previous = 0;
        for (position, &ordinal) in list.iter().enumerate() {
            let value = if position == 0 {
                ordinal
            } else {
                ordinal - previous
            };
            write_varint(value, &mut bytes);
            previous = ordinal;
        }
        offsets[age + 1] = (bytes.len() - INDEX_HEADER_BYTES) as u32;
    }
    for (position, offset) in offsets.iter().enumerate() {
        let start = OFFSETS_START + position * 4;
        bytes[start..start + 4].copy_from_slice(&offset.to_le_bytes());
    }
    let padded_len = INDEX_HEADER_BYTES + posting_capacity(rows.len() as u64)?;
    if bytes.len() > padded_len {
        return Err(Error::InvalidIndex);
    }
    bytes.resize(identity_offset(rows.len() as u64)?, 0);
    for id in ids {
        bytes.extend_from_slice(id.as_bytes());
    }
    Ok(bytes)
}

fn write_varint(mut value: u32, output: &mut Vec<u8>) {
    loop {
        let low = (value & 0x7f) as u8;
        value >>= 7;
        output.push(if value == 0 { low } else { low | 0x80 });
        if value == 0 {
            break;
        }
    }
}

fn page_bytes_counted(
    owner: &compact_store::Owner,
    snapshot: &EncryptedSnapshot,
    page: u64,
    transferred: &mut usize,
) -> Result<compact_store::PlainPage> {
    let limits = index_limits();
    let wire = snapshot.lookup(page, limits)?.encode();
    *transferred += wire.len();
    let verified =
        LookupResponse::decode(&wire, limits)?.verify(snapshot.commitment(), page, limits)?;
    Ok(owner.decrypt(&verified)?)
}

pub(crate) fn check_binding(
    owner: &compact_store::Owner,
    index: &EncryptedSnapshot,
    head: &Commitment,
    table_id: &TableId,
) -> Result<IndexHeader> {
    check_binding_counted(owner, index, head, table_id, &mut 0)
}

pub(crate) fn check_binding_counted(
    owner: &compact_store::Owner,
    index: &EncryptedSnapshot,
    head: &Commitment,
    table_id: &TableId,
    transferred: &mut usize,
) -> Result<IndexHeader> {
    let rows = head.layout().row_count;
    check_geometry(index.commitment(), rows)?;
    let first_page = page_bytes_counted(owner, index, 0, transferred)?;
    let first = first_page.as_bytes();
    if first.len() < INDEX_HEADER_BYTES {
        return Err(Error::InvalidIndex);
    }
    if first[..MANIFEST_BYTES] != head.encode() {
        return Err(Error::WrongVersion);
    }
    let parsed_id = TableId::from_bytes(first[TABLE_ID_START..COUNTS_START].try_into().unwrap())?;
    if &parsed_id != table_id {
        return Err(Error::WrongVersion);
    }
    let mut counts = [0_u32; AGE_BUCKETS];
    let mut offsets = [0_u32; AGE_BUCKETS + 1];
    for (position, count) in counts.iter_mut().enumerate() {
        let start = COUNTS_START + position * 4;
        *count = u32::from_le_bytes(first[start..start + 4].try_into().unwrap());
    }
    for (position, offset) in offsets.iter_mut().enumerate() {
        let start = OFFSETS_START + position * 4;
        *offset = u32::from_le_bytes(first[start..start + 4].try_into().unwrap());
    }
    let total = counts.iter().try_fold(0_u64, |sum, count| {
        sum.checked_add(u64::from(*count))
            .ok_or(Error::InvalidIndex)
    })?;
    let payload_bytes = posting_capacity(rows)? as u64;
    if total != rows || offsets[0] != 0 || u64::from(offsets[AGE_BUCKETS]) > payload_bytes {
        return Err(Error::InvalidIndex);
    }
    for (age, pair) in offsets.windows(2).enumerate() {
        let length = pair[1].checked_sub(pair[0]).ok_or(Error::InvalidIndex)?;
        let count = counts[age];
        if (count == 0) != (length == 0)
            || length < count
            || u64::from(length) > 5 * u64::from(count)
        {
            return Err(Error::InvalidIndex);
        }
    }
    Ok(IndexHeader {
        counts,
        offsets,
        first_page,
        table_id: parsed_id,
    })
}

/// Reads only selected posting pages, authenticating a page before its bytes are used.
/// A varint can cross a page boundary but cannot cross its bucket's byte boundary.
struct PostingReader<'a> {
    owner: &'a compact_store::Owner,
    snapshot: &'a EncryptedSnapshot,
    position: usize,
    page_index: u64,
    page: compact_store::PlainPage,
    transferred: &'a mut usize,
}
impl PostingReader<'_> {
    fn byte(&mut self, bucket_end: usize) -> Result<u8> {
        if self.position >= bucket_end {
            return Err(Error::InvalidIndex);
        }
        let page_index = (self.position / INDEX_PAGE_BYTES) as u64;
        if self.page_index != page_index {
            self.page =
                page_bytes_counted(self.owner, self.snapshot, page_index, self.transferred)?;
            self.page_index = page_index;
        }
        let byte = *self
            .page
            .as_bytes()
            .get(self.position % INDEX_PAGE_BYTES)
            .ok_or(Error::InvalidIndex)?;
        self.position += 1;
        Ok(byte)
    }

    fn varint(&mut self, bucket_end: usize) -> Result<u32> {
        let mut value = 0_u32;
        for group in 0..5 {
            let byte = self.byte(bucket_end)?;
            if group == 4 && byte & 0xf0 != 0 {
                return Err(Error::InvalidIndex);
            }
            value |= u32::from(byte & 0x7f) << (group * 7);
            if byte & 0x80 == 0 {
                if group != 0 && byte == 0 {
                    return Err(Error::InvalidIndex);
                }
                return Ok(value);
            }
        }
        Err(Error::InvalidIndex)
    }
}

pub(crate) fn select(
    owner: &compact_store::Owner,
    index: &EncryptedSnapshot,
    head: &Commitment,
    table_id: &TableId,
    range: AgeRange,
    budget: usize,
    transferred: &mut usize,
) -> Result<Vec<u64>> {
    range.validate()?;
    let header = check_binding_counted(owner, index, head, table_id, transferred)?;
    let selected = header.counts[range.lower as usize..=range.upper as usize]
        .iter()
        .try_fold(0_usize, |sum, count| {
            sum.checked_add(*count as usize).ok_or(Error::InvalidIndex)
        })?;
    let budget = budget.min(crate::MAX_ROWS);
    if selected > budget {
        return Err(Error::SelectionBudget { selected, budget });
    }
    let mut result = Vec::with_capacity(selected);
    let mut reader = PostingReader {
        owner,
        snapshot: index,
        position: INDEX_HEADER_BYTES + header.offsets[range.lower as usize] as usize,
        page_index: 0,
        page: header.first_page,
        transferred,
    };
    for age in range.lower as usize..=range.upper as usize {
        let bucket_end = INDEX_HEADER_BYTES + header.offsets[age + 1] as usize;
        let mut previous = 0_u32;
        for position in 0..header.counts[age] {
            let delta = reader.varint(bucket_end)?;
            let ordinal = if position == 0 {
                delta
            } else {
                if delta == 0 {
                    return Err(Error::InvalidIndex);
                }
                previous.checked_add(delta).ok_or(Error::InvalidIndex)?
            };
            if u64::from(ordinal) >= head.layout().row_count {
                return Err(Error::InvalidIndex);
            }
            result.push(u64::from(ordinal));
            previous = ordinal;
        }
        if reader.position != bucket_end {
            return Err(Error::InvalidIndex);
        }
    }
    result.sort_unstable();
    if result.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(Error::DuplicateAddress);
    }
    Ok(result)
}

/// Authenticates at most 256 ordinal references without decoding the full identity map.
/// Page zero is checked against BOTH trusted heads and the expected logical table first.
pub(crate) fn references(
    owner: &compact_store::Owner,
    table: &Table,
    ordinals: &[u64],
    transferred: &mut usize,
) -> Result<RowReferences> {
    if ordinals.len() > crate::MAX_ROWS {
        return Err(Error::SelectionBudget {
            selected: ordinals.len(),
            budget: crate::MAX_ROWS,
        });
    }
    let mut sorted = Zeroizing::new(ordinals.to_vec());
    sorted.sort_unstable();
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(Error::DuplicateAddress);
    }
    let count = table.commitment().layout().row_count;
    if ordinals.iter().any(|ordinal| *ordinal >= count) {
        return Err(Error::InvalidIndex);
    }
    let header = check_binding_counted(
        owner,
        &table.index,
        table.commitment(),
        table.table_id(),
        transferred,
    )?;
    let mut pages = BTreeMap::from([(0, header.first_page)]);
    let mut rows = Zeroizing::new(Vec::with_capacity(ordinals.len()));
    for ordinal in ordinals {
        let offset = identity_offset(count)? + *ordinal as usize * ID_BYTES;
        let page_index = (offset / INDEX_PAGE_BYTES) as u64;
        if let std::collections::btree_map::Entry::Vacant(entry) = pages.entry(page_index) {
            entry.insert(page_bytes_counted(
                owner,
                &table.index,
                page_index,
                transferred,
            )?);
        }
        let start = offset % INDEX_PAGE_BYTES;
        let page = pages[&page_index].as_bytes();
        let bytes = page
            .get(start..start + ID_BYTES)
            .ok_or(Error::InvalidIndex)?;
        rows.push(RowReference {
            ordinal: *ordinal,
            id: RowId::parse(bytes.try_into().unwrap())?,
        });
    }
    // Authenticated owner-created maps are unique; reject a corrupt selected duplicate as well.
    let mut ids = Zeroizing::new(rows.iter().map(|row| row.id).collect::<Vec<_>>());
    ids.sort_unstable();
    if ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(Error::InvalidIndex);
    }
    Ok(RowReferences {
        table: header.table_id,
        data: table.commitment().clone(),
        index: table.index_commitment().clone(),
        rows,
    })
}

/// Amount-only changes preserve every posting byte. Reencrypt just page zero,
/// which contains the exact current data commitment and may also contain postings.
pub(crate) fn rebound(
    owner: &compact_store::Owner,
    index: &EncryptedSnapshot,
    old: &Commitment,
    new: &Commitment,
    table_id: &TableId,
) -> Result<EncryptedSnapshot> {
    let header = check_binding(owner, index, old, table_id)?;
    if old.layout() != new.layout()
        || old.database() != new.database()
        || old.key_domain() != new.key_domain()
    {
        return Err(Error::InvalidIndex);
    }
    let mut staged = index.clone();
    let mut bytes = Zeroizing::new(header.first_page.as_bytes().to_vec());
    bytes[..MANIFEST_BYTES].copy_from_slice(&new.encode());
    let expected = staged.commitment().clone();
    owner.replace_page(&mut staged, &expected, 0, &bytes, index_limits())?;
    Ok(staged)
}

#[cfg(test)]
mod tests;
