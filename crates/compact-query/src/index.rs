use crate::{AgeRange, Error, INDEX_HEADER_BYTES, INDEX_SCHEMA, MAX_TABLE_ROWS, PlainRow, Result};
use compact_store::{
    Commitment, EncryptedSnapshot, Layout, Limits, LookupResponse, MANIFEST_BYTES,
};
use zeroize::Zeroizing;

const AGE_BUCKETS: usize = 256;
const INDEX_PAGE_BYTES: usize = 4096;
const COUNTS_START: usize = MANIFEST_BYTES;
const OFFSETS_START: usize = COUNTS_START + AGE_BUCKETS * 4;
const _: () = assert!(INDEX_HEADER_BYTES == OFFSETS_START + (AGE_BUCKETS + 1) * 4);

pub(crate) fn index_limits() -> Limits {
    Limits {
        max_rows: INDEX_HEADER_BYTES as u64 + 5 * MAX_TABLE_ROWS as u64,
        max_image_bytes: 8 * 1024 * 1024,
        ..Limits::default()
    }
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
}

pub(crate) fn build(
    owner: &compact_store::Owner,
    rows: &[PlainRow],
    head: &Commitment,
) -> Result<EncryptedSnapshot> {
    if rows.len() > MAX_TABLE_ROWS || rows.len() as u64 != head.layout().row_count {
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
    let mut bytes = Zeroizing::new(vec![0; INDEX_HEADER_BYTES]);
    bytes[..MANIFEST_BYTES].copy_from_slice(&head.encode());
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
    bytes.resize(padded_len, 0);
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
) -> Result<IndexHeader> {
    check_binding_counted(owner, index, head, &mut 0)
}

pub(crate) fn check_binding_counted(
    owner: &compact_store::Owner,
    index: &EncryptedSnapshot,
    head: &Commitment,
    transferred: &mut usize,
) -> Result<IndexHeader> {
    let layout = index.commitment().layout();
    let rows = head.layout().row_count;
    let expected_bytes = INDEX_HEADER_BYTES + posting_capacity(rows)?;
    if layout.schema != INDEX_SCHEMA
        || layout.row_width != 1
        || layout.rows_per_page != INDEX_PAGE_BYTES as u32
        || layout.row_count != expected_bytes as u64
    {
        return Err(Error::InvalidIndex);
    }
    let first_page = page_bytes_counted(owner, index, 0, transferred)?;
    let first = first_page.as_bytes();
    if first.len() < INDEX_HEADER_BYTES {
        return Err(Error::InvalidIndex);
    }
    if first[..MANIFEST_BYTES] != head.encode() {
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
    let payload_bytes = layout.row_count - INDEX_HEADER_BYTES as u64;
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
    range: AgeRange,
    budget: usize,
    transferred: &mut usize,
) -> Result<Vec<u64>> {
    range.validate()?;
    let header = check_binding_counted(owner, index, head, transferred)?;
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

/// Amount-only changes preserve every posting byte. Reencrypt just page zero,
/// which contains the exact current data commitment and may also contain postings.
pub(crate) fn rebound(
    owner: &compact_store::Owner,
    index: &EncryptedSnapshot,
    old: &Commitment,
    new: &Commitment,
) -> Result<EncryptedSnapshot> {
    let header = check_binding(owner, index, old)?;
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
