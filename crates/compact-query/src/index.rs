use crate::{AgeRange, Error, INDEX_HEADER_BYTES, INDEX_SCHEMA, PlainRow, Result};
use compact_store::{Commitment, EncryptedSnapshot, Layout, Limits, LookupResponse};
use zeroize::Zeroizing;

pub(crate) fn index_limits() -> Limits {
    Limits {
        max_rows: 4_100_000,
        max_image_bytes: 8 * 1024 * 1024,
        ..Limits::default()
    }
}
pub(crate) fn build(
    owner: &compact_store::Owner,
    rows: &[PlainRow],
    head: &Commitment,
) -> Result<EncryptedSnapshot> {
    let mut postings = Zeroizing::new((0..256).map(|_| Vec::<u32>::new()).collect::<Vec<_>>());
    for (ordinal, row) in rows.iter().enumerate() {
        postings[row.age as usize].push(ordinal as u32);
    }
    let mut bytes = Zeroizing::new(head.encode().to_vec());
    let mut offset = 0u64;
    for list in postings.iter() {
        bytes.extend_from_slice(&offset.to_le_bytes());
        offset += list.len() as u64;
    }
    bytes.extend_from_slice(&offset.to_le_bytes());
    for list in postings.iter() {
        for ordinal in list {
            bytes.extend_from_slice(&ordinal.to_le_bytes());
        }
    }
    Ok(owner.seal(
        Layout {
            schema: INDEX_SCHEMA,
            row_width: 1,
            rows_per_page: 4096,
            row_count: bytes.len() as u64,
        },
        &bytes,
        index_limits(),
    )?)
}
fn page_bytes(
    owner: &compact_store::Owner,
    snapshot: &EncryptedSnapshot,
    page: u64,
) -> Result<compact_store::PlainPage> {
    page_bytes_counted(owner, snapshot, page, &mut 0)
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
) -> Result<[u64; 257]> {
    check_binding_counted(owner, index, head, &mut 0)
}
pub(crate) fn check_binding_counted(
    owner: &compact_store::Owner,
    index: &EncryptedSnapshot,
    head: &Commitment,
    transferred: &mut usize,
) -> Result<[u64; 257]> {
    if index.commitment().layout().schema != INDEX_SCHEMA
        || index.commitment().layout().row_width != 1
        || index.commitment().layout().rows_per_page != 4096
        || index.commitment().layout().row_count
            != (INDEX_HEADER_BYTES as u64 + 4 * head.layout().row_count)
    {
        return Err(Error::InvalidIndex);
    }
    let first = page_bytes_counted(owner, index, 0, transferred)?;
    if first.as_bytes()[..112] != head.encode() {
        return Err(Error::WrongVersion);
    }
    let mut bounds = [0u64; 257];
    for (i, bound) in bounds.iter_mut().enumerate() {
        *bound = u64::from_le_bytes(
            first.as_bytes()[112 + i * 8..120 + i * 8]
                .try_into()
                .unwrap(),
        );
    }
    if bounds[0] != 0
        || bounds[256] != head.layout().row_count
        || bounds.windows(2).any(|pair| pair[0] > pair[1])
    {
        return Err(Error::InvalidIndex);
    }
    Ok(bounds)
}
pub(crate) fn select(
    owner: &compact_store::Owner,
    index: &EncryptedSnapshot,
    head: &Commitment,
    range: AgeRange,
    budget: usize,
    transferred: &mut usize,
) -> Result<Vec<u64>> {
    let bounds = check_binding_counted(owner, index, head, transferred)?;
    let start = bounds[range.lower as usize] as usize;
    let end = bounds[range.upper as usize + 1] as usize;
    let selected = end - start;
    if selected > budget || selected > crate::MAX_ROWS {
        return Err(Error::SelectionBudget {
            selected,
            budget: budget.min(crate::MAX_ROWS),
        });
    }
    let mut result = Vec::with_capacity(selected);
    let mut previous_page = u64::MAX;
    let mut plain = None;
    for offset in start..end {
        let byte = INDEX_HEADER_BYTES + 4 * offset;
        let page = (byte / 4096) as u64;
        if page != previous_page {
            plain = Some(page_bytes_counted(owner, index, page, transferred)?);
            previous_page = page;
        }
        let bytes = plain.as_ref().unwrap().as_bytes();
        let local = byte % 4096;
        result.push(u32::from_le_bytes(bytes[local..local + 4].try_into().unwrap()) as u64);
    }
    result.sort_unstable();
    if result.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(Error::DuplicateAddress);
    }
    if result
        .iter()
        .any(|ordinal| *ordinal >= head.layout().row_count)
    {
        return Err(Error::InvalidIndex);
    }
    Ok(result)
}
/// Reencrypt only the encrypted binding header after an amount-only update.
/// The full posting list is unchanged because no age field changes.
pub(crate) fn rebound(
    owner: &compact_store::Owner,
    index: &EncryptedSnapshot,
    old: &Commitment,
    new: &Commitment,
) -> Result<EncryptedSnapshot> {
    check_binding(owner, index, old)?;
    let mut staged = index.clone();
    let first = page_bytes(owner, index, 0)?;
    let mut bytes = Zeroizing::new(first.as_bytes().to_vec());
    bytes[..112].copy_from_slice(&new.encode());
    let expected = staged.commitment().clone();
    owner.replace_page(&mut staged, &expected, 0, &bytes, index_limits())?;
    Ok(staged)
}
