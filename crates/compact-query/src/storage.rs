//! Shared canonical storage lifecycle; never owns an FHE key or executes a predicate.
use crate::{
    Error, MAX_TABLE_ROWS, PlainRow, ROW_BYTES, Result, SCHEMA, Table, check_schema, index,
};
use compact_store::{Commitment, EncryptedSnapshot, Layout, Limits, Owner};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

pub(crate) fn seal(
    owner: &Owner,
    rows: &[PlainRow],
    rows_per_page: u32,
    limits: Limits,
) -> Result<Table> {
    if rows.len() > MAX_TABLE_ROWS {
        return Err(Error::SelectionBudget {
            selected: rows.len(),
            budget: MAX_TABLE_ROWS,
        });
    }
    let mut plain = Zeroizing::new(Vec::with_capacity(rows.len() * ROW_BYTES as usize));
    for row in rows {
        plain.push(row.age);
        plain.extend_from_slice(&row.amount.to_le_bytes());
    }
    let data = owner.seal(
        Layout {
            schema: SCHEMA,
            row_width: ROW_BYTES,
            rows_per_page,
            row_count: rows.len() as u64,
        },
        &plain,
        limits,
    )?;
    let index = index::build(owner, rows, data.commitment())?;
    Ok(Table { data, index })
}

pub(crate) fn restore(
    owner: &Owner,
    data: &[u8],
    index_bytes: &[u8],
    expected_data: &Commitment,
    expected_index: &Commitment,
    limits: Limits,
) -> Result<Table> {
    let data = EncryptedSnapshot::decode_for_head(data, expected_data, limits)?;
    let index =
        EncryptedSnapshot::decode_for_head(index_bytes, expected_index, index::index_limits())?;
    check_schema(data.commitment())?;
    index::check_binding(owner, &index, data.commitment())?;
    Ok(Table { data, index })
}

pub(crate) fn row(owner: &Owner, table: &Table, ordinal: u64, limits: Limits) -> Result<PlainRow> {
    let address = table.commitment().layout().address_of(ordinal)?;
    let verified = table.data.lookup(address.page_index, limits)?.verify(
        table.commitment(),
        address.page_index,
        limits,
    )?;
    let plain = owner.decrypt(&verified)?;
    let bytes = &plain.as_bytes()[address.byte_offset..address.byte_offset + 3];
    Ok(PlainRow {
        age: bytes[0],
        amount: u16::from_le_bytes([bytes[1], bytes[2]]),
    })
}

/// All plaintext answers must have been checked by the owning backend BEFORE invoking this.
/// Revisions/nonces and the complete index-page suffix are staged before either image is returned.
pub(crate) fn replace_amount_pages(
    owner: &Owner,
    table: &Table,
    expected_data: &Commitment,
    expected_index: &Commitment,
    pages: &BTreeMap<u64, Zeroizing<Vec<u8>>>,
    limits: Limits,
) -> Result<Table> {
    if table.commitment() != expected_data || table.index_commitment() != expected_index {
        return Err(Error::WrongVersion);
    }
    let mut data = table.data.clone();
    let replacements: Vec<_> = pages
        .iter()
        .map(|(page, bytes)| (*page, bytes.as_slice()))
        .collect();
    let next = owner.replace_pages(&mut data, expected_data, &replacements, limits)?;
    let index = index::rebound(owner, &table.index, expected_data, &next)?;
    Ok(Table { data, index })
}

/// Full output relation was already decoded from genuine peer BFV append and locally
/// checked against authenticated originals plus authorized input by the owning backend.
#[cfg(feature = "bfv-experiment")]
pub(crate) fn grow_checked(
    owner: &Owner,
    table: &Table,
    expected_data: &Commitment,
    expected_index: &Commitment,
    rows: &[PlainRow],
    limits: Limits,
) -> Result<Table> {
    if table.commitment() != expected_data || table.index_commitment() != expected_index {
        return Err(Error::WrongVersion);
    }
    if rows.len() as u64 != expected_data.layout().row_count + 1 {
        return Err(Error::InvalidOutput);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(rows.len() * ROW_BYTES as usize));
    for row in rows {
        bytes.push(row.age);
        bytes.extend_from_slice(&row.amount.to_le_bytes());
    }
    let data = owner.grow_from_checked_plaintext(
        &table.data,
        expected_data,
        rows.len() as u64,
        &bytes,
        limits,
    )?;
    let index = index::grow(owner, rows, data.commitment(), &table.index)?;
    Ok(Table { data, index })
}
