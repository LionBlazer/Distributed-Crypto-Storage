//! Shared canonical storage lifecycle; never owns an FHE key or executes a predicate.
use crate::{
    Error, MAX_TABLE_ROWS, PlainRow, ROW_BYTES, Result, RowIds, SCHEMA, Table, TableId,
    check_schema, index,
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
    seal_partition(
        owner,
        &TableId::generate()?,
        rows,
        RowIds::generate(rows.len())?,
        rows_per_page,
        limits,
    )
}

pub(crate) fn seal_partition(
    owner: &Owner,
    table_id: &TableId,
    rows: &[PlainRow],
    ids: RowIds,
    rows_per_page: u32,
    limits: Limits,
) -> Result<Table> {
    if ids.len() != rows.len() {
        return Err(Error::InvalidIndex);
    }
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
    let index = index::build(owner, rows, data.commitment(), table_id, &ids)?;
    Ok(Table {
        table_id: *table_id,
        data,
        index,
    })
}

pub(crate) fn restore(
    owner: &Owner,
    data: &[u8],
    index_bytes: &[u8],
    table_id: &TableId,
    expected_data: &Commitment,
    expected_index: &Commitment,
    limits: Limits,
) -> Result<Table> {
    let data = EncryptedSnapshot::decode_for_head(data, expected_data, limits)?;
    let index =
        EncryptedSnapshot::decode_for_head(index_bytes, expected_index, index::index_limits())?;
    check_schema(data.commitment())?;
    let heads = crate::ReadHeads::new(*table_id, data.commitment(), index.commitment(), limits)?;
    index::check_binding(owner, &index, &heads)?;
    Ok(Table {
        table_id: *table_id,
        data,
        index,
    })
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
    let data = replace_data_pages(owner, &table.data, expected_data, pages, limits)?;
    let next = data.commitment().clone();
    let index = index::rebound(owner, &table.index, expected_data, &next, table.table_id())?;
    Ok(Table {
        table_id: table.table_id,
        data,
        index,
    })
}

pub(crate) fn replace_data_pages(
    owner: &Owner,
    source: &EncryptedSnapshot,
    expected: &Commitment,
    pages: &BTreeMap<u64, Zeroizing<Vec<u8>>>,
    limits: Limits,
) -> Result<EncryptedSnapshot> {
    let mut data = source.clone();
    let replacements: Vec<_> = pages
        .iter()
        .map(|(page, bytes)| (*page, bytes.as_slice()))
        .collect();
    owner.replace_pages(&mut data, expected, &replacements, limits)?;
    Ok(data)
}

/// Full output relation was already decoded from genuine peer BFV append and locally
/// checked against authenticated originals plus authorized input by the owning backend.
#[cfg(feature = "bfv-experiment")]
pub(crate) fn grow_checked(
    owner: &Owner,
    table: &Table,
    expected_data: &Commitment,
    expected_index: &Commitment,
    incoming_ids: &RowIds,
    rows: &[PlainRow],
    limits: Limits,
) -> Result<Table> {
    if table.commitment() != expected_data || table.index_commitment() != expected_index {
        return Err(Error::WrongVersion);
    }
    let incoming_count = incoming_ids.len();
    if incoming_count == 0
        || rows.len() > crate::MAX_ROWS
        || expected_data
            .layout()
            .row_count
            .checked_add(incoming_count as u64)
            != Some(rows.len() as u64)
    {
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
    let index = index::grow(owner, rows, data.commitment(), table, incoming_ids)?;
    Ok(Table {
        table_id: table.table_id,
        data,
        index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_index_rebind_after_data_staging_preserves_both_original_images() {
        let owner = Owner::generate([63; 16]).unwrap();
        let limits = Limits::default();
        let rows = vec![PlainRow { age: 7, amount: 11 }; 9];
        let mut table = seal(&owner, &rows, 4, limits).unwrap();
        let index_head = table.index_commitment().clone();
        let first = table
            .index
            .lookup(0, index::index_limits())
            .unwrap()
            .verify(&index_head, 0, index::index_limits())
            .unwrap();
        let mut bad_binding = owner.decrypt(&first).unwrap().as_bytes().to_vec();
        // Valid owner AEAD/root, but the private header names another data root.
        bad_binding[80] ^= 1;
        owner
            .replace_page(
                &mut table.index,
                &index_head,
                0,
                &bad_binding,
                index::index_limits(),
            )
            .unwrap();
        let data_head = table.commitment().clone();
        let index_head = table.index_commitment().clone();
        let original_data = table.snapshot().encode();
        let original_index = table.encrypted_index().encode();
        let replacement = Zeroizing::new(vec![0; 4 * ROW_BYTES as usize]);
        let pages = BTreeMap::from([(0, replacement)]);

        assert!(
            replace_amount_pages(&owner, &table, &data_head, &index_head, &pages, limits).is_err()
        );

        assert_eq!(table.commitment(), &data_head);
        assert_eq!(table.index_commitment(), &index_head);
        assert_eq!(table.snapshot().encode(), original_data);
        assert_eq!(table.encrypted_index().encode(), original_index);
        let page = table
            .data
            .lookup(0, limits)
            .unwrap()
            .verify(&data_head, 0, limits)
            .unwrap();
        assert_eq!(
            owner.decrypt(&page).unwrap().as_bytes(),
            [7, 11, 0].repeat(4)
        );
    }
}
