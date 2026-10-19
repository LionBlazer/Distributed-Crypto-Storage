//! PUBLIC NONSECRET input rows and keys; all storage acts use the public API.
use crate::{Error, PlainRow, RowIds, Table, TableId, storage};
use compact_store::{AuditWorkers, Error as StorageError, Limits, Owner};
use zeroize::Zeroizing;

const DATABASE: [u8; 16] = [0x21; 16];
const DOMAIN: [u8; 16] = [0x42; 16];
const KEY: [u8; 32] = [0x63; 32];
const ROWS: [PlainRow; 4] = [
    PlainRow {
        age: 255,
        amount: 0,
    },
    PlainRow {
        age: 0,
        amount: 65535,
    },
    PlainRow {
        age: 255,
        amount: 1,
    },
    PlainRow {
        age: 1,
        amount: 128,
    },
];

fn public_owner() -> Owner {
    Owner::from_key(DATABASE, DOMAIN, Zeroizing::new(KEY))
}

fn public_table(owner: &Owner) -> Table {
    storage::seal_partition(
        owner,
        &TableId::from_bytes([0x84; 32]).unwrap(),
        &ROWS,
        RowIds::generate(ROWS.len()).unwrap(),
        256,
        Limits::default(),
    )
    .unwrap()
}

#[test]
fn caller_owned_storage_round_trips_every_canonical_original_row() {
    // Arrange: only the encrypted images and independently retained heads survive.
    let owner = public_owner();
    let table = public_table(&owner);
    let table_id = *table.table_id();
    let data_head = table.commitment().clone();
    let index_head = table.index_commitment().clone();
    let data = table.snapshot().encode();
    let index = table.encrypted_index().encode();
    drop(table);
    drop(owner);
    let owner = public_owner();
    let limits = Limits::default();

    // Act: restore using the same actual canonical writer and read ALL originals.
    let restored = storage::restore(
        &owner,
        (&data, &index),
        &table_id,
        &data_head,
        &index_head,
        limits,
        AuditWorkers::One,
    )
    .unwrap();
    let mut opened = Zeroizing::new(Vec::with_capacity(ROWS.len()));
    for ordinal in 0..ROWS.len() {
        opened.push(storage::row(&owner, &restored, ordinal as u64, limits).unwrap());
    }

    // Assert: the complete canonical N4 format and boundary amounts are retained.
    assert_eq!(data.len(), 172);
    assert_eq!(index.len(), 2496);
    assert_eq!(opened.as_slice(), &ROWS);
    assert_eq!(restored.table_id(), &table_id);
    assert_eq!(restored.snapshot().encode(), data);
    assert_eq!(restored.encrypted_index().encode(), index);
    assert!(matches!(
        storage::row(&owner, &restored, ROWS.len() as u64, limits),
        Err(Error::Storage(StorageError::InvalidPage))
    ));
}

#[test]
fn restore_requires_the_key_domain_table_and_exact_independent_heads() {
    let owner = public_owner();
    let table = public_table(&owner);
    let data = table.snapshot().encode();
    let index = table.encrypted_index().encode();
    let limits = Limits::default();

    // Correct public metadata cannot substitute for the supplied secret key/domain.
    for (other, expected) in [
        (
            Owner::from_key(DATABASE, DOMAIN, Zeroizing::new([0x64; 32])),
            StorageError::Authentication,
        ),
        (
            Owner::from_key([0x22; 16], DOMAIN, Zeroizing::new(KEY)),
            StorageError::WrongOwner,
        ),
        (
            Owner::from_key(DATABASE, [0x43; 16], Zeroizing::new(KEY)),
            StorageError::WrongOwner,
        ),
    ] {
        assert!(matches!(
            storage::restore(
                &other,
                (&data, &index),
                table.table_id(),
                table.commitment(),
                table.index_commitment(),
                limits,
                AuditWorkers::One,
            ),
            Err(Error::Storage(error)) if error == expected
        ));
    }

    let wrong_table = TableId::from_bytes([0x85; 32]).unwrap();
    assert!(matches!(
        storage::restore(
            &owner,
            (&data, &index),
            &wrong_table,
            table.commitment(),
            table.index_commitment(),
            limits,
            AuditWorkers::One,
        ),
        Err(Error::WrongVersion)
    ));

    // Both alternative heads are real owner-sealed images, not malformed metadata.
    let other = public_table(&owner);
    for (data_head, index_head) in [
        (other.commitment(), table.index_commitment()),
        (table.commitment(), other.index_commitment()),
    ] {
        assert!(matches!(
            storage::restore(
                &owner,
                (&data, &index),
                table.table_id(),
                data_head,
                index_head,
                limits,
                AuditWorkers::One,
            ),
            Err(Error::Storage(StorageError::WrongVersion))
        ));
    }
}

#[test]
fn complete_index_tail_corruption_is_rejected_before_row_access() {
    let owner = public_owner();
    let table = public_table(&owner);
    let data = table.snapshot().encode();
    let original_index = table.encrypted_index().encode();
    let mut damaged_index = original_index.clone();
    *damaged_index.last_mut().unwrap() ^= 1;
    let limits = Limits::default();

    assert!(matches!(
        storage::restore(
            &owner,
            (&data, &damaged_index),
            table.table_id(),
            table.commitment(),
            table.index_commitment(),
            limits,
            AuditWorkers::One,
        ),
        Err(Error::Storage(StorageError::InvalidProof))
    ));

    let restored = storage::restore(
        &owner,
        (&data, &original_index),
        table.table_id(),
        table.commitment(),
        table.index_commitment(),
        limits,
        AuditWorkers::One,
    )
    .unwrap();
    assert_eq!(storage::row(&owner, &restored, 3, limits).unwrap(), ROWS[3]);
}

#[test]
fn row_decryption_requires_the_given_key_after_restoration() {
    let owner = public_owner();
    let table = public_table(&owner);
    let data = table.snapshot().encode();
    let index = table.encrypted_index().encode();
    let limits = Limits::default();
    let restored = storage::restore(
        &owner,
        (&data, &index),
        table.table_id(),
        table.commitment(),
        table.index_commitment(),
        limits,
        AuditWorkers::One,
    )
    .unwrap();
    let wrong_key = Owner::from_key(DATABASE, DOMAIN, Zeroizing::new([0x64; 32]));

    assert!(matches!(
        storage::row(&wrong_key, &restored, 0, limits),
        Err(Error::Storage(StorageError::Authentication))
    ));
    assert_eq!(storage::row(&owner, &restored, 0, limits).unwrap(), ROWS[0]);
}
