#![cfg(feature = "bfv-experiment")]
use compact_query::{PlainRow, TableId, bfv::Owner};
use compact_store::Limits;

#[test]
fn owner_validates_the_complete_images_without_retaining_a_materialized_table() {
    let (owner, _) = Owner::generate([66; 16]).unwrap();
    let table = owner
        .seal(
            &[PlainRow { age: 18, amount: 7 }; 257],
            256,
            Limits::default(),
        )
        .unwrap();
    let data = table.snapshot().encode();
    let index = table.encrypted_index().encode();
    owner
        .validate_table_images_for_experiment(
            &data,
            &index,
            table.table_id(),
            table.commitment(),
            table.index_commitment(),
            Limits::default(),
        )
        .unwrap();
    let restored = owner
        .restore_table_for_experiment(
            &data,
            &index,
            table.table_id(),
            table.commitment(),
            table.index_commitment(),
            Limits::default(),
        )
        .unwrap();
    assert_eq!(restored.snapshot().encode(), data);
    assert_eq!(restored.encrypted_index().encode(), index);
    assert!(
        owner
            .validate_table_images_for_experiment(
                &data,
                &index,
                &TableId::generate().unwrap(),
                table.commitment(),
                table.index_commitment(),
                Limits::default()
            )
            .is_err()
    );
    let mut corrupt = index;
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(
        owner
            .validate_table_images_for_experiment(
                &data,
                &corrupt,
                table.table_id(),
                table.commitment(),
                table.index_commitment(),
                Limits::default()
            )
            .is_err()
    );
}
