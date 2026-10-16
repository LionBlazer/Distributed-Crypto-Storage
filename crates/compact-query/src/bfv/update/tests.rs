//! Complete owner-encrypted malformed fixtures, never a live fallback.
use super::*;

#[test]
fn update_source_rejects_a_later_candidate_whose_authenticated_age_disagrees_with_postings() {
    let (owner, _) = Owner::generate([111; 16]).unwrap();
    let limits = Limits::default();
    let mut rows = vec![PlainRow { age: 42, amount: 7 }; 256];
    rows[255].age = 7;
    let mut table = owner.seal(&rows, 17, limits).unwrap();
    let claimed = vec![PlainRow { age: 42, amount: 7 }; 256];
    table.index = crate::index::build(
        &owner.store,
        &claimed,
        table.commitment(),
        table.table_id(),
        &crate::RowIds::generate(256).unwrap(),
    )
    .unwrap();
    let before = (table.snapshot().encode(), table.encrypted_index().encode());

    assert!(matches!(
        owner.prepare_provable_update_from_source(
            &table.read_view(),
            Some(AgeRange::equal(42)),
            1,
            256,
            limits
        ),
        Err(Error::InvalidIndex)
    ));

    assert_eq!(
        (table.snapshot().encode(), table.encrypted_index().encode()),
        before
    );
}

#[test]
fn update_source_rejects_authenticated_unterminated_later_posting_before_input_encryption() {
    let (owner, _) = Owner::generate([112; 16]).unwrap();
    let limits = Limits::default();
    let mut rows = vec![PlainRow { age: 0, amount: 7 }; 10_000];
    for i in [1, 5000, 9999] {
        rows[i].age = 42;
    }
    let mut table = owner.seal(&rows, 256, limits).unwrap();
    let old = table.index_commitment().clone();
    let verified = table
        .lookup_index_page(0)
        .unwrap()
        .verify(&old, 0, index::index_limits())
        .unwrap();
    let first = owner.store.decrypt(&verified).unwrap();
    // Fixed private format: embedded head, TableId, counts, then257 offsets.
    let offsets = compact_store::MANIFEST_BYTES + 32 + 256 * 4;
    let end = u32::from_le_bytes(
        first.as_bytes()[offsets + 43 * 4..offsets + 44 * 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let last = crate::INDEX_HEADER_BYTES + end - 1;
    let page = (last / index::INDEX_PAGE_BYTES) as u64;
    assert!(page > 0);
    let verified = table
        .lookup_index_page(page)
        .unwrap()
        .verify(&old, page, index::index_limits())
        .unwrap();
    let mut bytes = owner.store.decrypt(&verified).unwrap().as_bytes().to_vec();
    bytes[last % index::INDEX_PAGE_BYTES] = 0x80;
    owner
        .store
        .replace_page(&mut table.index, &old, page, &bytes, index::index_limits())
        .unwrap();
    let before = (table.snapshot().encode(), table.encrypted_index().encode());

    assert!(matches!(
        owner.prepare_provable_update_from_source(
            &table.read_view(),
            Some(AgeRange::equal(42)),
            1,
            256,
            limits
        ),
        Err(Error::InvalidIndex)
    ));

    assert_eq!(
        (table.snapshot().encode(), table.encrypted_index().encode()),
        before
    );
}
