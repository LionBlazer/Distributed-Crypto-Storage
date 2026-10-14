fn posting_page_preflight(header: &IndexHeader, range: AgeRange) -> IndexResult<()> {
    range.validate()?;
    let (counts, offsets) = header.metadata();
    if counts[range.lower as usize..=range.upper as usize]
        .iter()
        .any(|count| *count != 0)
    {
        let start = INDEX_HEADER_BYTES + offsets[range.lower as usize] as usize;
        let end = INDEX_HEADER_BYTES + offsets[range.upper as usize + 1] as usize;
        if end <= start || start / 4096 != (end - 1) / 4096 {
            return Err(IndexError::PageBudget);
        }
    }
    Ok(())
}
fn data_page_preflight(selected: &[u64]) -> IndexResult<Option<u64>> {
    let page = selected.first().map(|row| row / PAGE_ROWS as u64);
    if selected
        .iter()
        .any(|row| Some(row / PAGE_ROWS as u64) != page)
    {
        return Err(IndexError::PageBudget);
    }
    Ok(page)
}
#[cfg(test)]
mod pipeline_tests {
    use super::*;
    #[test]
    fn a_selection_spanning_two_data_pages_is_rejected_without_truncation() {
        assert_eq!(
            data_page_preflight(&[2047, 2048]),
            Err(IndexError::PageBudget)
        );
    }
    #[test]
    fn absent_selection_has_no_real_data_address() {
        assert_eq!(data_page_preflight(&[]).unwrap(), None);
    }
    #[test]
    fn a_posting_varint_crossing_a_page_is_rejected_before_transport() {
        let mut counts = [0; 256];
        let mut offsets = [0; 257];
        counts[1] = 1;
        offsets[1] = (4095 - INDEX_HEADER_BYTES) as u32;
        offsets[2] = offsets[1] + 2;
        let header = IndexHeader::from_cached(counts, offsets);
        assert_eq!(
            posting_page_preflight(&header, AgeRange::equal(1)),
            Err(IndexError::PageBudget)
        );
    }
    #[test]
    fn cached_header_at_an_old_data_head_is_rejected_before_any_page_read() {
        let owner = Owner::generate([74; 16]).unwrap();
        let mut data = owner
            .seal(
                Layout {
                    schema: SCHEMA,
                    row_width: 3,
                    rows_per_page: PAGE_ROWS as u32,
                    row_count: 1,
                },
                &[250, 100, 0],
                Limits::default(),
            )
            .unwrap();
        let index = padded_index_codec::build(
            &owner,
            &[PlainRow {
                age: 250,
                amount: 100,
            }],
            data.commitment(),
        )
        .unwrap();
        let header = padded_index_codec::check_binding(&owner, &index, data.commitment()).unwrap();
        let cached = CachedHeader::capture(&header, data.commitment(), index.commitment());
        let old = data.commitment().clone();
        let new = owner
            .replace_page(&mut data, &old, 0, &[250, 101, 0], Limits::default())
            .unwrap();
        assert!(matches!(
            cached.restore(&new, index.commitment()),
            Err(IndexError::WrongVersion)
        ));
        assert_eq!(cached.payload_bytes(), 2276);
    }
}
