/// Complete contiguous bucket interval, checked before posting transport.
fn posting_page_preflight(header: &IndexHeader, range: AgeRange) -> IndexResult<Vec<u64>> {
    range.validate()?;
    let (counts, offsets) = header.metadata();
    if counts[range.lower as usize..=range.upper as usize]
        .iter()
        .all(|count| *count == 0)
    {
        return Ok(Vec::new());
    }
    let start = INDEX_HEADER_BYTES + offsets[range.lower as usize] as usize;
    let end = INDEX_HEADER_BYTES + offsets[range.upper as usize + 1] as usize;
    if end <= start {
        return Err(IndexError::InvalidIndex);
    }
    let first = start / 4096;
    let last = (end - 1) / 4096;
    if last - first + 1 > PAGE_BUDGET {
        return Err(IndexError::PageBudget);
    }
    Ok((first..=last).map(|page| page as u64).collect())
}
/// All complete ordinals are known before any data transport. Never keep a prefix.
fn data_page_preflight(selected: &[u64]) -> IndexResult<Vec<u64>> {
    if selected.len() > SLOT_BUDGET {
        return Err(IndexError::SelectionBudget {
            selected: selected.len(),
            budget: SLOT_BUDGET,
        });
    }
    if selected.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(IndexError::DuplicateAddress);
    }
    let mut pages = BTreeSet::new();
    for ordinal in selected {
        if *ordinal >= MAX_TABLE_ROWS as u64 {
            return Err(IndexError::InvalidIndex);
        }
        pages.insert(*ordinal / PAGE_ROWS as u64);
        if pages.len() > PAGE_BUDGET {
            return Err(IndexError::PageBudget);
        }
    }
    Ok(pages.into_iter().collect())
}
/// Fixed capacity before first plaintext copy; Drop clears live fields on every return.
/// This is not a compiler/allocator scratch guarantee.
struct SensitiveFields(Vec<SelectedField>);
impl Drop for SensitiveFields {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for field in &mut self.0 {
            field.age.zeroize();
            field.amount.zeroize();
            field.active.zeroize();
        }
    }
}
#[cfg(test)]
mod pipeline_tests {
    use super::*;
    #[test]
    fn complete_two_page_data_selection_is_kept_and_three_pages_reject() {
        assert_eq!(data_page_preflight(&[2047, 2048]).unwrap(), [0, 1]);
        assert_eq!(
            data_page_preflight(&[2047, 2048, 4096]),
            Err(IndexError::PageBudget)
        );
        assert_eq!(data_page_preflight(&[]).unwrap(), Vec::<u64>::new());
        assert_eq!(
            data_page_preflight(&[1, 1]),
            Err(IndexError::DuplicateAddress)
        );
    }
    #[test]
    fn crossing_varint_requires_both_pages_and_three_posting_pages_reject() {
        let mut counts = [0; 256];
        let mut offsets = [0; 257];
        counts[1] = 1;
        offsets[1] = (4095 - INDEX_HEADER_BYTES) as u32;
        offsets[2] = offsets[1] + 2;
        let header = IndexHeader::from_cached(counts, offsets);
        assert_eq!(
            posting_page_preflight(&header, AgeRange::equal(1)).unwrap(),
            [0, 1]
        );
        // Malformed cached metadata control, not claimed a canonical <=256 list.
        offsets[2] = (8193 - INDEX_HEADER_BYTES) as u32;
        let header = IndexHeader::from_cached(counts, offsets);
        assert_eq!(
            posting_page_preflight(&header, AgeRange::equal(1)),
            Err(IndexError::PageBudget)
        );
    }
}
