//! Complete authenticated input selection shared by reads and indexed amount UPDATE.
use crate::*;
pub(crate) struct Selection {
    pub selected: Vec<u64>,
    pub fields: Vec<SelectedField>,
    pub page: Option<u64>,
    pub plaintext: Option<compact_store::PlainPage>,
}
pub(crate) fn validate_ordinals(selected: &[u64], rows: u64) -> ProbeResult<()> {
    let mut unique = std::collections::BTreeSet::new();
    if selected.len() > SLOT_BUDGET
        || selected
            .iter()
            .any(|row| *row >= rows || !unique.insert(*row))
    {
        return Err("Duplicate, out-of-range or over-budget exact selection".into());
    }
    data_page_preflight(selected)?;
    Ok(())
}
pub(crate) fn select(
    plan: Plan,
    session: &Session<'_>,
    stages: &mut Stages,
) -> ProbeResult<Selection> {
    let range = plan.query.selection_range()?;
    let header_source = fault_source(
        source(plan.access, session.index, session.pir),
        session.replacement_wire,
    );
    let start = Instant::now();
    let header = match plan.header {
        HeaderMode::Uncached => {
            padded_index_codec::check_binding(session.owner, &header_source, session.data.head)?
        }
        HeaderMode::Cached => session
            .cached
            .restore(session.data.head, session.index.head)?,
    };
    stages.header = header_source.stats.into_inner();
    let (counts, _) = header.metadata();
    let complete_count = counts[range.lower as usize..=range.upper as usize]
        .iter()
        .try_fold(0usize, |sum, value| {
            sum.checked_add(*value as usize)
                .ok_or(IndexError::InvalidIndex)
        })?;
    if complete_count > SLOT_BUDGET {
        return Err(IndexError::SelectionBudget {
            selected: complete_count,
            budget: SLOT_BUDGET,
        }
        .into());
    }
    posting_page_preflight(&header, range)?;
    let posting_source = fault_source(
        source(plan.access, session.index, session.pir),
        session.replacement_wire,
    );
    let selected = padded_index_codec::select_from_header(
        session.owner,
        &posting_source,
        session.data.head,
        range,
        SLOT_BUDGET,
        &mut 0,
        header,
    )?;
    if matches!(plan.profile, Profile::Fixed256) && posting_source.stats.borrow().calls == 0 {
        drop(posting_source.plain(session.owner, 0)?);
    }
    stages.index_verify_decrypt_select_ms = ms(start);
    stages.posting = posting_source.stats.into_inner();
    let data_source = fault_source(
        source(plan.access, session.data, session.pir),
        session.replacement_wire,
    );
    let page = data_page_preflight(&selected)?;
    let data_page = if let Some(page) = page {
        Some(data_source.plain(session.owner, page)?)
    } else if matches!(plan.profile, Profile::Fixed256) {
        Some(data_source.plain(session.owner, 0)?)
    } else {
        None
    };
    let mut fields = Vec::with_capacity(SLOT_BUDGET);
    for ordinal in &selected {
        let offset = (*ordinal as usize % PAGE_ROWS) * 3;
        let bytes = data_page
            .as_ref()
            .ok_or("Missing selected page")?
            .as_bytes()
            .get(offset..offset + 3)
            .ok_or("Selected ordinal outside authenticated data page")?;
        fields.push(SelectedField {
            age: bytes[0],
            amount: u16::from_le_bytes([bytes[1], bytes[2]]),
            active: true,
        });
    }
    // The exact operation is permitted only for these complete authenticated postings.
    // Check every actual selected age before padding, counter increment or encryption.
    if matches!(plan.kernel, KernelMode::ExactIndex) {
        let start = Instant::now();
        check_exact_selected_ages(plan.query, &fields, selected.len())?;
        stages.exact_selected_age_check_ms = ms(start);
    }
    stages.data = data_source.stats.into_inner();
    if session.data.head != session.data.snapshot.commitment()
        || session.index.head != session.index.snapshot.commitment()
    {
        return Err("Trusted live heads changed during authenticated selection".into());
    }
    validate_ordinals(&selected, session.data.head.layout().row_count)?;
    Ok(Selection {
        selected,
        fields,
        page,
        plaintext: data_page,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duplicate_out_of_range_and_cross_page_ordinals_reject_without_filtering() {
        assert!(validate_ordinals(&[0, 0], 2).is_err());
        assert!(validate_ordinals(&[2], 2).is_err());
        assert!(validate_ordinals(&[2047, 2048], 4096).is_err());
        assert!(validate_ordinals(&(0..257).collect::<Vec<_>>(), 1024).is_err());
        assert!(validate_ordinals(&[0, 1], 2).is_ok());
        assert!(validate_ordinals(&[], 2).is_ok());
    }
}
