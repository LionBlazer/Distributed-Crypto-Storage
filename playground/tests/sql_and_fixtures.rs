use fhe_playground::{MAX_LAB_ROWS, PRESETS, format_rows, parse_rows, sample_rows};
use sql_plan::{QueryPlan, parse_sql};

#[test]
fn every_one_click_preset_has_a_supported_plan() {
    for preset in PRESETS {
        assert!(
            parse_sql(preset.sql).is_ok(),
            "{}: {}",
            preset.name,
            preset.sql
        );
    }
}

#[test]
fn presets_progress_from_reading_to_filtering_and_summary_then_real_writes() {
    use fhe_playground::PresetGroup;
    assert!(matches!(
        parse_sql(PRESETS.first().unwrap().sql),
        Ok(QueryPlan::Select { .. })
    ));
    let groups: Vec<_> =
        PRESETS
            .iter()
            .map(|preset| preset.group)
            .fold(Vec::new(), |mut groups, group| {
                if groups.last() != Some(&group) {
                    groups.push(group)
                }
                groups
            });
    assert_eq!(
        groups,
        vec![
            PresetGroup::Select,
            PresetGroup::Filter,
            PresetGroup::Aggregate,
            PresetGroup::Insert,
            PresetGroup::Update
        ]
    );
    let insert = PRESETS
        .iter()
        .find(|preset| preset.group == PresetGroup::Insert)
        .unwrap();
    assert!(matches!(
        parse_sql(insert.sql),
        Ok(QueryPlan::Insert { .. })
    ));
}

#[test]
fn owner_fixtures_round_trip_and_allow_an_empty_database() {
    let rows = parse_rows(" 0,0\n255,65535\n\n18,20 ").unwrap();

    assert_eq!(parse_rows(&format_rows(&rows)).unwrap(), rows);
    assert!(parse_rows(" \n").unwrap().is_empty());
    assert_eq!(sample_rows(4).unwrap().len(), 4);
}

#[test]
fn invalid_fixture_values_or_resource_limits_are_rejected() {
    for text in ["256,1", "1,65536", "-1,1", "18", "18,1,2", "age,amount"] {
        assert!(
            parse_rows(text).is_err(),
            "invalid fixture was accepted: {text}"
        );
    }
    assert!(parse_rows(&"18,1\n".repeat(MAX_LAB_ROWS + 1)).is_err());
    assert!(parse_rows(&" ".repeat(16385)).is_err());
    assert!(sample_rows(MAX_LAB_ROWS + 1).is_err());
}
