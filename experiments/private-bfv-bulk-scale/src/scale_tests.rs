//! Same-owner independent images and disk-only dispatch; public fixtures only.
use super::*;
#[test]
fn disk_preflight_rejects_count_budget_overflow_and_insufficient_actual_free_space() {
    assert!(disk_scale::preflight(1000, 6_500_000_000, 7_000_000_000).is_ok());
    for count in [0, 2, 1001, usize::MAX] {
        assert!(disk_scale::preflight(count, 6_500_000_000, u64::MAX).is_err());
    }
    assert!(disk_scale::preflight(1000, 6_000_000_000, u64::MAX).is_err());
    assert!(disk_scale::preflight(3, 6_500_000_001, u64::MAX).is_err());
    assert!(disk_scale::preflight(3, 6_500_000_000, 1).is_err());
}
fn fresh_catalog() -> (disk_scale::Catalog, roles::OwnerTable, bfv::Evaluator) {
    let mut nonce = [0_u8; 8];
    getrandom::getrandom(&mut nonce).unwrap();
    let directory = std::env::temp_dir().join(format!(
        "public-bulk-scale-test-{}-{}",
        std::process::id(),
        u64::from_le_bytes(nonce)
    ));
    std::fs::create_dir(&directory).unwrap();
    let (authority, evaluator) = bfv::Owner::generate(*b"public-scale-tst").unwrap();
    let catalog = disk_scale::Catalog::create(&directory, 3, 64 * 1024 * 1024, &authority).unwrap();
    let owner = roles::OwnerTable::new(authority, catalog.entries[0].trusted.clone());
    (catalog, owner, evaluator)
}
#[test]
fn one_owner_three_independent_tables_disk_dispatch_allgroups_and_zero_resident_state() {
    let (catalog, mut owner, evaluator) = fresh_catalog();
    assert_eq!(catalog.distinct_roots, 6);
    let before = evaluator.encode_public_setup_for_experiment().unwrap();
    let counters = roles::Counters::default();
    for table in [0, 1, 2] {
        for case in fixture::CASES {
            let result =
                disk_scale::execute(&catalog, table, &mut owner, &evaluator, case, &counters)
                    .unwrap();
            let (ids, sum) = fixture::oracle_for_table(table, case);
            assert_eq!(
                (result.inner.actual.count, result.inner.actual.sum),
                (ids.len() as u32, sum)
            );
            assert_eq!(result.inner.actual.proof, bfv::ProofStatus::Unavailable);
            assert_eq!(result.inner.stages.peer.rotations, 8);
            assert!(result.whole_ms >= result.inner.whole_ms);
        }
    }
    assert_eq!(
        (
            counters.prepare_successes.get(),
            counters.peer_evaluations.get(),
            counters.owner_completions.get()
        ),
        (9, 9, 9)
    );
    assert_eq!(
        before,
        evaluator.encode_public_setup_for_experiment().unwrap()
    );
    let ledger = catalog.ledger().unwrap();
    assert_eq!(ledger["all_file_count"], 7);
    assert_eq!(ledger["resident_ciphertext_response_bytes"], 0);
    assert_eq!(ledger["all_physical_lengths_and112byte_heads_match"], true);
    let point = fixture::CASES[1];
    assert_eq!(
        (
            fixture::oracle_for_table(0, point).1,
            fixture::oracle_for_table(2, point).1
        ),
        (4095, 4097)
    );
}
#[test]
fn swapped_same_owner_table_file_and_bad_routing_reject_before_fresh_bfv() {
    let (mut catalog, mut owner, evaluator) = fresh_catalog();
    let counters = roles::Counters::default();
    catalog.entries[0].data_path = catalog.entries[1].data_path.clone();
    assert!(
        disk_scale::execute(
            &catalog,
            0,
            &mut owner,
            &evaluator,
            fixture::CASES[0],
            &counters
        )
        .is_err()
    );
    assert_eq!(counters.prepare_calls.get(), 0);
    catalog.entries[0].trusted.table_id = 1;
    assert!(
        disk_scale::execute(
            &catalog,
            0,
            &mut owner,
            &evaluator,
            fixture::CASES[0],
            &counters
        )
        .is_err()
    );
    assert_eq!(
        (
            counters.prepare_calls.get(),
            counters.peer_evaluations.get()
        ),
        (0, 0)
    );
    assert!(
        disk_scale::execute(
            &catalog,
            99,
            &mut owner,
            &evaluator,
            fixture::CASES[0],
            &counters
        )
        .is_err()
    );
}
