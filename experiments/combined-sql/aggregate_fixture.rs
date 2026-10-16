//! Public benchmark input; consumes the real daemon test lifecycle and SQL API.
use super::*;

#[test]
#[ignore = "Run repeated quiet measurements as described in AGGREGATE-MEASUREMENTS.md"]
fn measure_sparse_million_row_count_sum() {
    let owner = identity();
    let connector = Connector::permissionless(&owner).unwrap();
    let process = Process::start(owner.fingerprint(), 1, None);
    let source: Vec<_> = (0..1_000_000usize)
        .map(|ordinal| PlainRow {
            age: if ordinal >= 997_440 { 42 } else { 7 },
            amount: (ordinal % 65_536) as u16,
        })
        .collect();
    let expected_sum: u64 = source[997_440..]
        .iter()
        .map(|row| u64::from(row.amount))
        .sum();
    let mut session = Session::create(
        "measured-static-aggregate".into(),
        &source,
        vec![process.participant(1, &connector)],
        test_contract(),
    )
    .unwrap();
    eprintln!(
        "measurement_profile={}",
        serde_json::json!({
            "owner_backend": format!("{:?}", bfv_query_proof::backend_kind()),
            "proof_profile": bfv_query_proof::PROOF_PROFILE_ID,
            "application": session.genesis().application_commitment,
            "rows": session.rows(),
            "rayon_threads": std::env::var("RAYON_NUM_THREADS").unwrap(),
            "peer_threads": std::env::var("DCS_TEST_PEER_THREADS").unwrap(),
        })
    );
    let initial = session.version();
    for (sql, expected_count, expected_sum) in [
        (
            "SELECT COUNT(*), SUM(amount) FROM records WHERE age = 42",
            2560,
            Some(expected_sum),
        ),
        ("SELECT COUNT(*) FROM records WHERE age = 18", 0, None),
        ("SELECT SUM(amount) FROM records WHERE age > 255", 0, None),
    ] {
        let VerifiedResult::Aggregated {
            count,
            sum,
            version,
            ..
        } = execute(&mut session, sql)
        else {
            panic!("Expected genuine proved aggregate")
        };
        assert_eq!(
            (count, sum, version),
            (expected_count, expected_sum, initial)
        );
    }
}
