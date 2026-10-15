//! Finite full SQL-boundary benchmark over explicitly public 128-row fixtures.
//! No window is opened, owner keys/rows are not written, and the oracle runs after timing.
#[path = "support/bfv_memory.rs"]
mod memory;
use fhe_playground::{
    DatabaseDraft, LabEngine, PeerConfig, PlainRow, Predicate, QueryOutcome, QueryPlan, parse_sql,
};
use serde_json::json;
use std::time::Instant;

const CASES: &[(&str, &str)] = &[
    (
        "point",
        "SELECT COUNT(*), SUM(amount) FROM records WHERE age = 42",
    ),
    (
        "duplicates",
        "SELECT COUNT(*), SUM(amount) FROM records WHERE age = 18",
    ),
    ("full_no_where", "SELECT COUNT(*), SUM(amount) FROM records"),
    (
        "ge18",
        "SELECT COUNT(*), SUM(amount) FROM records WHERE age >= 18",
    ),
    (
        "absent_eq255",
        "SELECT COUNT(*), SUM(amount) FROM records WHERE age = 255",
    ),
    (
        "ge255",
        "SELECT COUNT(*), SUM(amount) FROM records WHERE age >= 255",
    ),
    (
        "ge0",
        "SELECT COUNT(*), SUM(amount) FROM records WHERE age >= 0",
    ),
    (
        "age0",
        "SELECT COUNT(*), SUM(amount) FROM records WHERE age = 0",
    ),
    (
        "update_point",
        "UPDATE records SET amount = amount + 1 WHERE age = 42",
    ),
    (
        "update_duplicates",
        "UPDATE records SET amount = amount + 1 WHERE age = 18",
    ),
    (
        "update_full_no_where",
        "UPDATE records SET amount = amount + 1",
    ),
    (
        "update_ge18",
        "UPDATE records SET amount = amount + 5 WHERE age >= 18",
    ),
    (
        "update_absent",
        "UPDATE records SET amount = amount + 1 WHERE age = 255",
    ),
    ("update_zero", "UPDATE records SET amount = amount + 0"),
    (
        "update_overflow",
        "UPDATE records SET amount = amount + 65535 WHERE age >= 18",
    ),
    (
        "read_after_updates",
        "SELECT COUNT(*), SUM(amount) FROM records",
    ),
];
fn selected(row: &PlainRow, predicate: Predicate) -> bool {
    predicate
        .age_range()
        .is_some_and(|range| row.age >= range.lower && row.age <= range.upper)
}
fn memory_json() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let value = memory::guard(0)?;
    Ok(
        json!({"rss":value.working_set_bytes,"peak_rss":value.peak_working_set_bytes,
        "commit":value.private_commit_bytes,"peak_commit":value.peak_commit_bytes}),
    )
}
fn create(rows: &[PlainRow], peers: usize) -> Result<LabEngine, Box<dyn std::error::Error>> {
    memory::guard(200_000_000)?;
    let mut engine = LabEngine::default();
    let timer = Instant::now();
    let snapshot = engine.create(DatabaseDraft {
        name: "public-headless-bfv".into(),
        rows: rows.to_vec(),
        peers: (1..=peers).map(PeerConfig::numbered).collect(),
    })?;
    let setup_ms = timer.elapsed().as_secs_f64() * 1000.0;
    let info = engine.backend_info_for_experiment()?;
    println!(
        "{}",
        json!({"kind":"setup","peers":peers,"rows":rows.len(),"setup_ms":setup_ms,
        "profile":info.profile,"public_setup_bytes":info.public_setup_bytes,
        "owner_secret_serialized_byte_count":info.secret_key_serialized_bytes,
        "logical_bytes":rows.len()*3,
        "canonical_data_bytes":snapshot.peers.iter().map(|peer|peer.data_bytes).sum::<usize>(),
        "encrypted_index_bytes":snapshot.peers.iter().map(|peer|peer.index_bytes).sum::<usize>(),
        "stored_bytes":snapshot.peers.iter().map(|peer|peer.stored_bytes).sum::<usize>(),
        "accounting_exclusions":"expanded keys/trees, owner inspector rows, allocator/containers are included only in process memory",
        "memory":memory_json()?})
    );
    Ok(engine)
}
fn check(
    engine: &LabEngine,
    before: &[PlainRow],
    before_revision: u64,
    sql: &str,
    answer: QueryOutcome,
) -> Result<(usize, bool), Box<dyn std::error::Error>> {
    // Deliberately called only after the full execute timer stops.
    let after = engine.snapshot().ok_or("missing database")?;
    let (predicate, delta) = match parse_sql(sql)? {
        QueryPlan::Aggregate { predicate } => (predicate, None),
        QueryPlan::AddAmount { predicate, delta } => (predicate, Some(delta)),
        _ => {
            return Err(
                "this historical workload covers combined aggregates and UPDATE only".into(),
            );
        }
    };
    let count = before.iter().filter(|row| selected(row, predicate)).count();
    match delta {
        None => {
            let sum = before
                .iter()
                .filter(|row| selected(row, predicate))
                .map(|row| u32::from(row.amount))
                .sum::<u32>();
            let QueryOutcome::Aggregate {
                count: actual,
                sum: actual_sum,
                ..
            } = answer
            else {
                panic!("expected aggregate")
            };
            assert_eq!((actual, actual_sum), (count as u32, sum));
            assert_eq!(after.owner_rows, before);
            assert_eq!(after.revision, before_revision);
            Ok((count, false))
        }
        Some(delta) => {
            let overflow = before
                .iter()
                .any(|row| selected(row, predicate) && row.amount.checked_add(delta).is_none());
            let QueryOutcome::Updated { committed } = answer else {
                panic!("expected update")
            };
            assert_eq!(committed, !overflow);
            let expected = before
                .iter()
                .map(|row| PlainRow {
                    age: row.age,
                    amount: if !overflow && selected(row, predicate) {
                        row.amount.checked_add(delta).unwrap()
                    } else {
                        row.amount
                    },
                })
                .collect::<Vec<_>>();
            assert_eq!(after.owner_rows, expected);
            assert_eq!(after.revision, before_revision + u64::from(!overflow));
            Ok((count, overflow))
        }
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    let rounds = args
        .get(1)
        .map(String::as_str)
        .unwrap_or("3")
        .parse::<usize>()?;
    if !(1..=5).contains(&rounds) {
        return Err("rounds must be1..=5".into());
    }
    rayon::ThreadPoolBuilder::new()
        .num_threads(8)
        .build_global()?;
    let fixture = (0..128)
        .map(|index| PlainRow {
            age: if index == 0 {
                42
            } else if index <= 4 {
                18
            } else {
                (index % 17) as u8
            },
            amount: (index * 7 + 3) as u16,
        })
        .collect::<Vec<_>>();
    println!(
        "{}",
        json!({"kind":"contract","backend":"BFV exact authenticated index","geometry":256,"threads":8,"rounds":rounds,"case_count":CASES.len(),"peer_counts":[1,3,16],"rows":128,"proof":"Unavailable","network_rtt_ms":0,"access":"visible","timer":"LabEngine::execute including SQL parse, authenticated complete selection/age checks, fresh encryption, request/response serialization and evaluation, owner completion/local update oracle, staged all-shard publication; fixture oracle and memory sampling after timer"})
    );
    for peers in [1, 3, 16] {
        let mut engine = create(&fixture, peers)?;
        for round in 0..rounds {
            for (name, sql) in CASES {
                let before = engine.snapshot().unwrap();
                let timer = Instant::now();
                let answer = engine.execute(sql)?;
                let elapsed_ms = timer.elapsed().as_secs_f64() * 1000.0;
                let (selected_rows, overflow) =
                    check(&engine, &before.owner_rows, before.revision, sql, answer)?;
                let after = engine.snapshot().unwrap();
                assert_eq!(
                    after
                        .peers
                        .iter()
                        .map(|peer| peer.stored_bytes)
                        .collect::<Vec<_>>(),
                    before
                        .peers
                        .iter()
                        .map(|peer| peer.stored_bytes)
                        .collect::<Vec<_>>()
                );
                println!(
                    "{}",
                    json!({"kind":"query","peers":peers,"round":round,"case":name,"sql":sql,"elapsed_ms":elapsed_ms,"selected_rows":selected_rows,"overflow_rejected":overflow,"oracle_exact":true,"stable_image_sizes":true,"revision":after.revision,"memory":memory_json()?})
                );
            }
        }
        // A late selected slot/shard must abort earlier staged successful shard writes.
        drop(engine);
        let mut overflow = fixture.clone();
        overflow[127].amount = u16::MAX;
        let mut engine = create(&overflow, peers)?;
        let before = engine.snapshot().unwrap();
        let before_heads = engine.peer_heads_for_experiment()?;
        let sql = "UPDATE records SET amount = amount + 1";
        let timer = Instant::now();
        let answer = engine.execute(sql)?;
        let elapsed_ms = timer.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(
            check(&engine, &before.owner_rows, before.revision, sql, answer)?,
            (128, true)
        );
        let after = engine.snapshot().unwrap();
        assert_eq!(engine.peer_heads_for_experiment()?, before_heads);
        assert_eq!(
            after
                .peers
                .iter()
                .map(|peer| peer.stored_bytes)
                .collect::<Vec<_>>(),
            before
                .peers
                .iter()
                .map(|peer| peer.stored_bytes)
                .collect::<Vec<_>>()
        );
        println!(
            "{}",
            json!({"kind":"global_overflow_control","peers":peers,"late_ordinal":127,"elapsed_ms":elapsed_ms,"oracle_exact":true,"heads_unchanged":true,"revision_unchanged":true,"image_sizes_unchanged":true,"memory":memory_json()?})
        );
    }
    Ok(())
}
