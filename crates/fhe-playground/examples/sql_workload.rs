//! Headless SQL/manager benchmark with public synthetic data only.
//! No GUI is opened and no secret/data files are saved.
use fhe_playground::PlainRow;
use fhe_playground::{DatabaseDraft, LabEngine, PeerConfig, QueryOutcome};
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let rows: usize = args.get(1).map(String::as_str).unwrap_or("128").parse()?;
    let threads: usize = args.get(2).map(String::as_str).unwrap_or("8").parse()?;
    let rounds: usize = args.get(3).map(String::as_str).unwrap_or("5").parse()?;
    if !(16..=128).contains(&rows) || !(1..=32).contains(&threads) || !(1..=100).contains(&rounds) {
        return Err("Use 16..128 rows, 1..32 Rayon threads and 1..100 rounds".into());
    }
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()?;
    // One age=42 row, four age=18 rows; other public values vary.
    let fixture: Vec<_> = (0..rows)
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
        .collect();
    let mut engine = LabEngine::default();
    let timer = Instant::now();
    let snapshot = engine.create(DatabaseDraft {
        name: "public-workload".into(),
        rows: fixture.clone(),
        peers: vec![PeerConfig::numbered(1)],
    })?;
    println!(
        "{{\"kind\":\"setup\",\"rows\":{rows},\"threads\":{threads},\"logical_bytes\":{},\"canonical_data_bytes\":{},\"encrypted_index_bytes\":{},\"stored_bytes\":{},\"setup_ms\":{:.4}}}",
        rows * 3,
        snapshot
            .peers
            .iter()
            .map(|peer| peer.data_bytes)
            .sum::<usize>(),
        snapshot
            .peers
            .iter()
            .map(|peer| peer.index_bytes)
            .sum::<usize>(),
        snapshot
            .peers
            .iter()
            .map(|peer| peer.stored_bytes)
            .sum::<usize>(),
        timer.elapsed().as_secs_f64() * 1000.0,
    );
    for (name, sql, selected) in [
        (
            "point",
            "SELECT COUNT(*), SUM(amount) FROM records WHERE age = 42",
            1,
        ),
        (
            "duplicates",
            "SELECT COUNT(*), SUM(amount) FROM records WHERE age = 18",
            4,
        ),
        (
            "absent",
            "SELECT COUNT(*), SUM(amount) FROM records WHERE age = 255",
            0,
        ),
    ] {
        let expected_sum: u32 = fixture
            .iter()
            .filter(|row| match name {
                "point" => row.age == 42,
                "duplicates" => row.age == 18,
                _ => row.age == 255,
            })
            .map(|row| u32::from(row.amount))
            .sum();
        for round in 0..rounds {
            let timer = Instant::now();
            let answer = engine.execute(sql)?;
            let elapsed_ms = timer.elapsed().as_secs_f64() * 1000.0;
            let QueryOutcome::Aggregate { count, sum, .. } = answer else {
                panic!("Expected COUNT/SUM")
            };
            assert_eq!((count, sum), (selected, expected_sum));
            println!(
                "{{\"kind\":\"query\",\"name\":\"{name}\",\"round\":{round},\"selected_rows\":{count},\"elapsed_ms\":{elapsed_ms:.4},\"proof_implemented\":false,\"network_rtt_ms\":0}}"
            );
        }
    }
    let before = engine.snapshot().unwrap();
    let timer = Instant::now();
    let update = engine.execute("UPDATE records SET amount = amount + 1 WHERE age = 42")?;
    let elapsed_ms = timer.elapsed().as_secs_f64() * 1000.0;
    assert!(matches!(update, QueryOutcome::Updated { committed: true }));
    let after = engine.snapshot().unwrap();
    assert_eq!(after.revision, before.revision + 1);
    assert_eq!(after.owner_rows[0].amount, fixture[0].amount + 1);
    assert_eq!(after.owner_rows[1..], fixture[1..]);
    assert_eq!(after.peers[0].stored_bytes, before.peers[0].stored_bytes);
    println!(
        "{{\"kind\":\"update\",\"selected_rows\":1,\"elapsed_ms\":{elapsed_ms:.4},\"before_bytes\":{},\"after_bytes\":{},\"revision\":{}}}",
        before.peers[0].stored_bytes, after.peers[0].stored_bytes, after.revision
    );
    Ok(())
}
