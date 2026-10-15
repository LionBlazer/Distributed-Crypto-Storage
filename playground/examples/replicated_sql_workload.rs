//! Finite public-fixture SQL workload over actual ciphertext replicas. No GUI.
//! Timers include the local owner/peer operation; virtual/WAN delivery is absent.
#[path = "support/bfv_memory.rs"]
mod memory;

use fhe_playground::{DatabaseDraft, LabEngine, PeerConfig, QueryOutcome, sample_rows};
use serde_json::json;
use std::time::Instant;

const ALL: &str = "SELECT COUNT(*), SUM(amount) FROM records";

fn memory_json() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let value = memory::guard(0)?;
    Ok(json!({
        "working_set_bytes": value.working_set_bytes,
        "peak_working_set_bytes": value.peak_working_set_bytes,
        "private_commit_bytes": value.private_commit_bytes,
        "peak_private_commit_bytes": value.peak_commit_bytes,
    }))
}

fn read(
    engine: &mut LabEngine,
    name: &str,
    expected: (u32, u32),
) -> Result<f64, Box<dyn std::error::Error>> {
    let start = Instant::now();
    let result = engine.execute(ALL)?;
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    let QueryOutcome::Aggregate { count, sum, peers } = result else {
        return Err("expected a BFV aggregate".into());
    };
    // Public oracle is evaluated outside the operation timer.
    assert_eq!((count, sum), expected, "{name}");
    let snapshot = engine.snapshot().ok_or("missing database")?;
    println!(
        "{}",
        json!({
            "stage": name, "elapsed_ms": elapsed_ms, "count": count, "sum": sum,
            "evaluated_shards": peers.len(),
            "executors": peers.iter().map(|peer| peer.id).collect::<Vec<_>>(),
            "physical_data_bytes": snapshot.peers.iter().map(|peer| peer.data_bytes).sum::<usize>(),
            "physical_index_bytes": snapshot.peers.iter().map(|peer| peer.index_bytes).sum::<usize>(),
            "physical_stored_bytes": snapshot.peers.iter().map(|peer| peer.stored_bytes).sum::<usize>(),
            "proof_status": "unverified", "memory": memory_json()?,
        })
    );
    Ok(elapsed_ms)
}

fn repair(engine: &mut LabEngine, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let revision = engine.snapshot().ok_or("missing database")?.revision;
    let start = Instant::now();
    engine.repair_replicas()?;
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(
        engine.snapshot().ok_or("missing database")?.revision,
        revision
    );
    println!(
        "{}",
        json!({"stage": name, "elapsed_ms": elapsed_ms, "memory": memory_json()?})
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let peer_count: usize = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "3".into())
        .parse()?;
    if !(3..=16).contains(&peer_count) {
        return Err("expected 3..=16 peers".into());
    }
    memory::guard(200_000_000)?;
    let rows = sample_rows(128)?;
    let expected = (
        rows.len() as u32,
        rows.iter().map(|row| u32::from(row.amount)).sum(),
    );
    let expected_after = (
        expected.0,
        rows.iter()
            .map(|row| u32::from(row.amount) + if row.age >= 18 { 5 } else { 0 })
            .sum(),
    );
    let mut engine = LabEngine::default();
    let start = Instant::now();
    engine.create(DatabaseDraft {
        name: "public-replicated-workload".into(),
        rows,
        peers: (1..=peer_count).map(PeerConfig::numbered).collect(),
    })?;
    println!(
        "{}",
        json!({"stage": "setup", "peers": peer_count,
        "logical_bytes": 128 * 3, "elapsed_ms": start.elapsed().as_secs_f64() * 1000.0,
        "memory": memory_json()?})
    );

    engine.set_replication(2)?;
    repair(&mut engine, "initial_local_repair")?;
    let mut timings = vec![read(&mut engine, "replicated_read", expected)?];
    engine.set_peer_online(1, false)?;
    timings.push(read(&mut engine, "read_with_peer_offline", expected)?);

    let start = Instant::now();
    let outcome = engine.execute("UPDATE records SET amount = amount + 5 WHERE age >= 18")?;
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    assert!(matches!(outcome, QueryOutcome::Updated { committed: true }));
    timings.push(elapsed_ms);
    println!(
        "{}",
        json!({"stage": "update_with_peer_offline", "elapsed_ms": elapsed_ms,
        "memory": memory_json()?, "proof_status": "owner_locally_checked"})
    );
    timings.push(read(&mut engine, "read_updated_survivors", expected_after)?);
    engine.set_peer_online(1, true)?;
    timings.push(read(
        &mut engine,
        "returned_peer_stale_copies_are_excluded",
        expected_after,
    )?);
    repair(&mut engine, "refresh_returned_peer")?;
    timings.push(read(&mut engine, "read_after_repair", expected_after)?);
    println!(
        "{}",
        json!({"stage": "summary", "operations": timings.len(),
        "maximum_local_sql_ms": timings.into_iter().fold(0.0_f64, f64::max),
        "transport": "excluded", "memory": memory_json()?})
    );
    Ok(())
}
