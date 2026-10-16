//! Actual encrypted data/index sizes for public million-row fixtures.
//! No query evaluation, key/data files, or latency claim is made here.
use compact_query::{MAX_TABLE_ROWS, Owner, PlainRow};
use compact_store::Limits;
use serde_json::json;
use std::time::Instant;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let rows: usize = args.first().map_or(Ok(1_000_000), |value| value.parse())?;
    if args.len() > 1 || !(1..=MAX_TABLE_ROWS).contains(&rows) {
        return Err("Use index_storage [rows], with rows in 1..1000000".into());
    }
    rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build_global()?;
    let started = Instant::now();
    let (owner, evaluator) = Owner::generate([81; 16])?;
    let owner_fhe_key_bytes = owner.secret_key_serialized_bytes()?;
    let peer_fhe_key_bytes = evaluator.encode_evaluation_key_for_experiment()?.len();
    let key_generation_and_size_ms = started.elapsed().as_secs_f64() * 1000.0;
    println!(
        "{}",
        json!({
            "kind":"index_storage_setup", "rows":rows, "tfhe_version":"1.8.1",
            "owner_fhe_key_serialized_bytes":owner_fhe_key_bytes,
            "peer_evaluation_key_serialized_bytes":peer_fhe_key_bytes,
            "owner_symmetric_key_database_and_domains_bytes":80,
            "trusted_data_and_index_heads_bytes_per_table":224,
            "key_generation_and_size_ms":key_generation_and_size_ms,
            "query_executed":false, "computation_proof_implemented":false,
        })
    );
    for pattern in ["uniform", "skew", "random", "one_age"] {
        let mut random = 0x4271_caf0_99bd_3721_u64;
        let fixture: Vec<_> = (0..rows)
            .map(|ordinal| {
                random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
                let age = match pattern {
                    "uniform" => ordinal as u8,
                    "skew" if ordinal % 10 != 0 => 42,
                    "skew" => (ordinal / 10) as u8,
                    "random" => (random >> 32) as u8,
                    _ => 42,
                };
                PlainRow {
                    age,
                    amount: ((ordinal * 137 + 29) % 65536) as u16,
                }
            })
            .collect();
        let started = Instant::now();
        let table = owner.seal(&fixture, 256, Limits::default())?;
        let seal_and_index_ms = started.elapsed().as_secs_f64() * 1000.0;
        drop(fixture);
        let logical_bytes = rows * 3;
        let data_bytes = table.canonical_data_bytes();
        let index_bytes = table.encrypted_index_bytes();
        let combined_bytes = data_bytes + index_bytes;
        let joint_with_keys =
            combined_bytes as u64 + owner_fhe_key_bytes + peer_fhe_key_bytes as u64 + 80 + 224;
        let data_head = table.commitment().clone();
        let index_head = table.index_commitment().clone();
        let encoded_data = table.snapshot().encode();
        let encoded_index = table.encrypted_index().encode();
        let restored = owner.restore_table_for_experiment(
            &encoded_data,
            &encoded_index,
            table.table_id(),
            &data_head,
            &index_head,
            Limits::default(),
        )?;
        assert_eq!(restored.commitment(), &data_head);
        assert_eq!(restored.index_commitment(), &index_head);
        assert_eq!(restored.canonical_data_bytes(), data_bytes);
        assert_eq!(restored.encrypted_index_bytes(), index_bytes);
        println!(
            "{}",
            json!({
                "kind":"index_storage", "distribution":pattern, "rows":rows,
                "logical_plaintext_bytes":logical_bytes,
                "canonical_data_bytes":data_bytes, "encrypted_age_index_bytes":index_bytes,
                "encrypted_index_plaintext_bytes":index_head.layout().row_count,
                "canonical_data_and_index_bytes":combined_bytes,
                "data_and_index_expansion":combined_bytes as f64 / logical_bytes as f64,
                "owner_fhe_key_serialized_bytes":owner_fhe_key_bytes,
                "peer_evaluation_key_serialized_bytes":peer_fhe_key_bytes,
                "joint_persistent_bytes_including_keys_and_owner_state":joint_with_keys,
                "joint_expansion_including_keys_and_owner_state":joint_with_keys as f64 / logical_bytes as f64,
                "rebuildable_hash_payload_bytes":table.rebuildable_hash_bytes(),
                "canonical_plus_rebuildable_hash_payload_bytes":combined_bytes + table.rebuildable_hash_bytes(),
                "persistent_fhe_rows_bytes":0, "replicas":1, "restart_exact_heads_passed":true,
                "table_seal_and_index_ms":seal_and_index_ms,
                "query_executed":false, "computation_proof_implemented":false,
            })
        );
    }
    Ok(())
}
