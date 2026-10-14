//! Actual independent encrypted tables amortizing one shared key authority.
//! Public synthetic data only; table routing is supplied, not discovered by SQL.
#[path = "support/key_amortization_memory.rs"]
mod memory;

use compact_query::{
    AgeRange, Aggregate, Error, MAX_ROWS, Operation, Owner, PlainRow, Selection, Table,
    UnverifiedOutput,
};
use compact_store::Limits;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io::{self, Write};
use std::time::Instant;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const SHARED_OWNER_STATE_BYTES: u64 = 80;
const TABLE_RESERVE: u64 = 64 * 1024 * 1024;
const MAX_TABLES: usize = 210;

fn ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}
fn emit(value: Value) -> Result<()> {
    println!("{value}");
    io::stdout().flush()?;
    Ok(())
}
fn fixture(table: usize, ordinal: usize, rows: usize) -> PlainRow {
    if ordinal == (table * 4729 + 17) % rows {
        PlainRow {
            age: 250,
            amount: ((table * 997 + 101) % 65536) as u16,
        }
    } else {
        PlainRow {
            age: ((ordinal * 73 + table * 17 + 11) % 200) as u8,
            amount: ((ordinal * 137 + table * 997 + 29) % 65536) as u16,
        }
    }
}
#[derive(Default)]
struct Accounting {
    data: u64,
    index: u64,
    hashes: u64,
    heads: u64,
}
impl Accounting {
    fn canonical(&self, shared_keys: u64) -> u64 {
        self.data + self.index + self.heads + shared_keys + SHARED_OWNER_STATE_BYTES
    }
}
fn projected_private_commit(current: memory::Memory, held: &Accounting, count: usize) -> u64 {
    // An explicit planning estimate only. Runtime guards and the wrapper's job
    // limit, not this estimate, enforce the actual bounded run.
    let per_table = (held.data + held.index + held.hashes) / count as u64;
    current.private_commit_bytes
        + (MAX_TABLES - count) as u64 * (per_table + 128 * 1024) * 120 / 100
        + TABLE_RESERVE
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let count = args.first().map_or(Ok(2usize), |v| v.parse())?;
    let rows = args.get(1).map_or(Ok(1_000_000usize), |v| v.parse())?;
    let rows_per_page = args.get(2).map_or(Ok(2048u32), |v| v.parse())?;
    let samples = args.get(3).map_or(Ok(3usize), |v| v.parse())?;
    if !(2..=MAX_TABLES).contains(&count)
        || !(21..=1_000_000).contains(&rows)
        || rows_per_page != 2048
        || !(1..=5).contains(&samples)
    {
        return Err(
            "Use 2..210 tables, 21..1000000 rows, exactly2048 rows/page, 1..5 samples".into(),
        );
    }
    rayon::ThreadPoolBuilder::new()
        .num_threads(8)
        .build_global()?;
    memory::guard(256 * 1024 * 1024)?;
    let start = Instant::now();
    let (owner, evaluator) = Owner::generate(*b"PUBLIC-KEY-AMORT")?;
    let evaluator = evaluator.with_row_workers_for_experiment(8)?;
    let key_generation_ms = ms(start);
    memory::guard(256 * 1024 * 1024)?;
    let start = Instant::now();
    let key_wire = evaluator.encode_evaluation_key_for_experiment()?;
    let public_key_wire_bytes = key_wire.len() as u64;
    let public_key_serialize_ms = ms(start);
    let secret_key_serialized_bytes = owner.secret_key_serialized_bytes()?;
    drop(key_wire);
    let shared_keys = public_key_wire_bytes + secret_key_serialized_bytes;
    emit(
        json!({"kind":"setup", "requested_tables":count, "rows_per_table":rows,
        "rows_per_data_page":rows_per_page, "rayon_threads":8, "row_workers":8,
        "owner_authorities":1, "evaluation_key_sets":1,
        "evaluation_key_wire_bytes":public_key_wire_bytes,
        "owner_fhe_secret_key_serialized_bytes":secret_key_serialized_bytes,
        "owner_state_bytes":SHARED_OWNER_STATE_BYTES,
        "key_generation_ms":key_generation_ms, "public_key_serialize_ms":public_key_serialize_ms,
        "native_memory":memory::guard(0)?, "replicas":1,
        "fixture":"independently varied public rows; sequential fixture allocation/drop",
        "query_proof_implemented":false, "network_measured":false, "durable_io_measured":false}),
    )?;

    let mut tables: Vec<Table> = Vec::with_capacity(count);
    let mut data_roots = BTreeSet::new();
    let mut index_roots = BTreeSet::new();
    let mut held = Accounting::default();
    let all_seals = Instant::now();
    for table_id in 0..count {
        memory::guard(TABLE_RESERVE)?;
        let start = Instant::now();
        let fixture: Vec<_> = (0..rows).map(|i| fixture(table_id, i, rows)).collect();
        let fixture_capacity_bytes = fixture.capacity() * std::mem::size_of::<PlainRow>();
        let table = owner.seal(&fixture, rows_per_page, Limits::default())?;
        drop(fixture);
        // Count actual distinct images, serializing one image at a time and
        // immediately dropping the transient wire rather than retaining copies.
        let data_len = table.snapshot().encode().len();
        let index_len = table.encrypted_index().encode().len();
        assert_eq!(data_len, table.canonical_data_bytes());
        assert_eq!(index_len, table.encrypted_index_bytes());
        assert!(
            data_roots.insert(table.commitment().root()),
            "Duplicate data root"
        );
        assert!(
            index_roots.insert(table.index_commitment().root()),
            "Duplicate index root"
        );
        held.data += data_len as u64;
        held.index += index_len as u64;
        held.hashes += table.rebuildable_hash_bytes() as u64;
        held.heads +=
            (table.commitment().encode().len() + table.index_commitment().encode().len()) as u64;
        let seal_encode_ms = ms(start);
        tables.push(table);
        let current = memory::guard(0)?;
        if tables.len() <= 2 || tables.len().is_multiple_of(25) || tables.len() == count {
            emit(json!({"kind":"sealed", "actual_tables":tables.len(),
                "latest_seal_and_image_encode_ms":seal_encode_ms,
                "canonical_data_bytes":held.data, "encrypted_index_bytes":held.index,
                "trusted_head_bytes":held.heads, "rebuildable_hash_bytes":held.hashes,
                "fixture_allocation_bytes":fixture_capacity_bytes,
                "all_fixture_vectors_dropped":true, "distinct_data_and_index_roots":true,
                "native_memory":current}))?;
        }
        if tables.len() == 2 {
            let projected = projected_private_commit(current, &held, 2);
            emit(json!({"kind":"planning_estimate_only", "measured_tables":2,
                "projected_tables":MAX_TABLES, "projected_private_commit_bytes":projected,
                "private_commit_limit_bytes":memory::PRIVATE_LIMIT,
                "safety_model":"current private commit + remaining measured canonical/hash payload +128KiB/table, 20% margin,64MiB scratch",
                "projection_is_actual_measurement":false,
                "projection_below_limit":projected < memory::PRIVATE_LIMIT}))?;
            if count > 2 && projected >= memory::PRIVATE_LIMIT {
                return Err("Two-table projection rejects larger run before table3".into());
            }
        }
    }
    let seal_all_ms = ms(all_seals);
    assert_eq!(data_roots.len(), count);
    assert_eq!(index_roots.len(), count);
    let logical_bytes = count as u64 * rows as u64 * 3;
    let canonical = held.canonical(shared_keys);
    emit(
        json!({"kind":"actual_accounting", "actual_retained_tables":tables.len(),
        "actual_retained_rows":count as u64 * rows as u64,
        "logical_plaintext_bytes":logical_bytes,
        "canonical_data_bytes":held.data, "encrypted_index_bytes":held.index,
        "trusted_data_and_index_head_bytes":held.heads,
        "evaluation_key_wire_bytes":public_key_wire_bytes,
        "owner_fhe_secret_key_serialized_bytes":secret_key_serialized_bytes,
        "owner_state_bytes":SHARED_OWNER_STATE_BYTES,
        "joint_canonical_bytes":canonical, "joint_canonical_expansion":canonical as f64/logical_bytes as f64,
        "rebuildable_hash_bytes":held.hashes,
        "joint_with_hashes_bytes":canonical+held.hashes,
        "joint_with_hashes_expansion":(canonical+held.hashes) as f64/logical_bytes as f64,
        "table_seal_and_encode_total_ms":seal_all_ms,
        "actual_distinct_root_pairs":data_roots.len(),
        "canonical_tables_are_clones":false, "replicas":1,
        "fixture_retained_during_queries":false,
        "persistent_fhe_rows_or_pads_bytes":0,
        "native_memory":memory::guard(0)?}),
    )?;

    // Routing is supplied by this public experiment, not searched or hidden.
    let targets = BTreeSet::from([0, count / 2, count - 1]);
    for table_id in targets {
        for sample in 0..samples {
            memory::guard(TABLE_RESERVE)?;
            let table = &tables[table_id];
            let start = Instant::now();
            let range = AgeRange::equal(250);
            let mut query = owner.prepare(
                table,
                Selection::IndexedAgeRange(range),
                range,
                Operation::CountSum,
                MAX_ROWS,
                Limits::default(),
            )?;
            let request = query.encode_request()?;
            let mut output = evaluator.evaluate(table.snapshot(), &request, Limits::default())?;
            let wire = output.encode()?;
            let peer_stages = output.stages().clone();
            let decode_started = Instant::now();
            let output = UnverifiedOutput::decode(&wire)?;
            let owner_decode_ms = ms(decode_started);
            let decrypt_started = Instant::now();
            let result = owner.decrypt_aggregate_for_experiment(table, &query, &output)?;
            let owner_decrypt_ms = ms(decrypt_started);
            let total_ms = ms(start);
            // Reconstruct the public fixture oracle only AFTER the timed FHE flow.
            let expected = (0..rows)
                .map(|i| fixture(table_id, i, rows))
                .filter(|row| row.age == 250)
                .fold(Aggregate { count: 0, sum: 0 }, |mut a, row| {
                    a.count += 1;
                    a.sum += u32::from(row.amount);
                    a
                });
            assert_eq!(query.selected_rows(), 1);
            assert_eq!(result, expected);
            let wrong_table = &tables[(table_id + 1) % count];
            assert_eq!(
                owner.decrypt_aggregate_for_experiment(wrong_table, &query, &output),
                Err(Error::WrongVersion)
            );
            let page_bytes = query.stages().owner_index_response_bytes
                + query.stages().owner_data_response_bytes
                + peer_stages.page_response_bytes;
            emit(
                json!({"kind":"query", "supplied_table_id":table_id, "sample":sample,
                "full_owner_to_owner_ms":total_ms, "owner_stages":query.stages(),
                "peer_stages":peer_stages, "owner_output_decode_ms":owner_decode_ms,
                "owner_result_decrypt_ms":owner_decrypt_ms,
                "request_bytes":request.len(), "response_bytes":wire.len(),
                "separate_authenticated_page_bytes":page_bytes,
                "total_counted_query_flow_bytes":request.len()+wire.len()+page_bytes,
                "count":result.count, "sum":result.sum, "public_fixture_exact":true,
                "wrong_table_output_rejected":true, "actual_retained_tables":tables.len(),
                "table_choice_supplied":true, "global_sql_routing_measured":false,
                "native_memory":memory::guard(0)?, "query_proof_implemented":false}),
            )?;
        }
    }
    emit(
        json!({"kind":"complete", "actual_retained_tables":tables.len(),
        "actual_distinct_data_roots":data_roots.len(), "actual_distinct_index_roots":index_roots.len(),
        "all_requested_queries_exact":true, "joint_canonical_bytes":canonical,
        "joint_with_hashes_bytes":canonical+held.hashes,
        "rss_limit_bytes":memory::RSS_LIMIT, "private_commit_limit_bytes":memory::PRIVATE_LIMIT,
        "native_memory":memory::guard(0)?, "query_proof_implemented":false}),
    )?;
    Ok(())
}
