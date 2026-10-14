//! Full owner/peer round trips with public synthetic fixtures and ephemeral keys.
use compact_query::{
    AgeRange, Aggregate, Error, Evaluator, MAX_ROWS, Operation, Owner, PlainRow, PreparedQuery,
    Selection, Table, UnverifiedOutput,
};
use compact_store::Limits;
use serde_json::{Value, json};
use std::io::{self, Write};
use std::time::Instant;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}
fn emit(value: Value) -> Result<()> {
    println!("{value}");
    io::stdout().flush()?;
    Ok(())
}
fn fixture(ordinal: usize) -> PlainRow {
    match ordinal {
        0 => PlainRow {
            age: 250,
            amount: 100,
        },
        1..=4 => PlainRow {
            age: 251,
            amount: 200 + ordinal as u16,
        },
        5..=20 => PlainRow {
            age: 252,
            amount: 300 + ordinal as u16,
        },
        _ => PlainRow {
            age: ((ordinal * 73 + 11) % 200) as u8,
            amount: ((ordinal * 137 + 29) % 65536) as u16,
        },
    }
}
struct Trial {
    query: PreparedQuery,
    output: UnverifiedOutput,
    aggregate: Aggregate,
    record: Value,
}
fn trial(
    owner: &Owner,
    evaluator: &Evaluator,
    table: &Table,
    range: AgeRange,
    operation: Operation,
    kind: &str,
    round: usize,
) -> Result<Trial> {
    let full = Instant::now();
    let mut query = owner.prepare(
        table,
        Selection::IndexedAgeRange(range),
        range,
        operation,
        MAX_ROWS,
        Limits::default(),
    )?;
    let request = query.encode_request()?;
    let mut output = evaluator.evaluate(table.snapshot(), &request, Limits::default())?;
    let peer_stages = output.stages().clone();
    let timer = Instant::now();
    let wire = output.encode()?;
    let output_serialize_ms = ms(timer);
    let timer = Instant::now();
    let output = UnverifiedOutput::decode(&wire)?;
    let output_decode_ms = ms(timer);
    let timer = Instant::now();
    let aggregate = owner.decrypt_aggregate_for_experiment(table, &query, &output)?;
    let owner_decrypt_ms = ms(timer);
    let total_ms = ms(full);
    let record = json!({"kind":kind,"round":round,"selected_rows":query.selected_rows(),
        "range":[range.lower,range.upper],"full_round_trip_ms":total_ms,
        "owner_stages":query.stages(),"peer_stages":peer_stages,
        "output_bytes":wire.len(),"output_serialize_ms":output_serialize_ms,
        "owner_output_decode_ms":output_decode_ms,"owner_result_decrypt_ms":owner_decrypt_ms,
        "count":aggregate.count,"sum":aggregate.sum,
        "query_proof_implemented":false});
    Ok(Trial {
        query,
        output,
        aggregate,
        record,
    })
}
fn nearest(values: &[f64], q: f64) -> f64 {
    let mut values = values.to_vec();
    values.sort_by(f64::total_cmp);
    values[((values.len() as f64 * q).ceil() as usize).saturating_sub(1)]
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let rows = args.first().map_or(Ok(1_000_000usize), |v| v.parse())?;
    let rounds = args.get(1).map_or(Ok(5usize), |v| v.parse())?;
    let updates = args.get(2).map_or(Ok(100usize), |v| v.parse())?;
    let threads = args.get(3).map_or(Ok(8usize), |v| v.parse())?;
    if !(21..=1_000_000).contains(&rows)
        || !(1..=100).contains(&rounds)
        || !(1..=1000).contains(&updates)
        || !(1..=32).contains(&threads)
    {
        return Err("Use 21..1000000 rows, 1..100 rounds, 1..1000 updates, 1..32 threads".into());
    }
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()?;
    let timer = Instant::now();
    let (owner, evaluator) = Owner::generate([31; 16])?;
    let keygen_ms = ms(timer);
    let timer = Instant::now();
    let public_key = evaluator.encode_evaluation_key_for_experiment()?;
    let public_key_serialize_ms = ms(timer);
    let secret_key_bytes = owner.secret_key_serialized_bytes()?;
    let key_bytes = public_key.len();
    let fixture: Vec<_> = (0..rows).map(fixture).collect();
    let timer = Instant::now();
    let mut table = owner.seal(&fixture, 256, Limits::default())?;
    let seal_and_index_ms = ms(timer);
    let data_bytes = table.canonical_data_bytes();
    let index_bytes = table.encrypted_index_bytes();
    let logical_bytes = rows * 3;
    emit(
        json!({"kind":"setup","rows":rows,"threads":threads,"logical_plaintext_bytes":logical_bytes,
        "canonical_data_bytes":data_bytes,"encrypted_age_index_bytes":index_bytes,
        "rebuildable_hash_bytes":table.rebuildable_hash_bytes(),"data_expansion":data_bytes as f64/logical_bytes as f64,
        "data_and_index_expansion":(data_bytes+index_bytes) as f64/logical_bytes as f64,
        "owner_symmetric_key_and_domain_bytes":64,"trusted_data_and_index_heads_bytes":224,
        "owner_fhe_key_serialized_bytes":secret_key_bytes,"peer_evaluation_key_wire_bytes":key_bytes,
        "joint_persistent_bytes":data_bytes+index_bytes+64+224+secret_key_bytes as usize+key_bytes,
        "persistent_fhe_rows_bytes":0,"persistent_plaintext_or_pads_bytes":0,
        "key_generation_ms":keygen_ms,"evaluation_key_serialization_ms":public_key_serialize_ms,
        "table_seal_and_index_ms":seal_and_index_ms,"query_proof_implemented":false,
        "privacy_policy":"owner-private encrypted age index; visible complete candidate count and addresses",
        "index_table_binding":"encrypted exact data commitment; owner-held independent trusted index head",
        "canonical_tables":1,"replicas":1}),
    )?;
    drop(evaluator);
    let cold = Instant::now();
    let timer = Instant::now();
    let evaluator = Evaluator::restore_evaluation_key_for_experiment(&public_key)?;
    let key_restore_ms = ms(timer);
    drop(public_key);
    let timer = Instant::now();
    table = owner.restore_table_for_experiment(
        &table.snapshot().encode(),
        &table.encrypted_index().encode(),
        table.commitment(),
        table.index_commitment(),
        Limits::default(),
    )?;
    let image_roundtrip_ms = ms(timer);
    let first = trial(
        &owner,
        &evaluator,
        &table,
        AgeRange::equal(250),
        Operation::CountSum,
        "cold_query",
        0,
    )?;
    assert_eq!(first.aggregate, Aggregate { count: 1, sum: 100 });
    emit(
        json!({"kind":"cold_in_memory","evaluation_key_restore_ms":key_restore_ms,
        "data_index_encode_decode_rebuild_ms":image_roundtrip_ms,"full_cold_ms":ms(cold),"query":first.record,
        "cold_disk_io":false}),
    )?;
    for (age, selected, expected_sum) in
        [(250, 1, 100), (251, 4, 810), (252, 16, 5000), (255, 0, 0)]
    {
        let range = AgeRange::equal(age);
        let mut totals = Vec::new();
        for round in 0..rounds {
            let result = trial(
                &owner,
                &evaluator,
                &table,
                range,
                Operation::CountSum,
                "aggregate",
                round,
            )?;
            assert_eq!(result.query.selected_rows(), selected);
            assert_eq!(
                result.aggregate,
                Aggregate {
                    count: selected as u32,
                    sum: expected_sum
                }
            );
            totals.push(result.record["full_round_trip_ms"].as_f64().unwrap());
            emit(result.record)?;
        }
        emit(
            json!({"kind":"aggregate_summary","selected_rows":selected,"samples":rounds,
            "p50_ms":nearest(&totals,0.5),"p95_ms":nearest(&totals,0.95),"p99_ms":nearest(&totals,0.99),
            "maximum_ms":nearest(&totals,1.0)}),
        )?;
    }
    // Range index and narrower encrypted predicate are both exercised on 21 rows.
    let range = AgeRange {
        lower: 250,
        upper: 252,
    };
    let range_trial = trial(
        &owner,
        &evaluator,
        &table,
        range,
        Operation::CountSum,
        "range",
        0,
    )?;
    assert_eq!(
        range_trial.aggregate,
        Aggregate {
            count: 21,
            sum: 5910
        }
    );
    emit(range_trial.record)?;
    let mut update_totals = Vec::new();
    let mut final_image_bytes = 0;
    for round in 0..updates {
        let full = Instant::now();
        let result = trial(
            &owner,
            &evaluator,
            &table,
            AgeRange::equal(250),
            Operation::AddAmount(1),
            "update",
            round,
        )?;
        assert_eq!(
            result.aggregate,
            Aggregate {
                count: 1,
                sum: 100 + round as u32
            }
        );
        let timer = Instant::now();
        let applied = owner.apply_update_for_experiment(
            &mut table,
            &result.query,
            &result.output,
            Limits::default(),
        )?;
        let owner_verify_stage_writeback_ms = ms(timer);
        assert!(!applied.rejected);
        assert_eq!(applied.changed_rows, 1);
        let timer = Instant::now();
        let data_wire = table.snapshot().encode();
        let index_wire = table.encrypted_index().encode();
        final_image_bytes = data_wire.len() + index_wire.len();
        table = owner.restore_table_for_experiment(
            &data_wire,
            &index_wire,
            table.commitment(),
            table.index_commitment(),
            Limits::default(),
        )?;
        let fresh_image_encode_decode_rebuild_ms = ms(timer);
        assert_eq!(
            (table.canonical_data_bytes(), table.encrypted_index_bytes()),
            (data_bytes, index_bytes)
        );
        assert_eq!(
            owner
                .decrypt_row_for_experiment(&table, 0, Limits::default())?
                .amount,
            101 + round as u16
        );
        assert!(matches!(
            owner.decrypt_aggregate_for_experiment(&table, &result.query, &result.output),
            Err(Error::WrongVersion)
        ));
        let total = ms(full);
        update_totals.push(total);
        let mut record = result.record;
        record["full_update_including_writeback_and_fresh_decode_ms"] = json!(total);
        record["owner_local_verify_stage_writeback_ms"] = json!(owner_verify_stage_writeback_ms);
        record["fresh_image_encode_decode_rebuild_ms"] =
            json!(fresh_image_encode_decode_rebuild_ms);
        record["stale_output_rejected"] = json!(true);
        emit(record)?;
    }
    // A genuine multi-row UPDATE is included, rather than extrapolated from one row.
    let full = Instant::now();
    let result = trial(
        &owner,
        &evaluator,
        &table,
        AgeRange::equal(251),
        Operation::AddAmount(1),
        "multirow_update",
        0,
    )?;
    let applied = owner.apply_update_for_experiment(
        &mut table,
        &result.query,
        &result.output,
        Limits::default(),
    )?;
    assert_eq!(applied.changed_rows, 4);
    assert!(!applied.rejected);
    let mut record = result.record;
    record["full_update_including_writeback_ms"] = json!(ms(full));
    emit(record)?;
    emit(
        json!({"kind":"update_summary","updates":updates,"selected_rows":1,
        "p50_ms":nearest(&update_totals,0.5),"p95_ms":nearest(&update_totals,0.95),
        "p99_ms":nearest(&update_totals,0.99),"maximum_ms":nearest(&update_totals,1.0),
        "initial_data_and_index_bytes":data_bytes+index_bytes,"final_data_and_index_bytes":final_image_bytes,
        "final_revision":table.commitment().revision(),"every_iteration_fresh_decode":true,
        "every_stale_output_rejected":true,"query_proof_implemented":false}),
    )?;
    Ok(())
}
