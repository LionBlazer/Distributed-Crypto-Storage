//! Compare the previous and current evaluator kernels on identical encrypted inputs.
#[path = "../src/metrics.rs"]
mod metrics;

use serde::Serialize;
use std::time::Instant;
use tfhe::prelude::*;
use tfhe::shortint::parameters::{
    COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use tfhe::{
    ClientKey, ConfigBuilder, FheUint8, FheUint12, FheUint16, FheUint32, ServerKey, generate_keys,
    set_server_key, with_server_key_as_context,
};

#[derive(Serialize)]
struct UpdateMeasurement {
    threads: usize,
    rows: usize,
    round: usize,
    optimized: bool,
    update_and_status_decrypt_ms: f64,
    process_peak_resident_bytes: Option<u64>,
    rejected: bool,
}

#[derive(Serialize)]
struct Measurement {
    threads: usize,
    rows: usize,
    round: usize,
    optimized: bool,
    parallel_rows: bool,
    query_and_decrypt_ms: f64,
    process_peak_resident_bytes: Option<u64>,
    count: u32,
    sum: u32,
}

fn scan(
    rows: &[(FheUint8, FheUint16)],
    threshold: &FheUint8,
    optimized: bool,
    parallel_rows: bool,
    key: &ClientKey,
    server_key: &ServerKey,
) -> (u32, u32) {
    let zero32 = FheUint32::encrypt_trivial(0u32);
    let (count, sum) = if optimized {
        let zero16 = FheUint16::encrypt_trivial(0u16);
        if parallel_rows {
            // Initiating threads stay outside the Rayon pool: nested TFHE work
            // can steal tasks without replacing a borrowed thread-local key.
            // This experimental variant adds at most `threads` initiating threads.
            let threads = rayon::current_num_threads().min(rows.len()).max(1);
            let chunk_size = rows.len().div_ceil(threads).max(1);
            let contributions: Vec<_> = std::thread::scope(|scope| {
                let handles: Vec<_> = rows
                    .chunks(chunk_size)
                    .map(|chunk| {
                        let zero16 = &zero16;
                        scope.spawn(move || {
                            with_server_key_as_context(server_key.clone(), || {
                                chunk
                                    .iter()
                                    .map(|(age, amount)| {
                                        let bit = age.ge(threshold);
                                        (
                                            FheUint12::cast_from(bit.clone()),
                                            FheUint32::cast_from(bit.if_then_else(amount, zero16)),
                                        )
                                    })
                                    .collect::<Vec<_>>()
                            })
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .flat_map(|handle| handle.join().expect("scan worker panicked"))
                    .collect()
            });
            let (counts, amounts): (Vec<_>, Vec<_>) = contributions.into_iter().unzip();
            let count: FheUint12 = counts.into_iter().sum();
            let sum: FheUint32 = amounts.into_iter().sum();
            (FheUint32::cast_from(count), sum)
        } else {
            let matches: Vec<_> = rows.iter().map(|(age, _)| age.ge(threshold)).collect();
            // At most 1024 rows: 12 bits hold COUNT; 32 bits hold SUM without wraparound.
            let count: FheUint12 = matches
                .iter()
                .map(|bit| FheUint12::cast_from(bit.clone()))
                .sum();
            let sum: FheUint32 = rows
                .iter()
                .zip(&matches)
                .map(|((_, amount), bit)| FheUint32::cast_from(bit.if_then_else(amount, &zero16)))
                .sum();
            (FheUint32::cast_from(count), sum)
        }
    } else {
        let (mut count, mut sum) = (zero32.clone(), zero32.clone());
        for (age, amount) in rows {
            let matches = age.ge(threshold);
            count += FheUint32::if_then_else(&matches, 1u32, 0u32);
            let wide: FheUint32 = amount.clone().cast_into();
            sum += matches.if_then_else(&wide, &zero32);
        }
        (count, sum)
    };
    (count.decrypt(key), sum.decrypt(key))
}

fn update(
    rows: &[(FheUint8, FheUint16)],
    threshold: &FheUint8,
    delta: &FheUint16,
    optimized: bool,
) -> (Vec<FheUint16>, tfhe::FheBool) {
    let mut rejected = tfhe::FheBool::encrypt_trivial(false);
    let candidates: Vec<_> = rows
        .iter()
        .map(|(age, amount)| {
            let matches = age.ge(threshold);
            let (candidate, overflow) = if optimized {
                amount.overflowing_add(delta)
            } else {
                let candidate = amount + delta;
                let overflow = candidate.lt(amount);
                (candidate, overflow)
            };
            rejected |= &matches & overflow;
            (matches, candidate)
        })
        .collect();
    let permitted = !&rejected;
    let amounts = rows
        .iter()
        .zip(candidates)
        .map(|((_, amount), (matches, candidate))| {
            (matches & &permitted).if_then_else(&candidate, amount)
        })
        .collect();
    (amounts, rejected)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let threads: usize = std::env::args().nth(1).unwrap_or("2".into()).parse()?;
    let rounds: usize = std::env::args().nth(2).unwrap_or("3".into()).parse()?;
    if !(1..=32).contains(&threads) || !(1..=10).contains(&rounds) {
        return Err("Use 1..32 threads and 1..10 rounds.".into());
    }
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()?;
    let config =
        ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
            .enable_compression(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
            .build();
    let (key, server_key) = generate_keys(config);
    set_server_key(server_key.clone());
    let threshold = FheUint8::encrypt(18u8, &key);
    let delta = FheUint16::encrypt(5u16, &key);
    for rows in [4, 16] {
        // All input rows are deliberately public benchmark fixtures.
        let fixture: Vec<(u8, u16)> = (0..rows)
            .map(|i| [(17, 10), (18, 20), (42, 30), (7, 40)][i % 4])
            .collect();
        let encrypted: Vec<_> = fixture
            .iter()
            .map(|&(age, amount)| {
                (
                    FheUint8::encrypt(age, &key),
                    FheUint16::encrypt(amount, &key),
                )
            })
            .collect();
        let expected = ((rows / 2) as u32, (rows / 4 * 50) as u32);
        for round in 0..rounds {
            let scan_order = if round % 2 == 0 {
                [(false, false), (true, false), (true, true)]
            } else {
                [(true, true), (true, false), (false, false)]
            };
            for (optimized, parallel_rows) in scan_order {
                let timer = Instant::now();
                let actual = scan(
                    &encrypted,
                    &threshold,
                    optimized,
                    parallel_rows,
                    &key,
                    &server_key,
                );
                let query_and_decrypt_ms = timer.elapsed().as_secs_f64() * 1000.0;
                assert_eq!(
                    actual, expected,
                    "Encrypted scan must match the public fixture"
                );
                println!(
                    "{}",
                    serde_json::to_string(&Measurement {
                        threads,
                        rows,
                        round,
                        optimized,
                        parallel_rows,
                        query_and_decrypt_ms,
                        process_peak_resident_bytes: metrics::peak_resident_bytes(),
                        count: actual.0,
                        sum: actual.1,
                    })?
                );
            }
            let order = if round % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            };
            for optimized in order {
                let timer = Instant::now();
                let (amounts, rejected) = update(&encrypted, &threshold, &delta, optimized);
                let rejected = rejected.decrypt(&key);
                let update_and_status_decrypt_ms = timer.elapsed().as_secs_f64() * 1000.0;
                assert!(!rejected);
                // Verify every resulting amount outside the timed update/status boundary.
                for (amount, &(age, original)) in amounts.iter().zip(&fixture) {
                    let actual: u16 = amount.decrypt(&key);
                    assert_eq!(actual, original + if age >= 18 { 5 } else { 0 });
                }
                println!(
                    "{}",
                    serde_json::to_string(&UpdateMeasurement {
                        threads,
                        rows,
                        round,
                        optimized,
                        update_and_status_decrypt_ms,
                        process_peak_resident_bytes: metrics::peak_resident_bytes(),
                        rejected,
                    })?
                );
            }
        }
    }
    Ok(())
}
