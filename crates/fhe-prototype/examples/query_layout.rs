//! Compare two real encrypted scans; this does not change the production evaluator.
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
    ClientKey, ConfigBuilder, FheUint8, FheUint12, FheUint16, FheUint32, generate_keys,
    set_server_key,
};

#[derive(Serialize)]
struct Measurement {
    threads: usize,
    rows: usize,
    round: usize,
    optimized: bool,
    query_and_decrypt_ms: f64,
    process_peak_resident_bytes: Option<u64>,
    count: u32,
    sum: u32,
}

fn scan(
    rows: &[(FheUint8, FheUint16)],
    threshold: &FheUint8,
    optimized: bool,
    key: &ClientKey,
) -> (u32, u32) {
    let zero32 = FheUint32::encrypt_trivial(0u32);
    let (count, sum) = if optimized {
        let zero16 = FheUint16::encrypt_trivial(0u16);
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
    set_server_key(server_key);
    let threshold = FheUint8::encrypt(18u8, &key);
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
            let order = if round % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            };
            for optimized in order {
                let timer = Instant::now();
                let actual = scan(&encrypted, &threshold, optimized, &key);
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
                        query_and_decrypt_ms,
                        process_peak_resident_bytes: metrics::peak_resident_bytes(),
                        count: actual.0,
                        sum: actual.1,
                    })?
                );
            }
        }
    }
    Ok(())
}
