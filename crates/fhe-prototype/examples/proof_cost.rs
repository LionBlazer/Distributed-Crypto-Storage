//! Public-fixture operation accounting, not a proof implementation or SQL benchmark.
//! No key, ciphertext, database, or generated report files are written.

use std::error::Error;
use std::time::Instant;

use serde_json::json;
use tfhe::prelude::*;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use tfhe::{
    ClientKey, ConfigBuilder, FheBool, FheUint8, FheUint16, FheUint128, generate_keys,
    get_pbs_count, reset_pbs_count, set_server_key,
};

#[path = "../src/metrics.rs"]
mod metrics;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Clone, Copy)]
struct Fixture {
    name: &'static str,
    age: u8,
    amount: u16,
    threshold: u8,
    delta: u16,
    expected_count: u8,
    expected_sum: u16,
    expected_amount: u16,
    expected_rejected: bool,
}

fn measure<T>(fixture: &str, operation: &str, run: impl FnOnce() -> T) -> T {
    reset_pbs_count();
    let started = Instant::now();
    let result = run();
    let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
    let pbs_count = get_pbs_count();
    println!(
        "{}",
        json!({
            "record": "peer_operation",
            "fixture": fixture,
            "operation": operation,
            "pbs_count": pbs_count,
            "elapsed_ms": elapsed_ms,
            "proof_generated": false,
        })
    );
    result
}

fn restore(
    masked_age: u8,
    masked_amount: u16,
    age_mask: &FheUint8,
    amount_mask: &FheUint16,
) -> (FheUint8, FheUint16) {
    (age_mask ^ masked_age, amount_mask ^ masked_amount)
}

fn selected_aggregate(matches: &FheBool, amount: &FheUint16) -> (FheUint8, FheUint16) {
    (
        FheUint8::cast_from(matches.clone()),
        matches.if_then_else(amount, &FheUint16::encrypt_trivial(0_u16)),
    )
}

fn selected_update(
    matches: &FheBool,
    amount: &FheUint16,
    delta: &FheUint16,
) -> (FheUint16, FheBool) {
    let (candidate, overflow) = amount.overflowing_add(delta);
    let rejected = matches & overflow;
    let apply = matches & !&rejected;
    (apply.if_then_else(&candidate, amount), rejected)
}

fn check_fixture(fixture: Fixture, key: &ClientKey) -> Result<()> {
    // Deliberately public masks for reproducible operation accounting. Never use
    // these constants for private storage; this executable is only a public fixture.
    let age_pad = 0xa5_u8;
    let amount_pad = 0x5aa5_u16;
    let masked_age = fixture.age ^ age_pad;
    let masked_amount = fixture.amount ^ amount_pad;
    let age_mask = FheUint8::encrypt(age_pad, key);
    let amount_mask = FheUint16::encrypt(amount_pad, key);
    let threshold = FheUint8::encrypt(fixture.threshold, key);
    let delta = FheUint16::encrypt(fixture.delta, key);

    let (age, amount) = measure(fixture.name, "scalar_compact_to_fhe", || {
        restore(masked_age, masked_amount, &age_mask, &amount_mask)
    });
    let actual_age: u8 = age.decrypt(key);
    assert_eq!(actual_age, fixture.age);
    let actual_amount: u16 = amount.decrypt(key);
    assert_eq!(actual_amount, fixture.amount);

    let matches = measure(fixture.name, "uint8_ge", || age.ge(&threshold));
    let (count, sum) = measure(fixture.name, "selected_count_sum_after_predicate", || {
        selected_aggregate(&matches, &amount)
    });
    let actual_count: u8 = count.decrypt(key);
    assert_eq!(actual_count, fixture.expected_count);
    let actual_sum: u16 = sum.decrypt(key);
    assert_eq!(actual_sum, fixture.expected_sum);

    let (next_amount, rejected) = measure(fixture.name, "uint16_update_after_predicate", || {
        selected_update(&matches, &amount, &delta)
    });
    let actual_next_amount: u16 = next_amount.decrypt(key);
    assert_eq!(actual_next_amount, fixture.expected_amount);
    assert_eq!(rejected.decrypt(key), fixture.expected_rejected);

    let (count, sum) = measure(fixture.name, "point_count_sum_peer_total", || {
        let (age, amount) = restore(masked_age, masked_amount, &age_mask, &amount_mask);
        selected_aggregate(&age.ge(&threshold), &amount)
    });
    let actual_count: u8 = count.decrypt(key);
    assert_eq!(actual_count, fixture.expected_count);
    let actual_sum: u16 = sum.decrypt(key);
    assert_eq!(actual_sum, fixture.expected_sum);

    let (next_amount, rejected) = measure(fixture.name, "point_update_peer_total", || {
        let (age, amount) = restore(masked_age, masked_amount, &age_mask, &amount_mask);
        selected_update(&age.ge(&threshold), &amount, &delta)
    });
    let actual_next_amount: u16 = next_amount.decrypt(key);
    assert_eq!(actual_next_amount, fixture.expected_amount);
    assert_eq!(rejected.decrypt(key), fixture.expected_rejected);

    println!(
        "{}",
        json!({"record": "fixture_passed", "fixture": fixture.name, "proof_generated": false})
    );
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.iter().any(|arg| arg == "--help") {
        println!(
            "proof_cost [threads]\nUse 1..32 Rayon threads, default two. Reports exact native PBS counts and peer-only stage times for three public fixtures. No computation proof, network, authentication, owner preparation, or durable writeback is measured."
        );
        return Ok(());
    }
    let threads: usize = args.get(1).map_or("2", String::as_str).parse()?;
    if !(1..=32).contains(&threads) || args.len() > 2 {
        return Err("Use proof_cost [threads], with threads in 1..32".into());
    }
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()?;
    let started = Instant::now();
    let config =
        ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
            .build();
    let (key, server_key) = generate_keys(config);
    let key_generation_ms = started.elapsed().as_secs_f64() * 1000.0;
    set_server_key(server_key);
    println!(
        "{}",
        json!({
            "record": "setup", "tfhe_version": "1.8.1", "threads": threads,
            "parameters": "PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128",
            "key_generation_ms": key_generation_ms, "proof_generated": false,
            "scope": "public fixtures; peer stages only; not whole-query latency",
        })
    );

    for fixture in [
        Fixture {
            name: "nonmatch_with_local_overflow",
            age: 16,
            amount: u16::MAX,
            threshold: 17,
            delta: 1,
            expected_count: 0,
            expected_sum: 0,
            expected_amount: u16::MAX,
            expected_rejected: false,
        },
        Fixture {
            name: "equality_match_rejects_overflow",
            age: 17,
            amount: u16::MAX,
            threshold: 17,
            delta: 1,
            expected_count: 1,
            expected_sum: u16::MAX,
            expected_amount: u16::MAX,
            expected_rejected: true,
        },
        Fixture {
            name: "match_commits_exact_sum",
            age: 42,
            amount: 800,
            threshold: 17,
            delta: 5,
            expected_count: 1,
            expected_sum: 800,
            expected_amount: 805,
            expected_rejected: false,
        },
    ] {
        check_fixture(fixture, &key)?;
    }

    // Size and addition controls only. These are not authentication tags.
    let wide_a = FheUint128::encrypt(0x0123_4567_89ab_cdef_fedc_ba98_7654_3210_u128, &key);
    let wide_b = FheUint128::encrypt(17_u128, &key);
    let serialized_bytes = bincode::serialized_size(&wide_a)?;
    let wide_sum = measure("wide_integer_control", "uint128_add", || &wide_a + &wide_b);
    let actual: u128 = wide_sum.decrypt(&key);
    assert_eq!(actual, 0x0123_4567_89ab_cdef_fedc_ba98_7654_3221_u128);
    println!(
        "{}",
        json!({
            "record": "wide_integer_size", "plaintext_bits": 128,
            "bincode_serialized_bytes": serialized_bytes,
            "peak_whole_process_resident_bytes": metrics::peak_resident_bytes(),
            "proof_generated": false, "is_authenticator": false,
        })
    );
    Ok(())
}
