use bfv_ntt_circuit::{Basis, Direction};
use bfv_ntt_proof::{backend, fixture, prove, verify};
use std::time::Instant;
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 3 {
        return Err("usage: bfv-ntt-proof <security|prove> <forward|inverse> <basis0..9>".into());
    }
    let direction = match args[1].as_str() {
        "forward" => Direction::Forward,
        "inverse" => Direction::Inverse,
        _ => return Err("unknown fixed direction".into()),
    };
    let basis = Basis::new(args[2].parse()?)?;
    if !matches!(args[0].as_str(), "security" | "prove") {
        return Err("unknown mode".into());
    }
    println!(
        "{}",
        serde_json::to_string(&backend::analyze(direction, basis)?)?
    );
    if args[0] == "security" {
        return Ok(());
    }
    let request = fixture::request(direction, basis, [0x42; 32])?;
    let started = Instant::now();
    let generated = prove(&request)?;
    let proving_ms = started.elapsed().as_secs_f64() * 1000.0;
    let started = Instant::now();
    let checked = verify(&request, &generated.output, &generated.proof)?;
    let verification_ms = started.elapsed().as_secs_f64() * 1000.0;
    if !checked.matches(&request, &generated.output) {
        return Err("statement mismatch".into());
    }
    println!(
        "{}",
        serde_json::json!({"stage":"verified_experimental_public_ntt",
        "direction":backend::direction_name(direction),"basis_index":basis.index(),"modulus":basis.modulus(),
        "proving_ms":proving_ms,"verification_ms":verification_ms,"proof_bytes":generated.proof.len(),
        "input_coefficients":request.input().len(),"output_coefficients":generated.output.coefficients().len(),
        "public_nonsecret_fixture":true,"live_sql_grant":false,"full_mul_relin":false})
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
