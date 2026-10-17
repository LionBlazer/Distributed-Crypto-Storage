use bfv_rns_scale_proof::{backend, fixture, prove, verify};
use bfv_scale_circuit::Role;
use std::time::Instant;

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 2 {
        return Err("usage: bfv-rns-scale-proof <security|prove> <extend|down>".into());
    }
    let role = match args[1].as_str() {
        "extend" => Role::Extend5To10,
        "down" => Role::Scale10To5,
        _ => return Err("unknown fixed role".into()),
    };
    if !matches!(args[0].as_str(), "security" | "prove") {
        return Err("unknown mode".into());
    }
    println!("{}", serde_json::to_string(&backend::analyze(role)?)?);
    if args[0] == "security" {
        return Ok(());
    }
    let request = fixture::request(role, [0x42; 32])?;
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
        serde_json::json!({ "stage":"verified_experimental_public_rns_scaling",
        "role":backend::role_name(role), "proving_ms":proving_ms,
        "verification_ms":verification_ms, "proof_bytes":generated.proof.len(),
        "input_coefficients":request.input().len(),
        "output_coefficients":generated.output.coefficients().len(),
        "public_nonsecret_fixture":true, "live_sql_grant":false,
        "full_mul_relin":false, "ntt_routing_proved":false })
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
