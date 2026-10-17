use bfv_relinearization_circuit::Role;
use bfv_relinearization_proof::{backend, fixture, prove, verify};
use std::time::Instant;
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 2 || !matches!(args[0].as_str(), "security" | "prove") {
        return Err(
            "usage: bfv-relinearization-proof <security|prove> <embed|accumulate-and-add>".into(),
        );
    }
    let role = match args[1].as_str() {
        "embed" => Role::Embed,
        "accumulate-and-add" => Role::AccumulateAndAdd,
        _ => return Err("unknown fixed role".into()),
    };
    println!("{}", serde_json::to_string(&backend::analyze(role)?)?);
    if args[0] == "security" {
        return Ok(());
    }
    let request = fixture::request(role, [0x42; 32], [0x73; 32])?;
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
        serde_json::json!({"stage":"verified_experimental_public_relinearization_arithmetic",
        "role":backend::role_name(role),"proving_ms":proving_ms,"verification_ms":verification_ms,
        "proof_bytes":generated.proof.len(),"input_coefficients":request.input().len(),
        "output_coefficients":generated.output.coefficients().len(),"public_nonsecret_fixture":true,
        "key_source_verified":false,"same_secret_authority":false,"full_relinearization":false,
        "full_mul_relin":false,"live_sql_grant":false})
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
