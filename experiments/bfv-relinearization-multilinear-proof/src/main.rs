//! Public nonsecret fixtures; no whole Relin/MulRelin/SQL acceptance.
use bfv_relinearization_circuit::Role;
use bfv_relinearization_multilinear_proof::{backend, fixture, prove, verify};
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 || !matches!(args[0].as_str(), "security" | "prove") {
        return Err(
            "usage: bfv-relinearization-multilinear-proof <security|prove> <embed|accumulate>"
                .into(),
        );
    }
    let role = match args[1].as_str() {
        "embed" => Role::Embed,
        "accumulate" => Role::AccumulateAndAdd,
        _ => return Err("unknown fixed role".into()),
    };
    println!("{}", serde_json::to_string(&backend::analyze(role)?)?);
    if args[0] == "security" {
        return Ok(());
    }
    let input = fixture::request(role, [0x57; 32], [0x73; 32])?;
    let generated = prove(&input)?;
    let checked = verify(&input, &generated.output, &generated.proof)?;
    if !checked.matches(&input, &generated.output) {
        return Err("checked stage mismatch".into());
    }
    println!(
        "{}",
        serde_json::json!({"stage":"verified_experimental_multilinear_relinearization_arithmetic","role":backend::role_name(role),"coefficients":8192,"proof_bytes":generated.proof.len(),"prover_timings":generated.timings,"verifier_timings":checked.timings,"fixture":"public_nonsecret","public_auxiliary":true,"zero_knowledge":false,"complete_relinearization":false,"whole_mul_relin":false,"key_authority":false,"live_sql_grant":false})
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1)
    }
}
