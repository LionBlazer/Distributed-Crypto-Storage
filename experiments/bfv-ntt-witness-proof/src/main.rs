//! Public nonsecret standalone stage driver. No SQL or operation acceptance.
use bfv_ntt_circuit::{Basis, Direction};
use bfv_ntt_witness_proof::{analyze, direction_name, prove, verify};
mod fixture;
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 || !matches!(args[0].as_str(), "security" | "prove") {
        return Err(
            "usage: bfv-ntt-witness-proof <security|prove> <forward|inverse> <basis0..9>".into(),
        );
    }
    let direction = match args[1].as_str() {
        "forward" => Direction::Forward,
        "inverse" => Direction::Inverse,
        _ => return Err("direction must be forward or inverse".into()),
    };
    let basis = Basis::new(args[2].parse()?)?;
    // Actual full-statement gate before any NTT evaluation or main witness.
    // It allocates and commits job-specific public preprocessing, as documented.
    let report = {
        let (zero_input, zero_output) = fixture::zero_statement(direction, basis)?;
        analyze(&zero_input, &zero_output)?
    };
    println!("{}", serde_json::to_string(&report)?);
    if args[0] == "security" {
        return Ok(());
    }
    let input = fixture::request(direction, basis, [0x57; 32])?;
    let generated = prove(&input)?;
    let checked = verify(&input, &generated.output, &generated.proof)?;
    if !checked.matches(&input, &generated.output) {
        return Err("checked output binding mismatch".into());
    }
    println!(
        "{}",
        serde_json::json!({
            "stage":"verified_experimental_ntt_main_witness",
            "direction":direction_name(direction),"basis_index":basis.index(),
            "coefficients":8192,"proof_bytes":generated.proof.len(),
            "prover_timings":generated.timings,"verifier_timings":checked.timings,
            "fixture":"public_nonsecret","zero_knowledge":false,
            "whole_mul_relin":false,"live_sql_grant":false
        })
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
