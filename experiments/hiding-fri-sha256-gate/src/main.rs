//! Nonaccepting hiding-FRI/SHA-compression research gate. Never used for SQL acceptance.
#![forbid(unsafe_code)]

mod air;
mod backend;
mod statement;
#[cfg(test)]
mod tests;

use std::time::Instant;

use air::CompressionAir;
use backend::{AllocationEstimate, Backend, Error, analyze};
use statement::Statement;

fn run() -> Result<(), Error> {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "security".into());
    if !matches!(mode.as_str(), "security" | "prove") || std::env::args().count() > 2 {
        eprintln!("usage: hiding-fri-sha256-gate [security|prove]");
        return Err(Error::Shape);
    }
    let statement = Statement::fixture();
    let (_, report) = analyze(&CompressionAir::new(&statement))?;
    let allocation = AllocationEstimate::fixed();
    println!(
        "{{\"stage\":\"security\",\"trace_height\":{},\"trace_width\":{},\"proof_degree_bits\":{},\"queries\":{},\"random_codewords\":{},\"unique_decoding_bits\":{},\"list_decoding_bits\":{},\"constraints\":{},\"degree\":{},\"quotient_chunks\":{},\"batched_functions\":{},\"trace_bytes\":{},\"masked_trace_bytes\":{},\"main_lde_bytes\":{}}}",
        backend::TRACE_HEIGHT,
        p3_sha256_air::NUM_SHA256_COLS,
        backend::PROOF_DEGREE_BITS,
        backend::QUERIES,
        backend::RANDOM_CODEWORDS,
        report.unique_decoding_bits,
        report.list_decoding_bits,
        report.constraints,
        report.degree,
        report.quotient_chunks,
        report.batched_functions,
        allocation.trace_bytes,
        allocation.masked_trace_bytes,
        allocation.main_lde_bytes,
    );
    report.require_target()?;
    if mode == "prove" {
        let backend = Backend::new(&statement)?;
        let started = Instant::now();
        let proof = backend.prove(&statement)?;
        let proving = started.elapsed();
        let started = Instant::now();
        backend.verify(&statement, &proof)?;
        println!(
            "{{\"stage\":\"verified_public_compression\",\"proving_ms\":{},\"verification_ms\":{}}}",
            proving.as_secs_f64() * 1000.0,
            started.elapsed().as_secs_f64() * 1000.0,
        );
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("nonaccepting primitive gate rejected: {error}");
        std::process::exit(1);
    }
}
