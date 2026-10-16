//! Nonaccepting public source-primitive research gates. Never used for SQL acceptance.
#![forbid(unsafe_code)]

mod air;
mod backend;
mod chacha;
mod primitive;
mod statement;
#[cfg(test)]
mod tests;

use std::time::Instant;

use backend::{AllocationEstimate, Backend, Error, analyze};
use p3_air::BaseAir;
use primitive::PrimitiveStatement;

fn run() -> Result<(), Error> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments.len() != 2 || !matches!(arguments[0].as_str(), "security" | "prove") {
        eprintln!(
            "usage: hiding-fri-source-primitives <security|prove> <sha256|hchacha20|chacha20>"
        );
        return Err(Error::Shape);
    }
    match arguments[1].as_str() {
        "sha256" => gate(&statement::Statement::fixture(), &arguments[0]),
        "hchacha20" => gate(
            &chacha::statement::Statement::hchacha_fixture(),
            &arguments[0],
        ),
        "chacha20" => gate(
            &chacha::statement::Statement::chacha_fixture(),
            &arguments[0],
        ),
        _ => Err(Error::Shape),
    }
}

fn gate(statement: &impl PrimitiveStatement, mode: &str) -> Result<(), Error> {
    let air = statement.air();
    let (_, report) = analyze(&air)?;
    let allocation = AllocationEstimate::for_width(air.width());
    let points = 1 + usize::from(!air.main_next_row_columns().is_empty());
    println!(
        "{{\"stage\":\"security\",\"primitive\":\"{}\",\"trace_height\":{},\"trace_width\":{},\"proof_degree_bits\":{},\"queries\":{},\"random_codewords\":{},\"opening_points\":{},\"periodic_columns\":{},\"unique_decoding_bits\":{},\"list_decoding_bits\":{},\"constraints\":{},\"degree\":{},\"quotient_chunks\":{},\"batched_functions\":{},\"trace_bytes\":{},\"masked_trace_bytes\":{},\"main_lde_bytes\":{}}}",
        statement.kind().name(),
        backend::TRACE_HEIGHT,
        air.width(),
        backend::PROOF_DEGREE_BITS,
        backend::QUERIES,
        backend::RANDOM_CODEWORDS,
        points,
        air.num_periodic_columns(),
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
        let backend = Backend::new(statement)?;
        let started = Instant::now();
        let proof = backend.prove(statement)?;
        let proving = started.elapsed();
        let started = Instant::now();
        backend.verify(statement, &proof)?;
        println!(
            "{{\"stage\":\"verified_public_primitive\",\"primitive\":\"{}\",\"proving_ms\":{},\"verification_ms\":{}}}",
            statement.kind().name(),
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
